/**
 * =============================================================
 * Cursor Monitor - High Performance C++ Implementation (TCP)
 * =============================================================
 */

// 1. 必须定义 NOMINMAX 以禁用 Windows 的 min/max 宏
#define NOMINMAX

#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS

// 2. 头文件包含顺序：网络 -> Windows -> COM -> 图形 -> C++标准库
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

#include <windows.h>
#include <objidl.h>

#include <gdiplus.h>
#include <shellscalingapi.h>

#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <map>
#include <list>
#include <chrono>
#include <algorithm> // std::max, std::clamp
#include <iomanip>
#include <sstream>
#include <memory>
#include <fstream>

// 链接必要的库
#pragma comment (lib, "ws2_32.lib")
#pragma comment (lib, "gdi32.lib")
#pragma comment (lib, "user32.lib")
#pragma comment (lib, "gdiplus.lib")
#pragma comment (lib, "shcore.lib")
#pragma comment (lib, "ole32.lib")

// ==========================================
//           1. 配置与常量
// ==========================================

const int LISTEN_PORT = 5005;

// ==========================================
//           2. 工具类与日志
// ==========================================

enum class LogLevel {
    TRACE = 0,
    DEBUG = 1,
    INFO = 2,
    LOG_ERROR = 3
};

class Logger {
    std::mutex m_mutex;
    std::ofstream m_file; // 文件流
    LogLevel m_level;
public:
    static Logger& Get() {
        static Logger instance;
        return instance;
    }

    Logger() : m_level(LogLevel::DEBUG) {
        // 以追加模式打开日志文件
        m_file.open("cursor_monitor.log", std::ios::app);
        
        // 检查是否设置了环境变量来控制日志级别
        char* envLevel = nullptr;
        size_t len = 0;
        _dupenv_s(&envLevel, &len, "CURSOR_LOG_LEVEL");
        if (envLevel != nullptr) {
            std::string level(envLevel);
            if (level == "TRACE") m_level = LogLevel::TRACE;
            else if (level == "DEBUG") m_level = LogLevel::DEBUG;
            else if (level == "INFO") m_level = LogLevel::INFO;
            else if (level == "ERROR") m_level = LogLevel::LOG_ERROR;
            free(envLevel);
        }
    }

    ~Logger() {
        if (m_file.is_open()) m_file.close();
    }
    
    void SetLogLevel(LogLevel level) {
        m_level = level;
    }

    template<typename... Args>
    void Info(Args... args) {
        if (m_level <= LogLevel::INFO)
            Log("[信息] ", args...);
    }

    template<typename... Args>
    void Error(Args... args) {
        if (m_level <= LogLevel::LOG_ERROR)
            Log("[错误] ", args...);
    }

    template<typename... Args>
    void Debug(Args... args) {
        if (m_level <= LogLevel::DEBUG)
            Log("[调试] ", args...);
    }

    template<typename... Args>
    void Trace(Args... args) {
        if (m_level <= LogLevel::TRACE)
            Log("[跟踪] ", args...);
    }

private:
    template<typename... Args>
    void Log(const char* level, Args... args) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_file.is_open()) return;

        auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        std::tm tm_now;
        localtime_s(&tm_now, &now);

        m_file << std::put_time(&tm_now, "%Y-%m-%d %H:%M:%S") << " " << level;
        ((m_file << args << " "), ...);
        m_file << std::endl;
        m_file.flush(); // 确保立即写入
    }
};

// CRC32 实现
uint32_t CalculateCRC32(const std::vector<uint8_t>& data) {
    uint32_t crc = 0xFFFFFFFF;
    for (uint8_t byte : data) {
        crc ^= byte;
        for (int i = 0; i < 8; i++) {
            if (crc & 1) crc = (crc >> 1) ^ 0xEDB88320;
            else crc >>= 1;
        }
    }
    return ~crc;
}

// RAII Helpers
struct ScopedHDC {
    HDC hdc;
    HWND hwnd;
    ScopedHDC(HWND h) : hwnd(h), hdc(GetDC(h)) {}
    ~ScopedHDC() { if (hdc) ReleaseDC(hwnd, hdc); }
    operator HDC() const { return hdc; }
};

struct ScopedMemDC {
    HDC hdc;
    ScopedMemDC(HDC compat) : hdc(CreateCompatibleDC(compat)) {}
    ~ScopedMemDC() { if (hdc) DeleteDC(hdc); }
    operator HDC() const { return hdc; }
};

struct ScopedObject {
    HGDIOBJ handle;
    ScopedObject(HGDIOBJ h) : handle(h) {}
    ~ScopedObject() { if (handle) DeleteObject(handle); }
};

struct ScopedIcon {
    HICON handle;
    ScopedIcon(HICON h) : handle(h) {}
    ~ScopedIcon() { if (handle) DestroyIcon(handle); }
};

// ==========================================
//           3. 网络管理 (TCP)
// ==========================================

// 客户端会话结构
struct ClientSession {
    SOCKET socket;
    bool connected;
    uint32_t lastSentHash; // 记录该客户端最后一次收到的光标哈希，用于去重
};

class NetworkManager {
    SOCKET m_listenSocket;
    std::list<std::shared_ptr<ClientSession>> m_clients; // 所有连接的客户端
    std::mutex m_clientsMutex;
    std::atomic<bool> m_running{ true };

    // 全局 PNG 缓存 (Key: Hash, Value: PNG Data)
    // 目的：避免对同一张光标图片重复进行耗时的 GDI+ 压缩
    std::map<uint32_t, std::vector<uint8_t>> m_globalPngCache;
    std::mutex m_cacheMutex;

public:
    NetworkManager() : m_listenSocket(INVALID_SOCKET) {}

    bool Initialize() {
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            Logger::Get().Error("WSAStartup 失败");
            return false;
        }

        // 创建 TCP Socket
        m_listenSocket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
        if (m_listenSocket == INVALID_SOCKET) {
            Logger::Get().Error("创建监听套接字失败");
            return false;
        }

        int no = 0;
        setsockopt(m_listenSocket, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&no, sizeof(no));
        // 允许地址重用
        int reuse = 1;
        setsockopt(m_listenSocket, SOL_SOCKET, SO_REUSEADDR, (char*)&reuse, sizeof(reuse));

        sockaddr_in6 addr = {};
        addr.sin6_family = AF_INET6;
        addr.sin6_port = htons(LISTEN_PORT);
        addr.sin6_addr = in6addr_any;

        if (bind(m_listenSocket, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
            Logger::Get().Error("绑定端口失败:", LISTEN_PORT);
            return false;
        }
        if (listen(m_listenSocket, SOMAXCONN) == SOCKET_ERROR) {
            Logger::Get().Error("监听失败");
            return false;
        }

        Logger::Get().Info("TCP 服务端已启动，端口:", LISTEN_PORT);
        return true;
    }

    void Shutdown() {
        m_running = false;
        if (m_listenSocket != INVALID_SOCKET) {
            closesocket(m_listenSocket);
            m_listenSocket = INVALID_SOCKET;
        }
        
        // 关闭所有客户端连接
        std::lock_guard<std::mutex> lock(m_clientsMutex);
        for (auto& client : m_clients) {
            if (client->socket != INVALID_SOCKET) {
                closesocket(client->socket);
            }
        }
        m_clients.clear();
        WSACleanup();
    }

    // Accept 线程循环
    void AcceptLoop() {
        Logger::Get().Info("开始接受连接...");
        while (m_running) {
            sockaddr_in6 clientAddr;
            int len = sizeof(clientAddr);
            SOCKET clientSock = accept(m_listenSocket, (sockaddr*)&clientAddr, &len);
            
            if (clientSock != INVALID_SOCKET) {
                // 关键优化：禁用 Nagle 算法 (TCP_NODELAY)
                int yes = 1;
                setsockopt(clientSock, IPPROTO_TCP, TCP_NODELAY, (char*)&yes, sizeof(yes));

                auto session = std::make_shared<ClientSession>();
                session->socket = clientSock;
                session->connected = true;
                session->lastSentHash = 0; // 初始为0，确保新连接一定会收到一次全量包

                char ipStr[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, &clientAddr.sin6_addr, ipStr, INET6_ADDRSTRLEN);
                Logger::Get().Info("新客户端连接:", ipStr);

                std::lock_guard<std::mutex> lock(m_clientsMutex);
                m_clients.push_back(session);
            }
        }
        Logger::Get().Info("AcceptLoop 退出");
    }

    // 辅助：全局 PNG 缓存操作
    bool GetCachedPng(uint32_t hash, std::vector<uint8_t>& outPng) {
        std::lock_guard<std::mutex> lock(m_cacheMutex);
        auto it = m_globalPngCache.find(hash);
        if (it != m_globalPngCache.end()) {
            outPng = it->second;
            return true;
        }
        return false;
    }

    void CachePng(uint32_t hash, const std::vector<uint8_t>& pngData) {
        std::lock_guard<std::mutex> lock(m_cacheMutex);
        if (m_globalPngCache.size() > 200) m_globalPngCache.clear(); // 简单清理防止无限增长
        m_globalPngCache[hash] = pngData;
    }

    // 核心发送函数：智能广播
    void BroadcastCursor(uint32_t currentHash, int32_t hotX, int32_t hotY, const std::vector<uint8_t>& pngData) {
        std::lock_guard<std::mutex> lock(m_clientsMutex);
        
        // 准备数据包
        // 包结构: [Length(4)] [HotX(4)] [HotY(4)] [PNG...]
        uint32_t pngSize = (uint32_t)pngData.size();
        uint32_t bodySize = 8 + pngSize; // HotX(4) + HotY(4) + PNG Size

        std::vector<uint8_t> packet;
        packet.resize(4 + bodySize); // 4字节长度头 + 包体

        // 1. 写入包总长 (4字节)
        memcpy(packet.data(), &bodySize, 4);
        // 2. 写入 HotX, HotY
        memcpy(packet.data() + 4, &hotX, 4);
        memcpy(packet.data() + 8, &hotY, 4);
        // 3. 写入 PNG 数据
        memcpy(packet.data() + 12, pngData.data(), pngSize);

        for (auto it = m_clients.begin(); it != m_clients.end(); ) {
            auto& client = *it;
            
            if (!client->connected) {
                it = m_clients.erase(it);
                continue;
            }

            // === 核心逻辑：服务端去重 ===
            // 只有当客户端当前的哈希与最新哈希不一致时，才发送
            if (client->lastSentHash == currentHash) {
                ++it;
                continue; // 客户端已经是最新光标，跳过
            }

            // 发送数据
            int sent = send(client->socket, (const char*)packet.data(), (int)packet.size(), 0);
            
            if (sent == SOCKET_ERROR) {
                Logger::Get().Info("客户端连接断开");
                closesocket(client->socket);
                client->connected = false;
                it = m_clients.erase(it);
                continue;
            } else {
                // 更新状态：该客户端现在拥有最新的光标了
                client->lastSentHash = currentHash;
                Logger::Get().Debug("已向客户端发送光标更新, Hash:", currentHash, " Size:", packet.size());
            }
            ++it;
        }
    }
};

// ==========================================
//           4. 光标引擎
// ==========================================

class CursorEngine {
    ULONG_PTR m_gdiplusToken;
    NetworkManager& m_net;

    // COM IStream wrapper for GDI+ saving
    static int GetEncoderClsid(const WCHAR* format, CLSID* pClsid) {
        UINT  num = 0, size = 0;
        Gdiplus::GetImageEncodersSize(&num, &size);
        if (size == 0) return -1;
        
        std::vector<char> buffer(size);
        Gdiplus::ImageCodecInfo* pImageCodecInfo = (Gdiplus::ImageCodecInfo*)(buffer.data());
        Gdiplus::GetImageEncoders(num, size, pImageCodecInfo);
        
        for (UINT j = 0; j < num; ++j) {
            if (wcscmp(pImageCodecInfo[j].MimeType, format) == 0) {
                *pClsid = pImageCodecInfo[j].Clsid;
                return j;
            }
        }
        return -1;
    }

public:
    CursorEngine(NetworkManager& net) : m_net(net), m_gdiplusToken(0) {
        Gdiplus::GdiplusStartupInput gdiplusStartupInput;
        Gdiplus::GdiplusStartup(&m_gdiplusToken, &gdiplusStartupInput, NULL);
    }

    ~CursorEngine() {
        Gdiplus::GdiplusShutdown(m_gdiplusToken);
    }

    void CaptureAndSend() {
        // 1. 获取光标信息
        CURSORINFO ci = { 0 };
        ci.cbSize = sizeof(ci);
        if (!GetCursorInfo(&ci)) return;
        if (ci.flags == 0) return; // 光标隐藏

        HICON hIcon = CopyIcon(ci.hCursor);
        if (!hIcon) return;
        ScopedIcon scopedIcon(hIcon);

        ICONINFO ii;
        if (!GetIconInfo(hIcon, &ii)) return;
        ScopedObject scopedMask(ii.hbmMask);
        ScopedObject scopedColor(ii.hbmColor);

        // 获取光标尺寸
        BITMAP bmp;
        int w = 32, h = 32;
        if (ii.hbmColor && GetObject(ii.hbmColor, sizeof(bmp), &bmp)) {
            w = bmp.bmWidth; h = bmp.bmHeight;
        }
        else if (ii.hbmMask && GetObject(ii.hbmMask, sizeof(bmp), &bmp)) {
            w = bmp.bmWidth; h = bmp.bmHeight / (ii.hbmColor ? 1 : 2);
        }
        if (w > 512) w = 512;
        if (h > 512) h = 512;

        // 2. 准备绘制环境
        HDC hdcScreen = GetDC(NULL);
        ScopedMemDC dcMem(hdcScreen);
        ReleaseDC(NULL, hdcScreen);

        // 32-bit DIB 结构
        struct {
            BITMAPINFOHEADER bmiHeader;
            DWORD mask[3];
        } bmi = { 0 };
        bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
        bmi.bmiHeader.biWidth = w;
        bmi.bmiHeader.biHeight = -h; // Top-down
        bmi.bmiHeader.biPlanes = 1;
        bmi.bmiHeader.biBitCount = 32;
        bmi.bmiHeader.biCompression = BI_RGB;

        void* pBitsB = nullptr;
        void* pBitsW = nullptr;

        HBITMAP hBmpB = CreateDIBSection(dcMem, (BITMAPINFO*)&bmi, DIB_RGB_COLORS, &pBitsB, NULL, 0);
        HBITMAP hBmpW = CreateDIBSection(dcMem, (BITMAPINFO*)&bmi, DIB_RGB_COLORS, &pBitsW, NULL, 0);
        ScopedObject scBmpB(hBmpB);
        ScopedObject scBmpW(hBmpW);

        // 绘制两个版本用于 XOR 检测
        SelectObject(dcMem, hBmpB);
        RECT rc = { 0, 0, w, h };
        FillRect(dcMem, &rc, (HBRUSH)GetStockObject(BLACK_BRUSH));
        DrawIconEx(dcMem, 0, 0, hIcon, w, h, 0, NULL, DI_NORMAL);

        SelectObject(dcMem, hBmpW);
        FillRect(dcMem, &rc, (HBRUSH)GetStockObject(WHITE_BRUSH));
        DrawIconEx(dcMem, 0, 0, hIcon, w, h, 0, NULL, DI_NORMAL);

        // 3. 像素处理
        uint32_t* pxB = (uint32_t*)pBitsB;
        uint32_t* pxW = (uint32_t*)pBitsW;
        int numPixels = w * h;
        std::vector<uint32_t> outlinedPixels(numPixels);
        std::vector<bool> xorMask(numPixels, false);

        for (int i = 0; i < numPixels; ++i) {
            uint8_t bb = (pxB[i] & 0xFF);
            uint8_t bg = ((pxB[i] >> 8) & 0xFF);
            uint8_t br = ((pxB[i] >> 16) & 0xFF);
            uint8_t wb = (pxW[i] & 0xFF);
            uint8_t wg = ((pxW[i] >> 8) & 0xFF);
            uint8_t wr = ((pxW[i] >> 16) & 0xFF);

            int dr = (int)wr - br;
            int dg = (int)wg - bg;
            int db = (int)wb - bb;
            int maxDiff = std::max({ dr, dg, db });
            uint8_t alpha = (uint8_t)(std::clamp(255 - maxDiff, 0, 255));

            int lumB = (br * 299 + bg * 587 + bb * 114) / 1000;
            int lumW = (wr * 299 + wg * 587 + wb * 114) / 1000;
            bool isXor = (lumB > lumW + 50);

            if (isXor) {
                xorMask[i] = true;
                outlinedPixels[i] = 0xFFFFFFFF; // White
            } else {
                outlinedPixels[i] = (alpha << 24) | (br << 16) | (bg << 8) | bb;
            }
        }

        for (int y = 0; y < h; ++y) {
            for (int x = 0; x < w; ++x) {
                int idx = y * w + x;
                if (!xorMask[idx]) {
                    bool neighborIsXor = false;
                    if (y > 0     && xorMask[(y - 1) * w + x]) neighborIsXor = true;
                    if (!neighborIsXor && y < h - 1 && xorMask[(y + 1) * w + x]) neighborIsXor = true;
                    if (!neighborIsXor && x > 0     && xorMask[y * w + (x - 1)]) neighborIsXor = true;
                    if (!neighborIsXor && x < w - 1 && xorMask[y * w + (x + 1)]) neighborIsXor = true;
                    if (neighborIsXor) outlinedPixels[idx] = 0xFF000000; // Black Outline
                }
            }
        }

        // ==========================================
        //         新逻辑 (TCP + 服务端缓存优化)
        // ==========================================

        // 4. 计算内容哈希 (用于内部去重和缓存)
        const uint8_t* rawDataPtr = reinterpret_cast<const uint8_t*>(outlinedPixels.data());
        size_t rawDataSize = outlinedPixels.size() * sizeof(uint32_t);
        std::vector<uint8_t> rawBytes(rawDataPtr, rawDataPtr + rawDataSize);
        uint32_t contentHash = CalculateCRC32(rawBytes);

        // 5. 获取或生成 PNG
        std::vector<uint8_t> pngToSend;
        
        // 查全局缓存
        if (!m_net.GetCachedPng(contentHash, pngToSend)) {
            // 缓存未命中：压缩 PNG
            Gdiplus::Bitmap gdiBitmap(w, h, PixelFormat32bppARGB);
            Gdiplus::BitmapData data;
            Gdiplus::Rect rect(0, 0, w, h);

            gdiBitmap.LockBits(&rect, Gdiplus::ImageLockModeWrite, PixelFormat32bppARGB, &data);
            memcpy(data.Scan0, outlinedPixels.data(), rawDataSize);
            gdiBitmap.UnlockBits(&data);

            IStream* pStream = NULL;
            if (CreateStreamOnHGlobal(NULL, TRUE, &pStream) == S_OK) {
                CLSID pngClsid;
                GetEncoderClsid(L"image/png", &pngClsid);
                gdiBitmap.Save(pStream, &pngClsid, NULL);

                STATSTG stg;
                pStream->Stat(&stg, STATFLAG_NONAME);
                pngToSend.resize(stg.cbSize.LowPart);

                LARGE_INTEGER seekPos = { 0 };
                pStream->Seek(seekPos, STREAM_SEEK_SET, NULL);
                ULONG bytesRead = 0;
                pStream->Read(pngToSend.data(), (ULONG)pngToSend.size(), &bytesRead);
                pStream->Release();

                m_net.CachePng(contentHash, pngToSend);
            }
        }

        // 6. 广播 (智能发送)
        if (!pngToSend.empty()) {
            m_net.BroadcastCursor(contentHash, ii.xHotspot, ii.yHotspot, pngToSend);
        }
    }
};

// ==========================================
//           5. 主程序逻辑
// ==========================================

NetworkManager g_net;
std::unique_ptr<CursorEngine> g_cursorEngine;

// 并发控制
std::condition_variable g_cvCursorChanged;
std::mutex g_mutexCursor;
bool g_cursorChanged = false;
bool g_shouldExit = false;

// 钩子回调
void CALLBACK WinEventProc(HWINEVENTHOOK hWinEventHook, DWORD event, HWND hwnd,
                          LONG idObject, LONG idChild, DWORD dwEventThread, DWORD dwmsEventTime)
{
    if (idObject == OBJID_CURSOR) {
        // 通知工作线程
        std::lock_guard<std::mutex> lock(g_mutexCursor);
        g_cursorChanged = true;
        g_cvCursorChanged.notify_one();
    }
}

// 图像处理工作线程
void WorkerThread() {
    Logger::Get().Info("工作线程已启动");
    while (!g_shouldExit) {
        {
            std::unique_lock<std::mutex> lock(g_mutexCursor);
            g_cvCursorChanged.wait(lock, [] { return g_cursorChanged || g_shouldExit; });
            if (g_shouldExit) break;
            g_cursorChanged = false;
        }

        g_cursorEngine->CaptureAndSend();
    }
    Logger::Get().Info("工作线程已结束");
}

// TCP Accept 线程
void AcceptThreadFunc() {
    g_net.AcceptLoop();
}

void ShowUsage() {
    std::cout << "用法: cursor_monitor [选项]\n"
              << "选项:\n"
              << "  -l, --log-level LVL 设置日志级别 (TRACE, DEBUG, INFO, ERROR)\n";
}

LogLevel ParseLogLevel(const std::string& levelStr) {
    if (levelStr == "TRACE") return LogLevel::TRACE;
    if (levelStr == "DEBUG") return LogLevel::DEBUG;
    if (levelStr == "INFO") return LogLevel::INFO;
    if (levelStr == "ERROR") return LogLevel::LOG_ERROR;
    return LogLevel::DEBUG;
}

int main(int argc, char* argv[]) {
    LogLevel logLevel = LogLevel::DEBUG;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            ShowUsage();
            return 0;
        } else if (arg == "-l" || arg == "--log-level") {
            if (i + 1 < argc) {
                logLevel = ParseLogLevel(argv[++i]);
            }
        }
    }
    
    Logger::Get().SetLogLevel(logLevel);
    Logger::Get().Info("======= 程序启动 (TCP Mode) =======");

    SetProcessDpiAwareness(PROCESS_PER_MONITOR_DPI_AWARE);

    // 1. 初始化网络
    if (!g_net.Initialize()) {
        Logger::Get().Error("网络初始化失败");
        return 1;
    }

    g_cursorEngine = std::make_unique<CursorEngine>(g_net);

    // 2. 启动线程
    std::thread tWorker(WorkerThread);
    std::thread tNet(AcceptThreadFunc);

    // 3. 安装钩子
    HWINEVENTHOOK hHook = SetWinEventHook(
        EVENT_OBJECT_NAMECHANGE, EVENT_OBJECT_NAMECHANGE,
        NULL, WinEventProc, 0, 0, WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS
    );

    if (!hHook) {
        Logger::Get().Error("安装 WinEventHook 失败");
        return 1;
    }
    
    Logger::Get().Info("服务运行中...");
    
    // 4. 消息循环
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    // 5. 清理退出
    Logger::Get().Info("正在关闭...");
    g_shouldExit = true;
    g_cvCursorChanged.notify_all();
    
    g_net.Shutdown(); // 关闭 Socket 以中断 Accept
    
    if (tWorker.joinable()) tWorker.join();
    if (tNet.joinable()) tNet.join();
    
    UnhookWinEvent(hHook);
    
    Logger::Get().Info("======= 程序退出 =======");
    return 0;
}