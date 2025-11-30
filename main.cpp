/**
 * =============================================================
 * Cursor Monitor - High Performance C++ Implementation (Fixed)
 * =============================================================
 */

#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS

// 1. Winsock2 必须在 Windows.h 之前包含，防止重定义冲突
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

// 2. Windows 核心
#include <windows.h>

#include <objidl.h>

// 4. GDI+ 和其他图形库
#include <gdiplus.h>
#include <shellscalingapi.h>

// 5. C++ 标准库
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
#include <algorithm>
#include <iomanip>
#include <sstream>
#include <memory>
#include <fstream> // 用于文件日志

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
const double CLIENT_TIMEOUT_SEC = 30.0;
const double KEEPALIVE_INTERVAL_SEC = 1.0;
const int LRU_CACHE_SIZE = 100;
#define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)

// ==========================================
//           2. 工具类与日志
// ==========================================


class Logger {
    std::mutex m_mutex;
    std::ofstream m_file; // 文件流
public:
    static Logger& Get() {
        static Logger instance;
        return instance;
    }

    Logger() {
        // 以追加模式打开日志文件
        m_file.open("cursor_monitor.log", std::ios::app);
    }

    ~Logger() {
        if (m_file.is_open()) m_file.close();
    }

    template<typename... Args>
    void Info(Args... args) {
    Log("[信息] ", args...);
    }

    template<typename... Args>
    void Error(Args... args) {
    Log("[错误] ", args...);
    }

    template<typename... Args>
    void Debug(Args... args) {
         Log("[调试] ", args...);
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

// CRC32 实现 (zlib 等效)
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
//           3. 网络与客户端管理
// ==========================================

struct ClientInfo {
    sockaddr_in6 addr;
    std::chrono::steady_clock::time_point last_activity;

    std::string GetAddrStr() const {
        char str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &addr.sin6_addr, str, INET6_ADDRSTRLEN);
        return std::string(str) + ":" + std::to_string(ntohs(addr.sin6_port));
    }
};

// Socket 管理器
class NetworkManager {
    SOCKET m_socket;
    std::map<std::string, ClientInfo> m_clients;
    std::mutex m_clientsMutex;
    std::atomic<bool> m_running{ true };

public:
    NetworkManager() : m_socket(INVALID_SOCKET) {}

    bool Initialize() {
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) return false;

        // IPv6 Dual Stack
        m_socket = socket(AF_INET6, SOCK_DGRAM, 0);
        if (m_socket == INVALID_SOCKET) return false;

        int no = 0;
        setsockopt(m_socket, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&no, sizeof(no));

        // 绑定
        sockaddr_in6 addr = {};
        addr.sin6_family = AF_INET6;
        addr.sin6_port = htons(LISTEN_PORT);
        addr.sin6_addr = in6addr_any;

        if (bind(m_socket, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
            Logger::Get().Error("绑定端口失败:", LISTEN_PORT, "可能已被占用。");
            return false;
        }

        // 修复 UDP ConnectionReset 错误 (WinError 10054)
        DWORD bytesReturned = 0;
        BOOL bNewBehavior = FALSE;
        WSAIoctl(m_socket, SIO_UDP_CONNRESET, &bNewBehavior, sizeof(bNewBehavior), NULL, 0, &bytesReturned, NULL, NULL);

        // 设置非阻塞模式
        u_long mode = 1;
        ioctlsocket(m_socket, FIONBIO, &mode);

        Logger::Get().Info("网络已在端口启动", LISTEN_PORT);
        return true;
    }

    void Shutdown() {
        m_running = false;
        if (m_socket != INVALID_SOCKET) closesocket(m_socket);
        WSACleanup();
    }

    // 返回 true 表示是新客户端或重启的客户端
    bool HandleClientMessage(const std::string& msg, const sockaddr_in6& clientAddr) {
        char ipStr[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &clientAddr.sin6_addr, ipStr, INET6_ADDRSTRLEN);
        std::string ipKey(ipStr);
        std::string fullKey = ipKey + ":" + std::to_string(ntohs(clientAddr.sin6_port));

        std::lock_guard<std::mutex> lock(m_clientsMutex);

        if (msg == "CURSOR_HELLO") {
            // 清理来自同一 IP 但不同端口的旧连接
            auto it = m_clients.begin();
            while (it != m_clients.end()) {
                char existingIp[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, &it->second.addr.sin6_addr, existingIp, INET6_ADDRSTRLEN);
                if (ipKey == existingIp && it->first != fullKey) {
                    Logger::Get().Info("Client reconnected (new port), removing old:", it->first);
                    it = m_clients.erase(it);
                }
                else {
                    ++it;
                }
            }

            bool isNew = m_clients.find(fullKey) == m_clients.end();
            m_clients[fullKey] = { clientAddr, std::chrono::steady_clock::now() };
            if (isNew) Logger::Get().Info("新客户端已连接:", fullKey);
            
            return true; // 只要是 HELLO，都触发全量刷新
        }
        else if (msg == "KEEPALIVE") {
            if (m_clients.count(fullKey)) {
                m_clients[fullKey].last_activity = std::chrono::steady_clock::now();
            }
        }
        return false;
    }

    void BroadcastPacket(const std::vector<uint8_t>& packet) {
        std::lock_guard<std::mutex> lock(m_clientsMutex);
        for (const auto& [key, client] : m_clients) {
            sendto(m_socket, (const char*)packet.data(), (int)packet.size(), 0, (sockaddr*)&client.addr, sizeof(client.addr));
        }
    }

    void CleanUpTimeouts() {
        std::lock_guard<std::mutex> lock(m_clientsMutex);
        auto now = std::chrono::steady_clock::now();
        auto it = m_clients.begin();
        while (it != m_clients.end()) {
            std::chrono::duration<double> elapsed = now - it->second.last_activity;
            if (elapsed.count() > CLIENT_TIMEOUT_SEC) {
                Logger::Get().Info("客户端超时:", it->first);
                it = m_clients.erase(it);
            } else {
                ++it;
            }
        }
    }

    void SendHeartbeats() {
        // 心跳包 (Type 2)
        uint8_t hb = 2;
        BroadcastPacket({ hb });
    }

    SOCKET GetSocket() const { return m_socket; }
    bool HasClients() {
        std::lock_guard<std::mutex> lock(m_clientsMutex);
        return !m_clients.empty();
    }
};

// ==========================================
//           4. 图像处理与缓存
// ==========================================

// LRU 缓存
class ImageCache {
    struct CacheEntry {
        uint32_t hash;
        std::list<uint32_t>::iterator lruIterator;
    };
    std::list<uint32_t> m_lruList;
    std::map<uint32_t, CacheEntry> m_map;
    std::mutex m_lock;

public:
    // 返回 true 如果是新的
    bool Add(uint32_t hash) {
        std::lock_guard<std::mutex> lock(m_lock);
        auto it = m_map.find(hash);
        if (it != m_map.end()) {
            // 已存在，移动到头部
            m_lruList.erase(it->second.lruIterator);
            m_lruList.push_front(hash);
            it->second.lruIterator = m_lruList.begin();
            return false;
        }

        // 新项
        if (m_lruList.size() >= LRU_CACHE_SIZE) {
            uint32_t last = m_lruList.back();
            m_lruList.pop_back();
            m_map.erase(last);
        }

        m_lruList.push_front(hash);
        m_map[hash] = { hash, m_lruList.begin() };
        return true;
    }

    void Clear() {
        std::lock_guard<std::mutex> lock(m_lock);
        m_map.clear();
        m_lruList.clear();
    }
};

class CursorEngine {
    ULONG_PTR m_gdiplusToken;
    ImageCache m_cache;
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

    void ResetCache() {
        m_cache.Clear();
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

        // 限制尺寸
        if (w > 512) w = 512;
        if (h > 512) h = 512;

        // 2. 准备黑白背景绘制 (模拟 Python 中的 NumPy 异或检测)
        // 创建内存 DC
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

        // 绘制黑色背景
        SelectObject(dcMem, hBmpB);
        RECT rc = { 0, 0, w, h };
        FillRect(dcMem, &rc, (HBRUSH)GetStockObject(BLACK_BRUSH));
        DrawIconEx(dcMem, 0, 0, hIcon, w, h, 0, NULL, DI_NORMAL);

        // 绘制白色背景
        SelectObject(dcMem, hBmpW);
        FillRect(dcMem, &rc, (HBRUSH)GetStockObject(WHITE_BRUSH));
        DrawIconEx(dcMem, 0, 0, hIcon, w, h, 0, NULL, DI_NORMAL);

        // 3. 像素处理
        // 注意：GDI DIB 是 BGRA 格式
        uint32_t* pxB = (uint32_t*)pBitsB;
        uint32_t* pxW = (uint32_t*)pBitsW;
        int numPixels = w * h;
        std::vector<uint32_t> finalPixels(numPixels);

        // C++ 的直接内存访问比 Python 快得多
        for (int i = 0; i < numPixels; ++i) {
            uint8_t bb = (pxB[i] & 0xFF);
            uint8_t bg = ((pxB[i] >> 8) & 0xFF);
            uint8_t br = ((pxB[i] >> 16) & 0xFF);

            uint8_t wb = (pxW[i] & 0xFF);
            uint8_t wg = ((pxW[i] >> 8) & 0xFF);
            uint8_t wr = ((pxW[i] >> 16) & 0xFF);

            // 计算 Alpha: (White - Black) 的反向
            // 简单化：Alpha = 255 - (Diff)
            int dr = (int)wr - br;
            int dg = (int)wg - bg;
            int db = (int)wb - bb;

            // 真实的 diff 应该是 R_w - R_b
            int maxDiff = std::max({ dr, dg, db });
            uint8_t alpha = (uint8_t)(std::clamp(255 - maxDiff, 0, 255));

            // 检测 XOR 区域 (Black 背景比 White 背景亮)
            bool isXor = ((int)br > (int)wr + 50) || ((int)bg > (int)wg + 50) || ((int)bb > (int)wb + 50);

            if (isXor) {
                // XOR 变为白色，全不透明
                finalPixels[i] = 0xFFFFFFFF; // ARGB: White
            }
            else {
                // 正常颜色使用黑色背景的颜色
                finalPixels[i] = (alpha << 24) | (br << 16) | (bg << 8) | bb;
            }
        }

        // 4. 使用 GDI+ 生成 PNG
        Gdiplus::Bitmap gdiBitmap(w, h, PixelFormat32bppARGB);
        Gdiplus::BitmapData data;
        Gdiplus::Rect rect(0, 0, w, h);

        gdiBitmap.LockBits(&rect, Gdiplus::ImageLockModeWrite, PixelFormat32bppARGB, &data);
        memcpy(data.Scan0, finalPixels.data(), numPixels * 4);
        gdiBitmap.UnlockBits(&data);

        IStream* pStream = NULL;
        if (CreateStreamOnHGlobal(NULL, TRUE, &pStream) != S_OK) return;

        CLSID pngClsid;
        GetEncoderClsid(L"image/png", &pngClsid);
        gdiBitmap.Save(pStream, &pngClsid, NULL);

        // 获取 PNG 数据
        STATSTG stg;
        pStream->Stat(&stg, STATFLAG_NONAME);
        std::vector<uint8_t> pngData(stg.cbSize.LowPart);

        LARGE_INTEGER seekPos = { 0 };
        pStream->Seek(seekPos, STREAM_SEEK_SET, NULL);
        ULONG bytesRead = 0;
        pStream->Read(pngData.data(), pngData.size(), &bytesRead);
        pStream->Release();

        // 5. 缓存与发送
        uint32_t hash = CalculateCRC32(pngData);
        bool isNew = m_cache.Add(hash);

        // Packet Structure:
        // Type (1 byte) | Hash (8 bytes) | HotX (4 bytes) | HotY (4 bytes) | [Data]
        // Note: Python struct uses 'Q' for Hash (8 bytes unsigned long long)
        // But our CRC32 is 4 bytes. To match Python's 'Q', we cast or pad.
        // Python code: struct.pack('<BQii', 0/1, hash, hot_x, hot_y)

        std::vector<uint8_t> packet;
        packet.reserve(1 + 8 + 4 + 4 + (isNew ? pngData.size() : 0));

        packet.push_back(isNew ? 0 : 1); // Type 0=New, 1=Cached

        uint64_t hash64 = hash;
        packet.insert(packet.end(), (uint8_t*)&hash64, (uint8_t*)&hash64 + 8);

        int32_t hotX = (int32_t)ii.xHotspot;
        int32_t hotY = (int32_t)ii.yHotspot;
        packet.insert(packet.end(), (uint8_t*)&hotX, (uint8_t*)&hotX + 4);
        packet.insert(packet.end(), (uint8_t*)&hotY, (uint8_t*)&hotY + 4);

        if (isNew) {
            packet.insert(packet.end(), pngData.begin(), pngData.end());
            Logger::Get().Debug("发送了新的光标图像，大小:", pngData.size());
        }

        m_net.Broadcast(packet);
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
    Logger::Get().Info("工作线程已启动。");
    while (!g_shouldExit) {
        {
            std::unique_lock<std::mutex> lock(g_mutexCursor);
            g_cvCursorChanged.wait(lock, [] { return g_cursorChanged || g_shouldExit; });
            if (g_shouldExit) break;
            g_cursorChanged = false;
        }

        if (g_net.HasClients()) {
            g_cursorEngine->CaptureAndSend();
        }
    }
}

// 网络接收线程
void NetworkThread() {
    Logger::Get().Info("网络线程已启动。");
    char buffer[1024];
    sockaddr_in6 clientAddr;
    int addrLen = sizeof(clientAddr);
    
    auto lastKeepAlive = std::chrono::steady_clock::now();
    auto lastCleanup = std::chrono::steady_clock::now();

    while (!g_shouldExit) {
        // 1. 处理传入数据
        int received = recvfrom(g_net.GetSocket(), buffer, sizeof(buffer) - 1, 0, (sockaddr*)&clientAddr, &addrLen);

        if (received > 0) {
            buffer[received] = '\0';
            std::string msg(buffer);

            // 简单的 trim
            msg.erase(msg.find_last_not_of(" \n\r\t") + 1);

            bool isReset = g_net.HandleClientMessage(msg, clientAddr);
            if (isReset) {
                // 如果是新连接，清空缓存并强制触发一次发送
                g_cursorEngine->ResetCache();

                std::lock_guard<std::mutex> lock(g_mutexCursor);
                g_cursorChanged = true;
                g_cvCursorChanged.notify_one();
            }
        }
        else {
            int err = WSAGetLastError();
            if (err != WSAEWOULDBLOCK) {
                // Ignore ConnReset usually, handled by IOCTL but good to know
            }
        }

        // 2. 定时任务
        auto now = std::chrono::steady_clock::now();

        // 清理超时
        if (std::chrono::duration_cast<std::chrono::seconds>(now - lastCleanup).count() > 5) {
            g_net.CleanUpTimeouts();
            lastCleanup = now;
        }

        // 发送心跳
        std::chrono::duration<double> keepAliveElapsed = now - lastKeepAlive;
        if (keepAliveElapsed.count() > KEEPALIVE_INTERVAL_SEC) {
            g_net.SendHeartbeats();
            lastKeepAlive = now;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

int main() {
    // 1. 高 DPI 设置
    SetProcessDpiAwareness(PROCESS_PER_MONITOR_DPI_AWARE);

    // 2. 初始化网络
    if (!g_net.Initialize()) {
        return 1;
    }

    g_cursorEngine = std::make_unique<CursorEngine>(g_net);

    // 3. 启动线程
    std::thread tWorker(WorkerThread);
    std::thread tNet(NetworkThread);

    // 4. 安装钩子
    HWINEVENTHOOK hHook = SetWinEventHook(
        EVENT_OBJECT_NAMECHANGE, EVENT_OBJECT_NAMECHANGE,
        NULL, WinEventProc, 0, 0, WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS
    );

    if (!hHook) {
        Logger::Get().Error("安装 WinEventHook 失败！");
        return 1;
    }
    
    Logger::Get().Info("系统初始化完成。按 Ctrl+C 退出（如果在控制台中）。");
    
    // 5. 消息循环 (Message Loop) - 必须存在以保持 Hook 活跃
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    // 6. 清理退出
    Logger::Get().Info("正在关闭...");
    g_shouldExit = true;
    g_cvCursorChanged.notify_all();
    
    if (tWorker.joinable()) tWorker.join();
    if (tNet.joinable()) tNet.join();
    
    UnhookWinEvent(hHook);
    g_net.Shutdown();
    
    return 0;
}