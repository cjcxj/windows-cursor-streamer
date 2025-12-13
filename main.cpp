/**
 * =============================================================
 * Cursor Monitor - High Performance C++ Implementation (TCP)
 * Integrated with Advanced Python Extraction Logic
 * - RAW MODE: No Outlines
 * - Auto Hotspot Scaling
 * - Full Logging Support (+ PNG File Size)
 * =============================================================
 */

// 1. 必须定义 NOMINMAX 以禁用 Windows 的 min/max 宏
#define NOMINMAX

#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS

// 2. 头文件包含顺序
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
#include <algorithm>
#include <iomanip>
#include <sstream>
#include <memory>
#include <fstream>

#pragma comment (lib, "ws2_32.lib")
#pragma comment (lib, "gdi32.lib")
#pragma comment (lib, "user32.lib")
#pragma comment (lib, "gdiplus.lib")
#pragma comment (lib, "shcore.lib")
#pragma comment (lib, "ole32.lib")
#pragma comment (lib, "advapi32.lib") 

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
    std::ofstream m_file;
    LogLevel m_level;
public:
    static Logger& Get() {
        static Logger instance;
        return instance;
    }

    Logger() : m_level(LogLevel::INFO) {
        m_file.open("cursor_monitor.log", std::ios::app);
        
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

    ~Logger() { if (m_file.is_open()) m_file.close(); }
    
    void SetLogLevel(LogLevel level) { m_level = level; }

    template<typename... Args> void Info(Args... args) { if (m_level <= LogLevel::INFO) Log("[信息] ", args...); }
    template<typename... Args> void Error(Args... args) { if (m_level <= LogLevel::LOG_ERROR) Log("[错误] ", args...); }
    template<typename... Args> void Debug(Args... args) { if (m_level <= LogLevel::DEBUG) Log("[调试] ", args...); }
    template<typename... Args> void Trace(Args... args) { if (m_level <= LogLevel::TRACE) Log("[跟踪] ", args...); }

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
        m_file.flush();
    }
};

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

struct ScopedHDC {
    HDC hdc; HWND hwnd;
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

std::condition_variable g_cvCursorChanged;
std::mutex g_mutexCursor;
bool g_cursorChanged = false;

// ==========================================
//           3. 网络管理 (TCP)
// ==========================================

struct ClientSession {
    SOCKET socket;
    bool connected;
    uint32_t lastSentHash;
};

class NetworkManager {
    SOCKET m_listenSocket;
    std::list<std::shared_ptr<ClientSession>> m_clients;
    std::mutex m_clientsMutex;
    std::atomic<bool> m_running{ true };
    std::map<uint32_t, std::vector<uint8_t>> m_globalPngCache;
    std::mutex m_cacheMutex;

public:
    NetworkManager() : m_listenSocket(INVALID_SOCKET) {}

    bool Initialize() {
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) return false;
        m_listenSocket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
        if (m_listenSocket == INVALID_SOCKET) return false;
        int no = 0; setsockopt(m_listenSocket, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&no, sizeof(no));
        int reuse = 1; setsockopt(m_listenSocket, SOL_SOCKET, SO_REUSEADDR, (char*)&reuse, sizeof(reuse));
        sockaddr_in6 addr = {};
        addr.sin6_family = AF_INET6; addr.sin6_port = htons(LISTEN_PORT); addr.sin6_addr = in6addr_any;
        if (bind(m_listenSocket, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) return false;
        if (listen(m_listenSocket, SOMAXCONN) == SOCKET_ERROR) return false;
        Logger::Get().Info("TCP 服务端已启动，端口:", LISTEN_PORT);
        return true;
    }

    void Shutdown() {
        m_running = false;
        if (m_listenSocket != INVALID_SOCKET) { closesocket(m_listenSocket); m_listenSocket = INVALID_SOCKET; }
        std::lock_guard<std::mutex> lock(m_clientsMutex);
        for (auto& client : m_clients) if (client->socket != INVALID_SOCKET) closesocket(client->socket);
        m_clients.clear();
        WSACleanup();
    }

    void AcceptLoop() {
        Logger::Get().Info("开始接受连接...");
        while (m_running) {
            sockaddr_in6 clientAddr; int len = sizeof(clientAddr);
            SOCKET clientSock = accept(m_listenSocket, (sockaddr*)&clientAddr, &len);
            if (clientSock != INVALID_SOCKET) {
                int yes = 1; setsockopt(clientSock, IPPROTO_TCP, TCP_NODELAY, (char*)&yes, sizeof(yes));
                auto session = std::make_shared<ClientSession>();
                session->socket = clientSock; session->connected = true; session->lastSentHash = 0;
                char ipStr[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, &clientAddr.sin6_addr, ipStr, INET6_ADDRSTRLEN);
                Logger::Get().Info("新客户端连接:", ipStr);
                { std::lock_guard<std::mutex> lock(m_clientsMutex); m_clients.push_back(session); }
                { std::lock_guard<std::mutex> lock(g_mutexCursor); g_cursorChanged = true; }
                g_cvCursorChanged.notify_one();
            }
        }
    }

    bool GetCachedPng(uint32_t hash, std::vector<uint8_t>& outPng) {
        std::lock_guard<std::mutex> lock(m_cacheMutex);
        auto it = m_globalPngCache.find(hash);
        if (it != m_globalPngCache.end()) { outPng = it->second; return true; }
        return false;
    }

    void CachePng(uint32_t hash, const std::vector<uint8_t>& pngData) {
        std::lock_guard<std::mutex> lock(m_cacheMutex);
        if (m_globalPngCache.size() > 200) m_globalPngCache.clear();
        m_globalPngCache[hash] = pngData;
    }

    void BroadcastCursor(uint32_t currentHash, int32_t hotX, int32_t hotY, const std::vector<uint8_t>& pngData) {
        std::lock_guard<std::mutex> lock(m_clientsMutex);
        uint32_t pngSize = (uint32_t)pngData.size();
        uint32_t bodySize = 8 + pngSize;
        std::vector<uint8_t> packet(4 + bodySize);
        memcpy(packet.data(), &bodySize, 4);
        memcpy(packet.data() + 4, &hotX, 4);
        memcpy(packet.data() + 8, &hotY, 4);
        memcpy(packet.data() + 12, pngData.data(), pngSize);

        for (auto it = m_clients.begin(); it != m_clients.end(); ) {
            auto& client = *it;
            if (!client->connected) { it = m_clients.erase(it); continue; }
            if (client->lastSentHash == currentHash) { ++it; continue; }
            if (send(client->socket, (const char*)packet.data(), (int)packet.size(), 0) == SOCKET_ERROR) {
                closesocket(client->socket); client->connected = false; it = m_clients.erase(it); continue;
            } else {
                client->lastSentHash = currentHash;
                Logger::Get().Debug("向客户端同步光标数据, Hash:", currentHash);
            }
            ++it;
        }
    }
};

// ==========================================
//           4. 光标引擎
// ==========================================

typedef BOOL(WINAPI* GETCURSORFRAMEINFO)(HCURSOR, DWORD, DWORD, DWORD*, DWORD*);

class CursorEngine {
    ULONG_PTR m_gdiplusToken;
    NetworkManager& m_net;

    HCURSOR mLastCursor = NULL;
    uint32_t mLastHash = 0;
    std::vector<uint8_t> mLastPngData;
    int32_t mLastHotX = 0;
    int32_t mLastHotY = 0;

    HMODULE m_hUser32 = NULL;
    GETCURSORFRAMEINFO m_pGetCursorFrameInfo = NULL;

    static int GetEncoderClsid(const WCHAR* format, CLSID* pClsid) {
        UINT  num = 0, size = 0;
        Gdiplus::GetImageEncodersSize(&num, &size);
        if (size == 0) return -1;
        std::vector<char> buffer(size);
        Gdiplus::ImageCodecInfo* pImageCodecInfo = (Gdiplus::ImageCodecInfo*)(buffer.data());
        Gdiplus::GetImageEncoders(num, size, pImageCodecInfo);
        for (UINT j = 0; j < num; ++j) {
            if (wcscmp(pImageCodecInfo[j].MimeType, format) == 0) { *pClsid = pImageCodecInfo[j].Clsid; return j; }
        }
        return -1;
    }

    int GetTargetSizeFromRegistry() {
        HKEY hKey; int size = 32;
        if (RegOpenKeyExA(HKEY_CURRENT_USER, "Control Panel\\Cursors", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            DWORD dwType = REG_DWORD, dwSize = sizeof(DWORD), dwValue = 0;
            if (RegQueryValueExA(hKey, "CursorBaseSize", NULL, &dwType, (LPBYTE)&dwValue, &dwSize) == ERROR_SUCCESS) size = (int)dwValue;
            RegCloseKey(hKey);
        }
        return std::clamp(size, 32, 256);
    }

    std::pair<DWORD, DWORD> GetCursorAnimationDetails(HCURSOR hCursor) {
        if (!m_pGetCursorFrameInfo) return { 1, 0 };
        DWORD frameCount = 0, frameRate = 0;
        if (m_pGetCursorFrameInfo(hCursor, 0, 0, &frameRate, &frameCount)) return { frameCount == 0 ? 1 : frameCount, frameRate };
        return { 1, 0 };
    }

public:
    CursorEngine(NetworkManager& net) : m_net(net), m_gdiplusToken(0) {
        Gdiplus::GdiplusStartupInput gdiplusStartupInput;
        Gdiplus::GdiplusStartup(&m_gdiplusToken, &gdiplusStartupInput, NULL);
        m_hUser32 = LoadLibraryA("user32.dll");
        if (m_hUser32) m_pGetCursorFrameInfo = (GETCURSORFRAMEINFO)GetProcAddress(m_hUser32, "GetCursorFrameInfo");
    }

    ~CursorEngine() {
        if (m_hUser32) FreeLibrary(m_hUser32);
        Gdiplus::GdiplusShutdown(m_gdiplusToken);
    }

    void CaptureAndSend() {
        CURSORINFO ci = { 0 }; ci.cbSize = sizeof(ci);
        if (!GetCursorInfo(&ci)) return;
        if (!(ci.flags & CURSOR_SHOWING)) return;

        if (ci.hCursor == mLastCursor && mLastCursor != NULL && !mLastPngData.empty()) {
            m_net.BroadcastCursor(mLastHash, mLastHotX, mLastHotY, mLastPngData);
            return;
        }

        HCURSOR hCursor = ci.hCursor;
        int targetSize = GetTargetSizeFromRegistry(); 
        int w = targetSize;
        int h = targetSize;

        ICONINFO ii = { 0 };
        if (!GetIconInfo(hCursor, &ii)) return;
        ScopedObject scopedMask(ii.hbmMask);
        ScopedObject scopedColor(ii.hbmColor);

        // --- 热点自动缩放逻辑 ---
        int originalW = 32; 
        int originalH = 32;
        BITMAP bmp = { 0 };
        if (ii.hbmColor) {
            if (GetObject(ii.hbmColor, sizeof(bmp), &bmp)) {
                originalW = bmp.bmWidth; originalH = bmp.bmHeight;
            }
        } else if (ii.hbmMask) {
            if (GetObject(ii.hbmMask, sizeof(bmp), &bmp)) {
                originalW = bmp.bmWidth; originalH = bmp.bmHeight / 2;
            }
        }
        if (originalW <= 0) originalW = 32;
        if (originalH <= 0) originalH = 32;

        int hotX = (int)(ii.xHotspot * ((float)w / originalW));
        int hotY = (int)(ii.yHotspot * ((float)h / originalH));
        if (hotX >= w) hotX = w - 1;
        if (hotY >= h) hotY = h - 1;
        // -----------------------

        // 绘图捕获
        HDC hdcScreen = GetDC(NULL);
        ScopedMemDC dcMem(hdcScreen);
        ReleaseDC(NULL, hdcScreen);

        BITMAPINFOHEADER bi = { 0 };
        bi.biSize = sizeof(BITMAPINFOHEADER);
        bi.biWidth = w;
        bi.biHeight = -h; 
        bi.biPlanes = 1; bi.biBitCount = 32; bi.biCompression = BI_RGB;

        void* pBitsB = nullptr; void* pBitsW = nullptr;
        HBITMAP hBmpB = CreateDIBSection(dcMem, (BITMAPINFO*)&bi, DIB_RGB_COLORS, &pBitsB, NULL, 0);
        HBITMAP hBmpW = CreateDIBSection(dcMem, (BITMAPINFO*)&bi, DIB_RGB_COLORS, &pBitsW, NULL, 0);
        
        if (!hBmpB || !hBmpW) return;
        ScopedObject scBmpB(hBmpB); ScopedObject scBmpW(hBmpW);

        // 黑底绘制
        SelectObject(dcMem, hBmpB);
        RECT rc = { 0, 0, w, h };
        FillRect(dcMem, &rc, (HBRUSH)GetStockObject(BLACK_BRUSH));
        DrawIconEx(dcMem, 0, 0, hCursor, w, h, 0, NULL, DI_NORMAL);

        // 白底绘制
        SelectObject(dcMem, hBmpW);
        FillRect(dcMem, &rc, (HBRUSH)GetStockObject(WHITE_BRUSH));
        DrawIconEx(dcMem, 0, 0, hCursor, w, h, 0, NULL, DI_NORMAL);

        // 像素处理 (RAW MODE: Alpha Restore)
        uint32_t* pxB = (uint32_t*)pBitsB;
        uint32_t* pxW = (uint32_t*)pBitsW;
        int numPixels = w * h;
        std::vector<uint32_t> rawPixels(numPixels);

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

            rawPixels[i] = (alpha << 24) | (br << 16) | (bg << 8) | bb;
        }

        // 发送
        size_t rawDataSize = rawPixels.size() * sizeof(uint32_t);
        uint32_t contentHash = CalculateCRC32(std::vector<uint8_t>((uint8_t*)rawPixels.data(), (uint8_t*)rawPixels.data() + rawDataSize));

        std::vector<uint8_t> pngToSend;
        if (!m_net.GetCachedPng(contentHash, pngToSend)) {
            Gdiplus::Bitmap gdiBitmap(w, h, PixelFormat32bppARGB);
            Gdiplus::BitmapData data;
            Gdiplus::Rect rect(0, 0, w, h);
            gdiBitmap.LockBits(&rect, Gdiplus::ImageLockModeWrite, PixelFormat32bppARGB, &data);
            memcpy(data.Scan0, rawPixels.data(), rawDataSize);
            gdiBitmap.UnlockBits(&data);

            IStream* pStream = NULL;
            if (CreateStreamOnHGlobal(NULL, TRUE, &pStream) == S_OK) {
                CLSID pngClsid; GetEncoderClsid(L"image/png", &pngClsid);
                gdiBitmap.Save(pStream, &pngClsid, NULL);
                STATSTG stg; pStream->Stat(&stg, STATFLAG_NONAME);
                pngToSend.resize(stg.cbSize.LowPart);
                LARGE_INTEGER seekPos = { 0 }; pStream->Seek(seekPos, STREAM_SEEK_SET, NULL);
                ULONG bytesRead = 0; pStream->Read(pngToSend.data(), (ULONG)pngToSend.size(), &bytesRead);
                pStream->Release();
                m_net.CachePng(contentHash, pngToSend);
            }
        }

        if (!pngToSend.empty()) {
            mLastCursor = hCursor;
            mLastHash = contentHash;
            mLastPngData = pngToSend;
            mLastHotX = hotX;
            mLastHotY = hotY;
            
            // ===========================================
            // 【日志】显示详细信息（包含文件大小）
            // ===========================================
            Logger::Get().Info("发送光标: 尺寸:", w, "x", h, 
                               " 热点:", hotX, ",", hotY, 
                               " 文件大小:", pngToSend.size(), "Bytes",
                               " Hash:", contentHash);

            m_net.BroadcastCursor(contentHash, hotX, hotY, pngToSend);
        }
    }
};

// ==========================================
//           5. 主程序入口
// ==========================================

NetworkManager g_net;
std::unique_ptr<CursorEngine> g_cursorEngine;
bool g_shouldExit = false;

void CALLBACK WinEventProc(HWINEVENTHOOK, DWORD, HWND, LONG idObject, LONG, DWORD, DWORD) {
    if (idObject == OBJID_CURSOR) {
        std::lock_guard<std::mutex> lock(g_mutexCursor);
        g_cursorChanged = true;
        g_cvCursorChanged.notify_one();
    }
}

void WorkerThread() {
    Logger::Get().Info("工作线程已启动");
    while (!g_shouldExit) {
        {
            std::unique_lock<std::mutex> lock(g_mutexCursor);
            bool notified = g_cvCursorChanged.wait_for(lock, std::chrono::milliseconds(33), [] { return g_cursorChanged || g_shouldExit; });
            if (g_shouldExit) break;
            if (notified) g_cursorChanged = false;
        }
        g_cursorEngine->CaptureAndSend();
    }
    Logger::Get().Info("工作线程已结束");
}

void AcceptThreadFunc() { g_net.AcceptLoop(); }

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
    Logger::Get().Info("======= 程序启动 (TCP Mode + RAW Capture) =======");

    // 强制开启高 DPI 感知 (Shcore)
    HMODULE hShcore = LoadLibraryA("Shcore.dll");
    if (hShcore) {
        typedef HRESULT(WINAPI* SETPROCESSDPIAWARENESS)(PROCESS_DPI_AWARENESS);
        SETPROCESSDPIAWARENESS pSetProcessDpiAwareness = (SETPROCESSDPIAWARENESS)GetProcAddress(hShcore, "SetProcessDpiAwareness");
        if (pSetProcessDpiAwareness) pSetProcessDpiAwareness(PROCESS_PER_MONITOR_DPI_AWARE);
        FreeLibrary(hShcore);
    } else SetProcessDPIAware();

    if (!g_net.Initialize()) {
        Logger::Get().Error("网络初始化失败");
        return 1;
    }

    g_cursorEngine = std::make_unique<CursorEngine>(g_net);
    std::thread tWorker(WorkerThread);
    std::thread tNet(AcceptThreadFunc);
    HWINEVENTHOOK hHook = SetWinEventHook(EVENT_OBJECT_NAMECHANGE, EVENT_OBJECT_NAMECHANGE, NULL, WinEventProc, 0, 0, WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS);

    if (!hHook) {
        Logger::Get().Error("安装 WinEventHook 失败");
        return 1;
    }

    Logger::Get().Info("服务运行中...");

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) { TranslateMessage(&msg); DispatchMessage(&msg); }

    Logger::Get().Info("正在关闭...");
    g_shouldExit = true; g_cvCursorChanged.notify_all();
    g_net.Shutdown();
    if (tWorker.joinable()) tWorker.join();
    if (tNet.joinable()) tNet.join();
    UnhookWinEvent(hHook);
    Logger::Get().Info("======= 程序退出 =======");
    return 0;
}