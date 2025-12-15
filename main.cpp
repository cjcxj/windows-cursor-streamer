/**
 * =============================================================
 * Cursor Monitor - Ultimate Server (TCP)
 * Features:
 * 1. Animated Cursor Support (Sprite Sheet)
 * 2. High DPI & Registry Size Scaling
 * 3. Perfect Alpha Extraction (Raw Mode)
 * 4. Smart Caching & Network Optimization
 * =============================================================
 */

// 1. 禁用 Windows min/max 宏，防止与 std::min/max 冲突
#define NOMINMAX

#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS

// 2. 头文件
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
#include <unordered_set>
#include <list>
#include <chrono>
#include <algorithm>
#include <iomanip>
#include <sstream>
#include <memory>
#include <fstream>
#include <functional>

// 3. 链接库
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdiplus.lib")
#pragma comment(lib, "shcore.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")

// ==========================================
//           1. 配置
// ==========================================

const int LISTEN_PORT = 5005;

// ==========================================
//           2. 日志系统
// ==========================================

enum class LogLevel
{
    TRACE,
    DEBUG,
    INFO,
    LOG_ERROR
};

class Logger
{
    std::mutex m_mutex;
    std::ofstream m_file;
    LogLevel m_level;

public:
    static Logger &Get()
    {
        static Logger instance;
        return instance;
    }

    Logger() : m_level(LogLevel::INFO)
    {
        m_file.open("cursor_monitor.log", std::ios::app);
        char *envLevel = nullptr;
        size_t len = 0;
        _dupenv_s(&envLevel, &len, "CURSOR_LOG_LEVEL");
        if (envLevel)
        {
            std::string l(envLevel);
            if (l == "TRACE")
                m_level = LogLevel::TRACE;
            else if (l == "DEBUG")
                m_level = LogLevel::DEBUG;
            else if (l == "INFO")
                m_level = LogLevel::INFO;
            else if (l == "ERROR")
                m_level = LogLevel::LOG_ERROR;
            free(envLevel);
        }
    }
    ~Logger()
    {
        if (m_file.is_open())
            m_file.close();
    }
    void SetLogLevel(LogLevel l) { m_level = l; }

    template <typename... Args>
    void Info(Args... args)
    {
        if (m_level <= LogLevel::INFO)
            Log("[INFO] ", args...);
    }
    template <typename... Args>
    void Error(Args... args)
    {
        if (m_level <= LogLevel::LOG_ERROR)
            Log("[ERROR] ", args...);
    }
    template <typename... Args>
    void Debug(Args... args)
    {
        if (m_level <= LogLevel::DEBUG)
            Log("[DEBUG] ", args...);
    }

private:
    template <typename... Args>
    void Log(const char *prefix, Args... args)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        std::tm tm_now;
        localtime_s(&tm_now, &now);

        // 控制台输出
        std::cout << std::put_time(&tm_now, "%H:%M:%S ") << prefix;
        ((std::cout << args << " "), ...);
        std::cout << std::endl;

        // 文件输出
        if (m_file.is_open())
        {
            m_file << std::put_time(&tm_now, "%Y-%m-%d %H:%M:%S ") << prefix;
            ((m_file << args << " "), ...);
            m_file << std::endl;
        }
    }
};

uint32_t CalculateCRC32(const std::vector<uint8_t> &data)
{
    uint32_t crc = 0xFFFFFFFF;
    for (uint8_t byte : data)
    {
        crc ^= byte;
        for (int i = 0; i < 8; i++)
            crc = (crc & 1) ? (crc >> 1) ^ 0xEDB88320 : crc >> 1;
    }
    return ~crc;
}

// RAII 资源管理
struct ScopedMemDC
{
    HDC hdc;
    ScopedMemDC(HDC c) : hdc(CreateCompatibleDC(c)) {}
    ~ScopedMemDC() { DeleteDC(hdc); }
    operator HDC() { return hdc; }
};
struct ScopedObject
{
    HGDIOBJ h;
    ScopedObject(HGDIOBJ o) : h(o) {}
    ~ScopedObject() { DeleteObject(h); }
};

// 全局同步信号
std::condition_variable g_cvCursorChanged;
std::mutex g_mutexCursor;
bool g_cursorChanged = false;

// ==========================================
//           3. 网络管理 (完整版 - 支持缓存复用)
// ==========================================

// 客户端会话结构
struct ClientSession
{
    SOCKET socket;
    bool connected;
    uint32_t lastSentHash; // 上一次发送的 Hash (用于连续帧去重)

    // 记录该客户端已经接收并缓存过的光标 Hash ID
    // 服务端通过查询这个集合，决定是发图片还是只发 ID
    std::unordered_set<uint32_t> cachedHashes;
};

// 辅助函数：重启自身
void RestartApplication()
{
    char szPath[MAX_PATH];
    // 获取当前 exe 路径
    if (GetModuleFileNameA(NULL, szPath, MAX_PATH))
    {
        Logger::Get().Info("检测到 DPI 缩放变化，正在重启应用以刷新资源...");
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        STARTUPINFOA si = {sizeof(si)};
        PROCESS_INFORMATION pi = {0};

        // 直接把当前进程的完整命令行（路径+参数）传给新进程
        if (CreateProcessA(
                szPath,            // Exe 路径
                GetCommandLineA(), // 命令行参数 (包含 -l DEBUG 等)
                NULL, NULL, FALSE, 0, NULL, NULL,
                &si, &pi))
        {
            // 释放句柄
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);

            // 退出当前进程
            exit(0);
        }
    }
}

class NetworkManager
{
    SOCKET m_listenSocket;
    std::list<std::shared_ptr<ClientSession>> m_clients; // 客户端列表
    std::mutex m_clientsMutex;

    // 服务端全局 PNG 缓存 (用于 CursorEngine 避免重复压缩)
    std::map<uint32_t, std::vector<uint8_t>> m_cache;
    std::mutex m_cacheMutex;

    std::atomic<bool> m_running{true};

public:
    NetworkManager() : m_listenSocket(INVALID_SOCKET) {}
    std::function<void()> m_onClientConnected;

    // 1. 初始化 TCP 服务端

    void SetClientConnectedCallback(std::function<void()> callback)
    {
        m_onClientConnected = callback;
    }

    // 快速检查是否有客户端
    bool HasClients()
    {
        std::lock_guard<std::mutex> lock(m_clientsMutex);
        return !m_clients.empty();
    }

    bool Initialize()
    {
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
            return false;

        m_listenSocket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
        if (m_listenSocket == INVALID_SOCKET)
            return false;

        int no = 0;
        int yes = 1;
        // 允许 IPv4 和 IPv6 双栈
        setsockopt(m_listenSocket, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&no, sizeof(no));
        // 允许端口重用 (快速重启)
        setsockopt(m_listenSocket, SOL_SOCKET, SO_REUSEADDR, (char *)&yes, sizeof(yes));

        sockaddr_in6 addr = {};
        addr.sin6_family = AF_INET6;
        addr.sin6_port = htons(LISTEN_PORT); // 端口 5005
        addr.sin6_addr = in6addr_any;

        if (bind(m_listenSocket, (sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR)
            return false;
        if (listen(m_listenSocket, SOMAXCONN) == SOCKET_ERROR)
            return false;

        Logger::Get().Info("TCP 服务端已启动，端口:", LISTEN_PORT);
        return true;
    }

    // 2. 关闭与清理
    void Shutdown()
    {
        m_running = false;
        if (m_listenSocket != INVALID_SOCKET)
        {
            closesocket(m_listenSocket);
            m_listenSocket = INVALID_SOCKET;
        }

        std::lock_guard<std::mutex> lock(m_clientsMutex);
        for (auto &client : m_clients)
        {
            if (client->socket != INVALID_SOCKET)
                closesocket(client->socket);
        }
        m_clients.clear();
        WSACleanup();
    }

    // 3. 接受连接循环 (需在独立线程运行)
    void AcceptLoop()
    {
        Logger::Get().Info("开始等待客户端连接...");
        while (m_running)
        {
            sockaddr_in6 clientAddr;
            int len = sizeof(clientAddr);
            SOCKET clientSock = accept(m_listenSocket, (sockaddr *)&clientAddr, &len);

            if (clientSock != INVALID_SOCKET)
            {
                // 禁用 Nagle 算法，确保极低延迟
                int yes = 1;
                setsockopt(clientSock, IPPROTO_TCP, TCP_NODELAY, (char *)&yes, sizeof(yes));

                auto session = std::make_shared<ClientSession>();
                session->socket = clientSock;
                session->connected = true;
                session->lastSentHash = 0;
                // 新连接到来时，cachedHashes 默认为空，会强制客户端重新下载光标

                char ipStr[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, &clientAddr.sin6_addr, ipStr, INET6_ADDRSTRLEN);
                Logger::Get().Info("客户端已连接:", ipStr);

                {
                    std::lock_guard<std::mutex> lock(m_clientsMutex);
                    m_clients.push_back(session);
                }

                if (m_onClientConnected)
                {
                    m_onClientConnected();
                }

                // 唤醒主线程立即发送当前光标
                {
                    std::lock_guard<std::mutex> lock(g_mutexCursor);
                    g_cursorChanged = true;
                }
                g_cvCursorChanged.notify_one();
            }
        }
    }

    // 4. 服务端内部 PNG 缓存 (避免重复 GDI+ 压缩)
    bool GetCachedPng(uint32_t hash, std::vector<uint8_t> &outPng)
    {
        std::lock_guard<std::mutex> lock(m_cacheMutex);
        auto it = m_cache.find(hash);
        if (it != m_cache.end())
        {
            outPng = it->second;
            return true;
        }
        return false;
    }

    void CachePng(uint32_t hash, const std::vector<uint8_t> &pngData)
    {
        std::lock_guard<std::mutex> lock(m_cacheMutex);
        if (m_cache.size() > 50)
            m_cache.clear(); // 简单清理
        m_cache[hash] = pngData;
    }

    // 5. 核心广播函数 (支持缓存协议)
    void BroadcastCursor(uint32_t hash, int32_t hotX, int32_t hotY, int32_t frames, int32_t delay, const std::vector<uint8_t> &pngData)
    {
        std::lock_guard<std::mutex> lock(m_clientsMutex);

        // --- 预构建数据包 ---

        // Header 部分 (20 字节)
        // [Hash(4)] [HotX(4)] [HotY(4)] [Frames(4)] [Delay(4)]
        const uint32_t HEADER_SIZE = 20;

        // A. 完整包 (Full Packet)
        // [BodyLen(4)] + [Header(20)] + [PNG Data...]
        uint32_t fullBodySize = HEADER_SIZE + (uint32_t)pngData.size();
        std::vector<uint8_t> fullPacket(4 + fullBodySize);
        {
            uint8_t *p = fullPacket.data();
            memcpy(p, &fullBodySize, 4);
            p += 4; // BodyLen
            memcpy(p, &hash, 4);
            p += 4; // Hash
            memcpy(p, &hotX, 4);
            p += 4; // HotX
            memcpy(p, &hotY, 4);
            p += 4; // HotY
            memcpy(p, &frames, 4);
            p += 4; // Frames
            memcpy(p, &delay, 4);
            p += 4;                                    // Delay
            memcpy(p, pngData.data(), pngData.size()); // PNG
        }

        // B. 短包 (Cached Packet)
        // [BodyLen(4)] + [Header(20)]
        uint32_t cachedBodySize = HEADER_SIZE;
        std::vector<uint8_t> cachedPacket(4 + cachedBodySize);
        {
            uint8_t *p = cachedPacket.data();
            memcpy(p, &cachedBodySize, 4);
            p += 4; // BodyLen
            memcpy(p, &hash, 4);
            p += 4; // Hash
            memcpy(p, &hotX, 4);
            p += 4; // ...
            memcpy(p, &hotY, 4);
            p += 4;
            memcpy(p, &frames, 4);
            p += 4;
            memcpy(p, &delay, 4);
        }

        // --- 遍历发送 ---
        for (auto it = m_clients.begin(); it != m_clients.end();)
        {
            auto &client = *it;

            if (!client->connected)
            {
                it = m_clients.erase(it);
                continue;
            }

            // 1. 连续去重：如果该客户端刚刚才发过这个光标，跳过
            if (client->lastSentHash == hash)
            {
                ++it;
                continue;
            }

            // 2. 缓存检查
            const std::vector<uint8_t> *pPacketToSend = nullptr;
            bool isCacheHit = false;

            if (client->cachedHashes.find(hash) != client->cachedHashes.end())
            {
                // 命中缓存：只发头信息
                pPacketToSend = &cachedPacket;
                isCacheHit = true;
            }
            else
            {
                // 未命中：发全量数据
                pPacketToSend = &fullPacket;

                // 记录该客户端已拥有此 Hash
                client->cachedHashes.insert(hash);
                // 防止长时间运行内存膨胀 (保留最近的 100 个光标足够用了)
                if (client->cachedHashes.size() > 100)
                {
                    client->cachedHashes.clear();
                    // 清空后，下次遇到旧光标会重新发送一次全量包，这是安全的
                }
            }

            // 3. 执行发送
            int sentBytes = send(client->socket, (const char *)pPacketToSend->data(), (int)pPacketToSend->size(), 0);

            if (sentBytes == SOCKET_ERROR)
            {
                Logger::Get().Info("客户端断开连接");
                closesocket(client->socket);
                client->connected = false;
                it = m_clients.erase(it);
                continue;
            }
            else
            {
                client->lastSentHash = hash;
                if (isCacheHit)
                {
                    Logger::Get().Debug("客户端缓存命中 (24B) -> Hash:", hash);
                }
                else
                {
                    Logger::Get().Debug("发送完整数据 (", pPacketToSend->size(), "B) -> Hash:", hash);
                }
            }
            ++it;
        }
    }
};

// ==========================================
//           4. 光标引擎 (高性能优化版)
// ==========================================

// user32.dll 未公开 API 定义
typedef BOOL(WINAPI *GETCURSORFRAMEINFO)(HCURSOR, DWORD, DWORD, DWORD *, DWORD *);

class CursorEngine
{
    ULONG_PTR m_token;
    NetworkManager &m_net;
    HMODULE m_hUser32;
    GETCURSORFRAMEINFO m_pGetCursorFrameInfo;

    // --- 状态缓存 ---
    HCURSOR mLastCursor = NULL;
    int mLastTierSize = -1; // 上一次的档位
    std::chrono::steady_clock::time_point mLastProcessTime;

    // DPI 缓存优化
    HMONITOR mLastMonitor = NULL;
    UINT mLastDpi = 96;

    // 防抖与重启逻辑
    std::chrono::steady_clock::time_point m_dpiChangeStartTime;
    bool m_isDpiChanging = false;

    // --- GDI 资源池 (避免重复创建销毁) ---
    HDC m_hMemDC = NULL;
    HBITMAP m_hBmpB = NULL;
    HBITMAP m_hBmpW = NULL;
    void *m_pBitsB = NULL;
    void *m_pBitsW = NULL;
    int m_cachedWidth = 0;
    int m_cachedHeight = 0;

    // --- 内存复用池 (避免每帧 malloc) ---
    std::vector<uint32_t> m_rawPixels; // 复用的像素缓冲区
    std::vector<uint8_t> m_xorMask;    // 复用的掩码缓冲区
    std::vector<uint8_t> m_pngBuffer;  // 复用的 PNG 输出缓冲区

    // 辅助：获取编码器 CLSID
    static int GetEncoderClsid(const WCHAR *format, CLSID *pClsid)
    {
        UINT num, size;
        Gdiplus::GetImageEncodersSize(&num, &size);
        if (size == 0)
            return -1;
        std::vector<char> buf(size);
        Gdiplus::ImageCodecInfo *p = (Gdiplus::ImageCodecInfo *)buf.data();
        Gdiplus::GetImageEncoders(num, size, p);
        for (UINT j = 0; j < num; ++j)
        {
            if (wcscmp(p[j].MimeType, format) == 0)
            {
                *pClsid = p[j].Clsid;
                return j;
            }
        }
        return -1;
    }

    // 重新初始化 GDI 资源
    bool RecreateResources(int w, int hTotal)
    {
        if (m_hMemDC && m_hBmpB && m_hBmpW && w == m_cachedWidth && hTotal == m_cachedHeight)
            return true;

        FreeResources();

        HDC hScreen = GetDC(NULL);
        m_hMemDC = CreateCompatibleDC(hScreen);
        ReleaseDC(NULL, hScreen);

        if (!m_hMemDC)
            return false;

        BITMAPINFOHEADER bi = {sizeof(bi)};
        bi.biWidth = w;
        bi.biHeight = -hTotal; // Top-Down
        bi.biPlanes = 1;
        bi.biBitCount = 32;
        bi.biCompression = BI_RGB;

        m_hBmpB = CreateDIBSection(m_hMemDC, (BITMAPINFO *)&bi, DIB_RGB_COLORS, &m_pBitsB, NULL, 0);
        m_hBmpW = CreateDIBSection(m_hMemDC, (BITMAPINFO *)&bi, DIB_RGB_COLORS, &m_pBitsW, NULL, 0);

        if (!m_hBmpB || !m_hBmpW)
        {
            FreeResources();
            return false;
        }

        m_cachedWidth = w;
        m_cachedHeight = hTotal;
        return true;
    }

    void FreeResources()
    {
        if (m_hMemDC)
            DeleteDC(m_hMemDC);
        if (m_hBmpB)
            DeleteObject(m_hBmpB);
        if (m_hBmpW)
            DeleteObject(m_hBmpW);
        m_hMemDC = NULL;
        m_hBmpB = NULL;
        m_hBmpW = NULL;
        m_pBitsB = NULL;
        m_pBitsW = NULL;
        m_cachedWidth = 0;
        m_cachedHeight = 0;
    }

    // 优化：带缓存的注册表读取 (每5秒检查一次)
    int GetTargetSize()
    {
        static int s_size = 32;
        static auto s_lastCheck = std::chrono::steady_clock::now();
        auto now = std::chrono::steady_clock::now();

        if (std::chrono::duration_cast<std::chrono::seconds>(now - s_lastCheck).count() > 2)
        {
            s_lastCheck = now;
            HKEY k;
            if (RegOpenKeyExA(HKEY_CURRENT_USER, "Control Panel\\Cursors", 0, KEY_READ, &k) == 0)
            {
                DWORD t, sz = 4, v = 0;
                if (RegQueryValueExA(k, "CursorBaseSize", 0, &t, (BYTE *)&v, &sz) == 0)
                    s_size = v;
                RegCloseKey(k);
            }
        }
        return std::clamp(s_size, 32, 256);
    }

    // 获取光标当前所在显示器的 DPI
    std::chrono::steady_clock::time_point mLastDpiCheckTime;
    UINT GetCursorMonitorDPI()
    {
        POINT pt;
        if (GetCursorPos(&pt))
        {
            HMONITOR hMon = MonitorFromPoint(pt, MONITOR_DEFAULTTONEAREST);
            auto now = std::chrono::steady_clock::now();

            // 判断缓存是否失效：
            // 1. 显示器句柄变了 (跨屏)
            // 2. 或者，距离上次检查已经过了 2 秒 (定期刷新以检测同一屏幕的 DPI 变更)
            bool isCacheStale = (hMon != mLastMonitor) ||
                                (std::chrono::duration_cast<std::chrono::seconds>(now - mLastDpiCheckTime).count() >= 2);

            if (isCacheStale)
            {
                UINT dpiX, dpiY;
                if (SUCCEEDED(GetDpiForMonitor(hMon, MDT_EFFECTIVE_DPI, &dpiX, &dpiY)))
                {
                    // 只有当数值真的变了，或者显示器变了才记录，方便调试
                    if (dpiX != mLastDpi || hMon != mLastMonitor)
                    {
                        Logger::Get().Debug("DPI/显示器状态更新: ", dpiX);
                    }

                    mLastDpi = dpiX;
                    mLastMonitor = hMon;
                    mLastDpiCheckTime = now; // 更新检查时间
                }
            }
        }
        return mLastDpi;
    }

    // 根据 DPI 计算预期的系统光标档位
    int GetExpectedSystemCursorSize(int baseSize, UINT dpi)
    {
        int calculated = MulDiv(baseSize, dpi, 96);
        if (calculated >= 96)
            return 96;
        if (calculated >= 64)
            return 64;
        if (calculated >= 48)
            return 48;
        return 32;
    }

    std::pair<int, int> GetAnimInfo(HCURSOR h)
    {
        if (!m_pGetCursorFrameInfo)
            return {1, 0};
        DWORD rate = 0, count = 0;
        if (m_pGetCursorFrameInfo(h, 0, 0, &rate, &count))
        {
            if (count == 0)
                count = 1;
            int delay = (int)((rate * 1000) / 60);
            return {(int)count, delay < 10 ? 0 : delay};
        }
        return {1, 0};
    }

public:
    CursorEngine(NetworkManager &n) : m_net(n), m_token(0), m_hUser32(NULL), m_pGetCursorFrameInfo(NULL)
    {
        Gdiplus::GdiplusStartupInput i;
        Gdiplus::GdiplusStartup(&m_token, &i, NULL);
        m_hUser32 = LoadLibraryA("user32.dll");
        if (m_hUser32)
            m_pGetCursorFrameInfo = (GETCURSORFRAMEINFO)GetProcAddress(m_hUser32, "GetCursorFrameInfo");
        mLastProcessTime = std::chrono::steady_clock::now();

        // 预分配内存，减少运行时重新分配
        m_rawPixels.reserve(128 * 128);
        m_xorMask.reserve(128 * 128);
        m_pngBuffer.reserve(1024 * 50);
    }

    ~CursorEngine()
    {
        FreeResources();
        if (m_hUser32)
            FreeLibrary(m_hUser32);
        Gdiplus::GdiplusShutdown(m_token);
    }

    void ResetState()
    {
        mLastCursor = NULL;
        // 注意：不重置 mLastMonitor/DPI，因为物理屏幕没变
    }

    void CaptureAndSend()
    {
        if (!m_net.HasClients())
        {
            // 更新一下时间，防止连接后第一帧被限流逻辑卡住
            mLastProcessTime = std::chrono::steady_clock::now();
            // 重置上一次光标状态，确保当客户端连上时，
            // 系统认为这是“新光标”从而立即发送，而不是误判为“没变化”
            mLastCursor = NULL;
            return;
        }

        // 1. 基础频率限制 (33ms)
        auto now = std::chrono::steady_clock::now();
        if (std::chrono::duration_cast<std::chrono::milliseconds>(now - mLastProcessTime).count() < 30)
            return;
        mLastProcessTime = now;

        CURSORINFO ci = {sizeof(ci)};
        if (!GetCursorInfo(&ci) || !(ci.flags & CURSOR_SHOWING))
            return;

        // 2. DPI 检查 (使用优化后的带缓存版本)
        UINT currentDpi = GetCursorMonitorDPI();                            // 获取当前光标所在显示器的 DPI
        int expectedTierSize = GetExpectedSystemCursorSize(currentDpi, 32); // 光标预期档位

        // 初始化
        if (mLastTierSize == -1)
            mLastTierSize = expectedTierSize;

        // 3. 档位变化与防抖 (DPI 切换逻辑)
        if (expectedTierSize != mLastTierSize)
        {
            if (!m_isDpiChanging)
            {
                m_isDpiChanging = true;
                m_dpiChangeStartTime = now;
            }
            else
            {
                if (std::chrono::duration_cast<std::chrono::milliseconds>(now - m_dpiChangeStartTime).count() > 500)
                {
                    RestartApplication();
                }
            }
            return;
        }
        else
        {
            m_isDpiChanging = false;
        }

        // 4. 极速早期退出：如果句柄没变且DPI没变，直接返回 (0 CPU 消耗)
        if (ci.hCursor == mLastCursor)
            return;

        // ==========================================
        //  进入重绘流程 (只有光标真正改变时才执行)
        // ==========================================

        int regSize = GetTargetSize();
        auto [frames, delay] = GetAnimInfo(ci.hCursor);

        ICONINFO ii = {0};
        if (!GetIconInfo(ci.hCursor, &ii))
            return; // 失败保护

        int orgW = 32, orgH = 32;
        BITMAP bmp;
        bool hasColor = false;

        if (ii.hbmColor && GetObject(ii.hbmColor, sizeof(bmp), &bmp))
        {
            orgW = bmp.bmWidth;
            orgH = bmp.bmHeight;
            hasColor = true;
        }
        else if (ii.hbmMask && GetObject(ii.hbmMask, sizeof(bmp), &bmp))
        {
            orgW = bmp.bmWidth;
            orgH = bmp.bmHeight / 2;
        }

        // 资源清理 RAII 替代
        if (ii.hbmColor)
            DeleteObject(ii.hbmColor);
        if (ii.hbmMask)
            DeleteObject(ii.hbmMask);

        // 计算最终尺寸
        int finalSizeW = orgW;
        int finalSizeH = orgH;
        bool isSystemCursor = (orgW == 32 || orgW == regSize || orgW == expectedTierSize);

        // 格式：[DPI检测] DPI:144 | 档位:48 | 实际:48x48 -> SYSTEM (重置为32)
        Logger::Get().Debug(
            "[DPI检测]",
            "DPI:", currentDpi,
            "| 预测档位:", expectedTierSize,
            "| 实际尺寸:", orgW, "x", orgH,
            "->", isSystemCursor ? "SYSTEM (缩放)" : "CUSTOM (保持)");

        if (isSystemCursor)
        {
            double scaleFactor = expectedTierSize / 32.0;
            finalSizeW = int(regSize * scaleFactor);
            finalSizeH = int(regSize * scaleFactor);
        }

        // 热点计算
        float scaleRatioW = (float)finalSizeW / (float)orgW;
        float scaleRatioH = (float)finalSizeH / (float)orgH;
        int hotX = std::clamp((int)(ii.xHotspot * scaleRatioW), 0, finalSizeW - 1);
        int hotY = std::clamp((int)(ii.yHotspot * scaleRatioH), 0, finalSizeH - 1);

        int sheetW = finalSizeW;
        int sheetH = finalSizeH * frames;

        // 准备 GDI 资源
        if (!RecreateResources(sheetW, sheetH))
            return;

        // 批量绘制
        RECT allRc = {0, 0, sheetW, sheetH};

        // 黑底
        SelectObject(m_hMemDC, m_hBmpB);
        FillRect(m_hMemDC, &allRc, (HBRUSH)GetStockObject(BLACK_BRUSH));
        for (int i = 0; i < frames; ++i)
            DrawIconEx(m_hMemDC, 0, i * finalSizeH, ci.hCursor, finalSizeW, finalSizeH, i, NULL, DI_NORMAL);

        // 白底
        SelectObject(m_hMemDC, m_hBmpW);
        FillRect(m_hMemDC, &allRc, (HBRUSH)GetStockObject(WHITE_BRUSH));
        for (int i = 0; i < frames; ++i)
            DrawIconEx(m_hMemDC, 0, i * finalSizeH, ci.hCursor, finalSizeW, finalSizeH, i, NULL, DI_NORMAL);

        // =========================================================
        //           高性能像素处理 (指针操作 + 内存复用)
        // =========================================================

        int totalPixels = sheetW * sheetH;

        // 复用 vector 内存，避免 malloc
        m_rawPixels.resize(totalPixels);
        m_xorMask.resize(totalPixels);

        // 使用裸指针遍历，速度最快
        uint32_t *pOut = m_rawPixels.data();
        uint8_t *pMask = m_xorMask.data();
        const uint32_t *pB = (const uint32_t *)m_pBitsB;
        const uint32_t *pW = (const uint32_t *)m_pBitsW;

        // --- Pass 1: 颜色提取 ---
        for (int i = 0; i < totalPixels; ++i)
        {
            uint32_t cB = pB[i];
            uint32_t cW = pW[i];

            // 提取分量 (假设 Little Endian: BGRA)
            uint8_t bb = (cB & 0xFF);
            uint8_t bg = ((cB >> 8) & 0xFF);
            uint8_t br = ((cB >> 16) & 0xFF);

            uint8_t wb = (cW & 0xFF);
            uint8_t wg = ((cW >> 8) & 0xFF);
            uint8_t wr = ((cW >> 16) & 0xFF);

            // 快速 XOR 检测 (分支预测优化: 大部分像素不是 XOR)
            if (bg > 200 && wg < 50)
            {
                pOut[i] = 0xFFFFFFFF; // 纯白
                pMask[i] = 1;         // 标记
            }
            else
            {
                pMask[i] = 0;
                // Alpha 提取优化：避免 std::max 和重复类型转换
                int dr = (int)wr - br;
                int dg = (int)wg - bg;
                int db = (int)wb - bb;

                // 简单的 max 逻辑
                if (dr < 0)
                    dr = 0;
                if (dg < 0)
                    dg = 0;
                if (db < 0)
                    db = 0;

                int maxDiff = dr;
                if (dg > maxDiff)
                    maxDiff = dg;
                if (db > maxDiff)
                    maxDiff = db;

                uint8_t alpha = (uint8_t)(255 - maxDiff);

                if (alpha > 5)
                {
                    pOut[i] = (alpha << 24) | (br << 16) | (bg << 8) | bb;
                }
                else
                {
                    pOut[i] = 0; // 完全透明
                }
            }
        }

        // --- Pass 2: 智能描边 (仅处理 XOR 边界) ---
        // 优化：避免边界检查 if (x>0)，将循环范围缩小
        int wMinus1 = sheetW - 1;
        int hMinus1 = sheetH - 1;

        for (int y = 0; y < sheetH; ++y)
        {
            // 计算行指针，减少乘法
            uint32_t *rowOut = pOut + y * sheetW;
            uint8_t *rowMask = pMask + y * sheetW;

            // 指向上下行 Mask (注意边界)
            uint8_t *rowMaskUp = (y > 0) ? (rowMask - sheetW) : NULL;
            uint8_t *rowMaskDown = (y < hMinus1) ? (rowMask + sheetW) : NULL;

            for (int x = 0; x < sheetW; ++x)
            {
                if (rowOut[x] != 0)
                    continue; // 已有颜色跳过

                bool isBorder = false;
                // 左右
                if (x > 0 && rowMask[x - 1])
                    isBorder = true;
                else if (x < wMinus1 && rowMask[x + 1])
                    isBorder = true;
                // 上下
                else if (rowMaskUp && rowMaskUp[x])
                    isBorder = true;
                else if (rowMaskDown && rowMaskDown[x])
                    isBorder = true;

                if (isBorder)
                {
                    rowOut[x] = 0xFF000000; // 纯黑边框
                }
            }
        }

        // CRC32 计算
        size_t rawDataSize = m_rawPixels.size() * 4;
        uint32_t hash = CalculateCRC32(std::vector<uint8_t>((uint8_t *)m_rawPixels.data(), (uint8_t *)m_rawPixels.data() + rawDataSize));

        // 检查缓存或编码 PNG
        m_pngBuffer.clear(); // 清空复用
        if (!m_net.GetCachedPng(hash, m_pngBuffer))
        {
            // 只有未命中缓存时才调用 GDI+ 进行 PNG 编码
            Gdiplus::Bitmap gdiBmp(sheetW, sheetH, PixelFormat32bppARGB);
            Gdiplus::BitmapData bd;
            Gdiplus::Rect r(0, 0, sheetW, sheetH);

            gdiBmp.LockBits(&r, Gdiplus::ImageLockModeWrite, PixelFormat32bppARGB, &bd);
            memcpy(bd.Scan0, m_rawPixels.data(), rawDataSize); // 内存拷贝比逐点 SetPixel 快
            gdiBmp.UnlockBits(&bd);

            IStream *s = NULL;
            CreateStreamOnHGlobal(NULL, TRUE, &s);
            CLSID pngId;
            GetEncoderClsid(L"image/png", &pngId);
            gdiBmp.Save(s, &pngId, NULL);

            // 从流中提取数据
            STATSTG stg;
            s->Stat(&stg, STATFLAG_NONAME);

            // 使用临时 buffer 读取流，然后放入 cache
            std::vector<uint8_t> tempPng(stg.cbSize.LowPart);
            LARGE_INTEGER pos = {0};
            s->Seek(pos, STREAM_SEEK_SET, NULL);
            ULONG read;
            s->Read(tempPng.data(), (ULONG)tempPng.size(), &read);
            s->Release();

            // 存入网络缓存
            m_net.CachePng(hash, tempPng);
            m_pngBuffer = std::move(tempPng);
        }

        if (!m_pngBuffer.empty())
        {
            mLastCursor = ci.hCursor;
            Logger::Get().Debug("发送光标 Hash:", hash);
            m_net.BroadcastCursor(hash, hotX, hotY, frames, delay, m_pngBuffer);
        }
    }
};

// ==========================================
//           5. 主程序
// ==========================================

NetworkManager g_net;
std::unique_ptr<CursorEngine> g_engine;
bool g_exit = false;

// Windows 事件钩子：当光标改变时触发
void CALLBACK HookProc(HWINEVENTHOOK, DWORD, HWND, LONG id, LONG, DWORD, DWORD)
{
    if (id == OBJID_CURSOR)
    {
        std::lock_guard<std::mutex> l(g_mutexCursor);
        g_cursorChanged = true;
        g_cvCursorChanged.notify_one();
    }
}

// 工作线程：处理图像
void Worker()
{
    while (!g_exit)
    {
        {
            std::unique_lock<std::mutex> l(g_mutexCursor);
            // 等待信号，或者 33ms 超时轮询 (30FPS兜底)
            g_cvCursorChanged.wait_for(l, std::chrono::milliseconds(33), []
                                       { return g_cursorChanged || g_exit; });
            if (g_exit)
                break;
            g_cursorChanged = false;
        }
        g_engine->CaptureAndSend();
    }
}

// 命令行参数处理
void ShowUsage()
{
    std::cout << "Usage: cursor_monitor [options]\n  -l LVL  Set log level (TRACE, DEBUG, INFO, ERROR)\n";
}

int main(int argc, char *argv[])
{
    // 日志级别设置
    LogLevel lvl = LogLevel::INFO;
    for (int i = 1; i < argc; ++i)
    {
        std::string s = argv[i];
        if (s == "-l" && i + 1 < argc)
        {
            std::string v = argv[++i];
            if (v == "INFO")
                lvl = LogLevel::INFO;
            else if (v == "DEBUG")
                lvl = LogLevel::DEBUG;
            else if (v == "TRACE")
                lvl = LogLevel::TRACE;
            else if (v == "ERROR")
                lvl = LogLevel::LOG_ERROR;
        }
    }
    Logger::Get().SetLogLevel(lvl);

    // 强制开启高 DPI (Shcore)
    HMODULE h = LoadLibraryA("Shcore.dll");
    if (h)
    {
        typedef HRESULT(WINAPI * SDPA)(PROCESS_DPI_AWARENESS);
        SDPA p = (SDPA)GetProcAddress(h, "SetProcessDpiAwareness");
        if (p)
            p(PROCESS_PER_MONITOR_DPI_AWARE);
        FreeLibrary(h);
    }
    else
        SetProcessDPIAware();

    Logger::Get().Info("======= 程序启动 (TCP + Animated Sprite Sheet) =======");

    if (!g_net.Initialize())
        return 1;
    g_engine = std::make_unique<CursorEngine>(g_net);

    g_net.SetClientConnectedCallback([]()
                                     {
        if (g_engine)
        {
            g_engine->ResetState();
            Logger::Get().Info("新客户端连接，强制刷新光标状态");
        } });

    // 启动线程
    std::thread t1(Worker);
    std::thread t2([&]
                   { g_net.AcceptLoop(); });

    // 安装钩子
    HWINEVENTHOOK hHook = SetWinEventHook(EVENT_OBJECT_NAMECHANGE, EVENT_OBJECT_NAMECHANGE, NULL, HookProc, 0, 0, WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS);

    // 消息循环 (必须保留以响应钩子)
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0))
    {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    // 退出清理
    g_exit = true;
    g_cvCursorChanged.notify_all();
    g_net.Shutdown();
    t1.join();
    t2.join();
    UnhookWinEvent(hHook);
    return 0;
}