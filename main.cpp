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
//           4. 光标引擎 (Sprite Sheet Generator)
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
    // 上一次处理的时间点
    std::chrono::steady_clock::time_point mLastProcessTime;

    // --- GDI 资源池 (避免重复创建销毁) ---
    HDC m_hMemDC = NULL;
    HBITMAP m_hBmpB = NULL;
    HBITMAP m_hBmpW = NULL;
    HGDIOBJ m_hOldB = NULL;
    HGDIOBJ m_hOldW = NULL;
    void *m_pBitsB = NULL;
    void *m_pBitsW = NULL;
    int m_cachedWidth = 0;
    int m_cachedHeight = 0; // 单帧高度
    int mLastSize = 0;      // 记录上一次处理的目标尺寸

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
            if (wcscmp(p[j].MimeType, format) == 0)
            {
                *pClsid = p[j].Clsid;
                return j;
            }
        return -1;
    }

    // 重新初始化 GDI 资源 (仅当尺寸变化时调用)
    bool RecreateResources(int w, int hTotal)
    {
        // 如果尺寸没变且资源存在，直接复用
        if (m_hMemDC && m_hBmpB && m_hBmpW && w == m_cachedWidth && hTotal == m_cachedHeight)
        {
            return true;
        }

        FreeResources(); // 先清理旧的

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
        {
            DeleteDC(m_hMemDC);
            m_hMemDC = NULL;
        }
        if (m_hBmpB)
        {
            DeleteObject(m_hBmpB);
            m_hBmpB = NULL;
        }
        if (m_hBmpW)
        {
            DeleteObject(m_hBmpW);
            m_hBmpW = NULL;
        }
        m_pBitsB = NULL;
        m_pBitsW = NULL;
        m_cachedWidth = 0;
        m_cachedHeight = 0;
    }

    int GetTargetSize()
    {
        // 简单缓存注册表读取，避免每次读注册表
        static int s_size = 32;
        static auto s_lastCheck = std::chrono::steady_clock::now();
        auto now = std::chrono::steady_clock::now();

        // 每 2 秒才读一次注册表
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
    UINT GetCursorMonitorDPI()
    {
        POINT pt;
        // 获取光标位置
        if (GetCursorPos(&pt))
        {
            // 获取该点所在的显示器句柄
            HMONITOR hMon = MonitorFromPoint(pt, MONITOR_DEFAULTTONEAREST);
            if (hMon)
            {
                UINT dpiX, dpiY;
                // 获取该显示器的有效 DPI
                if (SUCCEEDED(GetDpiForMonitor(hMon, MDT_EFFECTIVE_DPI, &dpiX, &dpiY)))
                {
                    return dpiX;
                }
            }
        }
        return 96; // 默认 100%
    }

    // 根据 DPI 计算预期的系统光标档位 (32, 48, 64, 96)
    int GetExpectedSystemCursorSize(int baseSize, UINT dpi)
    {
        // 1. 计算理论上的线性缩放大小
        int calculated = MulDiv(baseSize, dpi, 96);

        // 2. 向下取整/阶梯匹配逻辑 (模拟 Windows 资源加载策略)
        // 即使 DPI 很高，如果计算出来是 42，Windows 可能还是用的 32 的资源
        // 只有达到了 48 的阈值，才会切到 48 的资源

        if (calculated >= 96)
            return 96;
        if (calculated >= 64)
            return 64;
        if (calculated >= 48)
            return 48;

        // 默认档位
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
            if (delay < 10)
                delay = 0;
            return {(int)count, delay};
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
        mLastSize = 0; // 重置
    }

    void CaptureAndSend()
    {
        auto now = std::chrono::steady_clock::now();
        if (std::chrono::duration_cast<std::chrono::milliseconds>(now - mLastProcessTime).count() < 30)
        {
            return;
        }
        mLastProcessTime = now;

        CURSORINFO ci = {sizeof(ci)};
        if (!GetCursorInfo(&ci) || !(ci.flags & CURSOR_SHOWING))
            return;

        // 获取当前 DPI 和 目标尺寸
        UINT currentDpi = GetCursorMonitorDPI();
        int expectedTierSize = GetExpectedSystemCursorSize(currentDpi, 32); // 假设基础是32

        // 注意：这里我们还需要简单判断一下是否是自定义光标来决定最终尺寸，
        // 为了性能，我们可以先简单用 expectedTierSize 做指纹判断。
        // 如果系统光标句柄没变，且预期档位没变，才算没变。

        // 同时检查句柄 和 尺寸
        if (ci.hCursor == mLastCursor && expectedTierSize == mLastSize)
        {
            return;
        }

        // 获取注册表的大小 (系统光标缩放大小)
        int regSize = GetTargetSize();

        // 获取动画帧数
        auto [frames, delay] = GetAnimInfo(ci.hCursor);

        // 获取光标原始物理尺寸
        ICONINFO ii = {0};
        GetIconInfo(ci.hCursor, &ii);

        int orgW = 32; // 默认为 32
        int orgH = 32;
        BITMAP bmp;

        // 尝试获取 Color 位图信息
        if (ii.hbmColor && GetObject(ii.hbmColor, sizeof(bmp), &bmp))
        {
            orgW = bmp.bmWidth;
            orgH = bmp.bmHeight;
        }
        // 如果没有 Color (黑白光标)，尝试获取 Mask 位图信息
        else if (ii.hbmMask && GetObject(ii.hbmMask, sizeof(bmp), &bmp))
        {
            orgW = bmp.bmWidth;
            orgH = bmp.bmHeight / 2; // Mask 高度通常是双倍的
        }

        // 这里的 hbmColor 和 hbmMask 用完需要释放，防止内存泄漏
        if (ii.hbmColor)
            DeleteObject(ii.hbmColor);
        if (ii.hbmMask)
            DeleteObject(ii.hbmMask);

        // =========================================================
        //           核心逻辑修改：基于 DPI 阶梯的系统光标判断
        // =========================================================
        int finalSizeW = 0;
        int finalSizeH = 0;

        // 获取当前屏幕 DPI
        UINT currentDpi = GetCursorMonitorDPI();

        // 计算当前 DPI 下，Windows 最可能加载的“标准档位尺寸”
        int expectedTierSize = GetExpectedSystemCursorSize(currentDpi, 32);

        // 判断逻辑
        bool isSystemCursor = (orgW == 32 || orgW == regSize || orgW == expectedTierSize);
        // 高dpi下的注册表光标大小倍率
        double scaleFactor = expectedTierSize / 32.0;

        // 格式：[DPI检测] DPI:144 | 档位:48 | 实际:48x48 -> SYSTEM (重置为32)
        Logger::Get().Debug(
            "[DPI检测]",
            "DPI:", currentDpi,
            "| 预测档位:", expectedTierSize,
            "| 实际尺寸:", orgW, "x", orgH,
            "->", isSystemCursor ? "SYSTEM (缩放)" : "CUSTOM (保持)");

        if (isSystemCursor)
        {
            // 判定为系统光标：
            // 这样客户端在 100% 缩放的电脑上看着才正常
            finalSizeW = int(regSize * scaleFactor);
            finalSizeH = int(regSize * scaleFactor);
        }
        else
        {
            // 判定为自定义光标：
            // 例如游戏里的特殊光标，或者非标准尺寸的光标 (如 40, 50, 128 等)
            // 保持原始物理分辨率，确保高清不模糊
            finalSizeW = orgW;
            finalSizeH = orgH;
        }
        // =========================================================

        // 根据最终决定的 finalSize 计算热点 (保持比例)
        float scaleRatioW = (float)finalSizeW / (float)orgW;
        float scaleRatioH = (float)finalSizeH / (float)orgH;

        int hotX = (int)(ii.xHotspot * scaleRatioW);
        int hotY = (int)(ii.yHotspot * scaleRatioH);

        // 边界钳制
        if (hotX >= finalSizeW)
            hotX = finalSizeW - 1;
        if (hotY >= finalSizeH)
            hotY = finalSizeH - 1;

        // 准备绘图尺寸
        int sheetW = finalSizeW;
        int sheetH = finalSizeH * frames;

        if (!RecreateResources(sheetW, sheetH))
            return;

        // 绘制背景 (批量清空)
        RECT allRc = {0, 0, sheetW, sheetH};
        SelectObject(m_hMemDC, m_hBmpB);
        FillRect(m_hMemDC, &allRc, (HBRUSH)GetStockObject(BLACK_BRUSH));

        SelectObject(m_hMemDC, m_hBmpW);
        FillRect(m_hMemDC, &allRc, (HBRUSH)GetStockObject(WHITE_BRUSH));

        // 绘制帧 (注意这里使用 finalSize 进行绘制)
        for (int i = 0; i < frames; ++i)
        {
            int drawY = i * finalSizeH;

            // DrawIconEx 会自动根据 destWidth/destHeight (finalSize) 进行缩放
            SelectObject(m_hMemDC, m_hBmpB);
            DrawIconEx(m_hMemDC, 0, drawY, ci.hCursor, finalSizeW, finalSizeH, i, NULL, DI_NORMAL);

            SelectObject(m_hMemDC, m_hBmpW);
            DrawIconEx(m_hMemDC, 0, drawY, ci.hCursor, finalSizeW, finalSizeH, i, NULL, DI_NORMAL);
        }

        // =========================================================
        //           像素提取与智能描边 (解决白底看不清问题)
        // =========================================================

        uint32_t *pxB = (uint32_t *)m_pBitsB;
        uint32_t *pxW = (uint32_t *)m_pBitsW;
        int totalPixels = sheetW * sheetH;

        std::vector<uint32_t> rawPixels(totalPixels, 0); // 初始化全透明
        std::vector<uint8_t> xorMask(totalPixels, 0);    // 标记哪些点是反色核心

        // --- 第一遍：提取颜色并标记反色区域 ---
        for (int i = 0; i < totalPixels; ++i)
        {
            uint32_t cB = pxB[i];
            uint32_t cW = pxW[i];

            uint8_t bb = (cB & 0xFF);
            uint8_t bg = ((cB >> 8) & 0xFF);
            uint8_t br = ((cB >> 16) & 0xFF);

            uint8_t wb = (cW & 0xFF);
            uint8_t wg = ((cW >> 8) & 0xFF);
            uint8_t wr = ((cW >> 16) & 0xFF);

            // 判定是否为 XOR 反色像素 (黑底极亮，白底极暗)
            if (bg > 200 && wg < 50)
            {
                // 强制设为纯白 (核心颜色)
                rawPixels[i] = 0xFFFFFFFF; // ARGB: 255, 255, 255, 255
                xorMask[i] = 1;            // 标记这个点是核心
                continue;
            }

            // 常规 Alpha 提取 (针对普通彩色光标)
            int dr = (int)wr - (int)br;
            int dg = (int)wg - (int)bg;
            int db = (int)wb - (int)bb;
            if (dr < 0)
                dr = 0;
            if (dg < 0)
                dg = 0;
            if (db < 0)
                db = 0;
            int maxDiff = std::max({dr, dg, db});
            uint8_t alpha = (uint8_t)(255 - maxDiff);

            if (alpha > 5)
            {
                rawPixels[i] = (alpha << 24) | (br << 16) | (bg << 8) | bb;
            }
        }

        // --- 第二遍：给白色核心加黑色描边 ---
        // 只有这样才能在纯白背景下看清纯白光标
        for (int y = 0; y < sheetH; ++y)
        {
            for (int x = 0; x < sheetW; ++x)
            {
                int idx = y * sheetW + x;

                // 如果当前像素已经有颜色了（是核心或普通光标），跳过
                if (rawPixels[idx] != 0)
                    continue;

                // 检查上下左右是否有 XOR 核心像素
                bool isBorder = false;
                if (x > 0 && xorMask[idx - 1])
                    isBorder = true;
                else if (x < sheetW - 1 && xorMask[idx + 1])
                    isBorder = true;
                else if (y > 0 && xorMask[idx - sheetW])
                    isBorder = true;
                else if (y < sheetH - 1 && xorMask[idx + sheetW])
                    isBorder = true;

                if (isBorder)
                {
                    // 绘制纯黑边框 (不透明)
                    rawPixels[idx] = 0xFF000000; // ARGB: 255, 0, 0, 0
                }
            }
        }

        // 计算 Hash 并发送
        size_t rawDataSize = rawPixels.size() * 4;
        uint32_t hash = CalculateCRC32(std::vector<uint8_t>((uint8_t *)rawPixels.data(), (uint8_t *)rawPixels.data() + rawDataSize));

        std::vector<uint8_t> png;
        if (!m_net.GetCachedPng(hash, png))
        {
            Gdiplus::Bitmap gdiBmp(sheetW, sheetH, PixelFormat32bppARGB);
            Gdiplus::BitmapData bd;
            Gdiplus::Rect r(0, 0, sheetW, sheetH);
            gdiBmp.LockBits(&r, Gdiplus::ImageLockModeWrite, PixelFormat32bppARGB, &bd);
            memcpy(bd.Scan0, rawPixels.data(), rawDataSize);
            gdiBmp.UnlockBits(&bd);

            IStream *s = NULL;
            CreateStreamOnHGlobal(NULL, TRUE, &s);
            CLSID pngId;
            GetEncoderClsid(L"image/png", &pngId);
            gdiBmp.Save(s, &pngId, NULL);
            STATSTG stg;
            s->Stat(&stg, STATFLAG_NONAME);
            png.resize(stg.cbSize.LowPart);
            LARGE_INTEGER pos = {0};
            s->Seek(pos, STREAM_SEEK_SET, NULL);
            ULONG read;
            s->Read(png.data(), (ULONG)png.size(), &read);
            s->Release();
            m_net.CachePng(hash, png);
        }

        if (!png.empty())
        {
            mLastCursor = ci.hCursor;
            mLastSize = expectedTierSize; 
            if (frames > 1)
                Logger::Get().Debug("发送动画 | Hash:", hash, " 尺寸:", finalSizeW, "x", finalSizeH, " 帧数:", frames);
            else
                Logger::Get().Debug("发送静态 | Hash:", hash, " 尺寸:", finalSizeW, "x", finalSizeH);

            m_net.BroadcastCursor(hash, hotX, hotY, frames, delay, png);
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