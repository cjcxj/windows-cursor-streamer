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
#include <list>
#include <chrono>
#include <algorithm>
#include <iomanip>
#include <sstream>
#include <memory>
#include <fstream>

// 3. 链接库
#pragma comment (lib, "ws2_32.lib")
#pragma comment (lib, "gdi32.lib")
#pragma comment (lib, "user32.lib")
#pragma comment (lib, "gdiplus.lib")
#pragma comment (lib, "shcore.lib")
#pragma comment (lib, "ole32.lib")
#pragma comment (lib, "advapi32.lib") 

// ==========================================
//           1. 配置
// ==========================================

const int LISTEN_PORT = 5005;

// ==========================================
//           2. 日志系统
// ==========================================

enum class LogLevel { TRACE, DEBUG, INFO, LOG_ERROR };

class Logger {
    std::mutex m_mutex;
    std::ofstream m_file;
    LogLevel m_level;
public:
    static Logger& Get() { static Logger instance; return instance; }

    Logger() : m_level(LogLevel::INFO) {
        m_file.open("cursor_monitor.log", std::ios::app);
        char* envLevel = nullptr; size_t len = 0;
        _dupenv_s(&envLevel, &len, "CURSOR_LOG_LEVEL");
        if (envLevel) {
            std::string l(envLevel);
            if (l == "TRACE") m_level = LogLevel::TRACE;
            else if (l == "DEBUG") m_level = LogLevel::DEBUG;
            else if (l == "INFO") m_level = LogLevel::INFO;
            else if (l == "ERROR") m_level = LogLevel::LOG_ERROR;
            free(envLevel);
        }
    }
    ~Logger() { if (m_file.is_open()) m_file.close(); }
    void SetLogLevel(LogLevel l) { m_level = l; }

    template<typename... Args> void Info(Args... args) { if(m_level<=LogLevel::INFO) Log("[INFO] ", args...); }
    template<typename... Args> void Error(Args... args) { if(m_level<=LogLevel::LOG_ERROR) Log("[ERROR] ", args...); }
    template<typename... Args> void Debug(Args... args) { if(m_level<=LogLevel::DEBUG) Log("[DEBUG] ", args...); }

private:
    template<typename... Args>
    void Log(const char* prefix, Args... args) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        std::tm tm_now; localtime_s(&tm_now, &now);
        
        // 控制台输出
        std::cout << std::put_time(&tm_now, "%H:%M:%S ") << prefix;
        ((std::cout << args << " "), ...);
        std::cout << std::endl;

        // 文件输出
        if (m_file.is_open()) {
            m_file << std::put_time(&tm_now, "%Y-%m-%d %H:%M:%S ") << prefix;
            ((m_file << args << " "), ...);
            m_file << std::endl;
        }
    }
};

uint32_t CalculateCRC32(const std::vector<uint8_t>& data) {
    uint32_t crc = 0xFFFFFFFF;
    for (uint8_t byte : data) {
        crc ^= byte;
        for (int i = 0; i < 8; i++) crc = (crc & 1) ? (crc >> 1) ^ 0xEDB88320 : crc >> 1;
    }
    return ~crc;
}

// RAII 资源管理
struct ScopedMemDC { HDC hdc; ScopedMemDC(HDC c) : hdc(CreateCompatibleDC(c)) {} ~ScopedMemDC() { DeleteDC(hdc); } operator HDC() { return hdc; } };
struct ScopedObject { HGDIOBJ h; ScopedObject(HGDIOBJ o) : h(o) {} ~ScopedObject() { DeleteObject(h); } };

// 全局同步信号
std::condition_variable g_cvCursorChanged;
std::mutex g_mutexCursor;
bool g_cursorChanged = false;

// ==========================================
//           3. 网络管理 (支持新协议)
// ==========================================

struct ClientSession { SOCKET socket; bool connected; uint32_t lastSentHash; };

class NetworkManager {
    SOCKET m_listenSocket;
    std::list<std::shared_ptr<ClientSession>> m_clients;
    std::mutex m_clientsMutex;
    std::map<uint32_t, std::vector<uint8_t>> m_cache;
    std::mutex m_cacheMutex;
    std::atomic<bool> m_running{ true };

public:
    NetworkManager() : m_listenSocket(INVALID_SOCKET) {}

    bool Initialize() {
        WSADATA wsa; WSAStartup(MAKEWORD(2,2), &wsa);
        m_listenSocket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
        if(m_listenSocket == INVALID_SOCKET) return false;
        
        int no=0, yes=1;
        setsockopt(m_listenSocket, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&no, sizeof(no));
        setsockopt(m_listenSocket, SOL_SOCKET, SO_REUSEADDR, (char*)&yes, sizeof(yes));
        
        sockaddr_in6 addr={0}; 
        addr.sin6_family=AF_INET6; 
        addr.sin6_port=htons(LISTEN_PORT);
        
        if(bind(m_listenSocket, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) return false;
        if(listen(m_listenSocket, SOMAXCONN) == SOCKET_ERROR) return false;
        
        Logger::Get().Info("TCP 服务端就绪，端口:", LISTEN_PORT);
        return true;
    }

    void Shutdown() {
        m_running = false;
        closesocket(m_listenSocket);
        { std::lock_guard<std::mutex> l(m_clientsMutex); for(auto& c : m_clients) closesocket(c->socket); m_clients.clear(); }
        WSACleanup();
    }

    void AcceptLoop() {
        while(m_running) {
            SOCKET c = accept(m_listenSocket, NULL, NULL);
            if(c == INVALID_SOCKET) break;
            int yes=1; setsockopt(c, IPPROTO_TCP, TCP_NODELAY, (char*)&yes, sizeof(yes));
            
            auto s = std::make_shared<ClientSession>();
            s->socket = c; s->connected = true; s->lastSentHash = 0;
            
            { std::lock_guard<std::mutex> l(m_clientsMutex); m_clients.push_back(s); }
            
            // 触发一次发送，让新客户端立即获得光标
            { std::lock_guard<std::mutex> l(g_mutexCursor); g_cursorChanged = true; } 
            g_cvCursorChanged.notify_one();
            
            Logger::Get().Info("新客户端已连接");
        }
    }

    bool GetCachedPng(uint32_t hash, std::vector<uint8_t>& out) {
        std::lock_guard<std::mutex> l(m_cacheMutex);
        if(m_cache.count(hash)) { out=m_cache[hash]; return true; }
        return false;
    }

    void CachePng(uint32_t hash, const std::vector<uint8_t>& data) {
        std::lock_guard<std::mutex> l(m_cacheMutex);
        if(m_cache.size() > 50) m_cache.clear();
        m_cache[hash] = data;
    }

    // 广播函数：支持帧数和延迟
    void BroadcastCursor(uint32_t hash, int32_t hotX, int32_t hotY, int32_t frames, int32_t delay, const std::vector<uint8_t>& png) {
        std::lock_guard<std::mutex> lock(m_clientsMutex);
        
        uint32_t pngSize = (uint32_t)png.size();
        // 包结构：[BodyLen 4] + [HotX 4] [HotY 4] [Frames 4] [Delay 4] + [PNG Data...]
        uint32_t bodySize = 16 + pngSize; 
        
        std::vector<uint8_t> packet(4 + bodySize);
        memcpy(packet.data(), &bodySize, 4);
        memcpy(packet.data() + 4, &hotX, 4);
        memcpy(packet.data() + 8, &hotY, 4);
        memcpy(packet.data() + 12, &frames, 4);
        memcpy(packet.data() + 16, &delay, 4);
        memcpy(packet.data() + 20, png.data(), pngSize);

        for (auto it = m_clients.begin(); it != m_clients.end(); ) {
            auto& c = *it;
            if (!c->connected) { it = m_clients.erase(it); continue; }
            
            // 去重：如果该客户端已经有这个 Hash，就不发了
            if (c->lastSentHash == hash) { ++it; continue; }
            
            if (send(c->socket, (const char*)packet.data(), (int)packet.size(), 0) == SOCKET_ERROR) {
                closesocket(c->socket); c->connected = false; it = m_clients.erase(it);
            } else {
                c->lastSentHash = hash;
                ++it;
            }
        }
    }
};

// ==========================================
//           4. 光标引擎 (Sprite Sheet Generator)
// ==========================================

// user32.dll 未公开 API 定义
typedef BOOL(WINAPI* GETCURSORFRAMEINFO)(HCURSOR, DWORD, DWORD, DWORD*, DWORD*);

class CursorEngine {
    ULONG_PTR m_token;
    NetworkManager& m_net;
    HMODULE m_hUser32;
    GETCURSORFRAMEINFO m_pGetCursorFrameInfo;

    // 状态缓存
    HCURSOR mLastCursor = NULL;
    uint32_t mLastHash = 0;
    std::vector<uint8_t> mLastPng;
    int mLastHotX=0, mLastHotY=0, mLastFrames=1, mLastDelay=0;

    static int GetEncoderClsid(const WCHAR* format, CLSID* pClsid) {
        UINT num, size; Gdiplus::GetImageEncodersSize(&num, &size);
        if(size==0) return -1;
        std::vector<char> buf(size); Gdiplus::ImageCodecInfo* p = (Gdiplus::ImageCodecInfo*)buf.data();
        Gdiplus::GetImageEncoders(num, size, p);
        for(UINT j=0; j<num; ++j) if(wcscmp(p[j].MimeType, format)==0) { *pClsid=p[j].Clsid; return j; }
        return -1;
    }

    // 从注册表读取用户设置的光标大小
    int GetTargetSize() {
        HKEY k; int s=32;
        if(RegOpenKeyExA(HKEY_CURRENT_USER, "Control Panel\\Cursors", 0, KEY_READ, &k)==0) {
            DWORD t, sz=4, v=0; 
            if(RegQueryValueExA(k, "CursorBaseSize", 0, &t, (BYTE*)&v, &sz)==0) s=v;
            RegCloseKey(k);
        }
        return std::clamp(s, 32, 256);
    }

    // 获取动画信息 <帧数, 延迟ms>
    std::pair<int, int> GetAnimInfo(HCURSOR h) {
        if(!m_pGetCursorFrameInfo) return {1, 0};
        DWORD rate=0, count=0;
        if(m_pGetCursorFrameInfo(h, 0, 0, &rate, &count)) {
            if(count == 0) count = 1;
            // rate 单位通常是 Jiffies (1/60s)
            int delay = (int)((rate * 1000) / 60);
            if(delay < 10) delay = 0;
            return { (int)count, delay };
        }
        return {1, 0};
    }

public:
    CursorEngine(NetworkManager& n) : m_net(n), m_token(0), m_hUser32(NULL), m_pGetCursorFrameInfo(NULL) {
        Gdiplus::GdiplusStartupInput i; Gdiplus::GdiplusStartup(&m_token, &i, NULL);
        m_hUser32 = LoadLibraryA("user32.dll");
        if(m_hUser32) m_pGetCursorFrameInfo = (GETCURSORFRAMEINFO)GetProcAddress(m_hUser32, "GetCursorFrameInfo");
    }
    ~CursorEngine() {
        if(m_hUser32) FreeLibrary(m_hUser32);
        Gdiplus::GdiplusShutdown(m_token);
    }

    void CaptureAndSend() {
        CURSORINFO ci={sizeof(ci)}; 
        if(!GetCursorInfo(&ci) || !(ci.flags & CURSOR_SHOWING)) return;

        // 快速缓存校验 (句柄+缓存均有效)
        if(ci.hCursor == mLastCursor && mLastCursor && !mLastPng.empty()) {
            m_net.BroadcastCursor(mLastHash, mLastHotX, mLastHotY, mLastFrames, mLastDelay, mLastPng);
            return;
        }

        int size = GetTargetSize();
        auto [frames, delay] = GetAnimInfo(ci.hCursor);
        
        // --- 1. 计算缩放后的热点 ---
        ICONINFO ii={0}; GetIconInfo(ci.hCursor, &ii);
        int orgW=32, orgH=32; BITMAP bmp;
        if(ii.hbmColor && GetObject(ii.hbmColor, sizeof(bmp), &bmp)) { orgW=bmp.bmWidth; orgH=bmp.bmHeight; }
        else if(ii.hbmMask && GetObject(ii.hbmMask, sizeof(bmp), &bmp)) { orgW=bmp.bmWidth; orgH=bmp.bmHeight/2; }
        DeleteObject(ii.hbmMask); DeleteObject(ii.hbmColor); // 必须释放

        int hotX = (int)(ii.xHotspot * ((float)size / orgW));
        int hotY = (int)(ii.yHotspot * ((float)size / orgH));
        if(hotX >= size) hotX = size-1; 
        if(hotY >= size) hotY = size-1;

        // --- 2. 准备 Sprite Sheet 画布 ---
        int sheetW = size;
        int sheetH = size * frames; // 总高度

        HDC hdc = GetDC(NULL);
        ScopedMemDC dcMem(hdc);
        ReleaseDC(NULL, hdc);

        BITMAPINFOHEADER bi={sizeof(bi)};
        bi.biWidth = sheetW; bi.biHeight = -sheetH; // Top-Down
        bi.biPlanes=1; bi.biBitCount=32; bi.biCompression=BI_RGB;

        void *pB=NULL, *pW=NULL;
        HBITMAP hBmpB = CreateDIBSection(dcMem, (BITMAPINFO*)&bi, DIB_RGB_COLORS, &pB, NULL, 0);
        HBITMAP hBmpW = CreateDIBSection(dcMem, (BITMAPINFO*)&bi, DIB_RGB_COLORS, &pW, NULL, 0);
        
        if(!hBmpB || !hBmpW) return;
        ScopedObject sb(hBmpB), sw(hBmpW);

        // --- 3. 绘制每一帧 (Sprite Sheet Generation) ---
        // 技巧：DrawIconEx 的 step 参数可以指定绘制动画的第几帧
        
        // 填充背景
        RECT allRc = {0, 0, sheetW, sheetH};
        SelectObject(dcMem, hBmpB);
        FillRect(dcMem, &allRc, (HBRUSH)GetStockObject(BLACK_BRUSH));
        SelectObject(dcMem, hBmpW);
        FillRect(dcMem, &allRc, (HBRUSH)GetStockObject(WHITE_BRUSH));

        for(int i=0; i<frames; ++i) {
            int drawY = i * size;
            
            // 在黑底上绘制第 i 帧
            SelectObject(dcMem, hBmpB);
            DrawIconEx(dcMem, 0, drawY, ci.hCursor, size, size, i, NULL, DI_NORMAL);

            // 在白底上绘制第 i 帧
            SelectObject(dcMem, hBmpW);
            DrawIconEx(dcMem, 0, drawY, ci.hCursor, size, size, i, NULL, DI_NORMAL);
        }

        // --- 4. 像素提取 (Raw Mode Alpha) ---
        uint32_t* pxB = (uint32_t*)pB;
        uint32_t* pxW = (uint32_t*)pW;
        int totalPixels = sheetW * sheetH;
        std::vector<uint32_t> rawPixels(totalPixels);

        for(int i=0; i<totalPixels; ++i) {
            uint8_t bb = (pxB[i]&0xFF), bg = ((pxB[i]>>8)&0xFF), br = ((pxB[i]>>16)&0xFF);
            uint8_t wb = (pxW[i]&0xFF), wg = ((pxW[i]>>8)&0xFF), wr = ((pxW[i]>>16)&0xFF);
            
            // Alpha 还原算法
            int dr=wr-br, dg=wg-bg, db=wb-bb;
            int maxDiff = std::max({dr, dg, db});
            uint8_t alpha = (uint8_t)std::clamp(255-maxDiff, 0, 255);
            
            // 合成 ARGB
            rawPixels[i] = (alpha<<24) | (br<<16) | (bg<<8) | bb;
        }

        // --- 5. 压缩与发送 ---
        size_t rawDataSize = rawPixels.size()*4;
        uint32_t hash = CalculateCRC32(std::vector<uint8_t>((uint8_t*)rawPixels.data(), (uint8_t*)rawPixels.data()+rawDataSize));

        std::vector<uint8_t> png;
        if(!m_net.GetCachedPng(hash, png)) {
            // GDI+ 保存 PNG
            Gdiplus::Bitmap bmp(sheetW, sheetH, PixelFormat32bppARGB);
            Gdiplus::BitmapData bd; Gdiplus::Rect r(0,0,sheetW,sheetH);
            bmp.LockBits(&r, Gdiplus::ImageLockModeWrite, PixelFormat32bppARGB, &bd);
            memcpy(bd.Scan0, rawPixels.data(), rawDataSize);
            bmp.UnlockBits(&bd);
            
            IStream* s=NULL; CreateStreamOnHGlobal(NULL, TRUE, &s);
            CLSID pngId; GetEncoderClsid(L"image/png", &pngId);
            bmp.Save(s, &pngId, NULL);
            STATSTG stg; s->Stat(&stg, STATFLAG_NONAME);
            png.resize(stg.cbSize.LowPart);
            LARGE_INTEGER pos={0}; s->Seek(pos, STREAM_SEEK_SET, NULL);
            ULONG read; s->Read(png.data(), (ULONG)png.size(), &read);
            s->Release();
            m_net.CachePng(hash, png);
        }

        if(!png.empty()) {
            // 更新缓存
            mLastCursor = ci.hCursor; mLastHash = hash; mLastPng = png;
            mLastHotX = hotX; mLastHotY = hotY; mLastFrames = frames; mLastDelay = delay;
            
            // 详细日志
            if(frames > 1) {
                Logger::Get().Info("发送动画光标 | 尺寸:", size, "x", size, 
                                   " | 帧数:", frames, " | 延迟:", delay, "ms",
                                   " | PNG大小:", png.size(), "B",
                                   " | Hash:", hash);
            } else {
                Logger::Get().Info("发送静态光标 | 尺寸:", size, "x", size,
                                   " | 热点:", hotX, ",", hotY,
                                   " | PNG大小:", png.size(), "B",
                                   " | Hash:", hash);
            }

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
void CALLBACK HookProc(HWINEVENTHOOK, DWORD, HWND, LONG id, LONG, DWORD, DWORD) {
    if(id==OBJID_CURSOR) { 
        std::lock_guard<std::mutex> l(g_mutexCursor); 
        g_cursorChanged=true; 
        g_cvCursorChanged.notify_one(); 
    }
}

// 工作线程：处理图像
void Worker() {
    while(!g_exit) {
        { 
            std::unique_lock<std::mutex> l(g_mutexCursor); 
            // 等待信号，或者 33ms 超时轮询 (30FPS兜底)
            g_cvCursorChanged.wait_for(l, std::chrono::milliseconds(33), []{return g_cursorChanged || g_exit;}); 
            if(g_exit) break; 
            g_cursorChanged=false; 
        }
        g_engine->CaptureAndSend();
    }
}

// 命令行参数处理
void ShowUsage() {
    std::cout << "Usage: cursor_monitor [options]\n  -l LVL  Set log level (TRACE, DEBUG, INFO, ERROR)\n";
}

int main(int argc, char* argv[]) {
    // 日志级别设置
    LogLevel lvl = LogLevel::DEBUG;
    for(int i=1; i<argc; ++i) {
        std::string s=argv[i];
        if(s=="-l" && i+1<argc) {
            std::string v=argv[++i];
            if(v=="INFO") lvl=LogLevel::INFO;
            else if(v=="ERROR") lvl=LogLevel::LOG_ERROR;
        }
    }
    Logger::Get().SetLogLevel(lvl);

    // 强制开启高 DPI (Shcore)
    HMODULE h=LoadLibraryA("Shcore.dll");
    if(h) { 
        typedef HRESULT(WINAPI* SDPA)(PROCESS_DPI_AWARENESS);
        SDPA p = (SDPA)GetProcAddress(h, "SetProcessDpiAwareness");
        if(p) p(PROCESS_PER_MONITOR_DPI_AWARE);
        FreeLibrary(h);
    } else SetProcessDPIAware();

    Logger::Get().Info("======= 程序启动 (TCP + Animated Sprite Sheet) =======");

    if(!g_net.Initialize()) return 1;
    g_engine = std::make_unique<CursorEngine>(g_net);
    
    // 启动线程
    std::thread t1(Worker);
    std::thread t2([&]{ g_net.AcceptLoop(); });
    
    // 安装钩子
    HWINEVENTHOOK hHook = SetWinEventHook(EVENT_OBJECT_NAMECHANGE, EVENT_OBJECT_NAMECHANGE, NULL, HookProc, 0, 0, WINEVENT_OUTOFCONTEXT|WINEVENT_SKIPOWNPROCESS);
    
    // 消息循环 (必须保留以响应钩子)
    MSG msg; while(GetMessage(&msg,NULL,0,0)) { TranslateMessage(&msg); DispatchMessage(&msg); }
    
    // 退出清理
    g_exit=true; g_cvCursorChanged.notify_all();
    g_net.Shutdown(); t1.join(); t2.join(); UnhookWinEvent(hHook);
    return 0;
}