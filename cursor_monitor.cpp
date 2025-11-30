#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <thread>
#include <atomic>
#include <cstring>
#include <zlib.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "zlib.lib")

#include "logger.hpp"
#include "lru_cache.hpp"
#include "client_manager.hpp"
#include "cursor_capture.hpp"

Logger g_logger("cursor_monitor. log");

// ===================== 全局变量 =====================
const int LISTEN_PORT = 5005;
const char* LISTEN_ADDR = "::";
const int KEEPALIVE_INTERVAL = 1;
const int CLIENT_TIMEOUT = 30;

SOCKET g_socket = INVALID_SOCKET;
ClientManager g_client_manager;
LRUCache g_image_cache(100);
DWORD g_last_hcursor = 0;
std::atomic<bool> g_running(true);

// ===================== 网络初始化 =====================
bool InitializeSocket() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        g_logger.Error("WSAStartup failed");
        return false;
    }
    
    g_socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (g_socket == INVALID_SOCKET) {
        g_logger.Error("Failed to create socket");
        return false;
    }
    
    // 禁用 SIO_UDP_CONNRESET
    DWORD dwBytesReturned = 0;
    BOOL bNewBehavior = FALSE;
    if (WSAIoctl(g_socket, SIO_UDP_CONNRESET, &bNewBehavior, sizeof(bNewBehavior),
                 nullptr, 0, &dwBytesReturned, nullptr, nullptr) == SOCKET_ERROR) {
        g_logger.Warning("Failed to disable SIO_UDP_CONNRESET");
    }
    
    sockaddr_in6 addr = {};
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(LISTEN_PORT);
    inet_pton(AF_INET6, "::", &addr.sin6_addr);
    
    if (bind(g_socket, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        g_logger.Error("bind() failed");
        closesocket(g_socket);
        return false;
    }
    
    u_long nonBlock = 1;
    if (ioctlsocket(g_socket, FIONBIO, &nonBlock) == SOCKET_ERROR) {
        g_logger.Error("ioctlsocket() failed");
        return false;
    }
    
    g_logger.Info("✓ Socket initialized on [::]:" + std::to_string(LISTEN_PORT));
    return true;
}

// ===================== 工作线程 =====================
void ProcessCursorWorker() {
    try {
        auto clients = g_client_manager.GetAllClients();
        if (clients.empty()) return;
        
        CursorCapture capture;
        std::vector<BYTE> png_data;
        int hotspot_x, hotspot_y;
        DWORD hcursor;
        
        if (!capture. Capture(png_data, hotspot_x, hotspot_y, hcursor)) {
            return;
        }
        
        // CRC32 校验和
        uint32_t img_hash = crc32(0, png_data.data(), png_data.size());
        bool is_new = g_image_cache.Add(img_hash);
        
        std::vector<BYTE> packet;
        
        if (is_new) {
            // 格式: 1字节类型(0) + 4字节hash + 4字节hotX + 4字节hotY + PNG数据
            packet.resize(1 + 4 + 4 + 4 + png_data.size());
            packet[0] = 0;
            memcpy(packet.data() + 1, &img_hash, 4);
            memcpy(packet.data() + 5, &hotspot_x, 4);
            memcpy(packet.data() + 9, &hotspot_y, 4);
            memcpy(packet.data() + 13, png_data.data(), png_data.size());
            
            g_logger.Info("📤 Sending new image: hash=" + std::to_string(img_hash) +
                         ", size=" + std::to_string(png_data.size()) + " bytes");
        } else {
            // 仅发送hash
            packet.resize(1 + 4 + 4 + 4);
            packet[0] = 1;
            memcpy(packet.data() + 1, &img_hash, 4);
            memcpy(packet. data() + 5, &hotspot_x, 4);
            memcpy(packet.data() + 9, &hotspot_y, 4);
        }
        
        // 发送给所有客户端
        for (const auto& client : clients) {
            if (sendto(g_socket, (const char*)packet.data(), packet.size(), 0,
                      (sockaddr*)&client. addr, sizeof(client.addr)) == SOCKET_ERROR) {
                int err = WSAGetLastError();
                if (err != WSAECONNRESET) {
                    g_logger.Error("sendto() error: " + std::to_string(err));
                }
            }
        }
        
    } catch (const std::exception& e) {
        g_logger.Error(std::string("ProcessCursorWorker error: ") + e.what());
    }
}

// ===================== 网络监听线程 =====================
void NetworkListenerThread() {
    g_logger.Info("🔊 Network listener started");
    
    std::time_t last_cleanup = std::time(nullptr);
    int error_count = 0;
    
    while (g_running) {
        try {
            sockaddr_in6 client_addr = {};
            int addr_len = sizeof(client_addr);
            char buffer[1024] = {};
            
            int recv_len = recvfrom(g_socket, buffer, sizeof(buffer) - 1, 0,
                                   (sockaddr*)&client_addr, &addr_len);
            
            if (recv_len == SOCKET_ERROR) {
                int err = WSAGetLastError();
                if (err == WSAEWOULDBLOCK) {
                    // 正常，非阻塞模式
                } else if (err == WSAECONNRESET) {
                    error_count++;
                    if (error_count <= 3) {
                        g_logger.Debug("⚠ UDP connection reset (normal)");
                    }
                } else {
                    g_logger.Error("recvfrom() error: " + std::to_string(err));
                }
            } else if (recv_len > 0) {
                error_count = 0;
                std::string message(buffer, recv_len);
                
                if (message == "CURSOR_HELLO") {
                    bool is_new = g_client_manager.AddClient(client_addr);
                    if (is_new) {
                        g_logger.Info("🔄 Client initialization: clearing cache");
                        g_image_cache.Clear();
                        g_last_hcursor = 0;
                        std::thread(ProcessCursorWorker).detach();
                    }
                    int count = g_client_manager.GetClientCount();
                    g_logger.Info("✓ Current online clients: " + std::to_string(count));
                    
                } else if (message == "KEEPALIVE") {
                    g_client_manager.UpdateActivity(client_addr);
                    g_logger.Debug("💓 Heartbeat received");
                }
            }
            
            // 定期清理超时客户端
            std::time_t now = std::time(nullptr);
            if (now - last_cleanup > 5) {
                g_client_manager.RemoveTimeoutClients(CLIENT_TIMEOUT);
                last_cleanup = now;
            }
            
            // 发送心跳
            auto clients = g_client_manager. GetAllClients();
            for (const auto& client : clients) {
                BYTE heartbeat = 2;
                sendto(g_socket, (const char*)&heartbeat, 1, 0,
                      (sockaddr*)&client.addr, sizeof(client.addr));
            }
            
            Sleep(100);
            
        } catch (const std::exception& e) {
            g_logger.Error(std::string("NetworkListenerThread error: ") + e.what());
        }
    }
}

// ===================== 钩子回调 =====================
HWINEVENTHOOK g_hook = nullptr;

void CALLBACK WinEventProc(HWINEVENTHOOK hWinEventHook, DWORD event, HWND hwnd,
                          LONG idObject, LONG idChild, DWORD dwEventThread,
                          DWORD dwmsEventTime) {
    if (idObject == OBJID_CURSOR) {
        CURSORINFO ci = {sizeof(CURSORINFO)};
        if (GetCursorInfo(&ci) && ci.hCursor != (HCURSOR)g_last_hcursor) {
            g_last_hcursor = (DWORD)ci.hCursor;
            std::thread(ProcessCursorWorker).detach();
        }
    }
}

// ===================== 主函数 =====================
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine, int nCmdShow) {
    try {
        g_logger.Info("===============================================");
        g_logger. Info("  光标监控网络传输 - C++ 版本");
        g_logger. Info("  Cursor Monitor Network Transmission - C++");
        g_logger.Info("===============================================");
        
        // 初始化GDI+
        GdiplusStartupInput gdiplusStartupInput;
        ULONG_PTR gdiplusToken;
        GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, nullptr);
        
        // 初始化socket
        if (! InitializeSocket()) {
            g_logger.Critical("✗ Failed to initialize socket");
            return 1;
        }
        
        // 启动网络监听线程
        std::thread net_listener(NetworkListenerThread);
        net_listener.detach();
        
        g_logger.Info("✓ System initialized successfully");
        
        // 安装钩子
        g_hook = SetWinEventHook(EVENT_OBJECT_NAMECHANGE, EVENT_OBJECT_NAMECHANGE, 0,
                               WinEventProc, 0, 0, WINEVENT_OUTOFCONTEXT);
        if (! g_hook) {
            g_logger.Critical("✗ Failed to install hook");
            return 1;
        }
        
        g_logger.Info("✓ Hook installed successfully");
        
        // 消息循环
        MSG msg;
        while (GetMessage(&msg, nullptr, 0, 0)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
        
        // 清理
        g_running = false;
        if (g_hook) UnhookWinEvent(g_hook);
        if (g_socket != INVALID_SOCKET) closesocket(g_socket);
        WSACleanup();
        GdiplusShutdown(gdiplusToken);
        
        g_logger.Info("✓ Cleanup completed");
        
    } catch (const std::exception& e) {
        g_logger. Critical(std::string("✗ Fatal error: ") + e.what());
        return 1;
    }
    
    return 0;
}