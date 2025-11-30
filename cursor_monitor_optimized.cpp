// 1. 瘦身 Windows 头文件，解决 Winsock 重定义冲突
#define WIN32_LEAN_AND_MEAN

// 2. 禁用 Windows 自带的 min/max 宏，防止干扰 C++ std::min/max
#define NOMINMAX

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

// 3. 【关键修复】手动引入 IStream 定义 (因为被 LEAN_AND_MEAN 排除掉了)
#include <objidl.h>

// 4. 引入算法库，弥补禁用宏后的 min/max
#include <algorithm>
// 方便代码中直接使用 min/max (你的代码里用到了)
using std::min;
using std::max;

#include <thread>
#include <atomic>
#include <cstring>
#include <zlib.h>
#include <gdiplus.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "gdiplus.lib")
#pragma comment(lib, "zlib.lib")

#include "logger.hpp"
#include "lru_cache.hpp"
#include "client_manager.hpp"
#include "cursor_capture.hpp"

using namespace Gdiplus;

Logger g_logger("cursor_monitor. log");

// ===================== 全局变量 =====================
const int LISTEN_PORT = 5005;
const char* LISTEN_ADDR = "::";
const int KEEPALIVE_INTERVAL = 1;
const int CLIENT_TIMEOUT = 30;

SOCKET g_socket = INVALID_SOCKET;
WSAEVENT g_socket_event = nullptr;           // ✅ Socket 事件
HANDLE g_shutdown_event = nullptr;           // ✅ 关闭事件
ClientManager g_client_manager;
LRUCache g_image_cache(100);
DWORD g_last_hcursor = 0;
std::atomic<bool> g_running(true);
time_t g_last_keepalive_send = 0;
time_t g_last_cleanup_time = 0;

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
    
    // ✅ 创建事件对象
    g_socket_event = WSACreateEvent();
    if (g_socket_event == WSA_INVALID_EVENT) {
        g_logger. Error("WSACreateEvent() failed");
        closesocket(g_socket);
        return false;
    }
    
    // ✅ 关联 socket 与事件（监控可读事件）
    if (WSAEventSelect(g_socket, g_socket_event, FD_READ) == SOCKET_ERROR) {
        g_logger.Error("WSAEventSelect() failed");
        WSACloseEvent(g_socket_event);
        closesocket(g_socket);
        return false;
    }
    
    g_logger.Info("✓ Socket initialized on [::]:5005 with event-driven mode");
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
        uint32_t img_hash = crc32(0, png_data.data(), (unsigned int)png_data.size());
        bool is_new = g_image_cache.Add(img_hash);
        
        std::vector<BYTE> packet;
        
        if (is_new) {
            // 格式: 1字节类型(0) + 4字节hash + 4字节hotX + 4字节hotY + PNG数据
            packet.resize(1 + 4 + 4 + 4 + png_data.size());
            packet[0] = 0;
            memcpy(packet.data() + 1, &img_hash, 4);
            memcpy(packet. data() + 5, &hotspot_x, 4);
            memcpy(packet.data() + 9, &hotspot_y, 4);
            memcpy(packet.data() + 13, png_data. data(), png_data.size());
            
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
        int success_count = 0;
        for (const auto& client : clients) {
            if (sendto(g_socket, (const char*)packet.data(), (int)packet.size(), 0,
                      (sockaddr*)&client.addr, sizeof(client.addr)) != SOCKET_ERROR) {
                success_count++;
            }
        }
        
        g_logger.Debug("Sent to " + std::to_string(success_count) + 
                      "/" + std::to_string(clients.size()) + " clients");
        
    } catch (const std::exception& e) {
        g_logger.Error(std::string("ProcessCursorWorker error: ") + e.what());
    }
}

// ===================== 网络监听线程（事件驱动版）✅ =====================
void NetworkListenerThread() {
    g_logger.Info("🔊 Network listener started (Event-driven mode, Low CPU)");
    
    // ✅ 创建关闭事件
    g_shutdown_event = CreateEvent(nullptr, TRUE, FALSE, nullptr);
    if (! g_shutdown_event) {
        g_logger.Error("CreateEvent() failed");
        return;
    }
    
    // ✅ 两个事件：socket 事件和关闭事件
    HANDLE events[2] = {g_socket_event, g_shutdown_event};
    
    g_last_keepalive_send = time(nullptr);
    g_last_cleanup_time = time(nullptr);
    
    while (g_running) {
        try {
            // ✅ 等待任意事件：socket有数据 或 收到关闭信号
            // 超时设置为 1000ms，用于定期清理和心跳
            DWORD dwRet = WSAWaitForMultipleEvents(
                2,                    // 监控 2 个事件
                events,               // 事件句柄数组
                FALSE,                // 任意一个事件触发即返回
                1000,                 // 超时 1000ms（用于心跳和清理）
                FALSE                 // 不自动重置
            );
            
            if (dwRet == WSA_WAIT_TIMEOUT) {
                // ✅ 超时：执行定期任务（心跳、清理）
                goto periodic_tasks;
            }
            
            if (dwRet == WSA_WAIT_EVENT_0) {
                // ✅ Socket 有数据可读
                WSANETWORKEVENTS networkEvents = {};
                if (WSAEnumNetworkEvents(g_socket, g_socket_event, &networkEvents) == SOCKET_ERROR) {
                    g_logger.Error("WSAEnumNetworkEvents() failed");
                    continue;
                }
                
                if (networkEvents.lNetworkEvents & FD_READ) {
                    sockaddr_in6 client_addr = {};
                    int addr_len = sizeof(client_addr);
                    char buffer[1024] = {};
                    
                    int recv_len = recvfrom(g_socket, buffer, sizeof(buffer) - 1, 0,
                                           (sockaddr*)&client_addr, &addr_len);
                    
                    if (recv_len > 0) {
                        std::string message(buffer, recv_len);
                        
                        if (message == "CURSOR_HELLO") {
                            // 客户端连接
                            bool is_new = g_client_manager.AddClient(client_addr);
                            if (is_new) {
                                g_logger.Info("🔄 Client initialization: clearing cache");
                                g_image_cache.Clear();
                                g_last_hcursor = 0;
                                
                                // 立即发送一帧图像
                                std::thread(ProcessCursorWorker).detach();
                            }
                            
                            int count = g_client_manager.GetClientCount();
                            g_logger.Info("✓ Current online clients: " + std::to_string(count));
                            
                        } else if (message == "KEEPALIVE") {
                            // 客户端心跳
                            g_client_manager.UpdateActivity(client_addr);
                            g_logger.Debug("💓 Heartbeat from client");
                        }
                    }
                }
                
            } else if (dwRet == WSA_WAIT_EVENT_0 + 1) {
                // ✅ 收到关闭信号
                g_logger.Info("Shutdown event received, exiting listener thread");
                break;
            }
            
        periodic_tasks:
            // ✅ 定期任务（每 5 秒清理一次超时客户端）
            time_t now = time(nullptr);
            
            if (now - g_last_cleanup_time > 5) {
                int old_count = g_client_manager.GetClientCount();
                g_client_manager.RemoveTimeoutClients(CLIENT_TIMEOUT);
                int new_count = g_client_manager.GetClientCount();
                
                if (old_count != new_count) {
                    g_logger.Info("🧹 Cleaned up " + std::to_string(old_count - new_count) + 
                                 " timeout clients, remaining: " + std::to_string(new_count));
                }
                
                g_last_cleanup_time = now;
            }
            
            // ✅ 发送心跳包（每 1 秒发送一次）
            if (now - g_last_keepalive_send > KEEPALIVE_INTERVAL) {
                auto clients = g_client_manager.GetAllClients();
                
                if (! clients.empty()) {
                    BYTE heartbeat = 2;
                    int sent_count = 0;
                    
                    for (const auto& client : clients) {
                        if (sendto(g_socket, (const char*)&heartbeat, 1, 0,
                                  (sockaddr*)&client.addr, sizeof(client. addr)) != SOCKET_ERROR) {
                            sent_count++;
                        }
                    }
                    
                    g_logger.Debug("💓 Sent heartbeat to " + std::to_string(sent_count) + 
                                  "/" + std::to_string(clients.size()) + " clients");
                }
                
                g_last_keepalive_send = now;
            }
            
        } catch (const std::exception& e) {
            g_logger. Error(std::string("NetworkListenerThread error: ") + e.what());
        }
    }
    
    // 清理事件
    if (g_shutdown_event) {
        CloseHandle(g_shutdown_event);
        g_shutdown_event = nullptr;
    }
    
    g_logger.Info("Network listener thread exited");
}

// ===================== 钩子回调 =====================
HWINEVENTHOOK g_hook = nullptr;
std::atomic<DWORD> g_hook_call_count(0);

void CALLBACK WinEventProc(HWINEVENTHOOK hWinEventHook, DWORD event, HWND hwnd,
                          LONG idObject, LONG idChild, DWORD dwEventThread,
                          DWORD dwmsEventTime) {
    if (idObject == OBJID_CURSOR) {
        CURSORINFO ci = {sizeof(CURSORINFO)};
        if (GetCursorInfo(&ci) && ci.hCursor) {
            DWORD current_hcursor = (DWORD)ci.hCursor;
            
            if (current_hcursor != g_last_hcursor) {
                g_last_hcursor = current_hcursor;
                g_hook_call_count++;
                
                // 后台线程处理，不阻塞钩子
                std::thread(ProcessCursorWorker).detach();
            }
        }
    }
}

// ===================== 主函数 =====================
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine, int nCmdShow) {
    try {
        g_logger.Info("===============================================");
        g_logger. Info("  Cursor Monitor Network Transmission - C++");
        g_logger.Info("  Event-Driven Mode (Low CPU Optimization)");
        g_logger. Info("===============================================");
        
        // 初始化GDI+
        GdiplusStartupInput gdiplusStartupInput;
        ULONG_PTR gdiplusToken;
        GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, nullptr);
        
        // 初始化socket
        if (! InitializeSocket()) {
            g_logger.Critical("✗ Failed to initialize socket");
            GdiplusShutdown(gdiplusToken);
            return 1;
        }
        
        // ✅ 启动网络监听线程（事件驱动版）
        std::thread net_listener(NetworkListenerThread);
        net_listener.detach();
        
        g_logger.Info("✓ System initialized successfully");
        
        // 安装钩子
        g_hook = SetWinEventHook(EVENT_OBJECT_NAMECHANGE, EVENT_OBJECT_NAMECHANGE, 0,
                               WinEventProc, 0, 0, WINEVENT_OUTOFCONTEXT);
        if (! g_hook) {
            g_logger.Critical("✗ Failed to install hook");
            GdiplusShutdown(gdiplusToken);
            return 1;
        }
        
        g_logger.Info("✓ Hook installed successfully");
        g_logger.Info("✓ Cursor monitoring is now active (CPU optimized)");
        
        // ===================== 消息循环 =====================
        MSG msg;
        while (GetMessage(&msg, nullptr, 0, 0)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
        
        // ===================== 清理 =====================
        g_logger. Info("Main message loop exited, starting cleanup...");
        
        g_running = false;
        
        // ✅ 发送关闭信号给监听线程
        if (g_shutdown_event) {
            SetEvent(g_shutdown_event);
        }
        
        // 等待监听线程结束
        Sleep(2000);
        
        // 卸载钩子
        if (g_hook) {
            UnhookWinEvent(g_hook);
            g_hook = nullptr;
        }
        
        // ✅ 关闭事件
        if (g_socket_event) {
            WSACloseEvent(g_socket_event);
            g_socket_event = nullptr;
        }
        
        if (g_shutdown_event) {
            CloseHandle(g_shutdown_event);
            g_shutdown_event = nullptr;
        }
        
        // 关闭socket
        if (g_socket != INVALID_SOCKET) {
            closesocket(g_socket);
            g_socket = INVALID_SOCKET;
        }
        
        WSACleanup();
        GdiplusShutdown(gdiplusToken);
        
        g_logger.Info("✓ Cleanup completed");
        g_logger.Info("Total cursor changes detected: " + std::to_string(g_hook_call_count));
        
    } catch (const std::exception& e) {
        g_logger.Critical(std::string("✗ Fatal error: ") + e.what());
        return 1;
    }
    
    return 0;
}