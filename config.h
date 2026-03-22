#pragma once

#include <cstdint>

/**
 * ====================================================================
 * Cursor Monitor - 配置系统
 * 所有性能参数和的硬编码数值都在此统一管理
 * ====================================================================
 */

// ==========================================
//         1. 网络配置
// ==========================================

// TCP 服务器监听端口
constexpr int LISTEN_PORT = 5005;

// 网络缓冲区配置
constexpr int SOCKET_SEND_BUFFER_SIZE = 256 * 1024;  // 256KB

// ==========================================
//         2. 缓存配置
// ==========================================

// 服务端 PNG 缓存最大条目数（内存优化）
constexpr int SERVER_PNG_CACHE_MAX_SIZE = 200;

// 客户端缓存最大条目数（每个连接）
constexpr int CLIENT_CACHE_MAX_SIZE = 100;

// LRU 清理比例（超过最大值时清空这个比例）
constexpr float CLIENT_CACHE_CLEANUP_RATIO = 0.5f;  // 50%

// ==========================================
//         3. 图像处理配置
// ==========================================

// Alpha 通道阈值（小于此值的像素判定为透明）
constexpr uint8_t ALPHA_THRESHOLD = 5;

// XOR 边界 Alpha 值（纯黑边框的不透明度）
constexpr uint8_t XOR_EDGE_ALPHA = 0xFF;

// 最大光标尺寸（防止内存溢出）
constexpr int MAX_CURSOR_SIZE = 256;

// 最小光标尺寸
constexpr int MIN_CURSOR_SIZE = 32;

// ==========================================
//         4. DPI 缩放配置
// ==========================================

// DPI 检查周期（毫秒）- 跨屏时检查，或定期检查
constexpr int DPI_CHECK_INTERVAL_MS = 500;

// DPI 变化防抖延迟（毫秒）- 防止快速切换触发重启
constexpr int DPI_DEBOUNCE_MS = 300;

// 系统标准 DPI（基准）
constexpr int STANDARD_DPI = 96;

// ==========================================
//         5. 帧率和性能配置
// ==========================================

// 光标采集最小间隔（毫秒）- 限制最高采样率
constexpr int MIN_CAPTURE_INTERVAL_MS = 30;  // ~33FPS

// 日志采样间隔（每 N 帧记录一次高频日志）
constexpr int LOG_SAMPLE_INTERVAL = 30;

// 日志轮转大小（MB）- 日志文件超过此大小自动归档
constexpr int LOG_ROTATE_SIZE_MB = 10;

// ==========================================
//         6. 文本光标检测配置
// ==========================================

// 鼠标位置变化阈值（万分比，即 1% = 100）
constexpr int TEXT_CURSOR_STATE_CHANGE_THRESHOLD = 100;  // 1%

// 状态防抖间隔（毫秒）
constexpr int TEXT_CURSOR_DEBOUNCE_MS = 50;

// ==========================================
//         7. 内存预分配配置
// ==========================================

// 像素缓冲区预分配大小（最大光标尺寸平方）
constexpr int PIXEL_BUFFER_RESERVE = 256 * 256;

// XOR 掩码缓冲区预分配
constexpr int XOR_MASK_BUFFER_RESERVE = 256 * 256;

// PNG 输出缓冲区预分配
constexpr int PNG_BUFFER_RESERVE = 1024 * 50;  // 50KB

// ==========================================
//         8. 调试和日志配置
// ==========================================

// 默认日志级别（TRACE/DEBUG/INFO/ERROR）
constexpr const char* DEFAULT_LOG_LEVEL = "INFO";

// 日志文件路径
constexpr const char* LOG_FILE_PATH = "cursor_monitor.log";

// 是否启用调试输出
constexpr bool ENABLE_DEBUG_OUTPUT = true;

// ==========================================
//         9. 错误处理配置
// ==========================================

// 网络连接超时（秒）
constexpr int NETWORK_TIMEOUT_SEC = 30;

// 最大重连次数
constexpr int MAX_RECONNECT_ATTEMPTS = 3;

// ==========================================
//         10. 资源限制
// ==========================================

// 最大同时连接数
constexpr int MAX_CONCURRENT_CONNECTIONS = 100;

// 每个客户端的最大缓冲数据量（字节）
constexpr int MAX_BUFFER_PER_CLIENT = 10 * 1024 * 1024;  // 10MB
