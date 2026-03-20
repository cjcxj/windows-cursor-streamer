# Cursor Monitor - 光标实时监控服务器

一个高性能的 Windows 光标监控系统，通过 TCP 协议实时捕获并传输系统光标图像和文本插入符位置。

## 核心特性

- **动画光标支持** - 完整支持 Windows 动画光标（精灵图表单帧传输）
- **高 DPI 自适应** - 自动检测并适配多显示器 DPI 缩放
- **完美 Alpha 通道提取** - 使用黑白底差分算法精确提取透明度
- **智能缓存机制** - 客户端/服务端双层缓存，大幅减少网络传输
- **文本光标追踪** - 实时监控系统插入符位置，防止遮挡
- **网络优化** - TCP 长连接 + 去重算法，极低延迟

## 技术架构

### 1. 光标捕获引擎
- 使用 GDI+ 进行 PNG 编码
- 黑白底差分法提取 Alpha 通道
- XOR 光标智能描边处理
- 内存池复用，减少动态分配

### 2. 网络协议
- TCP 服务端（默认端口 5005）
- 支持 IPv4/IPv6 双栈
- 自定义二进制协议，包含：
  - 光标图像数据（PNG 格式）
  - 热点坐标（HotSpot）
  - 动画帧数和延迟
  - 文本光标位置（Y 轴百分比）

### 3. 缓存策略
- **服务端缓存**：避免重复 PNG 编码（CRC32 哈希）
- **客户端缓存**：已发送的光标仅传输 Hash ID（24 字节）
- **连续去重**：相同光标连续出现时跳过发送

### 4. 文本光标监控
- 全局鼠标/键盘钩子
- 100ms 高频轮询
- 自动计算插入符在屏幕中的相对位置
- 防抖算法（0.5% 阈值）

## 编译要求

- **编译器**：MSVC（Visual Studio 2017+）或 MinGW-w64
- **CMake**：3.15+
- **C++ 标准**：C++17
- **依赖库**：
  - Windows SDK（Winsock2, GDI+, Shcore）
  - 静态链接运行时（MT）

## 构建步骤

```bash
# 创建构建目录
mkdir build && cd build

# 配置项目
cmake ..

# 编译
cmake --build . --config Release
```

## 使用方法

### 启动服务器
```bash
# 默认模式（INFO 日志级别）
CursorMonitor.exe

# 调试模式（DEBUG 日志级别）
CursorMonitor.exe -l DEBUG

# 完整日志（TRACE 级别）
CursorMonitor.exe -l TRACE
```

### 命令行参数
- `-l LEVEL` - 设置日志级别（TRACE / DEBUG / INFO / ERROR）

### 日志文件
程序运行时会在当前目录生成 `cursor_monitor.log` 文件。

## 网络协议说明

### 数据包格式

#### 完整光标包（Full Packet）
```
[BodyLen(4)] [Hash(4)] [HotX(4)] [HotY(4)] [Frames(4)] [Delay(4)] [PNG Data...]
```

#### 缓存命中包（Cached Packet）
```
[BodyLen(4)] [Hash(4)] [HotX(4)] [HotY(4)] [Frames(4)] [Delay(4)]
```
- BodyLen = 20（无 PNG 数据）

#### 文本光标状态包（Text Cursor State）
```
[BodyLen(4)] [0xFFFFFFFF(4)] [CmdID(4)] [YPercent(4)] [0(4)] [0(4)]
```
- CmdID = 2（文本光标指令）
- YPercent = -1（退出输入）或 0~10000（Y 轴百分比 × 100）

### 字段说明
- **BodyLen**：包体长度（不含自身 4 字节）
- **Hash**：光标图像 CRC32 哈希值
- **HotX/HotY**：热点坐标（像素）
- **Frames**：动画帧数（静态光标为 1）
- **Delay**：帧延迟（毫秒，0 表示静态）
- **PNG Data**：完整的 PNG 图像数据（精灵图表）

## 性能优化

1. **零拷贝设计** - 使用指针直接操作像素数据
2. **内存复用** - 预分配缓冲区，避免频繁 malloc
3. **早期退出** - 光标句柄未变化时直接返回（0 CPU）
4. **批量绘制** - 一次性绘制所有动画帧
5. **TCP_NODELAY** - 禁用 Nagle 算法，确保低延迟

## DPI 处理机制

- 自动检测光标所在显示器的 DPI
- 根据注册表 `CursorBaseSize` 计算目标尺寸
- 系统光标按 DPI 缩放，自定义光标保持原尺寸
- DPI 变化时自动重启程序刷新资源

## 故障排查

### 客户端无法连接
- 检查防火墙是否允许端口 5005
- 确认服务器 IP 地址正确
- 查看日志文件中的错误信息

### 光标显示异常
- 尝试使用 `-l DEBUG` 查看详细日志
- 检查 DPI 缩放设置是否正确
- 确认客户端正确解析 PNG 数据

### 性能问题
- 降低日志级别到 INFO 或 ERROR
- 检查网络延迟和带宽
- 确认客户端正确实现缓存机制

## 许可证

本项目为开源软件，具体许可证请参考项目根目录的 LICENSE 文件。

## 贡献指南

欢迎提交 Issue 和 Pull Request！

## 技术支持

如有问题，请通过以下方式联系：
- 提交 GitHub Issue
- 查看日志文件 `cursor_monitor.log`
