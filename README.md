# 光标监控网络传输程序原理

## 功能概述
该程序用于捕获Windows系统鼠标光标图像并通过UDP网络协议实时传输到远程设备。

## 核心组件

### 1. 光标捕获机制
- 使用 `SetWinEventHook` 监听系统事件 [EVENT_OBJECT_NAMECHANGE](file://E:\programming-language\Python\随便写写\光标监控网络传输.py#L95-L95)
- 通过 `win32gui.GetCursorInfo()` 获取当前光标句柄
- 利用 `GetIconInfo` 和 `DrawIconEx` 提取光标图像数据

### 2. 图像处理流程
- **双背景绘制**: 分别在黑色和白色背景下绘制光标
- **透明度计算**: 通过比较两背景图像差异生成Alpha通道
- **特殊处理**: 识别并处理XOR类型光标(如十字线)
- **格式输出**: 生成带透明度的RGBA PNG图像

### 3. 网络传输机制
- **UDP协议**: 使用UDP进行低延迟数据传输
- **握手连接**: 客户端发送 "CURSOR_HELLO" 建立连接
- **缓存优化**: 
  - 使用 `zlib.crc32` 计算图像哈希值
  - 已传输图像缓存在 [sent_hashes](file://E:\programming-language\Python\随便写写\光标监控网络传输.py#L119-L119) 集合中
  - 重复图像仅传输哈希值标识
- **心跳保活**: 每秒发送一次光标状态维持连接

### 4. 多线程架构
- **主线程**: 处理Windows消息循环和事件回调
- **网络线程**: 运行 [listen_for_client](file://E:\programming-language\Python\随便写写\取光标图片并发送.py#L182-L195) 处理客户端连接
- **工作线程**: 每个光标变化启动 [worker_process_cursor](file://E:\programming-language\Python\随便写写\光标监控网络传输.py#L249-L279) 线程处理图像捕获和传输

## 数据包结构
```python
# 新图像(Type 0): <type(1)> + <hash(8)> + <hot_x(4)> + <hot_y(4)> + <png_data>
# 缓存图像(Type 1): <type(1)> + <hash(8)> + <hot_x(4)> + <hot_y(4)>
```


## 关键特性
- DPI感知适配高分辨率屏幕
- 自动资源清理防止内存泄漏
- 异常处理保证程序稳定性
- 实时性和带宽优化兼顾
