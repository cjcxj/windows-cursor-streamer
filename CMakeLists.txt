cmake_minimum_required(VERSION 3.15)
project(CursorMonitorCpp LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 设置静态链接 (MT)，减少对 DLL 的依赖
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

# 增加源文件
add_executable(CursorMonitor main.cpp)

# 链接 Windows 系统库
target_link_libraries(CursorMonitor PRIVATE
    ws2_32      # Winsock2 (网络)
    gdi32       # GDI (绘图)
    user32      # User32 (窗口/钩子)
    gdiplus     # GDI+ (PNG 编码)
    shcore      # DPI Awareness
    ole32       # COM (IStream 用于内存流)
    advapi32    # Registry
)

# 嵌入 Manifest
if(MSVC)
    target_link_options(CursorMonitor PRIVATE 
        "/MANIFEST:EMBED"
        "/MANIFESTINPUT:${CMAKE_CURRENT_SOURCE_DIR}/cursor_monitor.manifest"
    )
endif()

# 针对 Windows 子系统设置 (如果你不想看到控制台黑框，改为 WIN32)
# 这里保留 CONSOLE 以便查看日志
set_target_properties(CursorMonitor PROPERTIES LINK_FLAGS "/SUBSYSTEM:WINDOWS /ENTRY:mainCRTStartup")

# 开启 Unicode 支持
add_compile_definitions(UNICODE _UNICODE)