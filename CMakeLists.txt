cmake_minimum_required(VERSION 3.15)
project(CursorMonitorCpp LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 设置静态链接 (MT)，生成的 exe 不依赖 VC++ 运行库 DLL
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
    ole32       # COM (IStream)
    advapi32    # 【新增】注册表操作必需 (RegOpenKeyEx 等)
)

# 【关键修改】
# 如果你想看到控制台日志，请使用 CONSOLE。
# 如果你想后台静默运行（无黑框），请使用 WINDOWS。
# 目前为了调试查看日志，建议使用 CONSOLE。
set_target_properties(CursorMonitor PROPERTIES LINK_FLAGS "/SUBSYSTEM:CONSOLE")

# 如果你想发布无黑框版本，请注释掉上面那行，使用下面这行：
# set_target_properties(CursorMonitor PROPERTIES LINK_FLAGS "/SUBSYSTEM:WINDOWS /ENTRY:mainCRTStartup")

# 开启 Unicode 支持，并定义 NOMINMAX 防止 min/max 宏冲突
add_compile_definitions(UNICODE _UNICODE NOMINMAX)