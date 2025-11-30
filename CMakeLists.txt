cmake_minimum_required(VERSION 3.15)
project(CursorMonitor)

# 设置 C++ 标准
set(CMAKE_CXX_STANDARD 17)

# === 关键设置：静态链接 (/MT) ===
# 这样生成的 EXE 可以在没有安装 VC++ 运行库的电脑上运行
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

# 查找 Zlib 库 (通过 vcpkg 自动提供)
find_package(ZLIB REQUIRED)

# 定义源文件
set(SOURCES
    cursor_monitor_optimized.cpp # 如果你改名了，这里也要改
    logger.hpp
    cursor_capture.hpp
    lru_cache.hpp
    client_manager.hpp
)

# 创建可执行文件
add_executable(CursorMonitor WIN32 ${SOURCES})

# 链接库
target_link_libraries(CursorMonitor PRIVATE
    ZLIB::ZLIB      # Zlib 库
    gdiplus.lib     # GDI+
    ws2_32.lib      # Winsock
    shlwapi.lib     # 系统辅助
)

# 设置生成目录输出名称
set_target_properties(CursorMonitor PROPERTIES OUTPUT_NAME "cursor_monitor")