#pragma once
#include <fstream>
#include <iostream>
#include <string>
#include <chrono>
#include <mutex>
#include <sstream>

class Logger {
private:
    std::ofstream log_file;
    std::mutex log_mutex;
    std::string GetTimestamp() {
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        std::stringstream ss;
        ss << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S");
        return ss.str();
    }
public:
    Logger(const std::string& filename = "cursor_monitor.log") {
        log_file.open(filename, std::ios::app);
    }
    ~Logger() { if (log_file.is_open()) log_file.close(); }
    
    void Info(const std::string& msg) { Log("INFO", msg); }
    void Debug(const std::string& msg) { Log("DEBUG", msg); }
    void Warning(const std::string& msg) { Log("WARNING", msg); }
    void Error(const std::string& msg) { Log("ERROR", msg); }
    void Critical(const std::string& msg) { Log("CRITICAL", msg); }
    
private:
    void Log(const std::string& level, const std::string& msg) {
        std::lock_guard<std::mutex> lock(log_mutex);
        std::string output = "[" + GetTimestamp() + "] [" + level + "] " + msg;
        std::cout << output << std::endl;
        if (log_file.is_open()) {
            log_file << output << std::endl;
            log_file.flush();
        }
    }
};

extern Logger g_logger;