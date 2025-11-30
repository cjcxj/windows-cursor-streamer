#pragma once
#include <map>
#include <vector>
#include <mutex>
#include <ctime>
#include <winsock2.h>
#include <ws2tcpip.h>

struct ClientInfo {
    sockaddr_in6 addr;
    time_t connected_time;
    time_t last_activity_time;
    
    bool IsTimeout(int timeout_sec) const {
        return (time(nullptr) - last_activity_time) > timeout_sec;
    }
    
    void UpdateActivity() {
        last_activity_time = time(nullptr);
    }
};

class ClientManager {
private:
    std::map<std::string, ClientInfo> clients; // key: IP:Port
    mutable std::mutex lock;
    
    std::string AddrToString(const sockaddr_in6& addr) {
        char ip_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &addr.sin6_addr, ip_str, INET6_ADDRSTRLEN);
        return std::string(ip_str) + ":" + std::to_string(ntohs(addr. sin6_port));
    }
    
public:
    bool AddClient(const sockaddr_in6& addr) {
        std::lock_guard<std::mutex> lg(lock);
        std::string key = AddrToString(addr);
        
        if (clients.find(key) != clients.end()) {
            clients[key].UpdateActivity();
            return false;
        }
        
        ClientInfo client_info{addr, time(nullptr), time(nullptr)};
        clients[key] = client_info;
        return true;
    }
    
    bool GetClient(const sockaddr_in6& addr, ClientInfo& out_info) {
        std::lock_guard<std::mutex> lg(lock);
        std::string key = AddrToString(addr);
        auto it = clients.find(key);
        if (it != clients.end()) {
            out_info = it->second;
            return true;
        }
        return false;
    }
    
    void UpdateActivity(const sockaddr_in6& addr) {
        std::lock_guard<std::mutex> lg(lock);
        std::string key = AddrToString(addr);
        auto it = clients. find(key);
        if (it != clients.end()) {
            it->second.UpdateActivity();
        }
    }
    
    void RemoveTimeoutClients(int timeout_sec) {
        std::lock_guard<std::mutex> lg(lock);
        std::vector<std::string> expired;
        for (auto& kv : clients) {
            if (kv.second.IsTimeout(timeout_sec)) {
                expired.push_back(kv.first);
            }
        }
        for (const auto& key : expired) {
            clients. erase(key);
        }
    }
    
    std::vector<ClientInfo> GetAllClients() const {
        std::lock_guard<std::mutex> lg(lock);
        std::vector<ClientInfo> result;
        for (const auto& kv : clients) {
            result.push_back(kv.second);
        }
        return result;
    }
    
    int GetClientCount() const {
        std::lock_guard<std::mutex> lg(lock);
        return clients.size();
    }
    
    void Clear() {
        std::lock_guard<std::mutex> lg(lock);
        clients.clear();
    }
};