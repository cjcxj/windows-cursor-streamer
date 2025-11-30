#pragma once
#include <unordered_map>
#include <list>
#include <mutex>
#include <cstdint>

class LRUCache {
private:
    struct Node {
        uint32_t key;
        Node* prev;
        Node* next;
    };
    
    int max_size;
    std::unordered_map<uint32_t, Node*> cache;
    Node* head;
    Node* tail;
    mutable std::mutex lock;
    
    void RemoveNode(Node* node) {
        if (node->prev) node->prev->next = node->next;
        if (node->next) node->next->prev = node->prev;
        if (head == node) head = node->next;
        if (tail == node) tail = node->prev;
    }
    
    void AddToHead(Node* node) {
        if (! head) {
            head = tail = node;
            node->prev = node->next = nullptr;
        } else {
            node->next = head;
            node->prev = nullptr;
            head->prev = node;
            head = node;
        }
    }
    
public:
    LRUCache(int maxsize = 100) : max_size(maxsize), head(nullptr), tail(nullptr) {}
    
    ~LRUCache() {
        std::lock_guard<std::mutex> lg(lock);
        Node* curr = head;
        while (curr) {
            Node* next = curr->next;
            delete curr;
            curr = next;
        }
    }
    
    bool Add(uint32_t key) {
        std::lock_guard<std::mutex> lg(lock);
        
        if (cache.find(key) != cache.end()) {
            RemoveNode(cache[key]);
            AddToHead(cache[key]);
            return false; // 已存在
        }
        
        if ((int)cache.size() >= max_size) {
            if (tail) {
                cache.erase(tail->key);
                RemoveNode(tail);
                delete tail;
            }
        }
        
        Node* new_node = new Node{key, nullptr, nullptr};
        AddToHead(new_node);
        cache[key] = new_node;
        return true; // 新增
    }
    
    void Clear() {
        std::lock_guard<std::mutex> lg(lock);
        Node* curr = head;
        while (curr) {
            Node* next = curr->next;
            delete curr;
            curr = next;
        }
        cache. clear();
        head = tail = nullptr;
    }
    
    int Size() const {
        std::lock_guard<std::mutex> lg(lock);
        return cache.size();
    }
};