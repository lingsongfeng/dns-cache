
#include <map>
#include <mutex>
#include <optional>
#include <utility>
#include <vector>

#include "base/mpsc.h"

/*
class DNSCache {
public:
    struct Key {
        // TODO
    };
    struct CachedInfo {
        // TODO
        std::string a;
    };
    struct Value {
        Value() = default;
        std::optional<CachedInfo> cached_info_;
        std::vector<base::SenderHandler<Task>> observers_;
    };

    std::optional<CachedInfo> get_or_register_observer(const Key& key, base::SenderHandler<Task> observer) {
        std::lock_guard<std::mutex> lg(mutex_);

        auto iter = inner_.find(key);
        if (iter == inner_.end()) {
            Value value;
            value.observers_.push_back(std::move(observer));
            inner_.insert({key, value});
            return {};
        } else if (iter->second.cached_info_ == std::nullopt) {
            iter->second.observers_.push_back(std::move(observer));
            return {};
        } else {
            return iter->second.cached_info_;
        }
    }

    void insert(Key key, CachedInfo info) {
        std::lock_guard<std::mutex> lg(mutex_);

        auto iter = inner_.find(key);
        if (iter == inner_.end()) {
            Value value;
            value.cached_info_ = std::move(info);
            inner_.insert({std::move(key), std::move(value)});
        } else {
            iter->second.cached_info_ = std::move(info);
            for (auto& observer : iter->second.observers_) {
                observer.send(CacheRefreshedTask());
            }
            iter->second.observers_.clear();
        }
    }

private:
    std::map<Key, Value> inner_;
    std::mutex mutex_;
};
*/