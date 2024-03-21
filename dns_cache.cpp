#include <chrono>
#include <cstdio>
#include <ctime>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "base/mpsc.h"
#include "base/threading/thread_pool.h"
#include "dns/dns_packet.h"
#include "dns_cache.h"
#include "gateway.h"

namespace {

inline bool
is_expired(const std::chrono::time_point<std::chrono::system_clock> &t) {
  return t < std::chrono::system_clock::now();
}

}; // namespace

using namespace std::chrono_literals;
DNSCache::DNSCache(std::weak_ptr<Gateway> gateway)
    : gateway_(gateway), clean_timer_([] {}, 100s) {}

std::optional<std::pair<int, std::vector<uint8_t>>>
DNSCache::query(const Key &key) {
  std::lock_guard<std::mutex> lg(mutex_);

  if (auto iter = mp_.find(key);
      iter != mp_.end() && std::get<3>(iter->second).empty()) {
    auto expire_time = std::get<2>(iter->second);
    if (!is_expired(expire_time)) {
      return {{std::get<0>(iter->second), std::get<1>(iter->second)}};
    } else {
      fprintf(stderr, "[INFO] record expired\n");
    }
  }

  return {};
}

std::optional<std::pair<int, std::vector<uint8_t>>>
DNSCache::query_or_register_callback(const Key &key,
                                     std::function<void()> &&cb) {
  std::lock_guard<std::mutex> lg(mutex_);

  if (auto iter = mp_.find(key);
      iter != mp_.end() && std::get<3>(iter->second).empty()) {
    auto expire_time = std::get<2>(iter->second);
    if (!is_expired(expire_time)) {
      return {{std::get<0>(iter->second), std::get<1>(iter->second)}};
    } else {
      std::get<3>(iter->second).push_back(std::move(cb));
      fprintf(stderr, "[INFO] record expired\n");
    }
  } else {
    Value value;
    std::get<3>(value).push_back(std::move(cb));
    mp_.insert({key, std::move(value)});
  }

  return {};
}

void DNSCache::update(const DNSPacket &packet) {
  std::lock_guard<std::mutex> lg(mutex_);

  if (packet.raw_answers.empty()) {
    return;
  }

  Key key = packet.raw_questions;
  uint32_t min_ttl = 1e7;
  for (const dns_answer &ans : packet.answers) {
    min_ttl = std::min(min_ttl, ans.ttl);
  }
  auto expire_at =
      std::chrono::system_clock::now() + std::chrono::seconds(min_ttl);
  Value value = {packet.get_ancount(), packet.raw_answers, expire_at, {}};

  if (auto iter = mp_.find(key); iter != mp_.end()) {
    auto cbs = std::move(std::get<3>(iter->second));
    iter->second = value;
    for (auto &&cb : cbs) {
      base::ThreadPool::GetInstance()->PostTask(std::move(cb));
    }
  } else {
    mp_.insert({key, value});
  }
}

// TODO(lingsong.feng)
void DNSCache::clean() { }