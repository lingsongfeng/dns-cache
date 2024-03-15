
#include <_types/_uint16_t.h>
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

DNSPacket make_query_packet(const DNSCache::Key &key) {
  DNSPacket packet;
  packet.header.id = rand() % 0x10000;
  packet.header.flag.from_host(0x0100); // standard query

  // TODO(lingsong.feng): combine DNSCache::Key and dns_question
  dns_question question;
  question.qname = std::get<0>(key);
  question.qtype = std::get<1>(key);
  question.qclass = std::get<2>(key);
  packet.questions.push_back(std::move(question));

  return packet;
}
}; // namespace


DNSCache::DNSCache(std::weak_ptr<Gateway> gateway,
                   std::weak_ptr<base::ThreadPool> thread_pool)
    : thread_pool_(thread_pool), gateway_(gateway) {}


std::vector<std::pair<DNSCache::Key, dns_record>> DNSCache::query(const Key &key) {
  std::lock_guard<std::mutex> lg(mutex_);

  std::vector<std::pair<Key, dns_record>> ret;
  bool will_query_upstream = false;
  
  auto precise_query = [&](const Key& key) {
    if (auto iter = mp_.find(key); iter != mp_.end()) {
      for (const auto &[data, expire_time] : iter->second) {
        // TODO(lingsong.feng): avoid always getting system time
        if (is_expired(expire_time)) {
          will_query_upstream = true;
          continue;
        }
        // TODO(lingsong.feng): fill TTL field
        ret.push_back({key, data});
      }
    } else {
      will_query_upstream = true;
    }
  };

  // TODO(lingsong.feng): recursive lookup
  Key cname_key = key;
  std::get<1>(cname_key) = 5; // for searching CNAME
  precise_query(key);
  precise_query(cname_key);


  if (will_query_upstream) {
    if (auto thread_pool = thread_pool_.lock()) {
      thread_pool->PostTask([key, gateway_weak = gateway_]() {
        auto packet = make_query_packet(key);
        if (auto gateway = gateway_weak.lock()) {
          gateway->Send(packet);
        } else {
          fprintf(stderr, "Gateway object released\n");
        }
      });
    } else {
      fprintf(stderr, "thread_pool object released\n");
    }
  }

  return ret;
}

void DNSCache::update(const std::vector<dns_answer> &answers) {
  std::lock_guard<std::mutex> lg(mutex_);

  printf("cache size: %lu\n", mp_.size());
  for (const auto &ans : answers) {
    std::string name = ans.name;
    auto expire_at =
        std::chrono::system_clock::now() + std::chrono::seconds(ans.ttl);
    auto data = ans.rdata;
    auto key = std::make_tuple(ans.name, ans.type, ans.ans_class);
    if (auto iter = mp_.find(key); iter != mp_.end()) {
      // replace with newest record
      iter->second.insert_or_assign(data, expire_at);
    } else {
      Value inner_mp = {{data, expire_at}};
      // TODO(lingsong.feng): consider std::move(key)
      mp_.insert({key, std::move(inner_mp)});
    }
  }
}