#ifndef DNS_CACHE_H_
#define DNS_CACHE_H_

#include "base/threading/thread_pool.h"
#include "base/threading/timer.h"
#include "dns/dns_packet.h"
#include <chrono>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

class Gateway;

class DNSCache : public std::enable_shared_from_this<DNSCache> {
public:
  DNSCache(std::weak_ptr<Gateway> gateway);

  // raw dns questions(bytes)
  using Key = std::vector<uint8_t>;

  // <ancount, raw dns answers(bytes), expire_time, callbacks>
  using Value = std::tuple<int, std::vector<uint8_t>,
                           std::chrono::time_point<std::chrono::system_clock>,
                           std::vector<std::function<void()>>>;

  // <ancount, raw dns answers(bytes)>
  std::optional<std::pair<int, std::vector<uint8_t>>> query(const Key &key);

  // <ancount, raw dns answers(bytes)>
  std::optional<std::pair<int, std::vector<uint8_t>>>
  query_or_register_callback(
      const Key &key, std::function<void()> &&cb = []() {});

  void clean();

  void update(const DNSPacket &packet);

private:
  std::map<Key, Value> mp_;
  std::mutex mutex_;
  std::weak_ptr<Gateway> gateway_;
  base::Timer clean_timer_;
};

#endif