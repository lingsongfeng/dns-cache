#ifndef DNS_CACHE_H_
#define DNS_CACHE_H_

#include "base/threading/thread_pool.h"
#include "dns/dns_packet.h"
#include <map>
#include <memory>
#include <mutex>
#include <vector>
#include <string>
#include <chrono>

class Gateway;

using dns_record = std::vector<uint8_t>;

class DNSCache : public std::enable_shared_from_this<DNSCache> {
public:
  DNSCache(std::weak_ptr<Gateway> gateway, std::weak_ptr<base::ThreadPool> thread_pool);
  // <name, type, class>
  using Key = std::tuple<std::string, uint16_t, uint16_t>;

  // <record, expire_time>
  using Value =
      std::map<dns_record, std::chrono::time_point<std::chrono::system_clock>>;

  std::vector<std::pair<Key, dns_record>> query(const Key &key);

  void update(const std::vector<dns_answer> &answers);

private:
  std::map<Key, Value> mp_;
  std::mutex mutex_;
  std::weak_ptr<base::ThreadPool> thread_pool_;
  std::weak_ptr<Gateway> gateway_;
};

#endif