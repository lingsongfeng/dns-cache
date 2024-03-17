#ifndef GATEWAY_H_
#define GATEWAY_H_

#include "base/net/udp_socket.h"
#include "base/threading/thread_pool.h"
#include "dns/dns_packet.h"
#include "dns_cache.h"
#include <arpa/inet.h>
#include <coroutine>
#include <iostream>
#include <map>
#include <memory>
#include <netinet/in.h>
#include <optional>
#include <span>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <utility>
#include <vector>

// a uniform module for receiving and sending DNS packets
class Gateway : public std::enable_shared_from_this<Gateway> {
public:
  Gateway();
  void Initialize();

  [[deprecated("deprecated")]] void Send(const DNSPacket &dns_packet);

  void ProcessRawPacket(std::vector<uint8_t> buffer, base::SocketAddr addr);

  void Run();

private:
  bool initialized_ = false;
  base::UDPSocket udp_socket_;
  std::shared_ptr<base::ThreadPool> thread_pool_;
  std::shared_ptr<DNSCache> dns_cache_;
};

#endif