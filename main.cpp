#include "base/net/udp_socket.h"
#include "base/threading/thread_pool.h"
#include "dns/dns_packet.h"
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
#include "gateway.h"

int main() {
  auto gateway = std::make_shared<Gateway>();
  gateway->Initialize();
  gateway->Run();
  // TestParsePacket();
  return 0;
}

int amain() {
  base::thread_pool_test();
  return 0;
}