#include "base/net/udp_socket.h"
#include "base/threading/thread_pool.h"
#include "dns/dns_packet.h"
#include <arpa/inet.h>
#include <coroutine>
#include <iostream>
#include <map>
#include <netinet/in.h>
#include <optional>
#include <span>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <utility>
#include <vector>

// a uniform module for receiving and sending DNS packets
class Gateway {
public:
  Gateway()
      : udp_socket_(
            base::UDPSocket::Bind(base::SocketAddr("0.0.0.0:53")).unwrap()) {}
  void Run() {

    printf("bound\n");

    std::vector<uint8_t> buffer(1000);
    while (true) {
      auto [bytes_received, client_addr] =
          udp_socket_.RecvFrom(buffer).unwrap();
      auto ip = base::to_string(client_addr);
      printf("Received %llu bytes from %s\n", bytes_received, ip.c_str());

      DNSPacket packet = *ParseDNSRawPacket(&buffer[0], bytes_received);
      printf("qr:%hhu opcode:%04hhu aa:%hhu tc:%hhu rd:%hhu ra:%hhu z:%hhu "
             "rcode:%04hhu\n",
             packet.header.flag.qr, packet.header.flag.opcode,
             packet.header.flag.aa, packet.header.flag.tc,
             packet.header.flag.rd, packet.header.flag.ra, packet.header.flag.z,
             packet.header.flag.rcode);
      if (packet.header.flag.qr == 0) {
        // query
        mp_.insert({packet.header.id, client_addr});
        //        mp_[packet.header.id] = client_addr;
        udp_socket_.SendTo(std::span(buffer.begin(), bytes_received),
                           base::SocketAddr("114.114.114.114:53"));
      } else {
        // response
        auto iter = mp_.find(packet.header.id);
        if (iter != mp_.end()) {
          auto addr = iter->second;
          udp_socket_.SendTo(std::span(buffer.begin(), bytes_received), addr);
        }
      }
    }
  }

private:
  base::UDPSocket udp_socket_;
  std::map<int, base::SocketAddr> mp_;
};

int main() {
  Gateway gateway;
  gateway.Run();
  return 0;
}