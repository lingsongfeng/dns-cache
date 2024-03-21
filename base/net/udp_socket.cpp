#include "base/net/udp_socket.h"

#include <arpa/inet.h>
#include <cstdio>
#include <netinet/in.h>
#include <optional>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <variant>
#include <vector>

namespace base {

std::string to_string(const IPv4Addr &addr) {
  char s[20];
  snprintf(s, 20, "%hhu.%hhu.%hhu.%hhu", addr.octets[0], addr.octets[1],
           addr.octets[2], addr.octets[3]);
  std::string ret = s;
  return ret;
}

std::string to_string(const SocketAddrV4 &addr) {
  return to_string(addr.ip) + ":" + std::to_string(addr.port);
}

std::string to_string(const SocketAddr &addr) {
  if (auto v4_addr = std::get_if<SocketAddrV4>(&addr.addr)) {
    return to_string(*v4_addr);
  } else {
    return "v6 not supported";
  }
}

// static
std::optional<UDPSocket> UDPSocket::Bind(SocketAddr addr) {
  UDPSocket udp_socket;
  udp_socket.socket_fd_ = socket(AF_INET, SOCK_DGRAM, 0);
  if (udp_socket.socket_fd_ < 0) {
    // TODO(lingsong.feng): elegant returning
    printf("socket create error\n");
    return {};
  }

  struct sockaddr_in server_addr;
  // TODO(lingsong.feng): adapt for IPv6
  server_addr.sin_family = AF_INET;
  auto addr_v4 = *std::get_if<SocketAddrV4>(&addr.addr);
  server_addr.sin_port = htons(addr_v4.port);
  auto addr_s = to_string(addr_v4.ip);
  server_addr.sin_addr.s_addr = inet_addr(addr_s.c_str());

  if (bind(udp_socket.socket_fd_, (const struct sockaddr *)&server_addr,
           sizeof(server_addr)) < 0) {
    // TODO(lingsong.feng): elegant returning
    printf("bind error\n");
    return {};
  }

  return udp_socket;
}

UDPSocket::UDPSocket() = default;

std::optional<std::pair<std::uint64_t, SocketAddr>>
UDPSocket::RecvFrom(std::span<uint8_t> buffer) {

  struct sockaddr_in client_addr;
  socklen_t addr_len = sizeof(client_addr);
  memset(&client_addr, 0, sizeof(client_addr));

  auto max_length = buffer.size_bytes();
  std::uint64_t bytes_received =
      recvfrom(socket_fd_, (void *)&buffer[0], max_length, MSG_WAITALL,
               (struct sockaddr *)&client_addr, &addr_len);
  // TODO(lingsong.feng): IPv6 support
  // TODO(lingsong.feng): refactor here
  char s[20];

  inet_ntop(AF_INET, &client_addr.sin_addr, s, 19);

  SocketAddrV4 addr_v4(s);

  addr_v4.port = htons(client_addr.sin_port);

  SocketAddr socket_addr(addr_v4);

  return {{bytes_received, socket_addr}};
}

// TODO(lingsong.feng): thread safety check
std::optional<std::uint64_t> UDPSocket::SendTo(std::span<uint8_t> buffer,
                                               const SocketAddr &addr) {
  struct sockaddr_in dst_addr;
  socklen_t addr_len = sizeof(dst_addr);
  memset(&dst_addr, 0, sizeof(dst_addr));

  auto v4_addr = *std::get_if<SocketAddrV4>(&addr.addr);
  dst_addr.sin_family = AF_INET;
  dst_addr.sin_port = htons(v4_addr.port);
  auto addr_s = to_string(v4_addr.ip);
  dst_addr.sin_addr.s_addr = inet_addr(addr_s.c_str());

  uint64_t rv = sendto(socket_fd_, &buffer[0], buffer.size(), 0,
                       (const struct sockaddr *)&dst_addr, addr_len);

  return rv;
}

} // namespace base