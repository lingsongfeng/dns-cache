#ifndef BASE_NET_UDP_SOCKET_H_
#define BASE_NET_UDP_SOCKET_H_

#include <array>
#include <cstdint>
#include <cstdio>
#include <optional>
#include <span>
#include <string>
#include <variant>

namespace base {

// TODO
struct Error {};

template <typename T> struct Result {
public:
  Result(T t) : inner_(std::move(t)) {

  }
  bool IsErr() { return std::get_if<Error>(inner_); }
  T &unwrap() {
    T *ptr = std::get_if<T>(&inner_);
    if (ptr) {
      return *ptr;
    } else {
      // TODO(lingsong.feng): implement an elegant halting
      printf("unwrap failed\n");
      exit(-1);
    }
  }
  static Result Ok(T t) {
    Result result(std::move(t));
    return result;
  }

private:
  std::variant<T, Error> inner_;
};

struct IPv4Addr {
  std::array<uint8_t, 4> octets;
};

struct SocketAddrV4 {
  // TODO(lingsong.feng): use string_view
  SocketAddrV4(const char* s) : SocketAddrV4(std::string(s)) {
  }
  SocketAddrV4(const std::string &s) {
    // TODO(lingsong.feng): implement an elegant conversion
    sscanf(s.c_str(), "%hhu.%hhu.%hhu.%hhu:%hu", &ip.octets[0], &ip.octets[1],
           &ip.octets[2], &ip.octets[3], &port);
  }
  IPv4Addr ip;
  std::uint16_t port;
};

struct IPv6Addr {
  std::array<std::uint8_t, 16> octets;
};

struct SocketAddrV6 {
  IPv6Addr ip;
  std::uint16_t port;
};

// TODO
struct SocketAddr {
  SocketAddr(SocketAddrV4 v4) : addr(v4) {}
  //SocketAddr(SocketAddrV6 v6) : addr(v6) {}
  std::variant<SocketAddrV4, SocketAddrV6> addr;
};

// thread safe because the class only holds a fd
// TODO(lingsong.feng): release fd when destructuring
class UDPSocket {
private:
  UDPSocket();

public:
  static Result<UDPSocket> Bind(SocketAddr addr);

  std::optional<std::pair<std::uint64_t, SocketAddr>> RecvFrom(std::span<uint8_t> buffer);

  Result<std::uint64_t> SendTo(std::span<uint8_t> buffer, const SocketAddr& addr);

private:
  int socket_fd_;
};

std::string to_string(const IPv4Addr &addr);

std::string to_string(const SocketAddr& addr);

} // namespace base

#endif