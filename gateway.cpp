#include "gateway.h"
#include "base/logging.h"
#include "base/net/udp_socket.h"
#include "base/threading/thread_pool.h"
#include "dns/dns_packet.h"
#include "dns_cache.h"
#include <cstdio>
#include <iostream>
#include <memory>
#include <span>
#include <thread>
#include <vector>

using namespace base::log_level;

// TODO(lingsong.feng): consider unwrap null optional
Gateway::Gateway()
    : udp_socket_(*base::UDPSocket::Bind(base::SocketAddr("0.0.0.0:53"))) {}

void Gateway::Initialize() {
  initialized_ = true;
  dns_cache_ = dns_cache_ = std::make_shared<DNSCache>(weak_from_this());
}

void Gateway::Send(const DNSPacket &dns_packet) {
  if (!initialized_) {
    base::log(ERROR, "gateway not initialized");
  }
  auto raw_packet = GenerateDNSRawPacket(dns_packet);
  udp_socket_.SendTo(std::span(raw_packet.begin(), raw_packet.size()),
                     base::SocketAddr("114.114.114.114:53"));
}

void Gateway::ProcessRawPacket(std::vector<uint8_t> buffer,
                               base::SocketAddr addr) {
  if (!initialized_) {
    base::log(ERROR, "gateway not initialized");
  }
  using namespace std::chrono_literals;
  DNSPacket packet;
  if (auto packet_opt = ParseDNSRawPacket(&buffer[0], buffer.size())) {
    packet = std::move(*packet_opt);
  } else {
    base::log(ERROR, "parse packet failed");
    return;
  }
  if (packet.header.flag.qr == 0) {
    if (packet.questions.empty()) {
      base::log(WARN, "empty question");
      return;
    }
    if (packet.header.flag.to_host() != kStandardQuery) {
      base::log(WARN, "not a standard query");
      PrintDNSPacket(packet);
    }

    DNSCache::Key key = packet.raw_questions;

    auto cb = [addr, key, packet, gateway_weak = weak_from_this()]() {
      base::log(INFO, "callback called");
      if (auto gateway = gateway_weak.lock()) {
        base::log(INFO, "cache hit");
        if (auto ans = gateway->dns_cache_->query(key)) {
          auto reply_header = packet.header;
          reply_header.flag.from_host(kStandardResponse);
          auto raw_reply_bufer = generate_dns_raw_from_raw_parts(
              reply_header, key, ans->second, packet.get_qdcount(), ans->first);
          gateway->udp_socket_.SendTo(raw_reply_bufer, addr);
        } else {
          base::log(WARN, "cache missed in callback");
        }
      } else {
        base::log(WARN, "gateway released");
      }
    };

    if (auto ans = dns_cache_->query_or_register_callback(key, cb)) {
      base::log(INFO, "cache hit");
      auto reply_header = packet.header;
      reply_header.flag.from_host(kStandardResponse);
      auto raw_reply_bufer = generate_dns_raw_from_raw_parts(
          reply_header, key, ans->second, packet.get_qdcount(), ans->first);
      udp_socket_.SendTo(raw_reply_bufer, addr);
      return;
    } else {
      base::log(INFO, "cache missed");
      udp_socket_.SendTo(buffer, base::SocketAddr("114.114.114.114:53"));
    }

  } else {
    // response
    if (packet.header.flag.to_host() != kStandardResponse) {
      base::log(WARN, "not a standard response");
      PrintDNSPacket(packet);
      return;
    }
    dns_cache_->update(packet);
  }
}

void Gateway::Run() {
  if (!initialized_) {
    base::log(ERROR, "gateway not initialized");
  }

  while (true) {
    // TODO(lingsong.feng): specify with a constant
    std::vector<uint8_t> buffer(1000);
    if (auto opt =
            udp_socket_.RecvFrom(std::span(buffer.begin(), buffer.size()))) {
      auto [cnt, addr] = *opt;
      base::log(INFO, "recv {} byte(s) from {}", cnt, base::to_string(addr));
      buffer.resize(cnt);

      base::ThreadPool::GetInstance()->PostTask(
          [this, buffer = std::move(buffer), addr]() {
            ProcessRawPacket(std::move(buffer), addr);
          });

    } else {
      base::log(WARN, "udp socket recvfrom failed");
    }
  }
}
