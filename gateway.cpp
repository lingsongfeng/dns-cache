#include "gateway.h"
#include "base/net/udp_socket.h"
#include "dns/dns_packet.h"
#include "dns_cache.h"
#include <cstdio>
#include <iostream>
#include <memory>
#include <span>
#include <thread>
#include <vector>

Gateway::Gateway()
    : udp_socket_(
          base::UDPSocket::Bind(base::SocketAddr("0.0.0.0:53")).unwrap()),
      thread_pool_(base::ThreadPool::MakeShared(10)) {}

void Gateway::Initialize() {
  initialized_ = true;
  dns_cache_ = dns_cache_ =
      std::make_shared<DNSCache>(weak_from_this(), thread_pool_);
}

void Gateway::Send(const DNSPacket &dns_packet) {
  if (!initialized_) {
    fprintf(stderr, "[ERROR] gateway not initialized\n");
  }
  auto raw_packet = GenerateDNSRawPacket(dns_packet);
  udp_socket_.SendTo(std::span(raw_packet.begin(), raw_packet.size()),
                     base::SocketAddr("114.114.114.114:53"));
}

void Gateway::ProcessRawPacket(std::vector<uint8_t> buffer,
                               base::SocketAddr addr) {
  if (!initialized_) {
    fprintf(stderr, "[ERROR] gateway not initialized\n");
  }
  using namespace std::chrono_literals;
  DNSPacket packet;
  if (auto packet_opt = ParseDNSRawPacket(&buffer[0], buffer.size())) {
    packet = std::move(*packet_opt);
  } else {
    fprintf(stderr, "[ERROR] parse packet failed\n");
    return;
  }
  if (packet.header.flag.qr == 0) {
    if (packet.questions.empty()) {
      fprintf(stderr, "[WARN] empty question\n");
      return;
    }
    if (packet.header.flag.to_host() != kStandardQuery) {
      fprintf(stderr, "[WARN] not a standard query\n");
      PrintDNSPacket(packet);
    }

    DNSCache::Key key = packet.raw_questions;

    auto cb = [addr, key, packet, gateway_weak = weak_from_this()]() {
      fprintf(stderr, "[INFO] callback called\n");
      if (auto gateway = gateway_weak.lock()) {
        fprintf(stderr, "[INFO] cache hit!\n");
        if (auto ans = gateway->dns_cache_->query(key)) {
          auto reply_header = packet.header;
          reply_header.flag.from_host(kStandardResponse);
          auto raw_reply_bufer = generate_dns_raw_from_raw_parts(
              reply_header, key, ans->second, packet.get_qdcount(), ans->first);
          gateway->udp_socket_.SendTo(raw_reply_bufer, addr);
        } else {
          fprintf(stderr, "[WARN] cache missed in callback\n");
        }
      } else {
        fprintf(stderr, "[WARN] gateway released\n");
      }
    };

    if (auto ans = dns_cache_->query_or_register_callback(key, cb)) {
      fprintf(stderr, "[INFO] cache hit!\n");
      auto reply_header = packet.header;
      reply_header.flag.from_host(kStandardResponse);
      auto raw_reply_bufer = generate_dns_raw_from_raw_parts(
          reply_header, key, ans->second, packet.get_qdcount(), ans->first);
      udp_socket_.SendTo(raw_reply_bufer, addr);
      return;
    } else {
      fprintf(stderr, "[INFO] cache missed\n");
      udp_socket_.SendTo(buffer, base::SocketAddr("114.114.114.114:53"));
    }

    // TODO(lingsong.feng): exponential backoff

  } else {
    // response
    if (packet.header.flag.to_host() != kStandardResponse) {
      fprintf(stderr, "[WARN] not a standard response\n");
      PrintDNSPacket(packet);
      return;
    }
    dns_cache_->update(packet);
  }
}

void Gateway::Run() {
  if (!initialized_) {
    fprintf(stderr, "[ERROR] gateway not initialized\n");
  }

  while (true) {
    // TODO(lingsong.feng): specify with a constant
    std::vector<uint8_t> buffer(1000);
    if (auto opt =
            udp_socket_.RecvFrom(std::span(buffer.begin(), buffer.size()))) {
      auto [cnt, addr] = *opt;
      printf("[INFO] recv %llu byte(s) from %s\n", cnt,
             base::to_string(addr).c_str());
      buffer.resize(cnt);

      thread_pool_->PostTask([this, buffer = std::move(buffer), addr]() {
        ProcessRawPacket(std::move(buffer), addr);
      });

    } else {
      fprintf(stderr, "[WARN] udp socket recvfrom failed\n");
    }
  }
}