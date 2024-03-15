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

void Gateway::ConstructDNSCache() {
  dns_cache_ = dns_cache_ =
      std::make_shared<DNSCache>(weak_from_this(), thread_pool_);
}

void Gateway::Send(const DNSPacket &dns_packet) {
  auto raw_packet = GenerateDNSRawPacket(dns_packet);
  udp_socket_.SendTo(std::span(raw_packet.begin(), raw_packet.size()),
                     base::SocketAddr("114.114.114.114:53"));
}

void Gateway::ProcessRawPacket(std::vector<uint8_t> buffer,
                               base::SocketAddr addr) {
  using namespace std::chrono_literals;
  DNSPacket packet;
  if (auto packet_opt = ParseDNSRawPacket(&buffer[0], buffer.size())) {
    packet = std::move(*packet_opt);
  } else {
    fprintf(stderr, "[ERROR] parse packet failed\n");
    return;
  }
  PrintDNSPacket(packet);
  if (packet.header.flag.qr == 0) {
    if (packet.questions.empty()) {
      fprintf(stderr, "[WARN] empty question\n");
      return;
    }
    DNSCache::Key key{packet.questions[0].qname, packet.questions[0].qtype,
                      packet.questions[0].qclass};

    auto records = dns_cache_->query(key);

    auto do_when_records_not_empty = [&]() {
      fprintf(stderr, "[INFO] cache hit\n");
      for (auto &[key, record] : records) {
        dns_answer ans;
        ans.name = std::get<0>(key);
        ans.type = std::get<1>(key);
        ans.ans_class = std::get<2>(key);
        ans.ttl = 100; // TODO(lingsong.feng): use actual TTL
        ans.rdata = record;
        packet.answers.push_back(std::move(ans));
      }
      packet.header.flag.from_host(kStandardQuery);

      auto buffer = GenerateDNSRawPacket(packet);
      udp_socket_.SendTo(buffer, addr);
    };

    if (!records.empty()) {
      do_when_records_not_empty();
      return;
    } else {
      fprintf(stderr, "cache missed\n");
    }

    // TODO(lingsong.feng): exponential backoff

  } else {
    // response
    dns_cache_->update(packet.answers);
  }
}

void Gateway::Run() {

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