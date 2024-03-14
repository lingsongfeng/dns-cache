#ifndef DNS_DNS_PACKET_H_
#define DNS_DNS_PACKET_H_

#include <cstdint>
#include <string>

// TODO(lingsong.feng): bit order check
struct dns_flag {
  // second byte
  uint8_t rcode : 4, // response code, 4bit
      z : 3,         // reserved, 3bit
      ra : 1;        // recursion available, 1bit
  // first byte
  uint8_t rd : 1, // recursion desired, 1bit
      tc : 1,     // truncation, 1bit
      aa : 1,     // authorative answer, 1bit
      opcode : 4, // kind of query, 4bit
      qr : 1;     // response(1) or query(0), 1bit
  void from_host(uint32_t flag) { *reinterpret_cast<uint16_t *>(this) = flag; }
  uint32_t to_host() const { return *reinterpret_cast<const uint16_t *>(this); }
};
static_assert(sizeof(dns_flag) == 2, "error size of dns_flag");

struct dns_header {
  uint16_t id;      // 2bytes
  dns_flag flag;    // 2bytes

  // TODO(lingsong.feng): deprecate in the future
  uint16_t qdcount; // 2bytes
  // TODO(lingsong.feng): deprecate in the future
  uint16_t ancount; // 2bytes
  // TODO(lingsong.feng): deprecate in the future
  uint16_t nscount; // 2bytes
  // TODO(lingsong.feng): deprecate in the future
  uint16_t arcount; // 2bytes
};

struct dns_question {
  std::string qname;
  uint16_t qtype;
  uint16_t qclass;
};

struct dns_answer {
  std::string name;
  uint16_t type;
  uint16_t ans_class;
  uint32_t ttl;
  uint16_t rdlength; // TODO(lingsong.feng): deprecate in the future
  std::vector<uint8_t> rdata;
};

class DNSPacket {
public:
  dns_header header;
  std::vector<dns_question> questions;
  std::vector<dns_answer> answers;
};

std::optional<DNSPacket> ParseDNSRawPacket(const uint8_t *data, uint32_t len);

std::vector<uint8_t> GenerateDNSRawPacket(const DNSPacket &packet);

void PrintDNSPacket(const DNSPacket& packet);

void TestParsePacket();

#endif