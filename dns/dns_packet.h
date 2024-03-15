#ifndef DNS_DNS_PACKET_H_
#define DNS_DNS_PACKET_H_

#include <algorithm>
#include <cstdint>
#include <limits>
#include <string>

constexpr const uint16_t kStandardQuery = 0x0100;
constexpr const uint16_t kStandardResponse = 0x8180;

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

// TODO(lingsong.feng): bit order check
constexpr bool check_dns_flag_bit_order() { return true; }

static_assert(sizeof(dns_flag) == 2, "error size of dns_flag");
static_assert(check_dns_flag_bit_order(),
              "bit order error of dns_flag, please che the endianness");

struct dns_header {
  uint16_t id;   // 2bytes
  dns_flag flag; // 2bytes
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
  std::vector<uint8_t> rdata;
  inline uint16_t get_rdlength() const { return rdata.size(); }
};

struct dns_authority_record {};
struct dns_additional_record {};

class DNSPacket {
public:
  dns_header header;
  std::vector<dns_question> questions;
  std::vector<dns_answer> answers;
  std::vector<dns_authority_record> authority_records;
  std::vector<dns_additional_record> additional_records;
  uint16_t get_qdcount() const { return questions.size(); }
  uint16_t get_ancount() const { return answers.size(); }
  uint16_t get_nscount() const { return authority_records.size(); }
  uint16_t get_arcount() const { return additional_records.size(); }
};

std::optional<DNSPacket> ParseDNSRawPacket(const uint8_t *data, uint32_t len);

std::vector<uint8_t> GenerateDNSRawPacket(const DNSPacket &packet);

void PrintDNSPacket(const DNSPacket &packet);

void TestParsePacket();

#endif