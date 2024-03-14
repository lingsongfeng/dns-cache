
#include "dns/dns_packet.h"
#include <_types/_uint16_t.h>
#include <_types/_uint32_t.h>
#include <_types/_uint8_t.h>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <optional>
#include <span>
#include <string>
#include <sys/_endian.h>
#include <vector>

// TODO(lingsong.feng): bit order is not well organized, which will be optimized
// in the future

inline uint16_t net_u8_to_u16(uint8_t u8_0, uint8_t u8_1) {
  return (u8_0 << 8) | u8_1;
}
inline uint16_t net_u8_to_u32(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
  return (a << 24) | (b << 16) | (c << 8) | d;
}

[[nodiscard("result should be used")]] inline std::optional<uint8_t>
consume_one_u8(const uint8_t **data, uint32_t *len) {
  if (*len < 1)
    return {};
  uint8_t ret = **data;
  (*data)++;
  (*len)--;
  return ret;
}

[[nodiscard("result should be used")]] inline std::optional<uint16_t>
consume_two_u8(const uint8_t **data, uint32_t *len) {
  if (*len < 2)
    return {};
  uint8_t a = (*data)[0];
  uint8_t b = (*data)[1];
  (*data) += 2;
  (*len) -= 2;
  return net_u8_to_u16(a, b);
}

[[nodiscard("result should be used")]] inline std::optional<uint32_t>
consume_four_u8(const uint8_t **data, uint32_t *len) {
  if (*len < 4)
    return {};
  uint8_t a = (*data)[0];
  uint8_t b = (*data)[1];
  uint8_t c = (*data)[2];
  uint8_t d = (*data)[3];
  (*data) += 4;
  (*len) -= 4;
  return net_u8_to_u32(a, b, c, d);
}

[[nodiscard(
    "result should be used")]] inline std::optional<std::vector<uint8_t>>
consume_n_u8(const uint8_t **data, uint32_t *len, uint32_t n) {
  if (*len < n) {
    return {};
  }
  std::vector<uint8_t> ret(n);
  memcpy(&ret[0], *data, n);
  (*data) += n;
  (*len) -= n;
  return ret;
}

std::optional<std::string> consume_dns_name_impl(const uint8_t **data,
                                                 uint32_t *len) {
  uint8_t s_length;
  if (auto s_length_opt = consume_one_u8(data, len)) {
    s_length = *s_length_opt;
  } else {
    return {};
  }

  std::string name;
  while (s_length != 0x0) {
    for (int i = 0; i < s_length; i++) {
      if (auto ch_opt = consume_one_u8(data, len)) {
        name.push_back(*ch_opt);
      } else {
        return {};
      }
    }
    name.push_back('.');

    if (auto s_length_opt = consume_one_u8(data, len)) {
      s_length = *s_length_opt;
    } else {
      return {};
    }
  }
  name.pop_back(); // remove trailing dot
  return name;
}

std::optional<std::string> consume_dns_name(const uint8_t **data, uint32_t *len,
                                            const uint8_t *packet_begin,
                                            uint32_t packet_len) {
  uint8_t s_length;
  if (auto s_length_opt = consume_one_u8(data, len)) {
    s_length = *s_length_opt;
  } else {
    return {};
  }

  if (s_length < 0xc0) {
    (*data)--;
    (*len)++;
    return consume_dns_name_impl(data, len);
  } else {
    uint8_t next_u8;
    if (auto next_u8_opt = consume_one_u8(data, len)) {
      next_u8 = *next_u8_opt;
    } else {
      return {};
    }
    uint16_t offset = net_u8_to_u16(s_length, next_u8) & 0b00111111;
    const uint8_t *start_pos = packet_begin + offset;
    uint32_t packet_len_remains = packet_len - offset;
    return consume_dns_name_impl(&start_pos, &packet_len_remains);
  }
}

std::optional<dns_question> ParseDNSRawQuestion(const uint8_t **data,
                                                uint32_t *len,
                                                const uint8_t *packet_begin,
                                                uint32_t packet_len) {
  std::string name;
  if (auto name_opt = consume_dns_name(data, len, packet_begin, packet_len)) {
    name = std::move(*name_opt);
  } else {
    return {};
  }

  uint16_t qtype;
  if (auto qtype_opt = consume_two_u8(data, len)) {
    qtype = *qtype_opt;
  } else {
    return {};
  }

  uint16_t qclass;
  if (auto qclass_opt = consume_two_u8(data, len)) {
    qclass = *qclass_opt;
  } else {
    return {};
  }

  dns_question ret;
  ret.qname = std::move(name);
  ret.qtype = qtype;
  ret.qclass = qclass;
  return ret;
}

std::optional<dns_answer> ParseDNSRawAnswer(const uint8_t **data, uint32_t *len,
                                            const uint8_t *packet_begin,
                                            uint32_t packet_len) {
  std::string name;
  if (auto name_opt = consume_dns_name(data, len, packet_begin, packet_len)) {
    name = std::move(*name_opt);
  } else {
    return {};
  }

  uint16_t type;
  if (auto type_opt = consume_two_u8(data, len)) {
    type = *type_opt;
  } else {
    return {};
  }

  uint16_t ans_class;
  if (auto ans_class_opt = consume_two_u8(data, len)) {
    ans_class = *ans_class_opt;
  } else {
    return {};
  }

  uint32_t ttl;
  if (auto ttl_opt = consume_four_u8(data, len)) {
    ttl = *ttl_opt;
  } else {
    return {};
  }

  uint16_t rdlength;
  if (auto rdlength_opt = consume_two_u8(data, len)) {
    rdlength = *rdlength_opt;
  } else {
    return {};
  }

  std::vector<uint8_t> rdata;
  if (auto rdata_opt = consume_n_u8(data, len, rdlength)) {
    rdata = std::move(*rdata_opt);
  } else {
    return {};
  }

  dns_answer ans;
  ans.name = std::move(name);
  ans.type = type;
  ans.ans_class = ans_class;
  ans.ttl = ttl;
  ans.rdlength = rdlength;
  ans.rdata = std::move(rdata);
  return ans;
}

void TestParseQuestion() {
  /*
  std::vector<uint8_t> data {
      0xdb, 0x42, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x03, 0x77, 0x77, 0x77, 0x0c, 0x6e, 0x6f, 0x72, 0x74, 0x68, 0x65, 0x61, 0x73,
  0x74, 0x65, 0x72, 0x6e, 0x03, 0x65, 0x64};
  */
  std::vector<uint8_t> data{0x03, 0x77, 0x77, 0x77, 0x0c, 0x6e, 0x6f,
                            0x72, 0x74, 0x68, 0x65, 0x61, 0x73, 0x74,
                            0x65, 0x72, 0x6e, 0x03, 0x65, 0x64, 0x75,
                            0x00, 0x00, 0x01, 0x00, 0x01};

  const uint8_t *pos = &data[0];
  uint32_t len = data.size();
  if (auto question = ParseDNSRawQuestion(&pos, &len, pos, len)) {
    if (question->qname != "www.northeastern.edu") {
      std::cerr << question->qname << std::endl;
    }
    if (question->qtype != 0x0001) {
      std::cerr << question->qtype << std::endl;
    }
    if (question->qclass != 0x0001) {
      std::cerr << question->qclass << std::endl;
    }
    printf("success\n");
  } else {
    std::cerr << "parse failed" << std::endl;
  }
}
/*
void TestParseAnswer() {
  std::vector<uint8_t> data{
      0x03, 0x77, 0x77, 0x77, 0x0c, 0x6e, 0x6f, 0x72, 0x74, 0x68, 0x65,
      0x61, 0x73, 0x74, 0x65, 0x72, 0x6e, 0x03, 0x65, 0x64, 0x75, 0x00,
      0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00,
      0x00, 0x02, 0x58, 0x00, 0x04, 0x9b, 0x21, 0x11, 0x44};

  if (auto ans = ParseDNSRawAnswer(&data[0], data.size())) {
    if (ans->name != "www.northeastern.edu") {
      std::cerr << ans->name << std::endl;
    }
    if (ans->type != 0x0001) {
      std::cerr << ans->type << std::endl;
    }
    if (ans->ans_class != 0x0001) {
      std::cerr << ans->ans_class << std::endl;
    }
    if (ans->ttl != 0x00000258) {
      std::cerr << ans->ttl << std::endl;
    }
    if (ans->rdlength != 0x0004) {
      std::cerr << ans->rdlength << std::endl;
    }
    if (ans->rdata.size() != 4 || ans->rdata[0] != 0x9b ||
        ans->rdata[1] != 0x21 || ans->rdata[2] != 0x11 ||
        ans->rdata[3] != 0x44) {
      std::cerr << "ip check failed" << std::endl;
    }
    printf("check finished\n");
  } else {
    printf("parse failed\n");
  }
}
*/
std::optional<DNSPacket> ParseDNSRawPacket(const uint8_t *data, uint32_t len) {
  printf("print begin\n");
  for (int i = 0; i < len; i++) {
    printf("%x ", data[i]);
  }
  printf("\nprint end\n");
  const uint8_t *packet_begin = data;
  uint32_t packet_len = len;

  DNSPacket packet;

  uint16_t id;
  if (auto id_opt = consume_two_u8(&data, &len)) {
    packet.header.id = *id_opt;
  } else {
    return {};
  }

  uint32_t flag;
  if (auto flag_opt = consume_two_u8(&data, &len)) {
    flag = *flag_opt;
  } else {
    return {};
  }
  packet.header.flag.from_host(flag);

/*
  uint8_t flag_1, flag_2;
  if (auto flag_opt = consume_one_u8(&data, &len)) {
    flag_1 = *flag_opt;
  } else {
    return {};
  }
  if (auto flag_opt = consume_one_u8(&data, &len)) {
    flag_2 = *flag_opt;
  } else {
    return {};
  }

  packet.header.qr = (flag_1 & 0b10000000) >> 7;
  packet.header.opcode = (flag_1 & 0b01111000) >> 3;
  packet.header.aa = (flag_1 & 0b00000100) >> 2;
  packet.header.tc = (flag_1 & 0b00000010) >> 1;
  packet.header.rd = flag_1 & 0b00000001;

  packet.header.ra = (flag_2 & 0b10000000) >> 7;
  ;
  packet.header.z = (flag_2 & 0b01110000) >> 4;
  packet.header.rcode = (flag_2 & 0b00001111);
  */

  uint16_t qdcount;
  if (auto qdcount_opt = consume_two_u8(&data, &len)) {
    packet.header.qdcount = qdcount = *qdcount_opt;
  } else {
    return {};
  }

  uint16_t ancount;
  if (auto ancount_opt = consume_two_u8(&data, &len)) {
    packet.header.ancount = ancount = *ancount_opt;
  } else {
    return {};
  }

  uint16_t nscount;
  if (auto nscount_opt = consume_two_u8(&data, &len)) {
    packet.header.nscount = nscount = *nscount_opt;
  } else {
    return {};
  }

  uint16_t arcount;
  if (auto arcount_opt = consume_two_u8(&data, &len)) {
    packet.header.arcount = arcount = *arcount_opt;
  } else {
    return {};
  }

  for (int i = 0; i < qdcount; i++) {
    if (auto opt_question =
            ParseDNSRawQuestion(&data, &len, packet_begin, packet_len)) {
      packet.questions.emplace_back(std::move(*opt_question));
    } else {
      return {};
    }
  }

  for (int i = 0; i < ancount; i++) {
    if (auto opt_answer =
            ParseDNSRawAnswer(&data, &len, packet_begin, packet_len)) {
      packet.answers.emplace_back(std::move(*opt_answer));
    } else {
      return {};
    }
  }

  return packet;
}

void append_u16_to_net(std::vector<uint8_t> &v, uint16_t val) {
  uint16_t net_val = htons(val);
  v.push_back(0);
  v.push_back(0);
  int idx = v.size() - 2;
  uint16_t *ptr = reinterpret_cast<uint16_t *>(&v[idx]);
  *ptr = val;
}

void append_u32_to_net(std::vector<uint8_t> &v, uint32_t val) {
  uint16_t net_val = htonl(val);
  v.push_back(0);
  v.push_back(0);
  v.push_back(0);
  v.push_back(0);
  int idx = v.size() - 4;
  uint32_t *ptr = reinterpret_cast<uint32_t *>(&v[idx]);
  *ptr = val;
}

void append_bytes(std::vector<uint8_t> &v, std::span<const uint8_t> data) {
  for (uint8_t byte : data) {
    v.push_back(byte);
  }
}

void append_string(std::vector<uint8_t> &v, const std::string &s) {
  for (char c : s) {
    v.push_back(static_cast<uint8_t>(c));
  }
}

void append_dns_name(std::vector<uint8_t> &v, const std::string &name) {
  std::string part;
  for (int i = 0; i < name.size(); i++) {
    if (name[i] != '.') {
      part.push_back(name[i]);
    } else {
      v.push_back(static_cast<uint8_t>(part.size()));
      append_string(v, part);
      part.clear();
    }
  }
  if (!part.empty()) {
    v.push_back(static_cast<uint8_t>(part.size()));
    append_string(v, part);
  }
  v.push_back(0);
}

std::vector<uint8_t> GenerateDNSRawPacket(const DNSPacket &packet) {
  std::vector<uint8_t> ret;
  append_u16_to_net(ret, packet.header.id);
  append_u16_to_net(ret, packet.header.flag.to_host()); // TODO(lingsong.feng): use real flag
  append_u16_to_net(ret, packet.header.qdcount);
  append_u16_to_net(ret, packet.header.ancount);
  append_u16_to_net(ret, packet.header.nscount);
  append_u16_to_net(ret, packet.header.arcount);

  for (const dns_question &q : packet.questions) {
    append_dns_name(ret, q.qname);
    append_u16_to_net(ret, q.qtype);
    append_u16_to_net(ret, q.qclass);
  }

  for (const dns_answer &ans : packet.answers) {
    append_dns_name(ret, ans.name);
    append_u16_to_net(ret, ans.type);
    append_u16_to_net(ret, ans.ans_class);
    append_u32_to_net(ret, ans.ttl);
    append_u16_to_net(ret, ans.rdlength);
    append_bytes(ret, std::span(ans.rdata.begin(), ans.rdata.size()));
  }

  return ret;
}

void TestParsePacket() {
  std::vector<uint8_t> data{
      0xdb, 0x42, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
      0x00, 0x03, 0x77, 0x77, 0x77, 0x0c, 0x6e, 0x6f, 0x72, 0x74, 0x68,
      0x65, 0x61, 0x73, 0x74, 0x65, 0x72, 0x6e, 0x03, 0x65, 0x64, 0x75,
      0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01,
      0x00, 0x00, 0x02, 0x58, 0x00, 0x04, 0x9b, 0x21, 0x11, 0x44};
  auto opt = ParseDNSRawPacket(&data[0], data.size());
  if (opt.has_value()) {
    printf("%s\n", opt->answers[0].name.c_str());
  } else {
    printf("parse failed\n");
  }
}
