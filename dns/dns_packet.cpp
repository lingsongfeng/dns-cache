
#include "dns/dns_packet.h"
#include <cstdint>
#include <cstring>
#include <iostream>
#include <optional>
#include <span>
#include <string>
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

[[nodiscard("result should be used")]] inline std::optional<std::string>
consume_n_u8_to_string(const uint8_t **data, uint32_t *len, uint32_t n) {
  if (*len < n) {
    return {};
  }
  std::string ret;
  for (uint32_t i = 0; i < n; i++) {
    ret.push_back(static_cast<char>((*data)[i]));
  }
  (*data) += n;
  (*len) -= n;
  return ret;
}

[[deprecated(
    "multiple jumps are not supported, use consume_dns_name_v2")]] std::
    optional<std::string>
    consume_dns_name_impl(const uint8_t **data, uint32_t *len) {
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

[[deprecated(
    "multiple jumps are not supported, use consume_dns_name_v2")]] std::
    optional<std::string>
    consume_dns_name(const uint8_t **data, uint32_t *len,
                     const uint8_t *packet_begin, uint32_t packet_len) {
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

// return true if success
bool consume_dns_name_impl_v2(const uint8_t **data, uint32_t *len,
                              const uint8_t *const packet_begin,
                              const uint32_t packet_len, std::string &s) {
  std::string ret;
  constexpr const uint64_t kMaxNameLength = 75;
  while (true) {
    if (s.size() >= kMaxNameLength) {
      return false;
    }
    uint8_t s_length;
    if (auto s_length_opt = consume_one_u8(data, len)) {
      s_length = *s_length_opt;
    } else {
      return false;
    }
    if (s_length == 0x0) {
      break;
    }

    if (s_length < 0xc0) {
      if (auto s_opt = consume_n_u8_to_string(data, len, s_length)) {
        s += *s_opt;
        s.push_back('.');
      } else {
        return false;
      }
    } else {
      uint8_t next_u8;
      if (auto next_u8_opt = consume_one_u8(data, len)) {
        next_u8 = *next_u8_opt;
      } else {
        return false;
      }
      uint16_t offset = net_u8_to_u16(s_length, next_u8) & 0b0011111111111111;
      const uint8_t *start_pos = packet_begin + offset;
      uint32_t packet_len_remains = packet_len - offset;
      if (consume_dns_name_impl_v2(&start_pos, &packet_len_remains,
                                   packet_begin, packet_len, s)) {
        break;
      } else {
        return false;
      }
    }
  }
  return true;
}

std::optional<std::string> consume_dns_name_v2(const uint8_t **data,
                                               uint32_t *len,
                                               const uint8_t *packet_begin,
                                               uint32_t packet_len) {
  std::string ret;
  if (consume_dns_name_impl_v2(data, len, packet_begin, packet_len, ret)) {
    if (!ret.empty())
      ret.pop_back();
    return ret;
  } else {
    return {};
  }
}

std::optional<dns_question> ParseDNSRawQuestion(const uint8_t **data,
                                                uint32_t *len,
                                                const uint8_t *packet_begin,
                                                uint32_t packet_len) {
  std::string name;
  if (auto name_opt =
          consume_dns_name_v2(data, len, packet_begin, packet_len)) {
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
  if (auto name_opt =
          consume_dns_name_v2(data, len, packet_begin, packet_len)) {
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
  const uint8_t *packet_begin = data;
  const uint32_t packet_len = len;

  DNSPacket packet;

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
    qdcount = *qdcount_opt;
  } else {
    return {};
  }

  uint16_t ancount;
  if (auto ancount_opt = consume_two_u8(&data, &len)) {
    ancount = *ancount_opt;
  } else {
    return {};
  }

  uint16_t nscount;
  if (auto nscount_opt = consume_two_u8(&data, &len)) {
    nscount = *nscount_opt;
  } else {
    return {};
  }

  uint16_t arcount;
  if (auto arcount_opt = consume_two_u8(&data, &len)) {
    arcount = *arcount_opt;
  } else {
    return {};
  }

  const uint8_t *start_pos = data;
  for (int i = 0; i < qdcount; i++) {
    if (auto opt_question =
            ParseDNSRawQuestion(&data, &len, packet_begin, packet_len)) {
      packet.questions.emplace_back(std::move(*opt_question));
    } else {
      return {};
    }
  }
  const uint8_t *end_pos = data;
  for (const uint8_t *pos = start_pos; pos < end_pos; pos++) {
    packet.raw_questions.push_back(*pos);
  }

  start_pos = data;
  for (int i = 0; i < ancount; i++) {
    if (auto opt_answer =
            ParseDNSRawAnswer(&data, &len, packet_begin, packet_len)) {
      packet.answers.emplace_back(std::move(*opt_answer));
    } else {
      return {};
    }
  }
  end_pos = data;
  for (const uint8_t *pos = start_pos; pos < end_pos; pos++) {
    packet.raw_answers.push_back(*pos);
  }

  // TODO(lingsong.feng): parse data
  for (int i = 0; i < nscount; i++) {
    packet.authority_records.emplace_back();
  }
  for (int i = 0; i < arcount; i++) {
    packet.additional_records.emplace_back();
  }

  return packet;
}

void append_u16_to_net(std::vector<uint8_t> &v, uint16_t val) {
  uint16_t net_val = htons(val);
  v.push_back(0);
  v.push_back(0);
  int idx = v.size() - 2;
  uint16_t *ptr = reinterpret_cast<uint16_t *>(&v[idx]);
  *ptr = net_val;
}

void append_u32_to_net(std::vector<uint8_t> &v, uint32_t val) {
  uint32_t net_val = htonl(val);
  v.push_back(0);
  v.push_back(0);
  v.push_back(0);
  v.push_back(0);
  int idx = v.size() - 4;
  uint32_t *ptr = reinterpret_cast<uint32_t *>(&v[idx]);
  *ptr = net_val;
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
  append_u16_to_net(ret, packet.header.flag.to_host());
  append_u16_to_net(ret, packet.get_qdcount());
  append_u16_to_net(ret, packet.get_ancount());
  append_u16_to_net(ret, packet.get_nscount());
  append_u16_to_net(ret, packet.get_arcount());

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
    append_u16_to_net(ret, ans.get_rdlength());
    append_bytes(ret, std::span(ans.rdata.begin(), ans.rdata.size()));
  }

  return ret;
}

void TestParsePacket() {
  std::vector<uint8_t> data{
      0x77, 0x92, 0x81, 0x80, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
      0x03, 0x77, 0x77, 0x77, 0x04, 0x73, 0x6f, 0x68, 0x75, 0x03, 0x63, 0x6f,
      0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01,
      0x00, 0x00, 0x02, 0xed, 0x00, 0x19, 0x03, 0x77, 0x77, 0x77, 0x04, 0x73,
      0x6f, 0x68, 0x75, 0x03, 0x63, 0x6f, 0x6d, 0x03, 0x64, 0x73, 0x61, 0x05,
      0x64, 0x6e, 0x73, 0x76, 0x31, 0xc0, 0x15, 0xc0, 0x2a, 0x00, 0x05, 0x00,
      0x01, 0x00, 0x00, 0x00, 0x65, 0x00, 0x1d, 0x04, 0x62, 0x65, 0x73, 0x74,
      0x05, 0x73, 0x63, 0x68, 0x65, 0x64, 0x05, 0x64, 0x30, 0x2d, 0x64, 0x6b,
      0x07, 0x74, 0x64, 0x6e, 0x73, 0x64, 0x70, 0x31, 0x02, 0x63, 0x6e, 0x00,
      0xc0, 0x4f, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x21, 0x00, 0x28,
      0x04, 0x62, 0x65, 0x73, 0x74, 0x05, 0x35, 0x31, 0x2d, 0x36, 0x35, 0x03,
      0x63, 0x6a, 0x74, 0x08, 0x73, 0x64, 0x79, 0x74, 0x75, 0x6e, 0x74, 0x78,
      0x0a, 0x64, 0x69, 0x61, 0x6e, 0x73, 0x75, 0x2d, 0x63, 0x64, 0x6e, 0x03,
      0x6e, 0x65, 0x74, 0x00, 0xc0, 0x78, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
      0x00, 0x2d, 0x00, 0x04, 0x7b, 0x7d, 0xf4, 0x6b};
  auto opt = ParseDNSRawPacket(&data[0], data.size());
  if (opt.has_value()) {
    printf("%s\n", opt->answers[0].name.c_str());
  } else {
    printf("parse failed\n");
  }
}

void PrintDNSPacket(const DNSPacket &packet) {
  printf("id:0x%04hx\n", packet.header.id);
  printf("qr:%hhu opcode:%hhu aa:%hhu tc:%hhu rd:%hhu ra:%hhu z:%hhu "
         "rcode:%hhu\n",
         packet.header.flag.qr, packet.header.flag.opcode,
         packet.header.flag.aa, packet.header.flag.tc, packet.header.flag.rd,
         packet.header.flag.ra, packet.header.flag.z, packet.header.flag.rcode);
  printf("qdcount:%hu ancount:%hu nscount:%hu arcount:%hu\n",
         packet.get_qdcount(), packet.get_ancount(), packet.get_nscount(),
         packet.get_arcount());
  printf("questions:\n");
  for (const dns_question &q : packet.questions) {
    printf("    %s type:%hu class:%hu\n", q.qname.c_str(), q.qtype, q.qclass);
  }
  printf("answers:\n");
  for (const dns_answer &ans : packet.answers) {
    printf("    %s type:%hu class:%hu ", ans.name.c_str(), ans.type,
           ans.ans_class);
    printf("ttl:%u rdlength:%hu data:[", ans.ttl, ans.get_rdlength());
    for (uint8_t byte : ans.rdata) {
      printf("%02hhx ", byte);
    }
    printf("]\n");
  }

  printf("\n");
}

std::vector<uint8_t> generate_dns_raw_from_raw_parts(
    const dns_header &header, const std::vector<uint8_t> &questions,
    const std::vector<uint8_t> &answers, int qdcount, int ancount) {
  std::vector<uint8_t> ret;
  append_u16_to_net(ret, header.id);
  append_u16_to_net(ret, header.flag.to_host());
  append_u16_to_net(ret, qdcount);
  append_u16_to_net(ret, ancount);
  append_u16_to_net(ret, 0);
  append_u16_to_net(ret, 0);
  for (uint8_t byte : questions) {
    ret.push_back(byte);
  }
  for (uint8_t byte : answers) {
    ret.push_back(byte);
  }
  return ret;
}