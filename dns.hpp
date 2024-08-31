#include <iomanip>
#include <iostream>
#include <map>
#include <random>
#include <sstream>
#include <optional>

template <typename T>
void hex_print(T buf) {
  std::cout << "(" << buf.size() << ") ";
  for (auto u: buf) {
    std::cout << std::hex << std::setfill('0') << std::setw(2) << (int) u << " ";
  }
  std::cout << std::dec << "\n";
}

template <typename T>
void hex_print(T buf, size_t length) {
  std::cout << "(" << length << "/" << buf.size() << ") ";
  int i = 0;
  for (auto u: buf) {
    if (i > length) break;
    std::cout << std::hex << std::setfill('0') << std::setw(2) << (int) u << " ";
    i++;
  }
  std::cout << std::dec << "\n";
}

void to_big_endian(uint16_t value, std::array<uint8_t, 2> &buf) {
  buf[0] = static_cast<uint8_t>(value >> 8);
  buf[1] = static_cast<uint8_t>(value & 0xff);
}

template <typename T>
std::vector<uint8_t> to_big_endian(T value) {
  size_t sz = sizeof(T);
  std::vector<uint8_t> result;
  for (size_t i = 0; i < sz; i++) {
    result.push_back(value >> ((sz - i - 1) * 8));
  }
  return result;
}

template <typename T>
T from_big_endian(const std::vector<uint8_t> &bytes, size_t &offset) {
  size_t sz = sizeof(T);
  T ret = 0;
  for (size_t i = 0; i < sz; i++) {
    ret <<= 8;
    ret |= bytes[offset++];
  }
  return ret;
}

struct dns_header {
  uint16_t id;
  uint16_t flags;
  uint16_t qdcount;
  uint16_t ancount;
  uint16_t nscount;
  uint16_t arcount;
  
  dns_header() = default;

  dns_header(std::vector<uint8_t> &bytes, size_t& offset) {
    id = from_big_endian<uint16_t>(bytes, offset);
    flags = from_big_endian<uint16_t>(bytes, offset);
    qdcount = from_big_endian<uint16_t>(bytes, offset);
    ancount = from_big_endian<uint16_t>(bytes, offset);
    nscount = from_big_endian<uint16_t>(bytes, offset);
    arcount = from_big_endian<uint16_t>(bytes, offset);
  }

  std::array<uint8_t, 12> to_bytes() const {
    std::array<uint8_t, 12> bytes;
    std::array<uint8_t, 2> buf;
    
    to_big_endian(id, buf);
    std::copy(buf.begin(), buf.end(), bytes.begin());

    to_big_endian(flags, buf);
    std::copy(buf.begin(), buf.end(), bytes.begin() + 2);

    to_big_endian(qdcount, buf);
    std::copy(buf.begin(), buf.end(), bytes.begin() + 4);

    to_big_endian(ancount, buf);
    std::copy(buf.begin(), buf.end(), bytes.begin() + 6);

    to_big_endian(nscount, buf);
    std::copy(buf.begin(), buf.end(), bytes.begin() + 8);

    to_big_endian(arcount, buf);
    std::copy(buf.begin(), buf.end(), bytes.begin() + 10);

    return bytes;
  }
};

std::ostream& operator<<(std::ostream& os, const dns_header& header) {
  os << "dns_header { "
     << "id: " << header.id << ", "
     << "flags: " << header.flags << ", "
     << "qdcount: " << header.qdcount << ", "
     << "ancount: " << header.ancount << ", "
     << "nscount: " << header.nscount << ", "
     << "arcount: " << header.arcount
     << " }";
  return os;
}

enum class dns_record_t : uint16_t {
  A = 1,
  AAAA = 28,
  CNAME = 5,
  MX = 15,
  NS = 2,
  PTR = 12,
  SOA = 6,
  TXT = 16,
};

std::ostream& operator<<(std::ostream& os, const dns_record_t &dns_rec) {
  using enum dns_record_t;
  switch (dns_rec) {
    case A:
      return os << "A";
    case AAAA:
      return os << "AAAA";
    case CNAME:
      return os << "CNAME";
    case MX:
      return os << "MX";
    case NS:
      return os << "NS";
    case PTR:
      return os << "PTR";
    case SOA:
      return os << "SOA";
    case TXT:
      return os << "TXT";
    default:
      return os << static_cast<uint16_t>(dns_rec);
  }
  return os;
}

std::string parse_domain(std::vector<uint8_t> &bytes, size_t &offset);

std::string parse_compressed_domain(uint8_t len, std::vector<uint8_t> &bytes, size_t &offset) {
  size_t pos = (static_cast<uint16_t>(len & 0b0011'0000) << 8) + bytes[offset++];
  return parse_domain(bytes, pos);
}

std::string parse_domain(std::vector<uint8_t> &bytes, size_t &offset) {
  uint8_t len = 0;
  std::string domain;
  while ((len = bytes[offset++]) != 0) {
    if (len & 0b1100'0000) {
      domain.append(parse_compressed_domain(len, bytes, offset));
      break;
    }
    domain.append(bytes.begin() + offset, bytes.begin() + offset + len);
    domain.push_back('.');
    offset += len;
  }
  return domain;
}

std::string parse_ipv4(std::vector<uint8_t> &bytes, size_t &offset) {
  std::string ipv4;
  for (size_t i = 0; i < 4; i++) {
    if (i > 0) ipv4.push_back('.');
    ipv4.append(std::to_string((int) bytes[offset++]));
  }
  return ipv4;
}

std::string parse_ipv6(const std::vector<uint8_t> &bytes, size_t &offset) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');

    for (size_t i = 0; i < 16; i += 2) {
        uint16_t part = (bytes[offset++] << 8) | bytes[offset++];
        oss << std::setw(4) << part;
        if (i < 14) {
            oss << ":";
        }
    }
    return oss.str();
}

struct dns_record {
  std::string name;
  dns_record_t type;
  uint16_t class_;
  uint32_t ttl;
  std::vector<uint8_t> rdata;
  std::string parsed_rdata;

  dns_record() = default;
  dns_record(std::vector<uint8_t> &bytes, size_t &offset) {
    name = parse_domain(bytes, offset);

    type = static_cast<dns_record_t>(from_big_endian<uint16_t>(bytes, offset));
    class_ = from_big_endian<uint16_t>(bytes, offset);
    ttl = from_big_endian<uint32_t>(bytes, offset);
    int rdlen = from_big_endian<uint16_t>(bytes, offset);
    rdata.insert(rdata.end(), bytes.begin() + offset, bytes.begin() + offset + rdlen);
    if (type == dns_record_t::NS) {
      parsed_rdata = parse_domain(bytes, offset);
    } else if (type == dns_record_t::A) {
      parsed_rdata = parse_ipv4(bytes, offset);
    } else if (type == dns_record_t::AAAA) {
      parsed_rdata = parse_ipv6(bytes, offset);
    } else {
      offset += rdata.size();
    }
  }

  std::vector<uint8_t> to_bytes() const {
    std::vector<uint8_t> bytes;

    std::stringstream ss(name);
    std::string token;
    while (std::getline(ss, token, '.')) {
      bytes.push_back(token.length());
      bytes.insert(bytes.end(), token.begin(), token.end());
    }
    bytes.push_back(0x00);

    auto buf = to_big_endian(static_cast<uint16_t>(type));
    bytes.insert(bytes.end(), buf.begin(), buf.end());

    buf = to_big_endian(class_);
    bytes.insert(bytes.end(), buf.begin(), buf.end());

    buf = to_big_endian(ttl);
    bytes.insert(bytes.end(), buf.begin(), buf.end());

    buf = to_big_endian(static_cast<uint16_t>(rdata.size()));
    bytes.insert(bytes.end(), buf.begin(), buf.end());
    bytes.insert(bytes.end(), rdata.begin(), rdata.end());

    return bytes;
  }
};

std::ostream& operator<<(std::ostream& os, const dns_record& record) {
    os << "dns_record { "
       << "name: " << record.name << ", "
       << "type: " << record.type << ", "
       << "class_: " << record.class_ << ", "
       << "ttl: " << record.ttl << ", "
       << "parsed_rdata: " << record.parsed_rdata << ", "
       << "rdlen: " << record.rdata.size() << ", "
       << "rdata: ";
    for (size_t i = 0; i < record.rdata.size(); i++) {
      os << (int) record.rdata[i] << " ";
    }
    os << "}";
    return os;
}

struct dns_question {
  std::string qname;
  dns_record_t qtype;
  uint16_t qclass;

  dns_question() = default;
  dns_question(const std::string& name, dns_record_t type, uint16_t qclass) 
    : qname(name), qtype(type), qclass(qclass) {}

  dns_question(std::vector<uint8_t> &bytes, size_t& offset) {
    qname = parse_domain(bytes, offset);
    qtype = static_cast<dns_record_t>(from_big_endian<uint16_t>(bytes, offset));
    qclass = from_big_endian<uint16_t>(bytes, offset);
  }

  std::vector<uint8_t> to_bytes() const {
    std::vector<uint8_t> bytes;

    std::stringstream ss(qname);
    std::string token;
    while (std::getline(ss, token, '.')) {
      bytes.push_back(token.length());
      bytes.insert(bytes.end(), token.begin(), token.end());
    }
    bytes.push_back(0x00);

    std::array<uint8_t, 2> buf;
    to_big_endian(static_cast<uint16_t>(qtype), buf);
    bytes.insert(bytes.end(), buf.begin(), buf.end());

    to_big_endian(qclass, buf);
    bytes.insert(bytes.end(), buf.begin(), buf.end());

    return bytes;
  }
};

std::ostream& operator<<(std::ostream& os, const dns_question& question) {
    os << "dns_question { "
       << "qname: " << question.qname << ", "
       << "qtype: " << question.qtype << ", "
       << "qclass: " << question.qclass
       << " }";
    return os;
}

std::random_device rdev;
std::mt19937 gen(rdev());
std::uniform_int_distribution<uint16_t> dist(0, 65535);

struct dns_packet {
  size_t offset = 0;
  dns_header header;
  std::vector<dns_question> questions;
  std::vector<dns_record> answers;
  std::vector<dns_record> authorities;
  std::vector<dns_record> additional;

  dns_packet(std::vector<uint8_t> bytes)
    : offset(0), header(bytes, offset) {
      for (size_t i = 0; i < header.qdcount; i++) {
        questions.push_back(dns_question(bytes, offset));
      }
      for (size_t i = 0; i < header.ancount; i++) {
        answers.push_back(dns_record(bytes, offset));
      }
      for (size_t i = 0; i < header.nscount; i++) {
        authorities.push_back(dns_record(bytes, offset));
      }
      for (size_t i = 0; i < header.arcount; i++) {
        additional.push_back(dns_record(bytes, offset));
      }
  }
  
  dns_packet(std::string domain_name, dns_record_t type) {
    header.id = dist(gen);
    header.flags = 0;
    header.qdcount = 1;
    header.ancount = 0;
    header.nscount = 0;
    header.arcount = 0;

    questions.push_back(dns_question(domain_name, type, 1));
  }

  std::vector<uint8_t> to_bytes() const {
    std::vector<uint8_t> bytes;
    auto header_bytes = header.to_bytes();

    bytes.insert(bytes.end(), header_bytes.begin(), header_bytes.end());
    for (size_t i = 0; i < header.qdcount; i++) {
      auto record_bytes = questions[i].to_bytes();
      bytes.insert(bytes.end(), record_bytes.begin(), record_bytes.end());
    }
    for (size_t i = 0; i < header.ancount; i++) {
      auto record_bytes = answers[i].to_bytes();
      bytes.insert(bytes.end(), record_bytes.begin(), record_bytes.end());
    }
    for (size_t i = 0; i < header.nscount; i++) {
      auto record_bytes = authorities[i].to_bytes();
      bytes.insert(bytes.end(), record_bytes.begin(), record_bytes.end());
    }
    for (size_t i = 0; i < header.arcount; i++) {
      auto record_bytes = additional[i].to_bytes();
      bytes.insert(bytes.end(), record_bytes.begin(), record_bytes.end());
    }
    return bytes;
  }
};

std::ostream& operator<<(std::ostream& os, const dns_packet& packet) {
  os << "dns_packet {\n";
  os << "  " << packet.header << "\n";
  for (size_t i = 0; i < packet.header.qdcount; i++) {
    os << "  qd " << packet.questions[i] << "\n";
  }
  for (size_t i = 0; i < packet.header.ancount; i++) {
    os << "  an " << packet.answers[i] << "\n";
  }
  for (size_t i = 0; i < packet.header.nscount; i++) {
    os << "  ns " << packet.authorities[i] << "\n";
  }
  for (size_t i = 0; i < packet.header.arcount; i++) {
    os << "  ad " << packet.additional[i] << "\n";
  }
  os << "}";
  return os;
}
