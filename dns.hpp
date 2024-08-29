#include <iomanip>
#include <iostream>
#include <map>
#include <random>
#include <sstream>

template <typename T>
void hex_print(T buf) {
  std::cout << "size: " << buf.size() << "\n";
  for (auto u: buf) {
    std::cout << std::hex << std::setfill('0') << std::setw(2) << (int) u << " ";
  }
  std::cout << "\n";
}

template <typename T>
void hex_print(T buf, size_t length) {
  std::cout << "size: " << length << " / " << buf.size() << "\n";
  int i = 0;
  for (auto u: buf) {
    if (i > length) break;
    std::cout << std::hex << std::setfill('0') << std::setw(2) << (int) u << " ";
    i++;
  }
  std::cout << "\n";
}

void to_big_endian(uint16_t value, std::array<uint8_t, 2> &buf) {
  buf[0] = static_cast<uint8_t>(value >> 8);
  buf[1] = static_cast<uint8_t>(value & 0xff);
}

template <typename T>
T from_big_endian(const std::vector<uint8_t> &bytes, size_t &offset) {
  size_t sz = sizeof(T);
  T ret = 0;
  for (int i = 0; i < sz; i++) {
    ret <<= 8;
    ret |= bytes[offset++];
  }
  return ret;
}

uint16_t from_big_endian(std::vector<uint8_t>::const_iterator it) {
  return (static_cast<uint16_t>(*it) << 8) | (static_cast<uint16_t>(*(it + 1)));
}

struct dns_header {
  uint16_t id;
  uint16_t flags;
  uint16_t qdcount;
  uint16_t ancount;
  uint16_t nscount;
  uint16_t arcount;
  
  dns_header() = default;

  dns_header(std::vector<uint8_t> bytes, size_t& offset) {
    id = from_big_endian(bytes.begin());
    flags = from_big_endian(bytes.begin() + 2);
    qdcount = from_big_endian(bytes.begin() + 4);
    ancount = from_big_endian(bytes.begin() + 6);
    nscount = from_big_endian(bytes.begin() + 8);
    arcount = from_big_endian(bytes.begin() + 10);

    offset += 12;
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

enum class dns_record_type : uint16_t {
  A = 1,
  AAAA = 28,
  CNAME = 5,
  MX = 15,
  NS = 2,
  PTR = 12,
  SOA = 6,
};

std::ostream& operator<<(std::ostream& os, const dns_record_type &dns_rec) {
  using enum dns_record_type;
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
  }
  return os;
}

std::string decode_name(std::vector<uint8_t> bytes, size_t &offset);

std::string decode_compressed_name(uint8_t len, std::vector<uint8_t> bytes, size_t &offset) {
  size_t pos = (static_cast<uint16_t>(len & 0b0011'0000) << 8) + bytes[offset++];
  return decode_name(bytes, pos);
}

std::string decode_name(std::vector<uint8_t> bytes, size_t &offset) {
  uint8_t len = 0;
  std::string domain;
  while ((len = bytes[offset++]) != 0) {
    if (len & 0b1100'0000) {
      domain.append(decode_compressed_name(len, bytes, offset));
      break;
    }
    domain.append(bytes.begin() + offset, bytes.begin() + offset + len);
    domain.push_back('.');
    offset += len;
  }
  return domain;
}

struct dns_record {
  std::string name;
  dns_record_type type;
  uint16_t class_;
  uint32_t ttl;
  std::vector<uint8_t> data;

  dns_record() = default;
  dns_record(std::vector<uint8_t> bytes, size_t &offset) {
    name = decode_name(bytes, offset);

    type = static_cast<dns_record_type>(from_big_endian<uint16_t>(bytes, offset));
    class_ = from_big_endian<uint16_t>(bytes, offset);
    ttl = from_big_endian<uint32_t>(bytes, offset);
    int rdlen = from_big_endian<uint16_t>(bytes, offset);
    data.insert(data.end(), bytes.begin() + offset, bytes.begin() + offset + rdlen);
    offset += rdlen;
  }
};

std::ostream& operator<<(std::ostream& os, const dns_record& record) {
    os << "dns_record { "
       << "name: " << record.name << ", "
       << "type: " << record.type << ", "
       << "class_: " << record.class_ << ", "
       << "ttl " << record.ttl << ", "
       << "data " << std::dec
       << (int) record.data[0] << " "
       << (int) record.data[1] << " "
       << (int) record.data[2] << " "
       << (int) record.data[3] << " "
       << " }";
    return os;
}

struct dns_question {
  std::string qname;
  dns_record_type qtype;
  uint16_t qclass;

  dns_question() = default;

  dns_question(std::vector<uint8_t> bytes, size_t& offset) {
    uint8_t len = 0;
    int x = offset;
    while ((len = bytes[offset++]) != 0) {
      qname.append(bytes.begin() + offset, bytes.begin() + offset + len);
      qname.push_back('.');
      offset += len;
    }
    qtype = static_cast<dns_record_type>(from_big_endian<uint16_t>(bytes, offset));
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
    to_big_endian(std::to_underlying(qtype), buf);
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
  dns_question question;
  std::vector<dns_record> records;

  dns_packet(std::vector<uint8_t> bytes)
    : offset(0), header(bytes, offset), question(bytes, offset) {
      std::cout << header << "\n";
      std::cout << question << "\n";
      records.push_back(dns_record(bytes, offset));
      std::cout << records[0] << "\n";
  }
  
  dns_packet(std::string domain_name, dns_record_type record_type) {
    header.id = dist(gen);
    header.flags = (1 << 8);
    header.qdcount = 1;
    header.ancount = 0;
    header.nscount = 0;
    header.arcount = 0;

    question.qname = domain_name;
    question.qtype = record_type;
    question.qclass = 1;
  }

  std::vector<uint8_t> to_bytes() const {
    std::vector<uint8_t> bytes;
    auto header_bytes = header.to_bytes();
    auto question_bytes = question.to_bytes();

    bytes.insert(bytes.end(), header_bytes.begin(), header_bytes.end());
    bytes.insert(bytes.end(), question_bytes.begin(), question_bytes.end());

    return bytes;

  }
};
