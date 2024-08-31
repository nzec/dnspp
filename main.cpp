#include <asio.hpp>

#include "dns.hpp"

using asio::ip::udp;

std::string resolve(std::string domain, dns_record_t type);
dns_packet send_query(std::string nameserver, std::string domain, dns_record_t type);

int main(int argc, char **argv) {
  std::string domain = argv[1];
  auto ipaddr = resolve(domain, dns_record_t::A);
  std::cout << "IPv4 Address found: " << ipaddr << "\n";
}

std::optional<std::string> get_answer(const dns_packet &packet) {
  for (const auto &record: packet.answers) {
    if (record.type == dns_record_t::A) {
      return record.parsed_rdata;
    }
  }
  return std::nullopt;
}

std::optional<std::string> get_nameserver_ip(const dns_packet &packet) {
  for (const auto &record: packet.additional) {
    if (record.type == dns_record_t::A) {
      return record.parsed_rdata;
    }
  }
  return std::nullopt;
}

std::optional<std::string> get_nameserver(const dns_packet &packet) {
  for (const auto &record: packet.authorities) {
    if (record.type == dns_record_t::NS) {
      return record.parsed_rdata;
    }
  }
  return std::nullopt;
}

std::string resolve(std::string domain, dns_record_t type) {
  std::string nameserver = "198.41.0.4";
  while (true) {
    std::cout << "Querying " << nameserver << " for " << domain << "\n";
    auto resp = send_query(nameserver, domain, type);
    std::optional<std::string> ans;
    if (ans = get_answer(resp)) {
      return ans.value();
    } else if (ans = get_nameserver_ip(resp)) {
      nameserver = ans.value();
    } else if (ans = get_nameserver(resp)) {
      nameserver = resolve(ans.value(), dns_record_t::A);
    }
  }
}

dns_packet send_query(std::string nameserver, std::string domain, dns_record_t type) {
  dns_packet d(domain, type);
  auto bytes = d.to_bytes();
  try {
    asio::io_context io_context;
    udp::resolver resolver(io_context);
    udp::endpoint endpoint(asio::ip::make_address(nameserver), 53);
    udp::socket socket(io_context);
    socket.open(udp::v4());

    socket.send_to(asio::buffer(bytes, bytes.size()), endpoint);

    std::vector<uint8_t> dns_response(1024);
    udp::endpoint sender_endpoint;
    size_t length = socket.receive_from(asio::buffer(dns_response), sender_endpoint);

    dns_packet out(dns_response);

    /*
    auto v = out.to_bytes();
    dns_packet vv{v};
    auto vvv = vv.to_bytes();
    hex_print(vvv);

    dns_packet vvvv{vvv};
    std::cout << vvvv << "\n";
    */

    socket.close();
    return out;
  } catch (std::exception& e) {
    std::cerr << "Error: " << e.what() << "\n";
    throw e;
  }
}
