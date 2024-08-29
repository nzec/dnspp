#include <asio.hpp>

#include "dns.hpp"

using asio::ip::udp;

int main() {
  dns_packet d("gmail.com.", dns_record_type::A);
  auto bytes = d.to_bytes();

  try {
    asio::io_context io_context;
    udp::resolver resolver(io_context);
    udp::endpoint endpoint(asio::ip::make_address("8.8.8.8"), 53);
    udp::socket socket(io_context);
    socket.open(udp::v4());

    socket.send_to(asio::buffer(bytes, bytes.size()), endpoint);

    std::array<uint8_t, 1024> dns_response{};
    udp::endpoint sender_endpoint;
    size_t length = socket.receive_from(asio::buffer(dns_response), sender_endpoint);

    hex_print(dns_response, length);
    dns_packet out{std::vector(dns_response.begin(), dns_response.end())};

    socket.close();
  } catch (std::exception& e) {
    std::cerr << "Error: " << e.what() << "\n";
  }
}
