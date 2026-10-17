// SPDX-License-Identifier: GPL-2.0-or-later
#include "envelope.hpp"
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
namespace message = biglybtc::plugins::msgsync;
std::string hex(std::span<const std::uint8_t> bytes) {
  std::ostringstream out; out << 'x' << std::hex << std::uppercase << std::setfill('0');
  for (const auto byte : bytes) { out << std::setw(2) << static_cast<unsigned>(byte); }
  return out.str();
}
std::span<const std::uint8_t> span(const std::string& bytes) {
  return {reinterpret_cast<const std::uint8_t*>(bytes.data()), bytes.size()};
}
std::string bytes(const std::string& token) {
  if (token.empty() || token[0] != 'x' || token.size() % 2 != 1) { throw std::runtime_error("Invalid token"); }
  std::string out;
  for (std::size_t i = 1; i < token.size(); i += 2) { out += static_cast<char>(std::stoul(token.substr(i, 2), nullptr, 16)); }
  return out;
}
int main(int argc, char** argv) {
  if (argc != 2) { return 2; }
  const auto path = std::filesystem::canonical(argv[1]);
  if (!path.native().starts_with("/tmp/biglybtc-") || std::filesystem::file_size(path) > 16 * 1024 * 1024) { return 2; }
  std::ifstream stream(path);
  if (!stream.good()) { return 3; }
  std::string line;
  while (std::getline(stream, line)) {
    std::istringstream input(line); char command = 0; input >> command;
    if (command == 'K' || command == 'F') {
      std::string token; input >> token; const auto raw = bytes(token);
      if (command == 'K') {
        const auto keys = message::deriveChannelKeys(span(raw));
        if (!keys) { std::cout << "KEYS -\n"; }
        else { std::cout << "KEYS " << hex(keys->general) << ' ' << hex(keys->listen) << ' ' << hex(keys->peek) << '\n'; }
      } else {
        const auto secret = message::fixSharedSecret(span(raw));
        std::cout << "FIX " << (secret ? hex(*secret) : "-") << '\n';
      }
    } else if (command == 'D' || command == 'E') {
      char kind = 0; std::string key, data; input >> kind >> key >> data;
      if (kind != 'G' && kind != 'P') { return 4; }
      const auto rawKey = bytes(key), rawData = bytes(data);
      const auto type = kind == 'G' ? message::Kind::General : message::Kind::Private;
      const auto result = command == 'D' ? message::decrypt(type, span(rawKey), span(rawData))
          : message::encrypt(type, span(rawKey), span(rawData));
      std::cout << (command == 'D' ? "PLAIN " : "ENCRYPTED ") << (result ? hex(span(*result)) : "-") << '\n';
    } else { return 5; }
  }
}
