// SPDX-License-Identifier: GPL-2.0-or-later
#include "legacy_sts.hpp"
#include "envelope.hpp"
#include <openssl/crypto.h>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
namespace sync = biglybtc::plugins::msgsync;
namespace {
std::string raw(const std::string& value) {
  if (value.empty() || value.front()!='x' || value.size()%2!=1) { throw std::runtime_error("Invalid fixture hex"); }
  std::string result;
  for (std::size_t i=1;i<value.size();i+=2) { result+=static_cast<char>(std::stoul(value.substr(i,2),nullptr,16)); }
  return result;
}
std::span<const std::uint8_t> bytes(std::string_view value) { return {reinterpret_cast<const std::uint8_t*>(value.data()),value.size()}; }
std::string hex(std::span<const std::uint8_t> value) {
  std::ostringstream out;out << 'x' << std::hex << std::uppercase << std::setfill('0');
  for (auto byte:value) { out << std::setw(2) << static_cast<unsigned>(byte); }return out.str();
}
std::string state(const sync::LegacySts& sts) {
  const auto value=sts.state();return (value.remotePublic?hex(bytes(*value.remotePublic)):"-")+' '+(value.keysDerived?"1":"0");
}
void run(std::istream& input) {
  std::optional<sync::LegacySts> current;
  std::string line;
  while (std::getline(input,line)) {
    try {
      if (line.size()>1024*1024) { throw std::runtime_error("Fixture line bound"); }
      std::istringstream in(line);std::string kind,a,b;in >> kind;
      if (kind=="INIT") {
        in >> a >> b;auto value=sync::LegacySts::create(raw(a),raw(b));
        if (value) { current.emplace(std::move(*value));std::cout << "INIT\n"; }else { current.reset();std::cout << "ERROR\n"; }
      } else if (kind=="INTEGER") {
        in >> a;const auto value=raw(a);auto result=sync::StsSecret::fromUnsigned(bytes(value));
        if (result) { std::cout << "INTEGER " << hex(result->view()) << '\n'; }else { std::cout << "ERROR\n"; }
      } else if (!current) { std::cout << "ERROR\n"; }
      else if (kind=="RESET") { std::cout << (current->reset()?"RESET":"ERROR") << '\n'; }
      else if (kind=="STATE") { std::cout << "STATE " << state(*current) << '\n'; }
      else if (kind=="GET_KEYS" || kind=="GET_AUTH") {
        auto packet=kind=="GET_KEYS"?current->keysPacket():current->authPacket();
        if (packet) { std::cout << kind << ' ' << hex(bytes(*packet)) << '\n'; }else { std::cout << "ERROR\n"; }
      } else if (kind=="PUT_KEYS" || kind=="PUT_AUTH") {
        in >> a;const auto packet=raw(a);const auto result=kind=="PUT_KEYS"?current->receiveKeys(packet):current->receiveAuth(packet);
        std::cout << kind << ' ' << static_cast<unsigned>(bool(result)) << ' ' << (result?*result:result.error().consumed)
            << ' ' << state(*current) << '\n';
      } else if (kind=="SECRET") {
        in >> a;auto secret=current->authenticatedSecret(raw(a));
        if (secret) { std::cout << "SECRET " << hex(secret->view()) << '\n'; }else { std::cout << "ERROR\n"; }
      } else if (kind=="ENCRYPT" || kind=="DECRYPT") {
        in >> a >> b;auto secret=current->authenticatedSecret(raw(a));
        if (!secret) { std::cout << "ERROR\n"; }
        else {
          auto fixed=sync::fixSharedSecret(secret->view());const auto data=raw(b);
          if (!fixed) { std::cout << "ERROR\n"; }
          else {
            const auto result=kind=="ENCRYPT"?sync::encrypt(sync::Kind::Private,*fixed,bytes(data)):
                sync::decrypt(sync::Kind::Private,*fixed,bytes(data));
            OPENSSL_cleanse(fixed->data(),fixed->size());
            if (result) { std::cout << (kind=="ENCRYPT"?"ENCRYPTED":"PLAIN") << ' ' << hex(bytes(*result)) << '\n'; }
            else { std::cout << "ERROR\n"; }
          }
        }
      } else { std::cout << "ERROR\n"; }
    } catch (const std::exception&) { std::cout << "ERROR\n"; }
    std::cout.flush();
  }
}
}
int main(int argc,char** argv) {
  if (argc==2 && std::string_view(argv[1])=="--stdio") { run(std::cin);return 0; }
  if (argc!=2 || !std::filesystem::canonical(argv[1]).string().starts_with("/tmp/biglybtc-")) { return 2; }
  std::ifstream input(argv[1]);if (!input) { return 3; }run(input);
}
