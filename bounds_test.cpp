// SPDX-License-Identifier: GPL-2.0-or-later
#include "envelope.hpp"
#include <cstdlib>
#include <iostream>
#include <vector>
using namespace biglybtc::plugins::msgsync;
void require(bool value) { if (!value) { std::abort(); } }
std::span<const std::uint8_t> span(const std::string& bytes) {
  return {reinterpret_cast<const std::uint8_t*>(bytes.data()), bytes.size()};
}
int main() {
  std::array<std::uint8_t, 24> key{};
  std::array<std::uint8_t, 16> general{};
  const std::string plain("\0test\xffmessage\r\n", 15);
  for (const auto kind : {Kind::General, Kind::Private}) {
    const auto selectedKey = kind == Kind::General ? std::span<const std::uint8_t>(general) : std::span<const std::uint8_t>(key);
    const auto first = encrypt(kind, selectedKey, span(plain)), second = encrypt(kind, selectedKey, span(plain));
    require(first.has_value() && second.has_value() && first->substr(0, 16) != second->substr(0, 16));
    require(decrypt(kind, selectedKey, span(*first)) == plain);
    require(!decrypt(kind, selectedKey, span(first->substr(0, first->size() - 1))));
    require(encrypt(kind, selectedKey.first(selectedKey.size() - 1), {}).error() == Error::InvalidInput);
    const std::vector<std::uint8_t> large(maximumPayload + 1, 0);
    require(encrypt(kind, selectedKey, large).error() == Error::Limit);
    const std::vector<std::uint8_t> largeCipher(maximumPayload + 33, 0);
    require(decrypt(kind, selectedKey, largeCipher).error() == Error::Limit);
  }
  std::vector<std::uint8_t> longKey(maximumUserKey + 1, 0);
  require(deriveChannelKeys(longKey).error() == Error::Limit);
  require(fixSharedSecret(longKey).error() == Error::Limit);
  std::array<std::uint8_t, 16> iv{};
  require(decrypt(Kind::General, general, iv) == std::string{});
  require(decrypt(Kind::Private, key, iv).error() == Error::InvalidEnvelope);
  std::cout << "PASS bounded message envelopes, native fresh IVs, roundtrip and legacy general/private empty-ciphertext distinction\n";
}
