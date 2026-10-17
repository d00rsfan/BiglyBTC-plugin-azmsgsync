// SPDX-License-Identifier: GPL-2.0-or-later
// Original MsgSyncHandler bounded behavior:
// 4209aa5029e3035cbb09dc3a83e9491d3f36fbc6, Copyright2014 Azureus Software, Inc.
#include "envelope.hpp"
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <algorithm>
#include <memory>
#include <string_view>
namespace biglybtc::plugins::msgsync {
namespace {
using Cipher = std::unique_ptr<EVP_CIPHER, decltype(&EVP_CIPHER_free)>;
using Context = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;
std::expected<std::array<std::uint8_t, 20>, Error> sha1(std::span<const std::uint8_t> bytes) {
  std::array<std::uint8_t, 20> result{};
  std::size_t length = 0;
  if (EVP_Q_digest(nullptr, "SHA1", nullptr, bytes.data(), bytes.size(), result.data(), &length) != 1
      || length != result.size()) { return std::unexpected(Error::CryptoFailure); }
  return result;
}
std::size_t keyLength(Kind kind) {
  switch (kind) { case Kind::General: return 16; case Kind::Private: return 24; }
  return 0;
}
Cipher cipher(Kind kind) {
  return {EVP_CIPHER_fetch(nullptr, kind == Kind::General ? "AES-128-CBC" : "AES-192-CBC", nullptr), EVP_CIPHER_free};
}
}
std::expected<ChannelKeys, Error> deriveChannelKeys(std::span<const std::uint8_t> userKey) {
  if (userKey.size() > maximumUserKey) { return std::unexpected(Error::Limit); }
  std::array<std::uint8_t, 16> salt{0x77,0x9a,0xb8,0xfd,0xe4,0x40,0x93,0x8d,0x58,0xad,0xf5,0xd4,0xa1,0x1b,0xe1,0xa8};
  for (std::size_t i = 0; i < userKey.size(); ++i) { salt[i % salt.size()] ^= userKey[i]; }
  auto general = sha1(salt);
  OPENSSL_cleanse(salt.data(), salt.size());
  if (!general) { return std::unexpected(general.error()); }
  constexpr std::string_view base = "com.vuze.plugins.azmsgsync.MsgSyncHandler";
  const auto baseKey = sha1({reinterpret_cast<const std::uint8_t*>(base.data()), base.size()});
  const auto listen = sha1(userKey);
  if (!baseKey || !listen) {
    OPENSSL_cleanse(general->data(), general->size()); return std::unexpected(Error::CryptoFailure);
  }
  ChannelKeys result{};
  std::copy_n(general->begin(), result.general.size(), result.general.begin());
  OPENSSL_cleanse(general->data(), general->size());
  for (std::size_t i = 0; i < result.listen.size(); ++i) { result.listen[i] = (*listen)[i] ^ (*baseKey)[i]; }
  result.peek = result.listen;
  result.peek[1] ^= 1;
  return result;
}
std::expected<std::array<std::uint8_t, 24>, Error> fixSharedSecret(std::span<const std::uint8_t> raw) {
  if (raw.size() > maximumUserKey) { return std::unexpected(Error::Limit); }
  std::array<std::uint8_t, 24> result{};
  if (raw.size() < result.size()) { std::copy(raw.begin(), raw.end(), result.begin()); }
  else { std::copy(raw.end() - result.size(), raw.end(), result.begin()); }
  return result;
}
std::expected<std::string, Error> encrypt(Kind kind, std::span<const std::uint8_t> key,
    std::span<const std::uint8_t> plaintext) {
  if (keyLength(kind) == 0 || key.size() != keyLength(kind)) { return std::unexpected(Error::InvalidInput); }
  if (plaintext.size() > maximumPayload) { return std::unexpected(Error::Limit); }
  const auto algorithm = cipher(kind);
  Context context(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
  if (!algorithm || !context) { return std::unexpected(Error::CryptoFailure); }
  std::string output(plaintext.size() + 32, '\0');
  auto* bytes = reinterpret_cast<unsigned char*>(output.data());
  if (RAND_priv_bytes(bytes, 16) != 1
      || EVP_EncryptInit_ex2(context.get(), algorithm.get(), key.data(), bytes, nullptr) != 1) {
    return std::unexpected(Error::CryptoFailure);
  }
  int length = 0, final = 0;
  if (EVP_EncryptUpdate(context.get(), bytes + 16, &length, plaintext.data(), static_cast<int>(plaintext.size())) != 1
      || EVP_EncryptFinal_ex(context.get(), bytes + 16 + length, &final) != 1) {
    return std::unexpected(Error::CryptoFailure);
  }
  output.resize(16 + static_cast<std::size_t>(length + final));
  return output;
}
std::expected<std::string, Error> decrypt(Kind kind, std::span<const std::uint8_t> key,
    std::span<const std::uint8_t> envelope) {
  if (keyLength(kind) == 0 || key.size() != keyLength(kind)) { return std::unexpected(Error::InvalidInput); }
  if (envelope.size() > maximumPayload + 32) { return std::unexpected(Error::Limit); }
  if (envelope.size() < 16 || envelope.size() % 16 != 0) { return std::unexpected(Error::InvalidEnvelope); }
  // SunJCE's original general decrypt returns empty data for an IV with no
  // ciphertext. The selected private BouncyCastle path rejects that same input.
  if (kind == Kind::General && envelope.size() == 16) { return std::string{}; }
  if (envelope.size() < 32) { return std::unexpected(Error::InvalidEnvelope); }
  const auto algorithm = cipher(kind);
  Context context(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
  if (!algorithm || !context || EVP_DecryptInit_ex2(context.get(), algorithm.get(), key.data(), envelope.data(), nullptr) != 1) {
    return std::unexpected(Error::CryptoFailure);
  }
  std::string output(envelope.size() - 16, '\0');
  auto* bytes = reinterpret_cast<unsigned char*>(output.data());
  int length = 0, final = 0;
  if (EVP_DecryptUpdate(context.get(), bytes, &length, envelope.data() + 16, static_cast<int>(envelope.size() - 16)) != 1
      || EVP_DecryptFinal_ex(context.get(), bytes + length, &final) != 1) {
    OPENSSL_cleanse(output.data(), output.size());
    return std::unexpected(Error::InvalidEnvelope);
  }
  output.resize(static_cast<std::size_t>(length + final));
  if (output.size() > maximumPayload) {
    OPENSSL_cleanse(output.data(), output.size()); return std::unexpected(Error::Limit);
  }
  return output;
}
}
