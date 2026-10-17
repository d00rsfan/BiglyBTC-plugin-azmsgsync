// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
namespace biglybtc::plugins::msgsync {
enum class Error { InvalidInput, Limit, CryptoFailure, InvalidEnvelope };
enum class Kind { General, Private };
inline constexpr std::size_t maximumPayload = 4 * 1024 * 1024, maximumUserKey = 64 * 1024;
struct ChannelKeys {
  std::array<std::uint8_t, 16> general;
  std::array<std::uint8_t, 20> listen, peek;
};
std::expected<ChannelKeys, Error> deriveChannelKeys(std::span<const std::uint8_t> userKey);
std::expected<std::array<std::uint8_t, 24>, Error> fixSharedSecret(std::span<const std::uint8_t> raw);
// Original compatible cipher envelope only. These functions do not establish
// sender authentication or replace original signature/identity/STS verification.
// Encryption generates a fresh OS-backed cryptographic IV through OpenSSL.
std::expected<std::string, Error> encrypt(Kind kind, std::span<const std::uint8_t> key,
    std::span<const std::uint8_t> plaintext);
std::expected<std::string, Error> decrypt(Kind kind, std::span<const std::uint8_t> key,
    std::span<const std::uint8_t> envelope);
}
