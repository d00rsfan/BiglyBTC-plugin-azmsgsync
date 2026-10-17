// SPDX-License-Identifier: GPL-2.0-or-later
// Original STS: Copyright (C) Azureus Software, Inc.
#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
namespace biglybtc::plugins::msgsync {
enum class StsError { Input, Limit, Version, Phase, Signature, Crypto, NotAuthenticated, PeerMismatch };
struct StsFailure { StsError code; std::size_t consumed = 0; };
inline constexpr std::size_t maximumStsPacket = 128 * 1024;
class StsSecret final {
public:
  StsSecret() = default;
  ~StsSecret();
  StsSecret(const StsSecret&) = delete;
  StsSecret& operator=(const StsSecret&) = delete;
  StsSecret(StsSecret&& other) noexcept;
  StsSecret& operator=(StsSecret&& other) noexcept;
  std::span<const std::uint8_t> view() const { return {bytes_.data(), length_}; }
  // Format conversion only, not a peer/authentication decision. Original DH
  // returns a positive Java BigInteger.toByteArray, not a fixed-width integer.
  static std::expected<StsSecret, StsFailure> fromUnsigned(std::span<const std::uint8_t> value);
private:
  std::array<std::uint8_t, 25> bytes_{};
  std::size_t length_ = 0;
  friend class LegacySts;
};
struct StsState {
  std::optional<std::string> remotePublic; // May be an unverified original candidate.
  bool keysDerived = false;
  bool peerAuthenticated = false; // Expected peer binding remains a separate check.
};
// One host owner thread, move-only state. No profile, process or network access.
class LegacySts final {
public:
  static std::expected<LegacySts, StsFailure> create(std::string_view publicKey, std::string_view privateKey);
  ~LegacySts();
  LegacySts(LegacySts&&) noexcept;
  LegacySts& operator=(LegacySts&&) noexcept;
  LegacySts(const LegacySts&) = delete;
  LegacySts& operator=(const LegacySts&) = delete;
  std::expected<void, StsFailure> reset(); // Same identity, fresh native ephemeral key.
  std::expected<std::string, StsFailure> keysPacket() const;
  std::expected<std::string, StsFailure> authPacket() const;
  std::expected<std::size_t, StsFailure> receiveKeys(std::string_view packet);
  std::expected<std::size_t, StsFailure> receiveAuth(std::string_view packet);
  StsState state() const;
  // Unlike the original raw getter, application key access requires successful
  // auth plus the exact expected encoded identity (as MsgSyncHandler checks).
  std::expected<StsSecret, StsFailure> authenticatedSecret(std::string_view expectedPeer) const;
private:
  struct Impl;
  explicit LegacySts(std::unique_ptr<Impl>);
  std::unique_ptr<Impl> impl_;
};
}
