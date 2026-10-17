// SPDX-License-Identifier: GPL-2.0-or-later
#include "legacy_sts.hpp"
#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <type_traits>
namespace msg = biglybtc::plugins::msgsync;
namespace {
void require(bool value) { if (!value) { std::abort(); } }
std::string ephemeral(std::string_view packet) {
  std::size_t offset=1;
  for (int i=0;i<2;++i) {
    require(packet.size()-offset>=2);
    const auto length=(static_cast<unsigned char>(packet[offset])<<8) | static_cast<unsigned char>(packet[offset+1]);offset+=2;
    require(packet.size()-offset>=static_cast<std::size_t>(length));
    const auto value=packet.substr(offset,length);if (i==1) { return std::string(value); }offset+=length;
  }
  std::abort();
}
}
int main() {
  static_assert(!std::is_copy_constructible_v<msg::StsSecret> && std::is_nothrow_move_constructible_v<msg::StsSecret>);
  static_assert(!std::is_copy_constructible_v<msg::LegacySts> && std::is_nothrow_move_constructible_v<msg::LegacySts>);
  // Public test scalar ONE and its standard prime192v2 generator; no user key.
  const unsigned char generator[]{0x03,0xee,0xa2,0xba,0xe7,0xe1,0x49,0x78,0x42,0xf2,0xde,0x77,0x69,
      0xcf,0xe9,0xc9,0x89,0xc0,0x72,0xad,0x69,0x6f,0x48,0x03,0x4a};
  const std::string pub(reinterpret_cast<const char*>(generator),sizeof(generator)),priv(1,'\1');
  for (const auto& invalid : {std::string{},std::string(1,'\0'),std::string(1,'\x80'),std::string(1,'\2'),std::string(26,'\0')}) {
    require(!msg::LegacySts::create(pub,invalid));
  }
  require(!msg::LegacySts::create({},priv));
  require(!msg::LegacySts::create(std::string(1,'\4')+std::string(48,'\0'),priv));
  auto a=msg::LegacySts::create(pub,priv),b=msg::LegacySts::create(pub,priv);require(a && b);
  require(!a->authPacket() && !a->authenticatedSecret(pub));
  auto ak=a->keysPacket(),bk=b->keysPacket();require(ak && bk);
  require(a->receiveKeys(*bk).has_value() && b->receiveKeys(*ak).has_value());
  require(a->state().keysDerived && !a->state().peerAuthenticated && !a->authenticatedSecret(pub));
  auto aa=a->authPacket(),ba=b->authPacket();require(aa && ba);
  require(a->receiveAuth(*ba).has_value() && b->receiveAuth(*aa).has_value());
  auto as=a->authenticatedSecret(pub),bs=b->authenticatedSecret(pub);require(as && bs);
  require(std::ranges::equal(as->view(),bs->view()) && a->state().peerAuthenticated);
  auto wrong=pub;wrong[0]^=1;
  const auto mismatch=a->authenticatedSecret(wrong);require(!mismatch && mismatch.error().code==msg::StsError::PeerMismatch);
  auto damaged=*ba;damaged.back()^=1;
  require(!a->receiveAuth(damaged) && !a->state().peerAuthenticated && a->state().keysDerived && !a->authenticatedSecret(pub));
  require(a->receiveAuth(*ba).has_value());
  const std::string large(msg::maximumStsPacket+1,'x');
  const auto largeAuth=a->receiveAuth(large),largeKeys=a->receiveKeys(large);
  require(!largeAuth && largeAuth.error().code==msg::StsError::Limit && largeAuth.error().consumed==0);
  require(!largeKeys && largeKeys.error().code==msg::StsError::Limit && largeKeys.error().consumed==0);
  require(a->state().peerAuthenticated && a->authenticatedSecret(pub).has_value());
  require(a->reset().has_value() && !a->state().keysDerived && !a->state().remotePublic && !a->authenticatedSecret(pub));
  const auto fresh=a->keysPacket();require(fresh && ephemeral(*fresh)!=ephemeral(*ak));
  auto moved=std::move(*b);require(!b->state().keysDerived && !b->reset() && !b->authPacket() && !b->authenticatedSecret(pub));
  require(moved.authenticatedSecret(pub).has_value());
  std::array<std::uint8_t,24> input{};input.fill(0x80);
  auto value=msg::StsSecret::fromUnsigned(input);require(value && value->view().size()==25);
  const auto prior=value->view();auto secret=std::move(*value);
  require(value->view().empty() && std::ranges::all_of(prior,[](auto byte){return byte==0;}));
  require(secret.view().size()==25 && secret.view()[0]==0 && secret.view()[1]==0x80);
  msg::StsSecret recipient;recipient=std::move(secret);require(secret.view().empty() && recipient.view().size()==25);
  for (std::size_t size : {0U,1U,23U,25U,26U}) {
    const std::string invalid(size,'\0');require(!msg::StsSecret::fromUnsigned({reinterpret_cast<const std::uint8_t*>(invalid.data()),invalid.size()}));
  }
  std::cout << "PASS STS identity validation, native mutual auth, peer binding, limits, failure/reset/move lifecycle and secret move cleansing\n";
}
