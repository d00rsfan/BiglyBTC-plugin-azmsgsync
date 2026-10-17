// SPDX-License-Identifier: GPL-2.0-or-later
// Original STS: Copyright (C) Azureus Software, Inc.
#include "legacy_sts.hpp"
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/rand.h>
#include <algorithm>
#include <utility>
namespace biglybtc::plugins::msgsync {
StsSecret::~StsSecret() { OPENSSL_cleanse(bytes_.data(), bytes_.size()); }
StsSecret::StsSecret(StsSecret&& other) noexcept : bytes_(other.bytes_), length_(std::exchange(other.length_,0)) {
  OPENSSL_cleanse(other.bytes_.data(),other.bytes_.size());
}
StsSecret& StsSecret::operator=(StsSecret&& other) noexcept {
  if (this != &other) {
    OPENSSL_cleanse(bytes_.data(),bytes_.size());bytes_=other.bytes_;length_=std::exchange(other.length_,0);
    OPENSSL_cleanse(other.bytes_.data(),other.bytes_.size());
  }
  return *this;
}
std::expected<StsSecret, StsFailure> StsSecret::fromUnsigned(std::span<const std::uint8_t> value) {
  if (value.size()!=24) { return std::unexpected(StsFailure{StsError::Input}); }
  StsSecret result;
  const auto first=std::find_if(value.begin(),value.end(),[](auto byte){return byte!=0;});
  if (first==value.end()) { result.length_=1; return result; }
  if ((*first & 0x80)!=0) { result.bytes_[result.length_++]=0; }
  std::copy(first,value.end(),result.bytes_.begin()+result.length_);
  result.length_+=static_cast<std::size_t>(value.end()-first);
  return result;
}
namespace {
struct Failure { StsError code; };
void require(bool value,StsError code=StsError::Crypto) { if (!value) { throw Failure{code}; } }
using Key=std::unique_ptr<EVP_PKEY,decltype(&EVP_PKEY_free)>;
using Context=std::unique_ptr<EVP_PKEY_CTX,decltype(&EVP_PKEY_CTX_free)>;
using Digest=std::unique_ptr<EVP_MD_CTX,decltype(&EVP_MD_CTX_free)>;
using Builder=std::unique_ptr<OSSL_PARAM_BLD,decltype(&OSSL_PARAM_BLD_free)>;
using Number=std::unique_ptr<BIGNUM,decltype(&BN_clear_free)>;
struct ParamCleanup {
  void operator()(OSSL_PARAM* params) const {
    if (!params) { return; }
    auto* secret=OSSL_PARAM_locate(params,OSSL_PKEY_PARAM_PRIV_KEY);
    if (secret && secret->data) { OPENSSL_cleanse(secret->data,secret->data_size); }
    OSSL_PARAM_free(params);
  }
};
using Params=std::unique_ptr<OSSL_PARAM,ParamCleanup>;
struct DerivationBuffer {
  std::array<std::uint8_t,24> bytes{};
  ~DerivationBuffer() { OPENSSL_cleanse(bytes.data(),bytes.size()); }
};
bool compressed(std::string_view raw) { return !raw.empty() && (raw.front()=='\2' || raw.front()=='\3'); }
Key importKey(std::string_view pub,std::string_view priv={}) {
  require((pub.size()==25 && compressed(pub)) || (pub.size()==49 &&
      (pub.front()=='\4' || pub.front()=='\6' || pub.front()=='\7')),StsError::Input);
  Builder builder(OSSL_PARAM_BLD_new(),OSSL_PARAM_BLD_free);require(bool(builder));
  require(OSSL_PARAM_BLD_push_utf8_string(builder.get(),OSSL_PKEY_PARAM_GROUP_NAME,"prime192v2",0)==1);
  require(OSSL_PARAM_BLD_push_octet_string(builder.get(),OSSL_PKEY_PARAM_PUB_KEY,pub.data(),pub.size())==1);
  Number scalar(nullptr,BN_clear_free);
  if (!priv.empty()) {
    require(priv.size()<=25 && (static_cast<unsigned char>(priv.front()) & 0x80)==0,StsError::Input);
    scalar.reset(BN_secure_new());require(bool(scalar));
    require(BN_bin2bn(reinterpret_cast<const unsigned char*>(priv.data()),static_cast<int>(priv.size()),scalar.get())==scalar.get());
    require(!BN_is_zero(scalar.get()),StsError::Input);
    require(OSSL_PARAM_BLD_push_BN(builder.get(),OSSL_PKEY_PARAM_PRIV_KEY,scalar.get())==1);
  }
  Params params(OSSL_PARAM_BLD_to_param(builder.get()));
  Context context(EVP_PKEY_CTX_new_from_name(nullptr,"EC",nullptr),EVP_PKEY_CTX_free);
  require(params && context && EVP_PKEY_fromdata_init(context.get())==1);
  EVP_PKEY* raw=nullptr;
  const auto imported=EVP_PKEY_fromdata(context.get(),&raw,priv.empty()?EVP_PKEY_PUBLIC_KEY:EVP_PKEY_KEYPAIR,params.get());
  Key key(raw,EVP_PKEY_free);require(imported==1 && key,StsError::Input);
  Context check(EVP_PKEY_CTX_new_from_pkey(nullptr,key.get(),nullptr),EVP_PKEY_CTX_free);require(bool(check));
  require(EVP_PKEY_public_check(check.get())==1,StsError::Input);
  if (!priv.empty()) { require(EVP_PKEY_private_check(check.get())==1 && EVP_PKEY_pairwise_check(check.get())==1,StsError::Input); }
  require(EVP_PKEY_set_utf8_string_param(key.get(),OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT,
      compressed(pub)?"compressed":"uncompressed")==1);
  return key;
}
std::string publicBytes(EVP_PKEY* key) {
  std::size_t size=0;require(EVP_PKEY_get_octet_string_param(key,OSSL_PKEY_PARAM_PUB_KEY,nullptr,0,&size)==1);
  require(size==25 || size==49);
  std::string result(size,'\0');
  require(EVP_PKEY_get_octet_string_param(key,OSSL_PKEY_PARAM_PUB_KEY,reinterpret_cast<unsigned char*>(result.data()),result.size(),&size)==1);
  result.resize(size);return result;
}
Key ephemeral() {
  Context context(EVP_PKEY_CTX_new_from_name(nullptr,"EC",nullptr),EVP_PKEY_CTX_free);
  require(context && EVP_PKEY_keygen_init(context.get())==1 && EVP_PKEY_CTX_set_group_name(context.get(),"prime192v2")==1);
  EVP_PKEY* raw=nullptr;const auto generated=EVP_PKEY_generate(context.get(),&raw);
  Key key(raw,EVP_PKEY_free);require(generated==1 && key);
  require(EVP_PKEY_set_utf8_string_param(key.get(),OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT,"compressed")==1);
  return key;
}
std::string sign(EVP_PKEY* key,std::string_view first,std::span<const std::uint8_t> second) {
  Digest digest(EVP_MD_CTX_new(),EVP_MD_CTX_free);require(bool(digest));
  require(EVP_DigestSignInit_ex(digest.get(),nullptr,"SHA1",nullptr,nullptr,key,nullptr)==1);
  require(EVP_DigestSignUpdate(digest.get(),first.data(),first.size())==1 && EVP_DigestSignUpdate(digest.get(),second.data(),second.size())==1);
  std::size_t size=0;require(EVP_DigestSignFinal(digest.get(),nullptr,&size)==1 && size<=128);
  std::string result(size,'\0');require(EVP_DigestSignFinal(digest.get(),reinterpret_cast<unsigned char*>(result.data()),&size)==1);
  result.resize(size);return result;
}
bool verify(EVP_PKEY* key,std::string_view first,std::span<const std::uint8_t> second,std::string_view signature) {
  if (signature.empty() || signature.size()>128) { return false; }
  Digest digest(EVP_MD_CTX_new(),EVP_MD_CTX_free);require(bool(digest));
  require(EVP_DigestVerifyInit_ex(digest.get(),nullptr,"SHA1",nullptr,nullptr,key,nullptr)==1);
  require(EVP_DigestVerifyUpdate(digest.get(),first.data(),first.size())==1 && EVP_DigestVerifyUpdate(digest.get(),second.data(),second.size())==1);
  return EVP_DigestVerifyFinal(digest.get(),reinterpret_cast<const unsigned char*>(signature.data()),signature.size())==1;
}
std::span<const std::uint8_t> bytes(std::string_view value) { return {reinterpret_cast<const std::uint8_t*>(value.data()),value.size()}; }
class Reader {
public:
  explicit Reader(std::string_view input):input_(input) { require(input.size()<=maximumStsPacket,StsError::Limit); }
  std::size_t position() const { return position_; }
  void version() {
    require(position_<input_.size(),StsError::Input);
    require(static_cast<unsigned char>(input_[position_++])==1,StsError::Version);
  }
  std::string_view blob() {
    require(input_.size()-position_>=2,StsError::Input);
    const auto length=(static_cast<unsigned char>(input_[position_])<<8) | static_cast<unsigned char>(input_[position_+1]);
    position_+=2;require(input_.size()-position_>=static_cast<std::size_t>(length),StsError::Input);
    const auto result=input_.substr(position_,length);position_+=length;return result;
  }
private:std::string_view input_;std::size_t position_=0;
};
void append(std::string& output,std::string_view value) {
  require(value.size()<=65535,StsError::Limit);
  output.push_back(static_cast<char>(value.size()>>8));output.push_back(static_cast<char>(value.size() & 255));output+=value;
}
std::string nonce(std::size_t base) {
  unsigned char size=0;require(RAND_priv_bytes(&size,1)==1);
  std::string result(base+(size & 31),'\0');
  if (!result.empty()) { require(RAND_priv_bytes(reinterpret_cast<unsigned char*>(result.data()),static_cast<int>(result.size()))==1); }
  return result;
}
}
struct LegacySts::Impl {
  Key identity{nullptr,EVP_PKEY_free},ephemeralKey{nullptr,EVP_PKEY_free},remote{nullptr,EVP_PKEY_free};
  std::string identityPublic,ephemeralPublic,remotePublic;
  StsSecret secret;
  bool authenticated=false;
};
LegacySts::LegacySts(std::unique_ptr<Impl> value):impl_(std::move(value)) {}
LegacySts::~LegacySts()=default;
LegacySts::LegacySts(LegacySts&&) noexcept=default;
LegacySts& LegacySts::operator=(LegacySts&&) noexcept=default;
std::expected<LegacySts,StsFailure> LegacySts::create(std::string_view pub,std::string_view priv) {
  try {
    require(!priv.empty(),StsError::Input);
    auto value=std::make_unique<Impl>();value->identity=importKey(pub,priv);value->identityPublic=publicBytes(value->identity.get());
    LegacySts result(std::move(value));auto reset=result.reset();if (!reset) { return std::unexpected(reset.error()); }return result;
  } catch (const Failure& error) { return std::unexpected(StsFailure{error.code}); }
}
std::expected<void,StsFailure> LegacySts::reset() {
  if (!impl_) { return std::unexpected(StsFailure{StsError::Phase}); }
  try {
    auto key=ephemeral();auto pub=publicBytes(key.get());
    impl_->ephemeralKey=std::move(key);impl_->ephemeralPublic=std::move(pub);impl_->remote.reset();impl_->remotePublic.clear();
    impl_->secret=StsSecret{};impl_->authenticated=false;return {};
  } catch (const Failure& error) { return std::unexpected(StsFailure{error.code}); }
}
std::expected<std::string,StsFailure> LegacySts::keysPacket() const {
  if (!impl_) { return std::unexpected(StsFailure{StsError::Phase}); }
  try {
    const auto signature=sign(impl_->identity.get(),impl_->identityPublic,bytes(impl_->ephemeralPublic));
    std::string result(1,'\1');append(result,impl_->identityPublic);append(result,impl_->ephemeralPublic);append(result,signature);append(result,nonce(0));return result;
  } catch (const Failure& error) { return std::unexpected(StsFailure{error.code}); }
}
std::expected<std::string,StsFailure> LegacySts::authPacket() const {
  if (!impl_ || impl_->secret.view().empty()) { return std::unexpected(StsFailure{StsError::Phase}); }
  try {
    const auto iv=nonce(20),signature=sign(impl_->identity.get(),iv,impl_->secret.view());
    std::string result(1,'\1');append(result,iv);append(result,signature);return result;
  } catch (const Failure& error) { return std::unexpected(StsFailure{error.code}); }
}
std::expected<std::size_t,StsFailure> LegacySts::receiveKeys(std::string_view packet) {
  if (!impl_) { return std::unexpected(StsFailure{StsError::Phase}); }
  std::size_t position=0;
  try {
    Reader reader(packet);
    try {
      impl_->authenticated=false;reader.version();require(impl_->secret.view().empty(),StsError::Phase);
      const auto pub=reader.blob(),other=reader.blob(),signature=reader.blob();reader.blob();
      auto identity=importKey(pub);const auto canonical=publicBytes(identity.get());
      impl_->remote=std::move(identity);impl_->remotePublic=canonical;
      require(verify(impl_->remote.get(),pub,bytes(other),signature),StsError::Signature);
      const auto peer=importKey(other);
      Context context(EVP_PKEY_CTX_new_from_pkey(nullptr,impl_->ephemeralKey.get(),nullptr),EVP_PKEY_CTX_free);
      require(context && EVP_PKEY_derive_init(context.get())==1 && EVP_PKEY_derive_set_peer(context.get(),peer.get())==1);
      DerivationBuffer unsignedSecret;std::size_t size=unsignedSecret.bytes.size();
      require(EVP_PKEY_derive(context.get(),unsignedSecret.bytes.data(),&size)==1 && size==unsignedSecret.bytes.size());
      auto secret=StsSecret::fromUnsigned(unsignedSecret.bytes);require(bool(secret));impl_->secret=std::move(*secret);
      return reader.position();
    } catch (const Failure&) { position=reader.position();throw; }
  } catch (const Failure& error) { return std::unexpected(StsFailure{error.code,position}); }
}
std::expected<std::size_t,StsFailure> LegacySts::receiveAuth(std::string_view packet) {
  if (!impl_) { return std::unexpected(StsFailure{StsError::Phase}); }
  std::size_t position=0;
  try {
    Reader reader(packet);
    try {
      impl_->authenticated=false;reader.version();require(!impl_->secret.view().empty(),StsError::Phase);
      const auto iv=reader.blob(),signature=reader.blob();
      require(verify(impl_->remote.get(),iv,impl_->secret.view(),signature),StsError::Signature);
      impl_->authenticated=true;return reader.position();
    } catch (const Failure&) { position=reader.position();throw; }
  } catch (const Failure& error) { return std::unexpected(StsFailure{error.code,position}); }
}
StsState LegacySts::state() const {
  if (!impl_) { return {}; }
  return {impl_->remote?std::optional<std::string>{impl_->remotePublic}:std::nullopt,!impl_->secret.view().empty(),impl_->authenticated};
}
std::expected<StsSecret,StsFailure> LegacySts::authenticatedSecret(std::string_view expectedPeer) const {
  if (!impl_ || !impl_->authenticated || impl_->secret.view().empty()) { return std::unexpected(StsFailure{StsError::NotAuthenticated}); }
  if (expectedPeer.size()!=impl_->remotePublic.size() || CRYPTO_memcmp(expectedPeer.data(),impl_->remotePublic.data(),expectedPeer.size())!=0) {
    return std::unexpected(StsFailure{StsError::PeerMismatch});
  }
  StsSecret result;result.bytes_=impl_->secret.bytes_;result.length_=impl_->secret.length_;return result;
}
}
