# BiglyBTC-plugin-azmsgsync

Bounded static key/envelope library at original azmsgsync baseline
`4209aa5029e3035cbb09dc3a83e9491d3f36fbc6`. This is not an operational message
sync plugin. No sockets, DHT, real identities, profile/config files or chat are
accessed. Protocol/identity/signature/STS verification and replay/order handling
remain required before plaintext is admitted as a message.

The native model preserves user-key folding with the original constant/SHA1,
16-byte general secret,20-byte listen/call key and peek-key bit change, plus
24-byte private shared-secret fixing (short values zero-padded, long values use
their trailing24 bytes). General envelopes use AES128-CBC and private envelopes
AES192-CBC, original PKCS padding and a16-byte IV prefix. OpenSSL3.5.5 supplies
the primitives and fresh cryptographic IVs for native encryption. These are
compatibility primitives for the original protocol, not a new message format.

The reference harness uses exact method bodies and the bounded original init
key block, supplied fields, original SHA1 and vendored BouncyCastle helpers.
The original SunJCE general path returns empty bytes for an IV-only envelope;
the private BouncyCastle path rejects it. Native preserves that distinction.
Malformed padding returns an explicit error and cleanses intermediate plaintext.
Input/output and user-key/shared-secret limits are4MiB and64KiB respectively.
The caller owns its input secrets, derived keys and returned plaintext.

Remaining work includes original persisted identities/history, signature/STS
integration, bencoded wire maps/compression, DHT/database transfer, privacy/network
separation, plugin lifecycle and UI. No publication or source/binary release is
enabled by this library. GPL-2.0-or-later; original Copyright2014 Azureus Software.
