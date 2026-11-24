// Fuzz the sim server's client-authorization token check
// (core_sim/src/client_authorization.cpp + client_authorization_linux.cpp).
//
// Every client that connects to the sim calls the "SetAuthorizationToken" service method
// with a base-64 token that it RSA-OAEP-encrypted under the server's transport key. The
// server base-64 decodes it, RSA-decrypts it, base-64 decodes the plaintext again, parses
// the binary TokenV1 (version, big-endian expiry) and checks its ECDSA/SHA-512 signature
// against the configured public key. The harness enters through that same registered
// service-method handler (ClientAuthorization::RegisterServiceMethods), not an internal
// helper.
//
// Input byte 0 selects the layer the fuzz bytes stand in for:
//   0: the rest is the raw token string a client sends (outer base-64 + RSA decrypt).
//   1: the rest is the token plaintext; the harness RSA-OAEP-encrypts it under the
//      server's transport public key and base-64 encodes it, exactly as a real client
//      does (client/python/projectairsim/src/projectairsim/client.py), so the fuzzer can
//      reach the inner base-64 decode, the TokenV1 parser and the signature check. The
//      plaintext bytes themselves are not altered.
//
// State kept across inputs, on purpose:
//   - one ClientAuthorization object, because its RSA-2048 transport key is generated
//     (randomly) by GetAuthorizationTokenPublicKey and generating one per input would take
//     ~100 ms. The key is read-only afterwards. The decrypted plaintext, and so every
//     result, does not depend on which key was generated.
//   - everything an input can change (the ECDSA public key bytes and the authorization
//     expiry) is reset before each input by SetPublicKey() with the fixed test key below.
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <stdint.h>
#include <string.h>

#include <exception>
#include <string>
#include <vector>

#include "core_sim/client_authorization.hpp"
#include "core_sim/service_method.hpp"

namespace pas = microsoft::projectairsim;

namespace {

// Fixed ECDSA P-256 test public key (DER SubjectPublicKeyInfo, base-64), the format
// the sim's "client-authorization-public-key" setting takes. Its private key signed the
// seeds in mayhem/client-auth/testsuite.
const char kPublicKey[] =
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEI2mjXgY8PRRHp9+KrXXGNPCA1izvlMcBwXxxgsyt3aFCIFEL"
    "YuZkv3/b4DEeahf4+zUqKv7pAp5aDQrtETulhA==";

pas::ClientAuthorization* g_auth = nullptr;
pas::MethodHandler g_get_key;
pas::MethodHandler g_set_token;
RSA* g_rsa_pub = nullptr;

uint32_t ReadBE32(const std::vector<uint8_t>& v, size_t off) {
  return (uint32_t(v[off]) << 24) | (uint32_t(v[off + 1]) << 16) |
         (uint32_t(v[off + 2]) << 8) | uint32_t(v[off + 3]);
}

// Parse the "ssh-rsa <base64>" public key the server hands to clients.
RSA* ParseSshRsa(const std::string& key) {
  const std::string prefix = "ssh-rsa ";
  if (key.compare(0, prefix.size(), prefix) != 0) return nullptr;
  std::string b64 = key.substr(prefix.size());
  std::vector<uint8_t> blob(b64.size());
  int n = EVP_DecodeBlock(blob.data(), reinterpret_cast<const uint8_t*>(b64.data()),
                          b64.size());
  if (n <= 0) return nullptr;
  blob.resize(n);
  std::vector<std::vector<uint8_t>> fields;
  size_t off = 0;
  while (fields.size() < 3 && off + 4 <= blob.size()) {
    uint32_t len = ReadBE32(blob, off);
    off += 4;
    if (off + len > blob.size()) return nullptr;
    fields.emplace_back(blob.begin() + off, blob.begin() + off + len);
    off += len;
  }
  if (fields.size() != 3) return nullptr;
  BIGNUM* e = BN_bin2bn(fields[1].data(), fields[1].size(), nullptr);
  BIGNUM* m = BN_bin2bn(fields[2].data(), fields[2].size(), nullptr);
  RSA* rsa = RSA_new();
  RSA_set0_key(rsa, m, e, nullptr);
  return rsa;
}

}  // namespace

extern "C" int LLVMFuzzerInitialize(int*, char***) {
  g_auth = new pas::ClientAuthorization();
  g_auth->RegisterServiceMethods(
      "/Sim", [](const pas::ServiceMethod& method, pas::MethodHandler handler) {
        if (method.GetName() == "GetAuthorizationTokenPublicKey") g_get_key = handler;
        if (method.GetName() == "SetAuthorizationToken") g_set_token = handler;
      });
  if (!g_get_key || !g_set_token) abort();
  // The sim generates the token-transport key pair when a client asks for it.
  std::string key = g_get_key(pas::MethodParameters{}).get<std::string>();
  g_rsa_pub = ParseSshRsa(key);
  if (g_rsa_pub == nullptr) abort();
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 1) return -1;
  const uint8_t mode = data[0];
  data++;
  size--;

  std::string token;
  if (mode == 0) {
    // ImplLinux::Base64Decode asserts its input is at most 1024 chars (BIO_f_base64 reads
    // one line of up to 1024 bytes); that is the documented precondition of the decoder.
    if (size > 1024) return -1;
    token.assign(reinterpret_cast<const char*>(data), size);
  } else if (mode == 1) {
    // RSA-OAEP (SHA-1) under a 2048-bit key carries at most 256 - 2*20 - 2 = 214 bytes.
    if (size > 214) return -1;
    std::vector<uint8_t> enc(RSA_size(g_rsa_pub));
    int cb = RSA_public_encrypt(size, data, enc.data(), g_rsa_pub, RSA_PKCS1_OAEP_PADDING);
    if (cb <= 0) abort();
    std::vector<uint8_t> b64(4 * ((cb + 2) / 3) + 1);
    int n = EVP_EncodeBlock(b64.data(), enc.data(), cb);
    token.assign(reinterpret_cast<const char*>(b64.data()), n);
  } else {
    return -1;
  }

  // Reset all per-input state: public key bytes + "not authorized" expiry.
  g_auth->SetPublicKey(kPublicKey, sizeof(kPublicKey) - 1);
  try {
    (void)g_set_token(pas::MethodParameters{pas::json(token)});
  } catch (const std::exception&) {
    // A rejected token is reported to the client as an exception from the handler.
  }
  (void)g_auth->IsAuthorized();
  return 0;
}
