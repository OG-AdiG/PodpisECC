#pragma once

#include <cstddef>
#include <string>

namespace ecc {

struct SignResult {
    std::string sha256_hex;
    double hash_ms = 0;
    double sign_ms = 0;
    std::size_t signature_bytes = 0;
};

struct VerifyResult {
    bool valid = false;
    std::string sha256_hex;
    double hash_ms = 0;
    double verify_ms = 0;
};

// Podpisuje dokument: SHA-256 + ECDSA. passphrase dla zaszyfrowanego PEM.
[[nodiscard]] SignResult sign_document(const std::string& document_path,
                                       const std::string& private_key_path,
                                       const std::string& signature_path,
                                       const std::string& passphrase = {});

[[nodiscard]] VerifyResult verify_document(const std::string& document_path,
                                           const std::string& public_key_path,
                                           const std::string& signature_path);

}  // namespace ecc
