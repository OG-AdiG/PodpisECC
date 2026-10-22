#pragma once

#include <string>

namespace ecc {

struct KeyPairPem {
    std::string private_pem;
    std::string public_pem;
    bool encrypted = false;
};

// Generuje parę ECDSA na krzywej secp256r1 (NIST P-256).
// Jeśli passphrase niepusty — klucz prywatny szyfrowany AES-256-CBC w PEM.
[[nodiscard]] KeyPairPem generate_key_pair_pem(const std::string& passphrase = {});

void generate_key_pair(const std::string& private_key_path,
                       const std::string& public_key_path,
                       const std::string& passphrase = {});

}  // namespace ecc
