#pragma once

#include <string>
#include <utility>

namespace ecc {

struct KeyPairPem {
    std::string private_pem;
    std::string public_pem;
};

// Generuje parę ECDSA na krzywej secp256r1 (NIST P-256).
[[nodiscard]] KeyPairPem generate_key_pair_pem();

// Generuje parę i zapisuje klucze w formacie PEM do plików.
void generate_key_pair(const std::string& private_key_path,
                       const std::string& public_key_path);

}  // namespace ecc
