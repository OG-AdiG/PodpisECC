#pragma once

#include <string>

namespace ecc {

// Podpisuje dokument: SHA-256 + ECDSA (secp256r1).
// Podpis zapisywany w kodowaniu DER (wartości r, s).
void sign_document(const std::string& document_path,
                   const std::string& private_key_path,
                   const std::string& signature_path);

// Weryfikuje podpis ECDSA względem klucza publicznego.
// Zwraca true, gdy podpis jest prawidłowy.
[[nodiscard]] bool verify_document(const std::string& document_path,
                                   const std::string& public_key_path,
                                   const std::string& signature_path);

}  // namespace ecc
