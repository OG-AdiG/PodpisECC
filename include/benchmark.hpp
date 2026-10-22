#pragma once

#include <string>

namespace ecc {

struct BenchmarkResult {
    double ecc_keygen_ms = 0;
    double ecc_sign_ms = 0;
    double ecc_verify_ms = 0;
    double rsa_keygen_ms = 0;
    double rsa_sign_ms = 0;
    double rsa_verify_ms = 0;
    int ecc_signature_bytes = 0;
    int rsa_signature_bytes = 0;
    int rounds = 0;
};

// Porównanie ECDSA P-256 vs RSA-3072 (SHA-256), kilka rund na uśrednienie.
[[nodiscard]] BenchmarkResult run_ecc_vs_rsa_benchmark(int rounds = 5);

[[nodiscard]] std::string benchmark_to_json(const BenchmarkResult& r);

}  // namespace ecc
