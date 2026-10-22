#include "benchmark.hpp"
#include "utils.hpp"

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

#include <chrono>
#include <cmath>
#include <memory>
#include <sstream>
#include <vector>

namespace ecc {
namespace {

struct EvpPkeyDeleter {
    void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); }
};
struct EvpPkeyCtxDeleter {
    void operator()(EVP_PKEY_CTX* c) const { EVP_PKEY_CTX_free(c); }
};

using Clock = std::chrono::steady_clock;

double ms_between(Clock::time_point a, Clock::time_point b) {
    return std::chrono::duration<double, std::milli>(b - a).count();
}

std::unique_ptr<EVP_PKEY, EvpPkeyDeleter> gen_ec() {
    std::unique_ptr<EVP_PKEY_CTX, EvpPkeyCtxDeleter> ctx(
        EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr));
    if (!ctx || EVP_PKEY_keygen_init(ctx.get()) <= 0) {
        openssl_fail("Benchmark: init EC");
    }
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx.get(), NID_X9_62_prime256v1) <= 0) {
        openssl_fail("Benchmark: krzywa P-256");
    }
    EVP_PKEY* raw = nullptr;
    if (EVP_PKEY_keygen(ctx.get(), &raw) <= 0) {
        openssl_fail("Benchmark: keygen EC");
    }
    return std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>(raw);
}

std::unique_ptr<EVP_PKEY, EvpPkeyDeleter> gen_rsa3072() {
    std::unique_ptr<EVP_PKEY_CTX, EvpPkeyCtxDeleter> ctx(
        EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr));
    if (!ctx || EVP_PKEY_keygen_init(ctx.get()) <= 0) {
        openssl_fail("Benchmark: init RSA");
    }
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), 3072) <= 0) {
        openssl_fail("Benchmark: RSA-3072 bits");
    }
    EVP_PKEY* raw = nullptr;
    if (EVP_PKEY_keygen(ctx.get(), &raw) <= 0) {
        openssl_fail("Benchmark: keygen RSA");
    }
    return std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>(raw);
}

std::vector<unsigned char> sign_digest(EVP_PKEY* pkey, const std::vector<unsigned char>& digest) {
    std::unique_ptr<EVP_PKEY_CTX, EvpPkeyCtxDeleter> pctx(
        EVP_PKEY_CTX_new(pkey, nullptr));
    if (!pctx || EVP_PKEY_sign_init(pctx.get()) <= 0 ||
        EVP_PKEY_CTX_set_signature_md(pctx.get(), EVP_sha256()) <= 0) {
        openssl_fail("Benchmark: sign init");
    }
    size_t len = 0;
    if (EVP_PKEY_sign(pctx.get(), nullptr, &len, digest.data(), digest.size()) <= 0) {
        openssl_fail("Benchmark: sign size");
    }
    std::vector<unsigned char> sig(len);
    if (EVP_PKEY_sign(pctx.get(), sig.data(), &len, digest.data(), digest.size()) <= 0) {
        openssl_fail("Benchmark: sign");
    }
    sig.resize(len);
    return sig;
}

bool verify_digest(EVP_PKEY* pkey,
                   const std::vector<unsigned char>& digest,
                   const std::vector<unsigned char>& sig) {
    std::unique_ptr<EVP_PKEY_CTX, EvpPkeyCtxDeleter> pctx(
        EVP_PKEY_CTX_new(pkey, nullptr));
    if (!pctx || EVP_PKEY_verify_init(pctx.get()) <= 0 ||
        EVP_PKEY_CTX_set_signature_md(pctx.get(), EVP_sha256()) <= 0) {
        openssl_fail("Benchmark: verify init");
    }
    return EVP_PKEY_verify(pctx.get(), sig.data(), sig.size(), digest.data(), digest.size()) == 1;
}

}  // namespace

BenchmarkResult run_ecc_vs_rsa_benchmark(int rounds) {
    if (rounds < 1) {
        rounds = 1;
    }
    if (rounds > 20) {
        rounds = 20;
    }

    // Stały skrót testowy (SHA-256("PodpisECC-benchmark"))
    const std::vector<unsigned char> digest = {
        0xb3, 0x6a, 0x1c, 0x8f, 0x4d, 0x2e, 0x91, 0x70,
        0xaa, 0x55, 0x12, 0xcc, 0x88, 0x33, 0xfe, 0x01,
        0x44, 0x67, 0x29, 0xab, 0xcd, 0xef, 0x10, 0x32,
        0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0x09, 0x87};

    BenchmarkResult out;
    out.rounds = rounds;

    double ecc_kg = 0, ecc_sg = 0, ecc_vf = 0;
    double rsa_kg = 0, rsa_sg = 0, rsa_vf = 0;

    for (int i = 0; i < rounds; ++i) {
        auto t0 = Clock::now();
        auto ec = gen_ec();
        auto t1 = Clock::now();
        auto sig_ec = sign_digest(ec.get(), digest);
        auto t2 = Clock::now();
        if (!verify_digest(ec.get(), digest, sig_ec)) {
            fail("Benchmark: weryfikacja ECC nie powiodła się");
        }
        auto t3 = Clock::now();

        ecc_kg += ms_between(t0, t1);
        ecc_sg += ms_between(t1, t2);
        ecc_vf += ms_between(t2, t3);
        out.ecc_signature_bytes = static_cast<int>(sig_ec.size());

        auto r0 = Clock::now();
        auto rsa = gen_rsa3072();
        auto r1 = Clock::now();
        auto sig_rsa = sign_digest(rsa.get(), digest);
        auto r2 = Clock::now();
        if (!verify_digest(rsa.get(), digest, sig_rsa)) {
            fail("Benchmark: weryfikacja RSA nie powiodła się");
        }
        auto r3 = Clock::now();

        rsa_kg += ms_between(r0, r1);
        rsa_sg += ms_between(r1, r2);
        rsa_vf += ms_between(r2, r3);
        out.rsa_signature_bytes = static_cast<int>(sig_rsa.size());
    }

    const double n = static_cast<double>(rounds);
    out.ecc_keygen_ms = ecc_kg / n;
    out.ecc_sign_ms = ecc_sg / n;
    out.ecc_verify_ms = ecc_vf / n;
    out.rsa_keygen_ms = rsa_kg / n;
    out.rsa_sign_ms = rsa_sg / n;
    out.rsa_verify_ms = rsa_vf / n;
    return out;
}

std::string benchmark_to_json(const BenchmarkResult& r) {
    auto f = [](double v) {
        std::ostringstream oss;
        oss.setf(std::ios::fixed);
        oss.precision(3);
        oss << v;
        return oss.str();
    };
    std::ostringstream oss;
    oss << "{"
        << "\"rounds\":" << r.rounds << ","
        << "\"ecc\":{"
        << "\"keygen_ms\":" << f(r.ecc_keygen_ms) << ","
        << "\"sign_ms\":" << f(r.ecc_sign_ms) << ","
        << "\"verify_ms\":" << f(r.ecc_verify_ms) << ","
        << "\"signature_bytes\":" << r.ecc_signature_bytes
        << "},"
        << "\"rsa3072\":{"
        << "\"keygen_ms\":" << f(r.rsa_keygen_ms) << ","
        << "\"sign_ms\":" << f(r.rsa_sign_ms) << ","
        << "\"verify_ms\":" << f(r.rsa_verify_ms) << ","
        << "\"signature_bytes\":" << r.rsa_signature_bytes
        << "}"
        << "}";
    return oss.str();
}

}  // namespace ecc
