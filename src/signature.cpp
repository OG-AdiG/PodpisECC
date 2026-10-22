#include "signature.hpp"
#include "hash.hpp"
#include "utils.hpp"

#include <openssl/evp.h>
#include <openssl/pem.h>

#include <cstdio>
#include <memory>
#include <vector>

namespace ecc {
namespace {

struct FileCloser {
    void operator()(FILE* f) const {
        if (f) {
            std::fclose(f);
        }
    }
};

struct EvpPkeyDeleter {
    void operator()(EVP_PKEY* p) const {
        EVP_PKEY_free(p);
    }
};

std::unique_ptr<EVP_PKEY, EvpPkeyDeleter> load_private_key(const std::string& path) {
    std::unique_ptr<FILE, FileCloser> in(std::fopen(path.c_str(), "rb"));
    if (!in) {
        fail("Nie można otworzyć klucza prywatnego: " + path);
    }
    EVP_PKEY* raw = PEM_read_PrivateKey(in.get(), nullptr, nullptr, nullptr);
    if (!raw) {
        openssl_fail("Nieprawidłowy format klucza prywatnego PEM");
    }
    return std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>(raw);
}

std::unique_ptr<EVP_PKEY, EvpPkeyDeleter> load_public_key(const std::string& path) {
    std::unique_ptr<FILE, FileCloser> in(std::fopen(path.c_str(), "rb"));
    if (!in) {
        fail("Nie można otworzyć klucza publicznego: " + path);
    }
    EVP_PKEY* raw = PEM_read_PUBKEY(in.get(), nullptr, nullptr, nullptr);
    if (!raw) {
        openssl_fail("Nieprawidłowy format klucza publicznego PEM");
    }
    return std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>(raw);
}

}  // namespace

void sign_document(const std::string& document_path,
                   const std::string& private_key_path,
                   const std::string& signature_path) {
    auto digest = sha256_file(document_path);
    auto pkey = load_private_key(private_key_path);

    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> pctx(
        EVP_PKEY_CTX_new(pkey.get(), nullptr), &EVP_PKEY_CTX_free);
    if (!pctx) {
        openssl_fail("Nie udało się utworzyć kontekstu EVP_PKEY_sign");
    }
    if (EVP_PKEY_sign_init(pctx.get()) <= 0) {
        openssl_fail("EVP_PKEY_sign_init nie powiodło się");
    }
    if (EVP_PKEY_CTX_set_signature_md(pctx.get(), EVP_sha256()) <= 0) {
        openssl_fail("Ustawienie SHA-256 dla podpisu nie powiodło się");
    }

    size_t sig_len = 0;
    if (EVP_PKEY_sign(pctx.get(), nullptr, &sig_len, digest.data(), digest.size()) <= 0) {
        openssl_fail("Nie udało się ustalić długości podpisu");
    }

    std::vector<unsigned char> signature(sig_len);
    if (EVP_PKEY_sign(pctx.get(), signature.data(), &sig_len, digest.data(), digest.size()) <= 0) {
        openssl_fail("Podpisywanie ECDSA nie powiodło się");
    }
    signature.resize(sig_len);

    write_file_bytes(signature_path, signature);
}

bool verify_document(const std::string& document_path,
                     const std::string& public_key_path,
                     const std::string& signature_path) {
    auto digest = sha256_file(document_path);
    auto pkey = load_public_key(public_key_path);
    auto signature = read_file_bytes(signature_path);

    if (signature.empty()) {
        fail("Plik podpisu jest pusty: " + signature_path);
    }

    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> pctx(
        EVP_PKEY_CTX_new(pkey.get(), nullptr), &EVP_PKEY_CTX_free);
    if (!pctx) {
        openssl_fail("Nie udało się utworzyć kontekstu weryfikacji");
    }
    if (EVP_PKEY_verify_init(pctx.get()) <= 0) {
        openssl_fail("EVP_PKEY_verify_init nie powiodło się");
    }
    if (EVP_PKEY_CTX_set_signature_md(pctx.get(), EVP_sha256()) <= 0) {
        openssl_fail("Ustawienie SHA-256 dla weryfikacji nie powiodło się");
    }

    const int rc = EVP_PKEY_verify(
        pctx.get(),
        signature.data(),
        signature.size(),
        digest.data(),
        digest.size());

    if (rc == 1) {
        return true;
    }
    if (rc == 0) {
        return false;  // podpis niepasujący — to wynik, nie wyjątek
    }
    openssl_fail("Błąd podczas weryfikacji podpisu");
    return false;
}

}  // namespace ecc
