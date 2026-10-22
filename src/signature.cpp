#include "signature.hpp"
#include "hash.hpp"
#include "utils.hpp"

#include <openssl/evp.h>
#include <openssl/pem.h>

#include <chrono>
#include <cstdio>
#include <cstring>
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
    void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); }
};

int pem_password_cb(char* buf, int size, int /*rwflag*/, void* userdata) {
    if (userdata == nullptr || size <= 0) {
        return 0;
    }
    const auto* pass = static_cast<const std::string*>(userdata);
    if (pass->empty()) {
        return 0;
    }
    const int n = static_cast<int>(std::min(pass->size(), static_cast<std::size_t>(size)));
    std::memcpy(buf, pass->data(), static_cast<std::size_t>(n));
    return n;
}

bool pem_looks_encrypted(const std::string& path) {
    const auto text = read_file_bytes_as_string(path);
    return text.find("ENCRYPTED") != std::string::npos ||
           text.find("Proc-Type: 4,ENCRYPTED") != std::string::npos;
}

bool pem_looks_public_only(const std::string& path) {
    const auto text = read_file_bytes_as_string(path);
    const bool has_pub = text.find("BEGIN PUBLIC KEY") != std::string::npos ||
                         text.find("BEGIN EC PUBLIC KEY") != std::string::npos;
    const bool has_priv = text.find("PRIVATE KEY") != std::string::npos;
    return has_pub && !has_priv;
}

bool pem_looks_private(const std::string& path) {
    const auto text = read_file_bytes_as_string(path);
    return text.find("PRIVATE KEY") != std::string::npos;
}

std::unique_ptr<EVP_PKEY, EvpPkeyDeleter> load_private_key(const std::string& path,
                                                          const std::string& passphrase) {
    std::unique_ptr<FILE, FileCloser> in(std::fopen(path.c_str(), "rb"));
    if (!in) {
        fail("Nie można otworzyć pliku klucza prywatnego");
    }

    if (pem_looks_public_only(path)) {
        fail("Wgrano klucz publiczny zamiast prywatnego — do podpisywania potrzebny jest klucz prywatny");
    }
    if (pem_looks_encrypted(path) && passphrase.empty()) {
        fail("Klucz prywatny jest zaszyfrowany — podaj hasło w polu formularza");
    }

    std::string pass = passphrase;
    EVP_PKEY* raw = nullptr;
    if (pass.empty()) {
        raw = PEM_read_PrivateKey(in.get(), nullptr, nullptr, nullptr);
    } else {
        raw = PEM_read_PrivateKey(in.get(), nullptr, pem_password_cb, &pass);
    }
    if (!raw) {
        if (pem_looks_encrypted(path)) {
            fail("Nieprawidłowe hasło do klucza prywatnego albo uszkodzony plik PEM");
        }
        openssl_fail("Nie udało się odczytać klucza prywatnego "
                     "(zły format PEM, uszkodzony plik lub to nie jest klucz prywatny ECDSA)");
    }
    return std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>(raw);
}

std::unique_ptr<EVP_PKEY, EvpPkeyDeleter> load_public_key(const std::string& path) {
    std::unique_ptr<FILE, FileCloser> in(std::fopen(path.c_str(), "rb"));
    if (!in) {
        fail("Nie można otworzyć pliku klucza publicznego");
    }
    if (pem_looks_private(path) && !pem_looks_public_only(path)) {
        fail("Wgrano klucz prywatny zamiast publicznego — do weryfikacji potrzebny jest klucz publiczny");
    }
    EVP_PKEY* raw = PEM_read_PUBKEY(in.get(), nullptr, nullptr, nullptr);
    if (!raw) {
        openssl_fail("Nieprawidłowy format klucza publicznego PEM "
                     "(oczekiwano BEGIN PUBLIC KEY)");
    }
    return std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>(raw);
}

double ms_since(std::chrono::steady_clock::time_point start) {
    using namespace std::chrono;
    return duration<double, std::milli>(steady_clock::now() - start).count();
}

}  // namespace

SignResult sign_document(const std::string& document_path,
                         const std::string& private_key_path,
                         const std::string& signature_path,
                         const std::string& passphrase) {
    SignResult result;

    auto t0 = std::chrono::steady_clock::now();
    auto digest = sha256_file(document_path);
    result.hash_ms = ms_since(t0);
    result.sha256_hex = to_hex(digest);

    auto pkey = load_private_key(private_key_path, passphrase);

    auto t1 = std::chrono::steady_clock::now();
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> pctx(
        EVP_PKEY_CTX_new(pkey.get(), nullptr), &EVP_PKEY_CTX_free);
    if (!pctx) {
        openssl_fail("Nie udało się utworzyć kontekstu podpisu");
    }
    if (EVP_PKEY_sign_init(pctx.get()) <= 0) {
        openssl_fail("Inicjalizacja podpisu ECDSA nie powiodła się");
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
    result.sign_ms = ms_since(t1);
    result.signature_bytes = signature.size();

    write_file_bytes(signature_path, signature);
    return result;
}

VerifyResult verify_document(const std::string& document_path,
                             const std::string& public_key_path,
                             const std::string& signature_path) {
    VerifyResult result;

    auto t0 = std::chrono::steady_clock::now();
    auto digest = sha256_file(document_path);
    result.hash_ms = ms_since(t0);
    result.sha256_hex = to_hex(digest);

    auto pkey = load_public_key(public_key_path);
    auto signature = read_file_bytes(signature_path);
    if (signature.empty()) {
        fail("Plik podpisu jest pusty");
    }

    auto t1 = std::chrono::steady_clock::now();
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> pctx(
        EVP_PKEY_CTX_new(pkey.get(), nullptr), &EVP_PKEY_CTX_free);
    if (!pctx) {
        openssl_fail("Nie udało się utworzyć kontekstu weryfikacji");
    }
    if (EVP_PKEY_verify_init(pctx.get()) <= 0) {
        openssl_fail("Inicjalizacja weryfikacji nie powiodła się");
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
    result.verify_ms = ms_since(t1);

    if (rc == 1) {
        result.valid = true;
        return result;
    }
    if (rc == 0) {
        result.valid = false;
        return result;
    }
    openssl_fail("Błąd podczas weryfikacji podpisu");
    return result;
}

}  // namespace ecc
