#include "keys.hpp"
#include "utils.hpp"

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include <memory>

namespace ecc {
namespace {

struct EvpPkeyDeleter {
    void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); }
};

struct EvpPkeyCtxDeleter {
    void operator()(EVP_PKEY_CTX* c) const { EVP_PKEY_CTX_free(c); }
};

struct BioDeleter {
    void operator()(BIO* b) const { BIO_free(b); }
};

std::unique_ptr<EVP_PKEY, EvpPkeyDeleter> create_ec_key() {
    std::unique_ptr<EVP_PKEY_CTX, EvpPkeyCtxDeleter> ctx(
        EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr));
    if (!ctx) {
        openssl_fail("Nie udało się utworzyć kontekstu generowania klucza EC");
    }
    if (EVP_PKEY_keygen_init(ctx.get()) <= 0) {
        openssl_fail("Nie udało się zainicjalizować generowania klucza");
    }
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx.get(), NID_X9_62_prime256v1) <= 0) {
        openssl_fail("Nie udało się ustawić krzywej secp256r1 (prime256v1)");
    }
    EVP_PKEY* raw = nullptr;
    if (EVP_PKEY_keygen(ctx.get(), &raw) <= 0) {
        openssl_fail("Generowanie pary kluczy ECDSA nie powiodło się");
    }
    return std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>(raw);
}

std::string bio_to_string(BIO* bio) {
    char* data = nullptr;
    const long len = BIO_get_mem_data(bio, &data);
    if (len <= 0 || data == nullptr) {
        fail("Nie udało się odczytać danych PEM z pamięci");
    }
    return std::string(data, static_cast<size_t>(len));
}

}  // namespace

KeyPairPem generate_key_pair_pem(const std::string& passphrase) {
    auto pkey = create_ec_key();

    std::unique_ptr<BIO, BioDeleter> priv_bio(BIO_new(BIO_s_mem()));
    std::unique_ptr<BIO, BioDeleter> pub_bio(BIO_new(BIO_s_mem()));
    if (!priv_bio || !pub_bio) {
        openssl_fail("Nie udało się utworzyć bufora BIO dla PEM");
    }

    const bool encrypt = !passphrase.empty();
    if (encrypt) {
        auto* pass_bytes = reinterpret_cast<unsigned char*>(const_cast<char*>(passphrase.data()));
        if (PEM_write_bio_PrivateKey(
                priv_bio.get(),
                pkey.get(),
                EVP_aes_256_cbc(),
                pass_bytes,
                static_cast<int>(passphrase.size()),
                nullptr,
                nullptr) != 1) {
            openssl_fail("Zapis zaszyfrowanego klucza prywatnego PEM nie powiódł się");
        }
    } else {
        if (PEM_write_bio_PrivateKey(priv_bio.get(), pkey.get(), nullptr, nullptr, 0, nullptr, nullptr) != 1) {
            openssl_fail("Zapis klucza prywatnego PEM do pamięci nie powiódł się");
        }
    }

    if (PEM_write_bio_PUBKEY(pub_bio.get(), pkey.get()) != 1) {
        openssl_fail("Zapis klucza publicznego PEM do pamięci nie powiódł się");
    }

    return KeyPairPem{bio_to_string(priv_bio.get()), bio_to_string(pub_bio.get()), encrypt};
}

void generate_key_pair(const std::string& private_key_path,
                       const std::string& public_key_path,
                       const std::string& passphrase) {
    const auto pair = generate_key_pair_pem(passphrase);
    write_text_file(private_key_path, pair.private_pem);
    write_text_file(public_key_path, pair.public_pem);
}

}  // namespace ecc
