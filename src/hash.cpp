#include "hash.hpp"
#include "utils.hpp"

#include <openssl/evp.h>

#include <fstream>
#include <memory>
#include <vector>

namespace ecc {
namespace {

struct EvpMdCtxDeleter {
    void operator()(EVP_MD_CTX* c) const {
        EVP_MD_CTX_free(c);
    }
};

}  // namespace

std::vector<unsigned char> sha256_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        fail("Nie można otworzyć dokumentu do skrótu: " + path);
    }

    std::unique_ptr<EVP_MD_CTX, EvpMdCtxDeleter> ctx(EVP_MD_CTX_new());
    if (!ctx) {
        openssl_fail("Nie udało się utworzyć kontekstu SHA-256");
    }

    if (EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1) {
        openssl_fail("Inicjalizacja SHA-256 nie powiodła się");
    }

    std::vector<char> buffer(8192);
    while (in) {
        in.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        const auto n = in.gcount();
        if (n > 0) {
            if (EVP_DigestUpdate(ctx.get(), buffer.data(), static_cast<size_t>(n)) != 1) {
                openssl_fail("Aktualizacja SHA-256 nie powiodła się");
            }
        }
    }
    if (in.bad()) {
        fail("Błąd odczytu dokumentu podczas liczenia skrótu: " + path);
    }

    std::vector<unsigned char> digest(EVP_MD_size(EVP_sha256()));
    unsigned int digest_len = 0;
    if (EVP_DigestFinal_ex(ctx.get(), digest.data(), &digest_len) != 1) {
        openssl_fail("Finalizacja SHA-256 nie powiodła się");
    }
    digest.resize(digest_len);
    return digest;
}

}  // namespace ecc
