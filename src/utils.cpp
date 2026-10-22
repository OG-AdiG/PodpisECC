#include "utils.hpp"

#include <openssl/err.h>

#include <algorithm>
#include <cctype>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace ecc {
namespace {

std::string translate_openssl_reason(const std::string& reason) {
    const std::string r = to_lower(reason);
    if (r.find("bad decrypt") != std::string::npos ||
        r.find("bad password") != std::string::npos ||
        r.find("wrong password") != std::string::npos) {
        return "nieprawidłowe hasło do klucza prywatnego";
    }
    if (r.find("no start line") != std::string::npos ||
        r.find("not enough data") != std::string::npos ||
        r.find("asn1") != std::string::npos) {
        return "nieprawidłowy lub uszkodzony format PEM/DER";
    }
    if (r.find("unsupported") != std::string::npos) {
        return "nieobsługiwany format lub algorytm";
    }
    if (r.find("malloc") != std::string::npos) {
        return "brak pamięci";
    }
    return reason;
}

}  // namespace

std::string read_file_bytes_as_string(const std::string& path) {
    const auto bytes = read_file_bytes(path);
    return std::string(bytes.begin(), bytes.end());
}

std::vector<unsigned char> read_file_bytes(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        fail("Nie można otworzyć pliku do odczytu: " + path);
    }
    return std::vector<unsigned char>(
        (std::istreambuf_iterator<char>(in)),
        std::istreambuf_iterator<char>());
}

void write_file_bytes(const std::string& path, const std::vector<unsigned char>& data) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) {
        fail("Nie można otworzyć pliku do zapisu: " + path);
    }
    out.write(reinterpret_cast<const char*>(data.data()),
              static_cast<std::streamsize>(data.size()));
    if (!out) {
        fail("Błąd zapisu pliku: " + path);
    }
}

void write_text_file(const std::string& path, const std::string& text) {
    std::ofstream out(path, std::ios::trunc);
    if (!out) {
        fail("Nie można otworzyć pliku do zapisu: " + path);
    }
    out << text;
    if (!out) {
        fail("Błąd zapisu pliku: " + path);
    }
}

std::string to_hex(const std::vector<unsigned char>& data) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (unsigned char b : data) {
        oss << std::setw(2) << static_cast<int>(b);
    }
    return oss.str();
}

std::string trim(const std::string& s) {
    const auto start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) {
        return {};
    }
    const auto end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

bool file_exists(const std::string& path) {
    std::ifstream in(path);
    return static_cast<bool>(in);
}

std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

void validate_upload_size(std::size_t size, std::size_t max_bytes, const std::string& label) {
    if (size == 0) {
        fail("Plik „" + label + "” jest pusty");
    }
    if (size > max_bytes) {
        fail("Plik „" + label + "” jest za duży (limit " +
             std::to_string(max_bytes / 1024) + " KiB)");
    }
}

void validate_key_filename(const std::string& filename) {
    const auto lower = to_lower(filename);
    if (lower.empty()) {
        return;
    }
    if (!(lower.size() >= 4 &&
          (lower.rfind(".pem") == lower.size() - 4 ||
           lower.rfind(".key") == lower.size() - 4 ||
           lower.rfind(".pub") == lower.size() - 4))) {
        fail("Oczekiwany plik klucza z rozszerzeniem .pem, .key lub .pub (otrzymano: " +
             filename + ")");
    }
}

void validate_signature_filename(const std::string& filename) {
    const auto lower = to_lower(filename);
    if (lower.empty()) {
        return;
    }
    if (!(lower.size() >= 4 &&
          (lower.rfind(".sig") == lower.size() - 4 ||
           lower.rfind(".bin") == lower.size() - 4 ||
           lower.rfind(".der") == lower.size() - 4))) {
        fail("Oczekiwany plik podpisu z rozszerzeniem .sig, .bin lub .der (otrzymano: " +
             filename + ")");
    }
}

void fail(const std::string& message) {
    throw std::runtime_error(message);
}

void openssl_fail(const std::string& context) {
    std::ostringstream details;
    bool any = false;
    while (true) {
        const unsigned long err = ERR_get_error();
        if (err == 0) {
            break;
        }
        char buf[256];
        ERR_error_string_n(err, buf, sizeof(buf));
        const std::string translated = translate_openssl_reason(buf);
        if (any) {
            details << "; ";
        }
        details << translated;
        any = true;
    }
    if (any) {
        fail(context + " — " + details.str());
    }
    fail(context);
}

}  // namespace ecc
