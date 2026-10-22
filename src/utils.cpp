#include "utils.hpp"

#include <openssl/err.h>

#include <cstdio>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>

namespace ecc {

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

void fail(const std::string& message) {
    throw std::runtime_error(message);
}

void openssl_fail(const std::string& context) {
    char buf[256];
    const unsigned long err = ERR_get_error();
    if (err != 0) {
        ERR_error_string_n(err, buf, sizeof(buf));
        fail(context + " (" + buf + ")");
    }
    fail(context);
}

}  // namespace ecc
