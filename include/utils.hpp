#pragma once

#include <string>
#include <vector>

namespace ecc {

[[nodiscard]] std::string read_file_bytes_as_string(const std::string& path);
[[nodiscard]] std::vector<unsigned char> read_file_bytes(const std::string& path);
void write_file_bytes(const std::string& path, const std::vector<unsigned char>& data);
void write_text_file(const std::string& path, const std::string& text);

[[nodiscard]] std::string to_hex(const std::vector<unsigned char>& data);
[[nodiscard]] std::string trim(const std::string& s);
[[nodiscard]] bool file_exists(const std::string& path);

[[noreturn]] void fail(const std::string& message);
void openssl_fail(const std::string& context);

}  // namespace ecc
