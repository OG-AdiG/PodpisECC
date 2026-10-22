#pragma once

#include <cstddef>
#include <string>
#include <vector>

namespace ecc {

inline constexpr std::size_t kMaxUploadBytes = 32 * 1024 * 1024;      // 32 MiB
inline constexpr std::size_t kMaxKeyUploadBytes = 64 * 1024;           // 64 KiB
inline constexpr std::size_t kMaxSignatureUploadBytes = 16 * 1024;     // 16 KiB

[[nodiscard]] std::string read_file_bytes_as_string(const std::string& path);
[[nodiscard]] std::vector<unsigned char> read_file_bytes(const std::string& path);
void write_file_bytes(const std::string& path, const std::vector<unsigned char>& data);
void write_text_file(const std::string& path, const std::string& text);

[[nodiscard]] std::string to_hex(const std::vector<unsigned char>& data);
[[nodiscard]] std::string trim(const std::string& s);
[[nodiscard]] bool file_exists(const std::string& path);
[[nodiscard]] std::string to_lower(std::string s);

void validate_upload_size(std::size_t size, std::size_t max_bytes, const std::string& label);
void validate_key_filename(const std::string& filename);
void validate_signature_filename(const std::string& filename);

[[noreturn]] void fail(const std::string& message);
void openssl_fail(const std::string& context);

}  // namespace ecc
