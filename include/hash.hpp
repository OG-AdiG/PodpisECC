#pragma once

#include <string>
#include <vector>

namespace ecc {

// Oblicza SHA-256 dla pliku (strumieniowo — bez limitu rozmiaru).
[[nodiscard]] std::vector<unsigned char> sha256_file(const std::string& path);

}  // namespace ecc
