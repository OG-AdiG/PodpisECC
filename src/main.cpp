#include "hash.hpp"
#include "keys.hpp"
#include "signature.hpp"
#include "utils.hpp"

// Świadomie bez CPPHTTPLIB_OPENSSL_SUPPORT — serwujemy lokalne HTTP (kryptografia ECC jest w libcrypto).
#include "httplib.h"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <random>
#include <sstream>
#include <string>

namespace fs = std::filesystem;

namespace {

fs::path find_web_root(const fs::path& exe_dir) {
    const fs::path candidates[] = {
        exe_dir / "web",
        fs::current_path() / "web",
        fs::current_path().parent_path() / "web",
        fs::current_path().parent_path().parent_path() / "web",
    };
    for (const auto& p : candidates) {
        if (fs::exists(p / "index.html")) {
            return fs::weakly_canonical(p);
        }
    }
    return {};
}

fs::path make_work_dir() {
    const auto base = fs::temp_directory_path() / "podpis_ecc";
    fs::create_directories(base);
    std::mt19937_64 rng{std::random_device{}()};
    const auto stamp = std::chrono::steady_clock::now().time_since_epoch().count();
    const auto dir = base / (std::to_string(stamp) + "_" + std::to_string(rng()));
    fs::create_directories(dir);
    return dir;
}

void save_upload(const httplib::MultipartFormData& part, const fs::path& path) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) {
        ecc::fail("Nie można zapisać przesłanego pliku");
    }
    out.write(part.content.data(), static_cast<std::streamsize>(part.content.size()));
    if (!out) {
        ecc::fail("Błąd zapisu przesłanego pliku");
    }
}

std::string json_escape(const std::string& s) {
    std::ostringstream oss;
    for (char c : s) {
        switch (c) {
            case '\\': oss << "\\\\"; break;
            case '"':  oss << "\\\""; break;
            case '\n': oss << "\\n"; break;
            case '\r': oss << "\\r"; break;
            case '\t': oss << "\\t"; break;
            default:   oss << c; break;
        }
    }
    return oss.str();
}

std::string json_error(const std::string& message) {
    return std::string("{\"error\":\"") + json_escape(message) + "\"}";
}

std::string json_ok_keys(const ecc::KeyPairPem& keys) {
    return std::string("{\"private_pem\":\"") + json_escape(keys.private_pem) +
           "\",\"public_pem\":\"" + json_escape(keys.public_pem) + "\"}";
}

}  // namespace

int main(int argc, char** argv) {
    const char* host = "127.0.0.1";
    int port = 8080;
    if (argc >= 2) {
        port = std::stoi(argv[1]);
    }

    const fs::path exe_dir = fs::absolute(fs::path(argv[0])).parent_path();
    const fs::path web_root = find_web_root(exe_dir);
    if (web_root.empty()) {
        std::cerr << "Nie znaleziono katalogu web/ (index.html).\n"
                     "Uruchom aplikację z katalogu projektu lub build/bin.\n";
        return 1;
    }

    httplib::Server svr;

    svr.Get("/", [web_root](const httplib::Request&, httplib::Response& res) {
        std::ifstream in(web_root / "index.html", std::ios::binary);
        if (!in) {
            res.status = 500;
            res.set_content(json_error("Brak pliku index.html"), "application/json");
            return;
        }
        std::ostringstream ss;
        ss << in.rdbuf();
        res.set_content(ss.str(), "text/html; charset=utf-8");
    });

    svr.set_mount_point("/static", (web_root / "static").string());

    svr.Post("/api/generate-keys", [](const httplib::Request&, httplib::Response& res) {
        try {
            const auto keys = ecc::generate_key_pair_pem();
            res.set_content(json_ok_keys(keys), "application/json; charset=utf-8");
        } catch (const std::exception& ex) {
            res.status = 400;
            res.set_content(json_error(ex.what()), "application/json; charset=utf-8");
        }
    });

    svr.Post("/api/hash", [](const httplib::Request& req, httplib::Response& res) {
        fs::path work;
        try {
            if (!req.has_file("document")) {
                throw std::runtime_error("Brak pliku document");
            }
            work = make_work_dir();
            const auto doc = work / "document.bin";
            save_upload(req.get_file_value("document"), doc);
            const auto digest = ecc::sha256_file(doc.string());
            res.set_content(
                std::string("{\"sha256\":\"") + ecc::to_hex(digest) + "\"}",
                "application/json; charset=utf-8");
        } catch (const std::exception& ex) {
            res.status = 400;
            res.set_content(json_error(ex.what()), "application/json; charset=utf-8");
        }
        if (!work.empty()) {
            std::error_code ec;
            fs::remove_all(work, ec);
        }
    });

    svr.Post("/api/sign", [](const httplib::Request& req, httplib::Response& res) {
        fs::path work;
        try {
            if (!req.has_file("document") || !req.has_file("private_key")) {
                throw std::runtime_error("Wymagane pliki: document oraz private_key");
            }
            work = make_work_dir();
            const auto doc = work / "document.bin";
            const auto priv = work / "private.pem";
            const auto sig = work / "document.sig";
            save_upload(req.get_file_value("document"), doc);
            save_upload(req.get_file_value("private_key"), priv);

            const auto digest = ecc::sha256_file(doc.string());
            ecc::sign_document(doc.string(), priv.string(), sig.string());
            const auto bytes = ecc::read_file_bytes(sig.string());

            res.set_header("X-Document-SHA256", ecc::to_hex(digest));
            res.set_header("Content-Disposition", "attachment; filename=\"document.sig\"");
            res.set_content(
                std::string(bytes.begin(), bytes.end()),
                "application/octet-stream");
        } catch (const std::exception& ex) {
            res.status = 400;
            res.set_content(json_error(ex.what()), "application/json; charset=utf-8");
        }
        if (!work.empty()) {
            std::error_code ec;
            fs::remove_all(work, ec);
        }
    });

    svr.Post("/api/verify", [](const httplib::Request& req, httplib::Response& res) {
        fs::path work;
        try {
            if (!req.has_file("document") ||
                !req.has_file("public_key") ||
                !req.has_file("signature")) {
                throw std::runtime_error("Wymagane pliki: document, public_key, signature");
            }
            work = make_work_dir();
            const auto doc = work / "document.bin";
            const auto pub = work / "public.pem";
            const auto sig = work / "document.sig";
            save_upload(req.get_file_value("document"), doc);
            save_upload(req.get_file_value("public_key"), pub);
            save_upload(req.get_file_value("signature"), sig);

            const bool ok = ecc::verify_document(doc.string(), pub.string(), sig.string());
            res.set_content(
                ok ? "{\"valid\":true}" : "{\"valid\":false}",
                "application/json; charset=utf-8");
        } catch (const std::exception& ex) {
            res.status = 400;
            res.set_content(json_error(ex.what()), "application/json; charset=utf-8");
        }
        if (!work.empty()) {
            std::error_code ec;
            fs::remove_all(work, ec);
        }
    });

    std::cout << "PodpisECC (web)\n"
              << "UI:  http://" << host << ":" << port << "/\n"
              << "web: " << web_root.string() << "\n"
              << "Ctrl+C aby zatrzymać.\n";

    if (!svr.listen(host, port)) {
        std::cerr << "Nie można nasłuchiwać na " << host << ":" << port << "\n";
        return 1;
    }
    return 0;
}
