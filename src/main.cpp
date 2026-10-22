#include "benchmark.hpp"
#include "hash.hpp"
#include "keys.hpp"
#include "signature.hpp"
#include "utils.hpp"

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

constexpr std::size_t kPayloadMax = ecc::kMaxUploadBytes + 256 * 1024;

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

void cleanup_work(const fs::path& work) {
    if (work.empty()) {
        return;
    }
    std::error_code ec;
    fs::remove_all(work, ec);
}

void save_upload(const httplib::MultipartFormData& part,
                 const fs::path& path,
                 std::size_t max_bytes,
                 const std::string& label) {
    ecc::validate_upload_size(part.content.size(), max_bytes, label);
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) {
        ecc::fail("Nie można zapisać przesłanego pliku „" + label + "”");
    }
    out.write(part.content.data(), static_cast<std::streamsize>(part.content.size()));
    if (!out) {
        ecc::fail("Błąd zapisu pliku „" + label + "”");
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

std::string form_get(const httplib::Request& req, const std::string& key) {
    if (req.has_param(key)) {
        return req.get_param_value(key);
    }
    // W multipart pola tekstowe trafiają często do files.
    if (req.has_file(key)) {
        return req.get_file_value(key).content;
    }
    return {};
}

std::string fmt_ms(double ms) {
    std::ostringstream oss;
    oss.setf(std::ios::fixed);
    oss.precision(3);
    oss << ms;
    return oss.str();
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
        std::cerr << "Nie znaleziono katalogu web/ (index.html).\n";
        return 1;
    }

    httplib::Server svr;
    svr.set_payload_max_length(kPayloadMax);

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

    svr.Post("/api/generate-keys", [](const httplib::Request& req, httplib::Response& res) {
        try {
            const std::string pass = form_get(req, "passphrase");
            const std::string pass2 = form_get(req, "passphrase_confirm");
            if (!pass.empty() && pass != pass2) {
                throw std::runtime_error("Hasła do klucza prywatnego nie są identyczne");
            }
            if (!pass.empty() && pass.size() < 6) {
                throw std::runtime_error("Hasło powinno mieć co najmniej 6 znaków");
            }

            auto t0 = std::chrono::steady_clock::now();
            const auto keys = ecc::generate_key_pair_pem(pass);
            const double keygen_ms = std::chrono::duration<double, std::milli>(
                                         std::chrono::steady_clock::now() - t0)
                                         .count();

            std::ostringstream oss;
            oss << "{\"private_pem\":\"" << json_escape(keys.private_pem) << "\","
                << "\"public_pem\":\"" << json_escape(keys.public_pem) << "\","
                << "\"encrypted\":" << (keys.encrypted ? "true" : "false") << ","
                << "\"keygen_ms\":" << fmt_ms(keygen_ms) << "}";
            res.set_content(oss.str(), "application/json; charset=utf-8");
        } catch (const std::exception& ex) {
            res.status = 400;
            res.set_content(json_error(ex.what()), "application/json; charset=utf-8");
        }
    });

    svr.Post("/api/hash", [](const httplib::Request& req, httplib::Response& res) {
        fs::path work;
        try {
            if (!req.has_file("document")) {
                throw std::runtime_error("Brak pliku dokumentu");
            }
            const auto& doc_part = req.get_file_value("document");
            work = make_work_dir();
            const auto doc = work / "document.bin";
            save_upload(doc_part, doc, ecc::kMaxUploadBytes, "dokument");

            auto t0 = std::chrono::steady_clock::now();
            const auto digest = ecc::sha256_file(doc.string());
            const double hash_ms = std::chrono::duration<double, std::milli>(
                                       std::chrono::steady_clock::now() - t0)
                                       .count();

            std::ostringstream oss;
            oss << "{\"sha256\":\"" << ecc::to_hex(digest) << "\","
                << "\"bytes\":" << doc_part.content.size() << ","
                << "\"hash_ms\":" << fmt_ms(hash_ms) << "}";
            res.set_content(oss.str(), "application/json; charset=utf-8");
        } catch (const std::exception& ex) {
            res.status = 400;
            res.set_content(json_error(ex.what()), "application/json; charset=utf-8");
        }
        cleanup_work(work);
    });

    svr.Post("/api/sign", [](const httplib::Request& req, httplib::Response& res) {
        fs::path work;
        try {
            if (!req.has_file("document")) {
                throw std::runtime_error("Brak pliku dokumentu — wybierz dokument do podpisania");
            }
            if (!req.has_file("private_key")) {
                throw std::runtime_error("Brak pliku klucza prywatnego — wybierz plik .pem / .key");
            }
            const auto& doc_part = req.get_file_value("document");
            const auto& key_part = req.get_file_value("private_key");
            if (doc_part.content.empty()) {
                throw std::runtime_error("Plik dokumentu jest pusty");
            }
            if (key_part.content.empty()) {
                throw std::runtime_error("Plik klucza prywatnego jest pusty");
            }
            ecc::validate_key_filename(key_part.filename);

            work = make_work_dir();
            const auto doc = work / "document.bin";
            const auto priv = work / "private.pem";
            const auto sig = work / "document.sig";
            save_upload(doc_part, doc, ecc::kMaxUploadBytes, "dokument");
            save_upload(key_part, priv, ecc::kMaxKeyUploadBytes, "klucz prywatny");

            const std::string pass = form_get(req, "passphrase");
            const auto signed_info =
                ecc::sign_document(doc.string(), priv.string(), sig.string(), pass);
            const auto bytes = ecc::read_file_bytes(sig.string());

            res.set_header("X-Document-SHA256", signed_info.sha256_hex);
            res.set_header("X-Hash-Ms", fmt_ms(signed_info.hash_ms));
            res.set_header("X-Sign-Ms", fmt_ms(signed_info.sign_ms));
            res.set_header("X-Signature-Bytes", std::to_string(signed_info.signature_bytes));
            res.set_header("Content-Disposition", "attachment; filename=\"document.sig\"");
            res.set_content(std::string(bytes.begin(), bytes.end()), "application/octet-stream");
        } catch (const std::exception& ex) {
            res.status = 400;
            res.set_content(json_error(ex.what()), "application/json; charset=utf-8");
        }
        cleanup_work(work);
    });

    svr.Post("/api/verify", [](const httplib::Request& req, httplib::Response& res) {
        fs::path work;
        try {
            if (!req.has_file("document")) {
                throw std::runtime_error("Brak pliku dokumentu — wybierz dokument do weryfikacji");
            }
            if (!req.has_file("public_key")) {
                throw std::runtime_error("Brak pliku klucza publicznego — wybierz plik .pem / .pub");
            }
            if (!req.has_file("signature")) {
                throw std::runtime_error("Brak pliku podpisu — wybierz plik .sig / .bin / .der");
            }
            const auto& doc_part = req.get_file_value("document");
            const auto& key_part = req.get_file_value("public_key");
            const auto& sig_part = req.get_file_value("signature");
            if (doc_part.content.empty()) {
                throw std::runtime_error("Plik dokumentu jest pusty");
            }
            if (key_part.content.empty()) {
                throw std::runtime_error("Plik klucza publicznego jest pusty");
            }
            if (sig_part.content.empty()) {
                throw std::runtime_error("Plik podpisu jest pusty");
            }
            ecc::validate_key_filename(key_part.filename);
            ecc::validate_signature_filename(sig_part.filename);

            work = make_work_dir();
            const auto doc = work / "document.bin";
            const auto pub = work / "public.pem";
            const auto sig = work / "document.sig";
            save_upload(doc_part, doc, ecc::kMaxUploadBytes, "dokument");
            save_upload(key_part, pub, ecc::kMaxKeyUploadBytes, "klucz publiczny");
            save_upload(sig_part, sig, ecc::kMaxSignatureUploadBytes, "podpis");

            const auto vr = ecc::verify_document(doc.string(), pub.string(), sig.string());
            std::ostringstream oss;
            oss << "{\"valid\":" << (vr.valid ? "true" : "false") << ","
                << "\"sha256\":\"" << vr.sha256_hex << "\","
                << "\"hash_ms\":" << fmt_ms(vr.hash_ms) << ","
                << "\"verify_ms\":" << fmt_ms(vr.verify_ms) << "}";
            res.set_content(oss.str(), "application/json; charset=utf-8");
        } catch (const std::exception& ex) {
            res.status = 400;
            res.set_content(json_error(ex.what()), "application/json; charset=utf-8");
        }
        cleanup_work(work);
    });

    svr.Post("/api/benchmark", [](const httplib::Request& req, httplib::Response& res) {
        try {
            int rounds = 3;
            const auto r = form_get(req, "rounds");
            if (!r.empty()) {
                rounds = std::stoi(r);
            }
            const auto result = ecc::run_ecc_vs_rsa_benchmark(rounds);
            res.set_content(ecc::benchmark_to_json(result), "application/json; charset=utf-8");
        } catch (const std::exception& ex) {
            res.status = 400;
            res.set_content(json_error(ex.what()), "application/json; charset=utf-8");
        }
    });

    std::cout << "PodpisECC (web)\n"
              << "UI:  http://" << host << ":" << port << "/\n"
              << "web: " << web_root.string() << "\n"
              << "limit uploadu: " << (ecc::kMaxUploadBytes / (1024 * 1024)) << " MiB\n"
              << "Ctrl+C aby zatrzymać.\n";

    if (!svr.listen(host, port)) {
        std::cerr << "Nie można nasłuchiwać na " << host << ":" << port << "\n";
        return 1;
    }
    return 0;
}
