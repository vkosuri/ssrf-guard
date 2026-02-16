#include "ssrf_guard.h"
#include <cctype>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

using std::string;

struct UrlEntry {
    string url;
    size_t line;
};

static string trimLine(const string& input) {
    size_t start = 0;
    while (start < input.size() &&
           std::isspace(static_cast<unsigned char>(input[start]))) {
        start++;
    }

    size_t end = input.size();
    while (end > start &&
           std::isspace(static_cast<unsigned char>(input[end - 1]))) {
        end--;
    }

    return input.substr(start, end - start);
}

static std::vector<UrlEntry> loadUrlsFromFile(const string& filename) {
    std::vector<UrlEntry> urls;
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Warning: Could not open " << filename << "\n";
        return urls;
    }

    string line;
    size_t lineNo = 0;
    while (std::getline(file, line)) {
        lineNo++;
        string trimmed = trimLine(line);
        if (trimmed.empty() || trimmed[0] == '#') {
            continue;
        }
        urls.push_back(UrlEntry{trimmed, lineNo});
    }

    return urls;
}

int main() {
    std::vector<string> files = {
        "data/url_validation_absolute_unicode.txt",
        "data/url_validation_absolute.txt",
        "data/url_validation_absolute_everything.txt",
        "data/url_validation_absolute_intruders.txt",
        "data/url_validation_absolute_special_chars.txt",
        "data/url_validation_cors.txt",
        "data/url_validation_cors_everything.txt",
        "data/url_validation_cors_special_chars.txt",
        "data/url_validation_cors_intruders.txt",
        "data/url_validation_cors_unicode.txt",
        "data/url_validation_host.txt",
        "data/url_validation_host_everything.txt",
        "data/url_validation_host_intruders.txt",
        "data/url_validation_host_special_chars.txt",
        "data/url_validation_host_unicode.txt",
        "data/url_validation_cloud_metadata.txt",
        "data/url_validation_complex.txt"
    };

    std::ofstream csv("test_results.csv");
    if (!csv.is_open()) {
        std::cerr << "Error: Could not open test_results.csv\n";
        return 1;
    }
    csv << "file,line,url,result\n";

    std::cout << "SSRF Guard Test Suite\n";
    std::cout << "====================\n\n";
    std::cout << "Testing URLs from data/ files\n\n";

    int totalTests = 0;
    int blocked = 0;
    int allowed = 0;

    for (const auto& file : files) {
        auto urls = loadUrlsFromFile(file);
        std::cout << "[" << file << "] - " << urls.size() << " patterns\n";
        std::cout << string(50, '-') << "\n";

        for (const auto& entry : urls) {
            bool result = ssrf::validateUrl(entry.url);
            csv << file << "," << entry.line << "," << entry.url << ","
                << (result ? "allowed" : "blocked") << "\n";
            if (!result) {
                blocked++;
            } else {
                allowed++;
                std::cout << "ALLOWED: " << file << ":" << entry.line
                          << ": " << entry.url << "\n";
            }
            totalTests++;
        }

        std::cout << "\n";
    }

    std::cout << string(50, '=') << "\n";
    std::cout << "Total: " << totalTests << " patterns\n";
    std::cout << "Blocked: " << blocked << "\n";
    std::cout << "Allowed: " << allowed << "\n";
    std::cout << "\nAllowed URLs should be reviewed.\n";

    return (allowed == 0) ? 0 : 1;
}
