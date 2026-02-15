#include "ssrf_guard.h"
#include <cctype>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

using std::string;

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

static std::vector<string> loadUrlsFromFile(const string& filename) {
    std::vector<string> urls;
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Warning: Could not open " << filename << "\n";
        return urls;
    }

    string line;
    while (std::getline(file, line)) {
        string trimmed = trimLine(line);
        if (trimmed.empty() || trimmed[0] == '#') {
            continue;
        }
        urls.push_back(trimmed);
    }

    return urls;
}

int main() {
    std::vector<string> files = {
        "data/url_validaiton_absolute_unicode.txt",
        "data/url_validaiton_cores_unicode.txt",
        "data/url_validaiton_host_special_chars.txt",
        "data/url_validaiton_host_unicode.txt",
        "data/url_validation_absolute.txt",
        "data/url_validation_absolute_everything.txt",
        "data/url_validation_absolute_introders.txt",
        "data/url_validation_absolute_special_chars.txt",
        "data/url_validation_cores.txt",
        "data/url_validation_cores_everything.txt",
        "data/url_validation_cores_special_chars.txt",
        "data/url_validation_cors_intruders.txt",
        "data/url_validation_host.txt",
        "data/url_validation_host_everything.txt",
        "data/url_validation_host_intruders.txt"
    };

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

        for (const auto& url : urls) {
            bool result = ssrf::validateUrl(url);
            if (!result) {
                blocked++;
            } else {
                allowed++;
                std::cout << "ALLOWED: " << url << "\n";
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
