#include "ssrf_guard.h"
#include <iostream>
#include <string>

int main() {
    std::string url;
    
    std::cout << "SSRF Guard Example\n";
    std::cout << "==================\n\n";
    
    std::cout << "Example URLs to test:\n";
    std::cout << "  Blocked: http://127.0.0.1\n";
    std::cout << "  Blocked: http://169.254.169.254\n";
    std::cout << "  Blocked: http://metadata.google.internal\n";
    std::cout << "  Allowed: http://example.com\n";
    std::cout << "  Allowed: http://trusted.com/redirect?url=http://127.0.0.1\n";
    std::cout << "           (Open redirect - app must validate redirects!)\n\n";
    
    std::cout << "Enter a URL to validate (or 'quit' to exit):\n\n";
    
    while (true) {
        std::cout << "> ";
        std::getline(std::cin, url);
        
        if (url == "quit" || url == "exit") {
            break;
        }
        
        if (url.empty()) {
            continue;
        }
        
        if (ssrf::validateUrl(url)) {
            std::cout << "✓ ALLOWED - URL is safe to access\n\n";
        } else {
            std::cout << "✗ BLOCKED - Potential SSRF attack detected\n\n";
        }
    }
    
    std::cout << "Goodbye!\n";
    return 0;
}
