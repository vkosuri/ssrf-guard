#include "ssrf_guard.h"
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <cctype>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <sys/time.h>
#include <sys/select.h>
#include <fcntl.h>
#include <errno.h>

using std::string;

/* ---------------- URL DECODING & NORMALIZATION ---------------- */

static string percentDecode(const string& str) {
    string result;
    result.reserve(str.length());
    
    for (size_t i = 0; i < str.length(); ++i) {
        if (str[i] == '%' && i + 2 < str.length()) {
            int value;
            std::istringstream iss(str.substr(i + 1, 2));
            if (iss >> std::hex >> value) {
                result += static_cast<char>(value);
                i += 2;
            } else {
                result += str[i];
            }
        } else if (str[i] == '+') {
            result += ' ';
        } else {
            result += str[i];
        }
    }
    return result;
}

static bool hasUnicodeOrIDN(const string& host) {
    // Detect non-ASCII characters (potential IDN/homograph)
    for (unsigned char c : host) {
        if (c > 127) return true;
    }
    // Detect xn-- prefix (punycode IDN)
    if (host.find(IDN_PREFIX) != string::npos) return true;
    return false;
}

static string normalizeUrl(const string& url) {
    // Decode percent-encoded characters to prevent bypasses
    string decoded = percentDecode(url);
    // Convert to lowercase for scheme/host comparison
    std::transform(decoded.begin(), decoded.end(), decoded.begin(), ::tolower);
    return decoded;
}

/* ---------------- SCHEME ---------------- */

static bool isAllowedScheme(const string& s) {
    // Only allow http and https - block file:// for security
    return s == SCHEME_HTTP || s == SCHEME_HTTPS;
}

/* ---------------- URL PARSE ---------------- */

static string getScheme(const string& url) {
    auto p = url.find(URL_SCHEME_SEP);
    return (p == string::npos) ? "" : url.substr(0, p);
}

static string getHost(const string& url) {
    auto start = url.find(URL_SCHEME_SEP);
    if (start == string::npos) return "";
    start += 3;

    // Find last @ to handle credentials
    auto at = url.find_last_of(AT_SYMBOL,
                                url.find_first_of(URL_DELIM_CHARS,
                                                  start));
    if (at != string::npos && at > start) {
        start = at + 1;
    }

    if (start >= url.size()) return "";

    // Handle IPv6 addresses in brackets
    if (url[start] == BRACKET_OPEN[0]) {
        auto end = url.find(BRACKET_CLOSE, start);
        if (end == string::npos) return "";
        return url.substr(start + 1, end - start - 1);
    }

    auto end = url.find_first_of(URL_DELIM_CHARS, start);
    if (end == string::npos) return url.substr(start);
    return url.substr(start, end - start);
}

/* ---------------- HOSTNAME BLOCKLIST ---------------- */

static bool isBlockedHostname(const string& host) {
    // Localhost aliases
    if (host == LOCALHOST_NAME || host == LOCALHOST_DOMAIN ||
        host == LOCALHOST_IPV4 || host == LOCALHOST_IPV6 ||
        host == UNSPECIFIED_IPV4 ||
        host == IP6_LOCALHOST || host == IP6_LOOPBACK) {
        return true;
    }
    
    // AWS Metadata
    if (host == AWS_METADATA_IPV4 || host == AWS_METADATA_IPV4_ALT ||
        host == AWS_METADATA_IPV6) {
        return true;
    }
    
    // GCP Metadata
    if (host == GCP_METADATA_HOST || host == GCP_METADATA_SHORT ||
        host.find(GCP_METADATA_GOOG) != string::npos) {
        return true;
    }
    
    // Azure Metadata
    if (host == AZURE_METADATA_HOST) {
        return true;
    }
    
    // Alibaba Cloud
    if (host == ALIBABA_METADATA_IPV4) {
        return true;
    }
    
    // Kubernetes
    if (host == K8S_DEFAULT || host == K8S_DEFAULT_SVC ||
        host == K8S_DEFAULT_FULL ||
        host.find(TLD_INTERNAL) != string::npos) {
        return true;
    }
    
    // Docker
    if (host == DOCKER_INTERNAL || host == DOCKER_HOST_INTERNAL) {
        return true;
    }
    
    // Internal TLDs
    if (host.find(TLD_LOCAL) != string::npos ||
        host.find(TLD_LOCALHOST) != string::npos ||
        host.find(TLD_TEST) != string::npos ||
        host.find(TLD_EXAMPLE) != string::npos ||
        host.find(TLD_INVALID) != string::npos) {
        return true;
    }

    // Suspicious patterns
    if (host.empty() || host == DOT || host == DOUBLE_DOT ||
        host == DASH) {
        return true;
    }
    
    // Unicode/IDN (homograph attacks)
    if (hasUnicodeOrIDN(host)) {
        return true;
    }
    
    return false;
}

/* ---------------- NUMERIC IP TRICK DETECTION ---------------- */

static bool hasSuspiciousIPEncoding(const string& host) {
    // Detect hex encoding (0x prefix)
    if (host.find(HEX_PREFIX_LOWER) != string::npos ||
        host.find(HEX_PREFIX_UPPER) != string::npos) {
        return true;
    }
    
    // Detect octal encoding (leading zeros)
    size_t pos = 0;
    while (pos < host.size()) {
        if (host[pos] == '0' && pos + 1 < host.size() &&
            isdigit(host[pos + 1])) {
            return true;  // Leading zero indicates octal
        }
        pos = host.find('.', pos);
        if (pos == string::npos) break;
        pos++;
    }
    
    // Detect decimal IP representation (all digits, no dots)
    if (host.find('.') == string::npos && host.find(':') == string::npos) {
        bool allDigits = !host.empty();
        for (char c : host) {
            if (!isdigit(c)) {
                allDigits = false;
                break;
            }
        }
        if (allDigits) return true;
    }
    
    // Detect percent encoding in IP
    if (host.find(PERCENT_CHAR) != string::npos) {
        return true;
    }
    
    return false;
}

/* ---------------- RANGE CHECKS ---------------- */

static bool isPrivateOrReservedIPv4(uint32_t ip) {
    uint8_t a = (ip >> SHIFT_24) & BYTE_MASK;
    uint8_t b = (ip >> SHIFT_16) & BYTE_MASK;
    uint8_t c = (ip >> SHIFT_8) & BYTE_MASK;

    // 127.0.0.0/8
    if (a == IPV4_LOOPBACK) return true;
    // 10.0.0.0/8
    if (a == IPV4_CLASS_A_PRIVATE) return true;
    // 172.16.0.0/12
    if (a == IPV4_CLASS_B_PRIVATE_A &&
        b >= IPV4_CLASS_B_PRIVATE_B_MIN &&
        b <= IPV4_CLASS_B_PRIVATE_B_MAX) return true;
    // 192.168.0.0/16
    if (a == IPV4_CLASS_C_PRIVATE_A &&
        b == IPV4_CLASS_C_PRIVATE_B) return true;
    // 169.254.0.0/16
    if (a == IPV4_LINK_LOCAL_A &&
        b == IPV4_LINK_LOCAL_B) return true;
    // 100.64.0.0/10
    if (a == IPV4_CGNAT_A &&
        b >= IPV4_CGNAT_B_MIN &&
        b <= IPV4_CGNAT_B_MAX) return true;
    // 255.255.255.255 (broadcast)
    if (a == IPV4_BROADCAST_255 && b == IPV4_BROADCAST_255 &&
        c == IPV4_BROADCAST_255) return true;
    // 0.0.0.0/8 (this network)
    if (a == IPV4_ZERO_OCTET) return true;
    // 224.0.0.0/4 (multicast)
    if (a >= IPV4_MULTICAST_START &&
        a <= IPV4_MULTICAST_END) return true;
    // 240.0.0.0/4 (reserved)
    if (a >= IPV4_RESERVED_START) return true;
    
    return false;
}

static bool isPrivateOrReservedIPv6(const in6_addr& a) {
    if (IN6_IS_ADDR_LOOPBACK(&a)) return true;     // ::1
    if (IN6_IS_ADDR_LINKLOCAL(&a)) return true;    // fe80::/10
    if (IN6_IS_ADDR_SITELOCAL(&a)) return true;    // fec0::/10
    if (IN6_IS_ADDR_MULTICAST(&a)) return true;    // ff00::/8
    if (IN6_IS_ADDR_UNSPECIFIED(&a)) return true;  // ::

    // Unique local: fc00::/7
    if ((a.s6_addr[0] & IPV6_ULA_MASK) == IPV6_ULA_PREFIX)
        return true;

    // Documentation: 2001:db8::/32
    if (a.s6_addr[0] == IPV6_DOC_PREFIX_0 &&
        a.s6_addr[1] == IPV6_DOC_PREFIX_1 &&
        a.s6_addr[2] == IPV6_DOC_PREFIX_2 &&
        a.s6_addr[3] == IPV6_DOC_PREFIX_3) return true;

    // 6to4: 2002::/16
    if (a.s6_addr[0] == IPV6_6TO4_PREFIX_0 &&
        a.s6_addr[1] == IPV6_6TO4_PREFIX_1) return true;

    // Teredo: 2001::/32
    if (a.s6_addr[0] == IPV6_TEREDO_PREFIX_0 &&
        a.s6_addr[1] == IPV6_TEREDO_PREFIX_1 &&
        a.s6_addr[2] == IPV6_TEREDO_PREFIX_2 &&
        a.s6_addr[3] == IPV6_TEREDO_PREFIX_3) return true;
    
    return false;
}

/* ---------------- IP ADDRESS VALIDATION ---------------- */

static bool isBlockedIP(const string& host) {
    // Block suspicious numeric encodings
    if (hasSuspiciousIPEncoding(host)) return true;
    
    // Try parsing as IPv4
    in_addr a4;
    if (inet_pton(AF_INET, host.c_str(), &a4) == 1) {
        return isPrivateOrReservedIPv4(ntohl(a4.s_addr));
    }
    
    // Try parsing as IPv6
    in6_addr a6;
    if (inet_pton(AF_INET6, host.c_str(), &a6) == 1) {
        // Check for IPv4-mapped IPv6 (::ffff:x.x.x.x)
        if (IN6_IS_ADDR_V4MAPPED(&a6)) {
            uint32_t v4;
            memcpy(&v4, &a6.s6_addr[IPV4_MAPPED_OFFSET],
                   IPV4_ADDR_SIZE);
            return isPrivateOrReservedIPv4(ntohl(v4));
        }
        return isPrivateOrReservedIPv6(a6);
    }
    
    return false;
}

static bool isIpLiteralHost(const string& host) {
    in_addr a4;
    if (inet_pton(AF_INET, host.c_str(), &a4) == 1) {
        return true;
    }

    in6_addr a6;
    if (inet_pton(AF_INET6, host.c_str(), &a6) == 1) {
        return true;
    }

    return false;
}

/* ---------------- DNS RESOLUTION CHECK (THREAD-SAFE) ---------------- */

static bool dnsResolvesToBlockedIP(const string& host) {
    // Thread-safe DNS resolution with timeout
    // Note: For production use, consider using a DNS cache with TTL
    // to mitigate DNS rebinding attacks at the application level
    
    addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    // Only return addresses if we have that family
    hints.ai_flags = AI_ADDRCONFIG;

    // Perform DNS lookup (blocking, but typically fast)
    // In production, use async DNS or timeout mechanism
    int status = getaddrinfo(host.c_str(), nullptr, &hints, &res);

    if (status != 0) {
        return true;  // Block on DNS failure (fail secure)
    }

    // Check ALL resolved IPs - block if ANY is private/reserved
    // Defense-in-depth against DNS rebinding:
    // - Even if DNS returns multiple IPs, we check all
    // - If attacker returns mix of public/private, we catch it
    bool blocked = false;
    for (auto p = res; p; p = p->ai_next) {
        if (p->ai_family == AF_INET) {
            auto* sa = (sockaddr_in*)p->ai_addr;
            if (isPrivateOrReservedIPv4(ntohl(sa->sin_addr.s_addr))) {
                blocked = true;
                break;  // Found at least one private IP
            }
        } else if (p->ai_family == AF_INET6) {
            auto* sa = (sockaddr_in6*)p->ai_addr;
            if (isPrivateOrReservedIPv6(sa->sin6_addr)) {
                blocked = true;
                break;  // Found at least one private IP
            }
        }
    }

    freeaddrinfo(res);
    return blocked;
}

/* ---------------- MAIN VALIDATOR ---------------- */

bool ssrf::validateUrl(const string& url) {
    // 0. Normalize URL to prevent encoding bypasses
    // e.g., http://example.com%2f@127.0.0.1
    string normalized = normalizeUrl(url);
    
    // 1. Check scheme is allowed (http/https only)
    string scheme = getScheme(normalized);
    if (!isAllowedScheme(scheme)) {
        return false;
    }

    // 2. Extract and validate hostname
    string host = getHost(normalized);
    if (host.empty()) {
        return false;
    }
    
    // Convert host to lowercase for consistent comparison
    std::transform(host.begin(), host.end(), host.begin(), ::tolower);

    // 3. Only allow IP literal hosts
    if (!isIpLiteralHost(host)) {
        return false;
    }

    // 4. Check against hostname blocklist
    // Includes localhost, metadata, internal TLDs, Unicode/IDN
    if (isBlockedHostname(host)) {
        return false;
    }

    // 5. Check if host is a blocked IP literal
    // Detects hex/octal/decimal, IPv4-mapped IPv6, etc.
    if (isBlockedIP(host)) {
        return false;
    }

    // 6. Resolve DNS and check if it points to blocked IPs
    // Defense against DNS rebinding: checks ALL resolved IPs
    // IMPORTANT: For TOCTOU mitigation, call immediately before
    // HTTP request. Consider DNS caching with TTL.
    if (dnsResolvesToBlockedIP(host)) {
        return false;
    }
    
    return true;
}
