#ifndef SSRF_GUARD_H
#define SSRF_GUARD_H

#include <string>

/* -------------------- CONSTANTS & MACROS -------------------- */

// Bit manipulation
#define BYTE_MASK 0xff
#define SHIFT_24 24
#define SHIFT_16 16
#define SHIFT_8 8

// IPv4 special octets
#define IPV4_ZERO_OCTET 0
#define IPV4_BROADCAST_255 255

// IPv4-mapped IPv6 offset
#define IPV4_MAPPED_OFFSET 12
#define IPV4_ADDR_SIZE 4

// Localhost and loopback addresses
#define LOCALHOST_IPV4 "127.0.0.1"
#define LOCALHOST_IPV6 "::1"
#define LOCALHOST_NAME "localhost"
#define LOCALHOST_DOMAIN "localhost.localdomain"
#define UNSPECIFIED_IPV4 "0.0.0.0"
#define UNSPECIFIED_IPV6 "::"

// AWS Metadata Service
#define AWS_METADATA_IPV4 "169.254.169.254"
#define AWS_METADATA_IPV4_ALT "169.254.170.2"
#define AWS_METADATA_IPV6 "fd00:ec2::254"

// GCP Metadata Service
#define GCP_METADATA_HOST "metadata.google.internal"
#define GCP_METADATA_SHORT "metadata"

// Azure Metadata Service
#define AZURE_METADATA_HOST "metadata.azure.com"

// Alibaba Cloud Metadata
#define ALIBABA_METADATA_IPV4 "100.100.100.200"

// Kubernetes
#define K8S_DEFAULT "kubernetes.default"
#define K8S_DEFAULT_SVC "kubernetes.default.svc"
#define K8S_DEFAULT_FULL "kubernetes.default.svc.cluster.local"

// Docker
#define DOCKER_INTERNAL "docker.internal"
#define DOCKER_HOST_INTERNAL "host.docker.internal"

// URL Components
#define SCHEME_HTTP "http"
#define SCHEME_HTTPS "https"
#define URL_SCHEME_SEP "://"
#define URL_DELIM_CHARS ":/?#"
#define BRACKET_OPEN "["
#define BRACKET_CLOSE "]"
#define AT_SYMBOL "@"

// IP Encoding Patterns
#define HEX_PREFIX_LOWER "0x"
#define HEX_PREFIX_UPPER "0X"
#define IDN_PREFIX "xn--"
#define PERCENT_CHAR "%"

// Special Hostnames
#define IP6_LOCALHOST "ip6-localhost"
#define IP6_LOOPBACK "ip6-loopback"

// Special Characters
#define DOT "."
#define DOUBLE_DOT ".."
#define DASH "-"

// TLD Suffixes
#define TLD_LOCAL ".local"
#define TLD_LOCALHOST ".localhost"
#define TLD_TEST ".test"
#define TLD_EXAMPLE ".example"
#define TLD_INVALID ".invalid"
#define TLD_INTERNAL ".internal"

// Metadata Patterns
#define GCP_METADATA_GOOG "metadata.goog"

// IPv4 Network Ranges (First Octet)
#define IPV4_CLASS_A_PRIVATE 10
#define IPV4_LOOPBACK 127
#define IPV4_LINK_LOCAL_A 169
#define IPV4_LINK_LOCAL_B 254
#define IPV4_MULTICAST_START 224
#define IPV4_MULTICAST_END 239
#define IPV4_RESERVED_START 240
#define IPV4_CLASS_C_PRIVATE_A 192
#define IPV4_CLASS_C_PRIVATE_B 168
#define IPV4_CLASS_B_PRIVATE_A 172
#define IPV4_CLASS_B_PRIVATE_B_MIN 16
#define IPV4_CLASS_B_PRIVATE_B_MAX 31
#define IPV4_CGNAT_A 100
#define IPV4_CGNAT_B_MIN 64
#define IPV4_CGNAT_B_MAX 127

// IPv6 Special Prefixes
#define IPV6_ULA_PREFIX 0xfc
#define IPV6_ULA_MASK 0xfe
#define IPV6_DOC_PREFIX_0 0x20
#define IPV6_DOC_PREFIX_1 0x01
#define IPV6_DOC_PREFIX_2 0x0d
#define IPV6_DOC_PREFIX_3 0xb8
#define IPV6_6TO4_PREFIX_0 0x20
#define IPV6_6TO4_PREFIX_1 0x02
#define IPV6_TEREDO_PREFIX_0 0x20
#define IPV6_TEREDO_PREFIX_1 0x01
#define IPV6_TEREDO_PREFIX_2 0x00
#define IPV6_TEREDO_PREFIX_3 0x00

/**
 * SSRF Guard - Server-Side Request Forgery Protection
 * 
 * Validates URLs to prevent SSRF attacks by blocking:
 * - Non-IP hosts (domains are blocked)
 * - Private/internal IP addresses (IPv4 and IPv6)
 * - Localhost in various encodings
 * - Metadata service endpoints (AWS, GCP, Azure, etc.)
 * - Suspicious numeric IP representations (hex, octal, decimal)
 * - Disallowed URL schemes (file://, ftp://, etc.)
 * - URL encoding tricks and normalization bypasses
 * - Unicode/IDN homograph attacks
 * 
 * Security Features:
 * - DNS rebinding protection (checks all resolved IPs)
 * - TOCTOU mitigation (fail-secure design)
 * - URL normalization and percent-decoding
 * - Comprehensive IPv6 coverage
 * - Thread-safe DNS resolution
 * 
 * @param url The URL to validate
 * @return true if URL is safe to access, false if blocked
 * 
 * @note Validate immediately before making HTTP requests.
 *       For redirects, validate each redirect URL separately.
 *       Consider DNS caching with TTL to mitigate DNS rebinding.
 */
namespace ssrf {
bool validateUrl(const std::string& url);
}

#endif // SSRF_GUARD_H
