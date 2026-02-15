# SSRF Guard

[![Build Status](https://github.com/USERNAME/REPO/workflows/SSRF%20Guard%20Tests/badge.svg)](https://github.com/USERNAME/REPO/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Production-ready C++ library for SSRF (Server-Side Request Forgery) protection.

## Features

- ✅ Blocks private IPs, localhost, metadata services
- ✅ Detects hex/octal/decimal IP encoding
- ✅ URL normalization & percent-decoding
- ✅ Comprehensive IPv6 coverage
- ✅ Thread-safe, no signal handlers
- ✅ Data-driven test suite from PortSwigger cheat sheet
- ✅ Strict IP-literal-only validation (domains blocked)

## Build

```bash
make all     # Build library and tests
make run     # Run test suite
make example # Build interactive demo
```

## Usage

```cpp
#include "ssrf_guard.h"

if (validateUrl("http://8.8.8.8")) {
    // Safe - make HTTP request
} else {
    // Blocked - potential SSRF attack
}
```

## Policy

- Only IPv4/IPv6 literals are allowed.
- All hostnames/domains are blocked.
- Private, loopback, link-local, metadata, multicast, and reserved IPs are blocked.
- Hex/octal/decimal IP encodings are blocked.

## Security

See [SECURITY.md](SECURITY.md) for attack vectors and mitigations.

## Files

- `ssrf_guard.h` - Public API
- `ssrf_guard.cpp` - Implementation  
- `test_ssrf.cpp` - Data-driven tests (loads files in data/)
- `example.cpp` - Interactive demo
- `Makefile` - Build system
- `data/` - PortSwigger URL cheat sheet data (see license notice)

## License

MIT

