// DNS transports: UDP, TCP, DNS-over-TLS and DNS-over-HTTPS.
#pragma once

#include <cstdint>
#include <memory>
#include <string>

#include "servers.h"

struct LookupResult {
    bool ok = false;         // the server answered (NOERROR / NXDOMAIN)
    double ms = 0;           // query latency, excluding connection setup
    int rcode = -1;
    std::string error;       // empty when ok
    double connect_ms = -1;  // >= 0 when a new connection was set up for this lookup
};

class Transport {
public:
    virtual ~Transport() = default;
    virtual LookupResult lookup(const std::string& qname, uint16_t qtype, int timeout_ms) = 0;
};

// Returns nullptr if the server has no configuration for this protocol.
// `port` overrides the protocol's standard port (0 = default: 53, 853, or the
// DoH URL's port).
std::unique_ptr<Transport> make_transport(const Server& server, Protocol proto, int port = 0);

// Strict HTTP/1.1 size parsing: digits only (hex for chunk sizes, whose
// ";extensions" are ignored), surrounding blanks allowed, value <= max.
bool parse_chunk_size(const std::string& line, size_t max, size_t& out);
bool parse_content_length(const std::string& value, size_t max, size_t& out);

// Random 16-bit query id / label material from a per-thread generator.
uint16_t random_id();
std::string random_label(size_t len);
