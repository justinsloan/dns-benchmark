// Minimal DNS wire-format encoding/decoding: just enough to send a query and
// validate that a reply actually answers it.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace dns {

constexpr uint16_t kTypeA = 1;
constexpr uint16_t kTypeAAAA = 28;
constexpr uint16_t kClassIN = 1;

// Appends `name` in label format. Returns false for malformed names
// (empty labels, labels > 63 bytes, total > 255 bytes).
bool encode_name(const std::string& name, std::vector<uint8_t>& out);

// Builds a recursive query (RD=1) with one question and, optionally, an EDNS0
// OPT record advertising a 1232-byte UDP payload. Empty vector on bad name.
std::vector<uint8_t> build_query(uint16_t id, const std::string& name,
                                 uint16_t qtype = kTypeA, bool edns = true);

struct Reply {
    bool valid = false;      // well-formed and matches the query
    std::string error;       // why it is not valid
    uint16_t id = 0;
    int rcode = -1;
};

// Parses a reply and checks it is a response to (expected_id, expected_name,
// qtype). Name comparison is case-insensitive.
Reply parse_reply(const uint8_t* data, size_t len, uint16_t expected_id,
                  const std::string& expected_name, uint16_t qtype);

// NOERROR, NXDOMAIN, ... ; "RCODE<n>" for unknown values.
std::string rcode_name(int rcode);

// A server "answered" if it returned anything other than a server-side failure.
// NXDOMAIN is a perfectly good (and expected) answer for uncached lookups.
inline bool rcode_is_answer(int rcode) { return rcode == 0 || rcode == 3; }

}  // namespace dns
