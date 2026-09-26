#include "dns_message.h"

#include <cctype>

namespace dns {

namespace {

void put16(std::vector<uint8_t>& out, uint16_t v) {
    out.push_back(static_cast<uint8_t>(v >> 8));
    out.push_back(static_cast<uint8_t>(v & 0xff));
}

uint16_t get16(const uint8_t* p) { return static_cast<uint16_t>((p[0] << 8) | p[1]); }

// Decodes a (possibly compressed) name starting at `pos`. On success sets
// `name` (lower-case, no trailing dot) and `next` to the byte after the name
// in the original position.
bool decode_name(const uint8_t* data, size_t len, size_t pos, std::string& name, size_t& next) {
    name.clear();
    bool jumped = false;
    int hops = 0;
    while (true) {
        if (pos >= len) return false;
        uint8_t l = data[pos];
        if ((l & 0xc0) == 0xc0) {
            if (pos + 1 >= len || ++hops > 16) return false;
            if (!jumped) next = pos + 2;
            pos = static_cast<size_t>(((l & 0x3f) << 8) | data[pos + 1]);
            jumped = true;
            continue;
        }
        if (l & 0xc0) return false;  // reserved label types
        if (l == 0) {
            if (!jumped) next = pos + 1;
            return true;
        }
        if (pos + 1 + l > len) return false;
        if (!name.empty()) name.push_back('.');
        for (size_t i = 0; i < l; ++i)
            name.push_back(static_cast<char>(std::tolower(data[pos + 1 + i])));
        pos += 1 + l;
        if (name.size() > 255) return false;
    }
}

std::string normalize(const std::string& in) {
    std::string s;
    s.reserve(in.size());
    for (char c : in) s.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    while (!s.empty() && s.back() == '.') s.pop_back();
    return s;
}

}  // namespace

bool encode_name(const std::string& name, std::vector<uint8_t>& out) {
    std::string n = name;
    while (!n.empty() && n.back() == '.') n.pop_back();
    if (n.empty()) {  // root
        out.push_back(0);
        return true;
    }
    if (n.size() > 253) return false;
    size_t start = 0;
    while (start <= n.size()) {
        size_t dot = n.find('.', start);
        if (dot == std::string::npos) dot = n.size();
        size_t l = dot - start;
        if (l == 0 || l > 63) return false;
        out.push_back(static_cast<uint8_t>(l));
        out.insert(out.end(), n.begin() + static_cast<long>(start), n.begin() + static_cast<long>(dot));
        start = dot + 1;
    }
    out.push_back(0);
    return true;
}

std::vector<uint8_t> build_query(uint16_t id, const std::string& name, uint16_t qtype, bool edns) {
    std::vector<uint8_t> q;
    q.reserve(64 + name.size());
    put16(q, id);
    put16(q, 0x0100);          // RD
    put16(q, 1);               // QDCOUNT
    put16(q, 0);               // ANCOUNT
    put16(q, 0);               // NSCOUNT
    put16(q, edns ? 1 : 0);    // ARCOUNT
    if (!encode_name(name, q)) return {};
    put16(q, qtype);
    put16(q, kClassIN);
    if (edns) {
        q.push_back(0);        // root owner
        put16(q, 41);          // TYPE OPT
        put16(q, 1232);        // UDP payload size (DNS flag day 2020 value)
        put16(q, 0);           // ext-rcode + version
        put16(q, 0);           // flags
        put16(q, 0);           // RDLEN
    }
    return q;
}

Reply parse_reply(const uint8_t* data, size_t len, uint16_t expected_id,
                  const std::string& expected_name, uint16_t qtype) {
    Reply r;
    if (len < 12) {
        r.error = "short reply";
        return r;
    }
    r.id = get16(data);
    uint16_t flags = get16(data + 2);
    uint16_t qdcount = get16(data + 4);
    r.rcode = flags & 0x0f;

    if (r.id != expected_id) {
        r.error = "ID mismatch";
        return r;
    }
    if (!(flags & 0x8000)) {
        r.error = "not a response";
        return r;
    }
    if (qdcount != 1) {
        // Some servers omit the question on errors like FORMERR; accept only
        // for failure rcodes so we still report the rcode.
        if (qdcount == 0 && !rcode_is_answer(r.rcode)) {
            r.valid = true;
            return r;
        }
        r.error = "bad question count";
        return r;
    }
    std::string qname;
    size_t next = 0;
    if (!decode_name(data, len, 12, qname, next) || next + 4 > len) {
        r.error = "malformed question";
        return r;
    }
    if (qname != normalize(expected_name) || get16(data + next) != qtype ||
        get16(data + next + 2) != kClassIN) {
        r.error = "question mismatch";
        return r;
    }
    r.valid = true;
    return r;
}

std::string rcode_name(int rcode) {
    switch (rcode) {
        case 0: return "NOERROR";
        case 1: return "FORMERR";
        case 2: return "SERVFAIL";
        case 3: return "NXDOMAIN";
        case 4: return "NOTIMP";
        case 5: return "REFUSED";
        default: return "RCODE" + std::to_string(rcode);
    }
}

}  // namespace dns
