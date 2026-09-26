#include "transport.h"

#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstring>
#include <random>
#include <vector>

#include "dns_message.h"
#include "net.h"
#include "tls.h"

namespace {

bool parse_size(std::string s, int base, size_t max, size_t& out) {
    size_t a = s.find_first_not_of(" \t"), b = s.find_last_not_of(" \t");
    if (a == std::string::npos) return false;
    s = s.substr(a, b - a + 1);
    size_t v = 0;
    for (char c : s) {
        int digit;
        if (c >= '0' && c <= '9') digit = c - '0';
        else if (base == 16 && c >= 'a' && c <= 'f') digit = c - 'a' + 10;
        else if (base == 16 && c >= 'A' && c <= 'F') digit = c - 'A' + 10;
        else return false;
        v = v * static_cast<size_t>(base) + static_cast<size_t>(digit);
        if (v > max) return false;  // checked every step, so it can never wrap
    }
    out = v;
    return true;
}

}  // namespace

bool parse_chunk_size(const std::string& line, size_t max, size_t& out) {
    return parse_size(line.substr(0, line.find(';')), 16, max, out);  // drop chunk extensions
}

bool parse_content_length(const std::string& value, size_t max, size_t& out) {
    return parse_size(value, 10, max, out);
}

namespace {

std::mt19937& rng() {
    thread_local std::mt19937 gen{std::random_device{}()};
    return gen;
}

LookupResult fail(std::string err) {
    LookupResult r;
    r.error = std::move(err);
    return r;
}

// Turns a parsed, validated reply into a result.
LookupResult finish(const dns::Reply& p, double ms) {
    if (!p.valid) return fail(p.error);
    LookupResult r;
    r.ms = ms;
    r.rcode = p.rcode;
    r.ok = dns::rcode_is_answer(p.rcode);
    if (!r.ok) r.error = dns::rcode_name(p.rcode);
    return r;
}

// ---------------------------------------------------------------- UDP

class UdpTransport : public Transport {
public:
    UdpTransport(std::string ip, int port) : ip_(std::move(ip)), port_(port) {}

    LookupResult lookup(const std::string& qname, uint16_t qtype, int timeout_ms) override {
        sockaddr_storage sa{};
        socklen_t len = 0;
        if (!make_sockaddr(ip_, port_, sa, len)) return fail("bad address");
        // A fresh socket per query gives each query a new random source port,
        // as a real stub resolver would.
        int fd = socket(sa.ss_family, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (fd < 0) return fail(std::string("socket: ") + std::strerror(errno));
        struct Closer {
            int fd;
            ~Closer() { ::close(fd); }
        } closer{fd};
        if (::connect(fd, reinterpret_cast<sockaddr*>(&sa), len) < 0)
            return fail(std::string("connect: ") + std::strerror(errno));

        uint16_t id = random_id();
        std::vector<uint8_t> q = dns::build_query(id, qname, qtype);
        if (q.empty()) return fail("bad name");

        Deadline d = deadline_in_ms(timeout_ms);
        auto start = Clock::now();
        if (::send(fd, q.data(), q.size(), 0) < 0)
            return fail(std::string("send: ") + std::strerror(errno));

        uint8_t buf[4096];
        std::string err;
        while (true) {
            ssize_t n = ::recv(fd, buf, sizeof buf, 0);
            if (n < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                    if (!wait_fd(fd, POLLIN, d, err)) return fail(err);
                    continue;
                }
                // ECONNREFUSED here means an ICMP port-unreachable came back.
                return fail(std::string("recv: ") + std::strerror(errno));
            }
            double ms = ms_since(start);
            dns::Reply p = dns::parse_reply(buf, static_cast<size_t>(n), id, qname, qtype);
            if (!p.valid) continue;  // stray/spoofed datagram: keep waiting
            return finish(p, ms);
        }
    }

private:
    std::string ip_;
    int port_;
};

// ------------------------------------------ connection-oriented base

// Keeps one connection open across lookups, the way a real stub resolver
// would, and reconnects transparently when the server closed it while idle.
//
// The whole lookup (connection setup, any retry, and the exchange) shares
// one deadline, so a lookup never blocks for longer than timeout_ms.
// Reported latency covers only the exchange; setup time goes in connect_ms.
class ConnectedTransport : public Transport {
public:
    LookupResult lookup(const std::string& qname, uint16_t qtype, int timeout_ms) override {
        Deadline d = deadline_in_ms(timeout_ms);
        double connect_ms = -1;
        auto with_connect = [&connect_ms](LookupResult r) {
            r.connect_ms = connect_ms;
            return r;
        };

        bool fresh = false;
        std::string err;
        if (!stream().is_open() || stream().looks_closed()) {
            if (!reconnect(d, connect_ms, err)) return fail(err);
            fresh = true;
        }
        LookupResult r;
        if (attempt(qname, qtype, d, r, err)) return with_connect(r);

        // Retry once, on a new connection, only when a reused connection died
        // before any of the response arrived: the server most likely closed
        // it while idle. Anything else (HTTP 503, stream reset, a truncated
        // or malformed reply, timeout) is a real failure and is recorded.
        if (fresh || response_started_ || err == kTimeoutError) return with_connect(fail(err));
        if (!reconnect(d, connect_ms, err)) return with_connect(fail(err));
        if (attempt(qname, qtype, d, r, err)) return with_connect(r);
        return with_connect(fail(err));
    }

protected:
    virtual Stream& stream() = 0;
    virtual bool open(Deadline d, std::string& err) = 0;
    // Sends `query` and reads the reply. Implementations must set
    // response_started_ once any part of the response to this query arrives.
    virtual bool exchange(const std::vector<uint8_t>& query, std::vector<uint8_t>& reply,
                          bool& keep_open, Deadline d, std::string& err) = 0;

    bool response_started_ = false;

private:
    bool reconnect(Deadline d, double& connect_ms, std::string& err) {
        stream().close();
        auto t0 = Clock::now();
        if (!open(d, err)) return false;
        connect_ms = ms_since(t0);
        return true;
    }

    // One query on the current connection. Returns false (and closes the
    // connection) on transport failure; `r` is set when it returns true.
    bool attempt(const std::string& qname, uint16_t qtype, Deadline d, LookupResult& r,
                 std::string& err) {
        uint16_t id = random_id();
        std::vector<uint8_t> q = dns::build_query(id, qname, qtype);
        if (q.empty()) {
            r = fail("bad name");
            return true;
        }
        std::vector<uint8_t> reply;
        bool keep_open = true;
        response_started_ = false;
        auto start = Clock::now();
        if (!exchange(q, reply, keep_open, d, err)) {
            stream().close();
            return false;
        }
        double ms = ms_since(start);
        if (!keep_open) stream().close();
        r = finish(dns::parse_reply(reply.data(), reply.size(), id, qname, qtype), ms);
        return true;
    }
};

// RFC 1035 4.2.2 / RFC 7858: messages framed by a 2-byte length prefix.
bool framed_exchange(Stream& s, const std::vector<uint8_t>& q, std::vector<uint8_t>& reply,
                     Deadline d, std::string& err, bool& response_started) {
    std::vector<uint8_t> msg;
    msg.reserve(q.size() + 2);
    msg.push_back(static_cast<uint8_t>(q.size() >> 8));
    msg.push_back(static_cast<uint8_t>(q.size() & 0xff));
    msg.insert(msg.end(), q.begin(), q.end());
    if (!s.write_all(msg.data(), msg.size(), d, err)) return false;
    uint8_t lenbuf[2];
    if (!s.read_exact(lenbuf, 1, d, err)) return false;
    response_started = true;
    if (!s.read_exact(lenbuf + 1, 1, d, err)) return false;
    size_t len = static_cast<size_t>((lenbuf[0] << 8) | lenbuf[1]);
    reply.resize(len);
    return s.read_exact(reply.data(), len, d, err);
}

class TcpTransport : public ConnectedTransport {
public:
    TcpTransport(std::string ip, int port) : ip_(std::move(ip)), port_(port) {}

protected:
    Stream& stream() override { return s_; }
    bool open(Deadline d, std::string& err) override { return s_.connect(ip_, port_, d, err); }
    bool exchange(const std::vector<uint8_t>& q, std::vector<uint8_t>& reply, bool&, Deadline d,
                  std::string& err) override {
        return framed_exchange(s_, q, reply, d, err, response_started_);
    }

private:
    std::string ip_;
    int port_;
    PlainStream s_;
};

class DotTransport : public ConnectedTransport {
public:
    DotTransport(std::string ip, int port, std::string host)
        : ip_(std::move(ip)), port_(port), host_(std::move(host)) {}

protected:
    Stream& stream() override { return s_; }
    bool open(Deadline d, std::string& err) override {
        return s_.connect(ip_, port_, host_, {"dot"}, d, err);
    }
    bool exchange(const std::vector<uint8_t>& q, std::vector<uint8_t>& reply, bool&, Deadline d,
                  std::string& err) override {
        return framed_exchange(s_, q, reply, d, err, response_started_);
    }

private:
    std::string ip_;
    int port_;
    std::string host_;
    TlsStream s_;
};

// ---------------------------------------------------------------- DoH

// RFC 8484 POST. We connect straight to the server's IP and use the URL host
// only for SNI, :authority/Host and certificate checks. HTTP/2 is negotiated
// via ALPN (RFC 8484 5.2 names it the minimum, and e.g. Quad9 insists on it);
// HTTP/1.1 keep-alive is the fallback for servers that don't offer h2.
class DohTransport : public ConnectedTransport {
public:
    DohTransport(std::string ip, std::string host, int port, std::string path)
        : ip_(std::move(ip)), host_(std::move(host)), port_(port), path_(std::move(path)),
          authority_(host_ + (port_ != 443 ? ":" + std::to_string(port_) : "")) {}

protected:
    Stream& stream() override { return s_; }

    bool open(Deadline d, std::string& err) override {
        buf_.clear();
        if (!s_.connect(ip_, port_, host_, {"h2", "http/1.1"}, d, err)) return false;
        h2_ = s_.alpn_selected() == "h2";
        if (!h2_) return true;
        // Connection preface + our (empty) SETTINGS frame.
        std::string out = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        h2_frame(out, kSettings, 0, 0, "");
        next_stream_ = 1;
        return write_str(out, d, err);
    }

    bool exchange(const std::vector<uint8_t>& q, std::vector<uint8_t>& reply, bool& keep_open,
                  Deadline d, std::string& err) override {
        return h2_ ? h2_exchange(q, reply, keep_open, d, err) : h1_exchange(q, reply, keep_open, d, err);
    }

private:
    static constexpr size_t kMaxBody = 65535;  // largest possible DNS message

    // ---- HTTP/2 (RFC 9113) with a request-only HPACK encoder (RFC 7541).

    enum : uint8_t { kData = 0, kHeaders = 1, kRstStream = 3, kSettings = 4, kPing = 6,
                     kGoaway = 7, kWindowUpdate = 8 };
    enum : uint8_t { kEndStream = 0x1, kAck = 0x1, kEndHeaders = 0x4, kPadded = 0x8 };

    static void h2_frame(std::string& out, uint8_t type, uint8_t flags, uint32_t stream,
                         const std::string& payload) {
        size_t n = payload.size();
        out.push_back(static_cast<char>((n >> 16) & 0xff));
        out.push_back(static_cast<char>((n >> 8) & 0xff));
        out.push_back(static_cast<char>(n & 0xff));
        out.push_back(static_cast<char>(type));
        out.push_back(static_cast<char>(flags));
        for (int shift = 24; shift >= 0; shift -= 8)
            out.push_back(static_cast<char>((stream >> shift) & 0xff));
        out += payload;
    }

    static void hpack_int(std::string& out, uint8_t high_bits, int prefix, size_t v) {
        size_t max = (1u << prefix) - 1;
        if (v < max) {
            out.push_back(static_cast<char>(high_bits | v));
            return;
        }
        out.push_back(static_cast<char>(high_bits | max));
        for (v -= max; v >= 128; v /= 128) out.push_back(static_cast<char>((v % 128) | 0x80));
        out.push_back(static_cast<char>(v));
    }

    // "Literal header field without indexing", name from the static table,
    // raw (non-Huffman) value. Leaves the server's dynamic table untouched.
    static void hpack_literal(std::string& out, size_t name_index, const std::string& value) {
        hpack_int(out, 0x00, 4, name_index);
        hpack_int(out, 0x00, 7, value.size());
        out += value;
    }

    static uint32_t be32(const std::string& s, size_t at) {
        return (static_cast<uint32_t>(static_cast<uint8_t>(s[at])) << 24) |
               (static_cast<uint32_t>(static_cast<uint8_t>(s[at + 1])) << 16) |
               (static_cast<uint32_t>(static_cast<uint8_t>(s[at + 2])) << 8) |
               static_cast<uint32_t>(static_cast<uint8_t>(s[at + 3]));
    }

    bool h2_exchange(const std::vector<uint8_t>& q, std::vector<uint8_t>& reply, bool& keep_open,
                     Deadline d, std::string& err) {
        uint32_t sid = next_stream_;
        next_stream_ += 2;
        if (next_stream_ > 0x7ffffff0u) keep_open = false;

        std::string hb;
        hb.push_back(static_cast<char>(0x83));  // :method POST   (static index 3)
        hb.push_back(static_cast<char>(0x87));  // :scheme https  (static index 7)
        hpack_literal(hb, 4, path_);            // :path
        hpack_literal(hb, 1, authority_);       // :authority
        hpack_literal(hb, 31, "application/dns-message");  // content-type
        hpack_literal(hb, 19, "application/dns-message");  // accept
        hpack_literal(hb, 28, std::to_string(q.size()));   // content-length
        std::string out;
        h2_frame(out, kHeaders, kEndHeaders, sid, hb);
        h2_frame(out, kData, kEndStream, sid, std::string(q.begin(), q.end()));
        if (!write_str(out, d, err)) return false;

        // We never decode response headers: the DATA must be a DNS message
        // that matches our query, which is a stricter check than :status.
        std::string body;
        while (true) {
            if (!need(9, d, err)) return false;
            size_t len = (static_cast<size_t>(static_cast<uint8_t>(buf_[0])) << 16) |
                         (static_cast<size_t>(static_cast<uint8_t>(buf_[1])) << 8) |
                         static_cast<uint8_t>(buf_[2]);
            uint8_t type = static_cast<uint8_t>(buf_[3]);
            uint8_t flags = static_cast<uint8_t>(buf_[4]);
            uint32_t stream = be32(buf_, 5) & 0x7fffffffu;
            if (len > (1u << 20)) {
                err = "HTTP/2 frame too large";
                return false;
            }
            if (!need(9 + len, d, err)) return false;
            std::string payload = buf_.substr(9, len);
            buf_.erase(0, 9 + len);
            if (stream == sid) response_started_ = true;

            switch (type) {
                case kSettings:
                    if (!(flags & kAck)) {
                        std::string ack;
                        h2_frame(ack, kSettings, kAck, 0, "");
                        if (!write_str(ack, d, err)) return false;
                    }
                    break;
                case kPing:
                    if (!(flags & kAck)) {
                        std::string pong;
                        h2_frame(pong, kPing, kAck, 0, payload);
                        if (!write_str(pong, d, err)) return false;
                    }
                    break;
                case kGoaway: {
                    keep_open = false;
                    uint32_t last = payload.size() >= 4 ? be32(payload, 0) & 0x7fffffffu : 0;
                    if (sid > last) {
                        err = "HTTP/2 GOAWAY";
                        return false;
                    }
                    break;
                }
                case kRstStream:
                    if (stream == sid) {
                        err = "HTTP/2 stream reset";
                        return false;
                    }
                    break;
                case kHeaders:
                    if (stream == sid && (flags & kEndStream)) {
                        if (body.empty()) {
                            err = "HTTP error (no body)";
                            return false;
                        }
                        reply.assign(body.begin(), body.end());
                        return true;
                    }
                    break;
                case kData:
                    if (stream != sid) break;
                    if (flags & kPadded) {
                        size_t pad = payload.empty() ? 0 : static_cast<uint8_t>(payload[0]);
                        if (pad + 1 > payload.size()) {
                            err = "HTTP/2 bad padding";
                            return false;
                        }
                        body.append(payload, 1, payload.size() - 1 - pad);
                    } else {
                        body += payload;
                    }
                    if (body.size() > kMaxBody) {
                        err = "HTTP body too large";
                        return false;
                    }
                    if (len > 0) {
                        // Hand the flow-control credit straight back so a long
                        // benchmark never exhausts the connection window.
                        std::string wu, inc(4, '\0');
                        inc[0] = static_cast<char>((len >> 24) & 0x7f);
                        inc[1] = static_cast<char>((len >> 16) & 0xff);
                        inc[2] = static_cast<char>((len >> 8) & 0xff);
                        inc[3] = static_cast<char>(len & 0xff);
                        h2_frame(wu, kWindowUpdate, 0, 0, inc);
                        if (!write_str(wu, d, err)) return false;
                    }
                    if (flags & kEndStream) {
                        reply.assign(body.begin(), body.end());
                        return true;
                    }
                    break;
                default:  // WINDOW_UPDATE, PRIORITY, CONTINUATION, unknown: ignore
                    break;
            }
        }
    }

    // ---- HTTP/1.1

    bool h1_exchange(const std::vector<uint8_t>& q, std::vector<uint8_t>& reply, bool& keep_open,
                     Deadline d, std::string& err) {
        std::string req = "POST " + path_ + " HTTP/1.1\r\n"
                          "Host: " + authority_ + "\r\n"
                          "User-Agent: dns-benchmark/1.0\r\n"
                          "Accept: application/dns-message\r\n"
                          "Content-Type: application/dns-message\r\n"
                          "Content-Length: " + std::to_string(q.size()) + "\r\n\r\n";
        req.append(reinterpret_cast<const char*>(q.data()), q.size());
        if (!write_str(req, d, err)) return false;

        size_t hdr_end;
        while ((hdr_end = buf_.find("\r\n\r\n")) == std::string::npos) {
            if (buf_.size() > 32 * 1024) {
                err = "HTTP headers too large";
                return false;
            }
            if (!fill(d, err)) return false;
        }
        std::string head = buf_.substr(0, hdr_end);
        buf_.erase(0, hdr_end + 4);

        std::string lower = head;
        std::transform(lower.begin(), lower.end(), lower.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        int status = 0;
        if (std::sscanf(head.c_str(), "HTTP/%*d.%*d %d", &status) != 1) {
            err = "bad HTTP status line";
            return false;
        }
        if (lower.rfind("http/1.0", 0) == 0 || header(lower, "connection") == "close")
            keep_open = false;
        if (status != 200) {  // don't bother reading the body; drop the connection
            err = "HTTP " + std::to_string(status);
            return false;
        }

        std::string body;
        if (header(lower, "transfer-encoding").find("chunked") != std::string::npos) {
            if (!read_chunked(body, d, err)) return false;
        } else if (std::string cl = header(lower, "content-length"); !cl.empty()) {
            size_t n = 0;
            if (!parse_content_length(cl, kMaxBody, n)) {
                err = "bad or oversized Content-Length";
                return false;
            }
            if (!need(n, d, err)) return false;
            body = buf_.substr(0, n);
            buf_.erase(0, n);
        } else {  // body delimited by connection close
            keep_open = false;
            std::string e;
            while (buf_.size() <= kMaxBody && fill(d, e)) {}
            if (e != "connection closed") {
                err = e.empty() ? "HTTP body too large" : e;
                return false;
            }
            body.swap(buf_);
        }
        reply.assign(body.begin(), body.end());
        return true;
    }

    // Value of a header in the lower-cased header block, trimmed; "" if absent.
    static std::string header(const std::string& lower_head, const std::string& name) {
        size_t pos = lower_head.find("\r\n" + name + ":");
        if (pos == std::string::npos) return "";
        size_t start = pos + 2 + name.size() + 1;
        size_t end = lower_head.find("\r\n", start);
        std::string v = lower_head.substr(start, end == std::string::npos ? std::string::npos : end - start);
        size_t a = v.find_first_not_of(" \t"), b = v.find_last_not_of(" \t");
        return a == std::string::npos ? "" : v.substr(a, b - a + 1);
    }

    bool read_chunked(std::string& body, Deadline d, std::string& err) {
        while (true) {
            size_t eol;
            while ((eol = buf_.find("\r\n")) == std::string::npos)
                if (!fill(d, err)) return false;
            size_t n = 0;
            if (!parse_chunk_size(buf_.substr(0, eol), kMaxBody, n)) {
                err = "bad HTTP chunk size";
                return false;
            }
            buf_.erase(0, eol + 2);
            if (body.size() + n > kMaxBody) {  // both <= kMaxBody: no overflow
                err = "HTTP body too large";
                return false;
            }
            if (n == 0) {  // trailer section ends with an empty line
                while (true) {
                    while ((eol = buf_.find("\r\n")) == std::string::npos)
                        if (!fill(d, err)) return false;
                    bool empty = eol == 0;
                    buf_.erase(0, eol + 2);
                    if (empty) return true;
                }
            }
            if (!need(n + 2, d, err)) return false;
            if (buf_.compare(n, 2, "\r\n") != 0) {  // chunk data must end in CRLF
                err = "bad HTTP chunk framing";
                return false;
            }
            body.append(buf_, 0, n);
            buf_.erase(0, n + 2);
        }
    }

    // ---- buffered I/O

    bool write_str(const std::string& s, Deadline d, std::string& err) {
        return s_.write_all(reinterpret_cast<const uint8_t*>(s.data()), s.size(), d, err);
    }

    bool fill(Deadline d, std::string& err) {
        uint8_t tmp[4096];
        long n = s_.read_some(tmp, sizeof tmp, d, err);
        if (n == 0) {
            err = "connection closed";
            return false;
        }
        if (n < 0) return false;
        buf_.append(reinterpret_cast<char*>(tmp), static_cast<size_t>(n));
        // HTTP/1.1 carries one response at a time, so any bytes are ours.
        // (HTTP/2 marks this per stream in h2_exchange.)
        if (!h2_) response_started_ = true;
        return true;
    }

    bool need(size_t n, Deadline d, std::string& err) {
        while (buf_.size() < n)
            if (!fill(d, err)) return false;
        return true;
    }

    std::string ip_, host_;
    int port_;
    std::string path_, authority_;
    TlsStream s_;
    std::string buf_;
    bool h2_ = false;
    uint32_t next_stream_ = 1;
};

}  // namespace

uint16_t random_id() {
    return static_cast<uint16_t>(std::uniform_int_distribution<int>(0, 0xffff)(rng()));
}

std::string random_label(size_t len) {
    static const char chars[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    std::uniform_int_distribution<size_t> pick(0, sizeof chars - 2);
    std::string s;
    for (size_t i = 0; i < len; ++i) s.push_back(chars[pick(rng())]);
    return s;
}

std::unique_ptr<Transport> make_transport(const Server& s, Protocol p, int port) {
    if (!s.supports(p)) return nullptr;
    switch (p) {
        case Protocol::UDP: return std::make_unique<UdpTransport>(s.address, port ? port : 53);
        case Protocol::TCP: return std::make_unique<TcpTransport>(s.address, port ? port : 53);
        case Protocol::DoT: return std::make_unique<DotTransport>(s.address, port ? port : 853, s.tls_host);
        case Protocol::DoH: {
            std::string host, path;
            int url_port = 443;
            if (!parse_https_url(s.doh_url, host, url_port, path)) return nullptr;
            return std::make_unique<DohTransport>(s.address, host, port ? port : url_port, path);
        }
    }
    return nullptr;
}
