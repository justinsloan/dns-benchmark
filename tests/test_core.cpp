// Unit tests for the network-free parts of the core. Run with `make test`.
#include <cmath>
#include <cstdio>
#include <sstream>
#include <string>
#include <vector>

#include "benchmark.h"
#include "dns_message.h"
#include "servers.h"
#include "stats.h"
#include "system_dns.h"
#include "tls.h"

#include <netinet/in.h>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <functional>
#include <thread>

#include "transport.h"

static int g_failed = 0, g_checks = 0;

#define CHECK(cond)                                                              \
    do {                                                                         \
        ++g_checks;                                                              \
        if (!(cond)) {                                                           \
            ++g_failed;                                                          \
            std::fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #cond); \
        }                                                                        \
    } while (0)

static std::vector<uint8_t> fake_reply(const std::vector<uint8_t>& query, int rcode) {
    std::vector<uint8_t> r = query;
    r[2] |= 0x80;  // QR
    r[3] = static_cast<uint8_t>((r[3] & 0xf0) | rcode);
    return r;
}

static void test_encode_name() {
    std::vector<uint8_t> out;
    CHECK(dns::encode_name("www.Example.com.", out));
    std::vector<uint8_t> want = {3, 'w', 'w', 'w', 7, 'E', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0};
    CHECK(out == want);
    out.clear();
    CHECK(!dns::encode_name("bad..name", out));
    out.clear();
    CHECK(!dns::encode_name(std::string(64, 'a') + ".com", out));
}

static void test_query_and_reply() {
    auto q = dns::build_query(0x1234, "example.com", dns::kTypeA, true);
    CHECK(q.size() == 12 + 13 + 4 + 11);
    CHECK(q[0] == 0x12 && q[1] == 0x34);
    CHECK(q[2] == 0x01);  // RD

    auto ok = dns::parse_reply(fake_reply(q, 0).data(), q.size(), 0x1234, "EXAMPLE.com.", dns::kTypeA);
    CHECK(ok.valid && ok.rcode == 0);

    auto nx = dns::parse_reply(fake_reply(q, 3).data(), q.size(), 0x1234, "example.com", dns::kTypeA);
    CHECK(nx.valid && nx.rcode == 3 && dns::rcode_is_answer(nx.rcode));
    CHECK(!dns::rcode_is_answer(2));

    auto badid = dns::parse_reply(fake_reply(q, 0).data(), q.size(), 0x9999, "example.com", dns::kTypeA);
    CHECK(!badid.valid);
    auto badname = dns::parse_reply(fake_reply(q, 0).data(), q.size(), 0x1234, "example.org", dns::kTypeA);
    CHECK(!badname.valid);
    auto notresp = dns::parse_reply(q.data(), q.size(), 0x1234, "example.com", dns::kTypeA);
    CHECK(!notresp.valid);
    CHECK(!dns::parse_reply(q.data(), 5, 0x1234, "example.com", dns::kTypeA).valid);
    CHECK(dns::rcode_name(3) == "NXDOMAIN");
}

static void test_stats() {
    std::vector<Sample> s = {{10, true, true}, {30, true, false}, {20, true, true}, {0, false, true}};
    Summary sum = summarize(s);
    CHECK(sum.sent == 4 && sum.ok == 3);
    CHECK(std::fabs(sum.loss_pct - 25.0) < 1e-9);
    CHECK(sum.median == 20 && sum.mean == 20 && sum.min == 10 && sum.max == 30);
    CHECK(sum.median_cached == 15 && sum.median_uncached == 30);
    CHECK(std::isnan(summarize({}).median));
    CHECK(median_of({4, 1, 3, 2}) == 2.5);
}

static void test_resolv_conf() {
    std::istringstream in(
        "# comment\nnameserver 127.0.0.53\nnameserver   8.8.8.8 \n"
        "nameserver 2606:4700:4700::1111\nnameserver bogus\nsearch lan\n");
    auto v = parse_resolv_conf(in);
    CHECK(v.size() == 3);
    CHECK(v.size() == 3 && v[0] == "127.0.0.53" && v[1] == "8.8.8.8" && v[2] == "2606:4700:4700::1111");

    auto r = parse_resolvectl_dns(
        "Global: 1.1.1.1#cloudflare-dns.com\nLink 2 (eth0):\nLink 3 (wlan0): 10.20.30.1 fe80::1%3\n");
    CHECK(r.size() == 3);
    CHECK(r.size() == 3 && r[0] == "1.1.1.1" && r[1] == "10.20.30.1");
    CHECK(is_loopback_address("127.0.0.53") && !is_loopback_address("10.0.0.1"));
}

static void test_servers() {
    CHECK(is_valid_ip("1.1.1.1"));
    CHECK(is_valid_ip("2001:db8::1"));
    CHECK(!is_valid_ip("1.1.1"));
    CHECK(!is_valid_ip("example.com"));
    CHECK(!is_valid_ip(""));

    std::string host, path;
    int port = 0;
    CHECK(parse_https_url("https://dns.google/dns-query", host, port, path));
    CHECK(host == "dns.google" && port == 443 && path == "/dns-query");
    CHECK(parse_https_url("https://example.net:8443/q?x=1", host, port, path));
    CHECK(host == "example.net" && port == 8443 && path == "/q?x=1");
    CHECK(parse_https_url("https://[2606:4700::1111]/dns-query", host, port, path));
    CHECK(host == "[2606:4700::1111]" && port == 443);
    CHECK(!parse_https_url("http://dns.google/dns-query", host, port, path));
    CHECK(!parse_https_url("https://host:99999/", host, port, path));

    for (const auto& s : public_servers()) {
        CHECK(is_valid_ip(s.address));
        CHECK(s.supports(Protocol::DoT) && s.supports(Protocol::DoH));
    }
    Server lan;
    lan.address = "192.168.1.1";
    CHECK(lan.supports(Protocol::UDP) && !lan.supports(Protocol::DoT) && !lan.supports(Protocol::DoH));

    // Round-trip custom servers through the config file.
    std::string path_conf = "build/test_servers.conf";
    Server c;
    c.name = "My\tDNS";
    c.address = "94.140.14.14";
    c.tls_host = "dns.adguard-dns.com";
    c.enabled = false;
    CHECK(save_custom_servers(path_conf, {c}));
    auto loaded = load_custom_servers(path_conf);
    CHECK(loaded.size() == 1);
    if (loaded.size() == 1) {
        CHECK(loaded[0].address == c.address && loaded[0].name == "My DNS");
        CHECK(loaded[0].tls_host == c.tls_host && loaded[0].doh_url.empty() && !loaded[0].enabled);
        CHECK(loaded[0].source == Source::Custom);
    }
}

static Server make_server(const std::string& addr, Source src, const std::string& name,
                          const std::string& tls = "") {
    Server s;
    s.address = addr;
    s.source = src;
    s.name = name;
    s.tls_host = tls;
    return s;
}

static void test_merge_servers() {
    std::vector<Server> sys = {make_server("192.168.1.1", Source::System, "System"),
                               make_server("1.1.1.1", Source::System, "System")};
    std::vector<Server> pub = {make_server("1.1.1.1", Source::Public, "Cloudflare", "one.one.one.one"),
                               make_server("8.8.8.8", Source::Public, "Google", "dns.google")};
    std::vector<Server> custom = {make_server("192.168.1.1", Source::Custom, "Router", "router.lan"),
                                  make_server("94.140.14.14", Source::Custom, "AdGuard"),
                                  make_server("94.140.14.14", Source::Custom, "Dup")};
    auto m = merge_server_lists(sys, pub, custom);
    CHECK(m.size() == 4);
    if (m.size() != 4) return;
    // A custom server whose address became a system server keeps its settings
    // and position, and stays Custom so it is still saved.
    CHECK(m[0].address == "192.168.1.1" && m[0].source == Source::Custom);
    CHECK(m[0].name == "Router" && m[0].tls_host == "router.lan");
    // System beats public for the same address; order is system, public, custom.
    CHECK(m[1].address == "1.1.1.1" && m[1].source == Source::System);
    CHECK(m[2].address == "8.8.8.8");
    CHECK(m[3].address == "94.140.14.14" && m[3].name == "AdGuard");
}

// A peer that closes during the TLS handshake must be reported as a closed
// connection, not as an unrelated I/O error.
static void test_tls_closed_during_handshake() {
    int ls = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t len = sizeof sa;
    CHECK(bind(ls, reinterpret_cast<sockaddr*>(&sa), sizeof sa) == 0);
    CHECK(listen(ls, 1) == 0);
    getsockname(ls, reinterpret_cast<sockaddr*>(&sa), &len);
    std::thread peer([ls] {
        int c = accept(ls, nullptr, nullptr);
        if (c >= 0) close(c);
    });
    TlsStream tls;
    std::string err;
    bool ok = tls.connect("127.0.0.1", ntohs(sa.sin_port), "example.com", {}, deadline_in_ms(2000), err);
    peer.join();
    close(ls);
    CHECK(!ok);
    CHECK(err.find("connection closed") != std::string::npos);
    if (err.find("connection closed") == std::string::npos) std::fprintf(stderr, "  got: %s\n", err.c_str());
}

static void test_http_sizes() {
    size_t n = 0;
    CHECK(parse_chunk_size("1a", 65535, n) && n == 26);
    CHECK(parse_chunk_size("FF;name=value", 65535, n) && n == 255);
    CHECK(parse_chunk_size(" 0 ", 65535, n) && n == 0);
    CHECK(!parse_chunk_size("", 65535, n));
    CHECK(!parse_chunk_size("zz", 65535, n));       // strtoul would have said 0 = last chunk
    CHECK(!parse_chunk_size("ffffffffffffffff", 65535, n));  // used to wrap around
    CHECK(!parse_chunk_size("10000", 65535, n));
    CHECK(parse_content_length("512", 65535, n) && n == 512);
    CHECK(!parse_content_length("12abc", 65535, n));
    CHECK(!parse_content_length("-1", 65535, n));
    CHECK(!parse_content_length("99999999999999999999999", 65535, n));
}

static void test_server_validation() {
    CHECK(is_valid_tls_host("dns.google"));
    CHECK(is_valid_tls_host("dns.google."));
    CHECK(is_valid_tls_host("1.1.1.1"));
    CHECK(!is_valid_tls_host(""));
    CHECK(!is_valid_tls_host("dns..google"));
    CHECK(!is_valid_tls_host("https://dns.google"));
    CHECK(!is_valid_tls_host("dns google"));

    // A hand-edited config with bad DoT/DoH values: shown as unsupported
    // ("n/a") and planned for UDP/TCP only, instead of failing every lookup.
    Server s = make_server("9.9.9.9", Source::Custom, "x", "bad host!");
    s.doh_url = "dns.quad9.net/dns-query";
    CHECK(s.supports(Protocol::UDP) && !s.supports(Protocol::DoT) && !s.supports(Protocol::DoH));
    BenchmarkConfig cfg;
    cfg.lookups = 5;
    CHECK(planned_lookups(s, cfg) == 10);
    CHECK(make_transport(s, Protocol::DoH) == nullptr);
}

static void test_add_or_update_server() {
    std::vector<Server> list = {make_server("8.8.8.8", Source::Public, "Google", "dns.google")};
    add_or_update_server(list, make_server("8.8.8.8", Source::Custom, "8.8.8.8"));  // -s 8.8.8.8
    CHECK(list.size() == 1);
    CHECK(list[0].name == "Google" && list[0].tls_host == "dns.google" && list[0].source == Source::Public);
    add_or_update_server(list, make_server("8.8.8.8", Source::Custom, "8.8.8.8", "other.example"));
    CHECK(list.size() == 1 && list[0].tls_host == "other.example");
    add_or_update_server(list, make_server("9.9.9.9", Source::Custom, "9.9.9.9"));
    add_or_update_server(list, make_server("9.9.9.9", Source::Custom, "9.9.9.9"));
    CHECK(list.size() == 2);
}

// ---- A scriptable DNS-over-TCP server on localhost, to exercise the
// connection reuse / retry rules of the connection-oriented transports.

enum class Act { Answer, Close, SlowClose, Partial, Silent };

class MiniTcpServer {
public:
    // plan(connection_index, query_index_on_that_connection) -> what to do
    explicit MiniTcpServer(std::function<Act(int, int)> plan) : plan_(std::move(plan)) {
        ls_ = socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in sa{};
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        socklen_t len = sizeof sa;
        bind(ls_, reinterpret_cast<sockaddr*>(&sa), sizeof sa);
        listen(ls_, 4);
        getsockname(ls_, reinterpret_cast<sockaddr*>(&sa), &len);
        port = ntohs(sa.sin_port);
        th_ = std::thread([this] { run(); });
    }
    ~MiniTcpServer() {
        stop_ = true;
        shutdown(ls_, SHUT_RDWR);  // wakes accept()
        th_.join();
        close(ls_);
    }
    int port = 0;
    std::atomic<int> accepts{0};

private:
    static bool read_n(int fd, uint8_t* p, size_t n) {
        while (n) {
            ssize_t r = recv(fd, p, n, 0);
            if (r <= 0) return false;
            p += r;
            n -= static_cast<size_t>(r);
        }
        return true;
    }
    void run() {
        for (int conn = 0; !stop_; ++conn) {
            int c = accept(ls_, nullptr, nullptr);
            if (c < 0) return;
            ++accepts;
            timeval tv{3, 0};
            setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
            for (int q = 0;; ++q) {
                uint8_t lenbuf[2];
                if (!read_n(c, lenbuf, 2)) break;
                std::vector<uint8_t> msg(static_cast<size_t>((lenbuf[0] << 8) | lenbuf[1]));
                if (!read_n(c, msg.data(), msg.size())) break;
                Act a = plan_(conn, q);
                if (a == Act::Close) break;
                if (a == Act::SlowClose) {  // hang up only after 300 ms
                    std::this_thread::sleep_for(std::chrono::milliseconds(300));
                    break;
                }
                if (a == Act::Partial) {
                    send(c, lenbuf, 1, MSG_NOSIGNAL);  // one byte of the length prefix
                    break;
                }
                if (a == Act::Silent) {
                    uint8_t b;
                    while (!stop_ && recv(c, &b, 1, 0) > 0) {}  // until the client gives up
                    break;
                }
                msg[2] |= 0x80;  // QR: echo the query back as a NOERROR response
                send(c, lenbuf, 2, MSG_NOSIGNAL);
                send(c, msg.data(), msg.size(), MSG_NOSIGNAL);
            }
            close(c);
        }
    }
    std::function<Act(int, int)> plan_;
    int ls_ = -1;
    std::atomic<bool> stop_{false};
    std::thread th_;
};

static void test_retry_rules() {
    Server local = make_server("127.0.0.1", Source::Custom, "local");

    {   // Reused connection closed before any reply: retried on a new one.
        MiniTcpServer srv([](int conn, int q) { return conn == 0 && q == 1 ? Act::Close : Act::Answer; });
        auto t = make_transport(local, Protocol::TCP, srv.port);
        LookupResult r1 = t->lookup("example.com", dns::kTypeA, 2000);
        LookupResult r2 = t->lookup("example.com", dns::kTypeA, 2000);
        CHECK(r1.ok && r1.connect_ms >= 0);
        CHECK(r2.ok && r2.connect_ms >= 0);  // second lookup needed a new connection
        CHECK(srv.accepts == 2);
    }
    {   // Part of the reply arrived, then the connection died: a real failure,
        // recorded as such and NOT retried.
        MiniTcpServer srv([](int, int q) { return q == 1 ? Act::Partial : Act::Answer; });
        auto t = make_transport(local, Protocol::TCP, srv.port);
        CHECK(t->lookup("example.com", dns::kTypeA, 2000).ok);
        LookupResult r2 = t->lookup("example.com", dns::kTypeA, 2000);
        CHECK(!r2.ok);
        CHECK(srv.accepts == 1);
    }
    {   // Connection setup, the retry and the exchange share one deadline:
        // 300 ms lost on the dead connection leave only ~100 ms for the retry.
        MiniTcpServer srv([](int conn, int q) {
            if (conn == 0) return q == 0 ? Act::Answer : Act::SlowClose;
            return Act::Silent;
        });
        auto t = make_transport(local, Protocol::TCP, srv.port);
        CHECK(t->lookup("example.com", dns::kTypeA, 2000).ok);
        auto t0 = std::chrono::steady_clock::now();
        LookupResult r = t->lookup("example.com", dns::kTypeA, 400);
        double ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
        CHECK(!r.ok && r.error == "timeout");
        CHECK(ms < 550);  // not 400 ms per attempt
        if (ms >= 550) std::fprintf(stderr, "  lookup took %.0f ms\n", ms);
        t.reset();  // close our side so the silent server thread can finish
    }
}

static ServerResults make_results(Protocol p, std::vector<Sample> samples) {
    ServerResults r;
    r.proto[static_cast<int>(p)].samples = std::move(samples);
    return r;
}

static void test_ranking() {
    auto fast = make_results(Protocol::UDP, {{5, true, true}, {7, true, true}, {6, true, true}});
    auto slow = make_results(Protocol::UDP, {{50, true, true}, {70, true, true}, {60, true, true}});
    auto lossy = make_results(Protocol::UDP, {{1, true, true}, {0, false, true}, {0, false, true}});
    auto dead = make_results(Protocol::UDP, {{0, false, true}, {0, false, true}});
    ServerResults empty;

    Score f = score_server(fast, -1), s = score_server(slow, -1), l = score_server(lossy, -1),
          d = score_server(dead, -1), e = score_server(empty, -1);
    CHECK(f.healthy && f.median == 6);
    CHECK(score_better(f, s) && !score_better(s, f));
    CHECK(score_better(s, l));  // lossy is faster but unhealthy
    CHECK(score_better(l, d));  // some answers beat none
    CHECK(score_better(d, e) || !score_better(e, d));

    // Best-protocol mode picks the faster protocol.
    ServerResults multi;
    multi.proto[static_cast<int>(Protocol::UDP)].samples = {{20, true, true}};
    multi.proto[static_cast<int>(Protocol::DoH)].samples = {{12, true, true}};
    Score m = score_server(multi, -1);
    CHECK(m.proto == Protocol::DoH && m.median == 12);
    CHECK(score_server(multi, static_cast<int>(Protocol::UDP)).median == 20);

    BenchmarkConfig cfg;
    cfg.lookups = 10;
    Server lan;
    lan.address = "192.168.1.1";
    CHECK(planned_lookups(lan, cfg) == 20);  // UDP + TCP only
    CHECK(planned_lookups(public_servers()[0], cfg) == 40);
    lan.enabled = false;
    CHECK(planned_lookups(lan, cfg) == 0);
}

int main() {
    signal(SIGPIPE, SIG_IGN);  // as in the apps: writes to a closed peer must not kill us
    test_encode_name();
    test_query_and_reply();
    test_stats();
    test_resolv_conf();
    test_servers();
    test_ranking();
    test_merge_servers();
    test_http_sizes();
    test_server_validation();
    test_add_or_update_server();
    test_retry_rules();
    test_tls_closed_during_handshake();
    std::printf("%d/%d checks passed\n", g_checks - g_failed, g_checks);
    return g_failed ? 1 : 0;
}
