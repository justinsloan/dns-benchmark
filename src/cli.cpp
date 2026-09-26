#include "cli.h"

#include <signal.h>

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <thread>

#include "benchmark.h"
#include "dns_message.h"
#include "system_dns.h"

namespace {

volatile sig_atomic_t g_interrupted = 0;

void usage(const char* argv0) {
    std::printf(
        "Usage: %s --cli [options]\n"
        "  -n, --lookups N      lookups per protocol per server (default 50)\n"
        "  -i, --interval MS    minimum ms between lookups to one server (default 1000)\n"
        "  -t, --timeout MS     per-lookup timeout (default 2000)\n"
        "  -p, --protocols LIST comma list of udp,tcp,dot,doh (default all)\n"
        "  -s, --server IP[,TLS_HOST[,DOH_URL]]  add a server (repeatable)\n"
        "      --only           benchmark only servers given with --server\n"
        "      --no-system      skip the system's configured servers\n"
        "      --no-public      skip the built-in public servers\n"
        "      --no-custom      skip custom servers saved from the GUI\n"
        "  -v, --verbose        print every lookup\n",
        argv0);
}

std::string fmt_ms(double v) {
    if (std::isnan(v)) return "-";
    char b[32];
    std::snprintf(b, sizeof b, "%.1f", v);
    return b;
}

bool parse_int(const char* s, int lo, int hi, int& out) {
    char* end = nullptr;
    long v = std::strtol(s, &end, 10);
    if (!*s || *end || v < lo || v > hi) return false;
    out = static_cast<int>(v);
    return true;
}

}  // namespace

int run_cli(int argc, char** argv) {
    BenchmarkConfig cfg;
    std::vector<Server> extra;
    bool only = false, sys = true, pub = true, custom = true, verbose = false;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto val = [&](const char* name) -> const char* {
            if (i + 1 >= argc) {
                std::fprintf(stderr, "%s needs a value\n", name);
                std::exit(2);
            }
            return argv[++i];
        };
        if (a == "--cli") continue;
        if (a == "-h" || a == "--help") {
            usage(argv[0]);
            return 0;
        } else if (a == "-n" || a == "--lookups") {
            if (!parse_int(val("-n"), 1, 100000, cfg.lookups)) return std::fprintf(stderr, "bad -n\n"), 2;
        } else if (a == "-i" || a == "--interval") {
            if (!parse_int(val("-i"), 0, 3600000, cfg.interval_ms)) return std::fprintf(stderr, "bad -i\n"), 2;
        } else if (a == "-t" || a == "--timeout") {
            if (!parse_int(val("-t"), 1, 60000, cfg.timeout_ms)) return std::fprintf(stderr, "bad -t\n"), 2;
        } else if (a == "-p" || a == "--protocols") {
            cfg.protocols = {false, false, false, false};
            std::stringstream ss(val("-p"));
            std::string p;
            while (std::getline(ss, p, ',')) {
                std::transform(p.begin(), p.end(), p.begin(), ::tolower);
                bool found = false;
                for (Protocol pr : kAllProtocols) {
                    std::string n = protocol_name(pr);
                    std::transform(n.begin(), n.end(), n.begin(), ::tolower);
                    if (n == p) cfg.protocols[static_cast<int>(pr)] = found = true;
                }
                if (!found) return std::fprintf(stderr, "unknown protocol '%s'\n", p.c_str()), 2;
            }
        } else if (a == "-s" || a == "--server") {
            std::stringstream ss(val("-s"));
            Server s;
            std::getline(ss, s.address, ',');
            std::getline(ss, s.tls_host, ',');
            std::getline(ss, s.doh_url);
            if (!is_valid_ip(s.address)) return std::fprintf(stderr, "invalid IP '%s'\n", s.address.c_str()), 2;
            std::string host, path;
            int port;
            if (!s.doh_url.empty() && !parse_https_url(s.doh_url, host, port, path))
                return std::fprintf(stderr, "invalid DoH URL '%s'\n", s.doh_url.c_str()), 2;
            if (!s.tls_host.empty() && !is_valid_tls_host(s.tls_host))
                return std::fprintf(stderr, "invalid DoT hostname '%s'\n", s.tls_host.c_str()), 2;
            s.name = s.address;
            extra.push_back(s);
        } else if (a == "--only") {
            only = true;
        } else if (a == "--no-system") {
            sys = false;
        } else if (a == "--no-public") {
            pub = false;
        } else if (a == "--no-custom") {
            custom = false;
        } else if (a == "-v" || a == "--verbose") {
            verbose = true;
        } else {
            std::fprintf(stderr, "unknown option '%s'\n", a.c_str());
            usage(argv[0]);
            return 2;
        }
    }

    // Same list the GUI builds (deduplicated by address), then -s servers:
    // a -s address already in the list only adds its DoT/DoH settings, so no
    // server is ever benchmarked twice (which would double its query rate).
    std::vector<Server> servers;
    if (!only) {
        servers = merge_server_lists(sys ? discover_system_servers() : std::vector<Server>{},
                                     pub ? public_servers() : std::vector<Server>{},
                                     custom ? load_custom_servers(custom_servers_path()) : std::vector<Server>{});
        std::erase_if(servers, [](const Server& s) { return !s.enabled; });
    }
    for (auto& s : extra) add_or_update_server(servers, s);
    if (servers.empty()) {
        std::fprintf(stderr, "no servers to benchmark\n");
        return 2;
    }

    std::vector<ServerResults> results(servers.size());
    int total = 0, max_per_server = 0;
    for (size_t i = 0; i < servers.size(); ++i) {
        results[i].planned = planned_lookups(servers[i], cfg);
        total += results[i].planned;
        max_per_server = std::max(max_per_server, results[i].planned);
    }
    std::fprintf(stderr, "Benchmarking %zu servers, %d lookups total (~%.0f s)...\n", servers.size(), total,
                 max_per_server * static_cast<double>(cfg.interval_ms) / 1000.0);

    signal(SIGINT, [](int) { g_interrupted = 1; });
    Benchmark bench;
    bench.start(servers, cfg);
    int done = 0;
    auto drain = [&] {
        for (auto& ev : bench.take_events()) {
            results[ev.server].add(ev);
            if (ev.server_finished) continue;
            ++done;
            if (verbose)
                std::fprintf(stderr, "%9.1f  %-28s %-3s %8s ms  %-40s %s\n", ev.at_ms,
                             servers[ev.server].label().c_str(), protocol_name(ev.proto),
                             ev.result.ok ? fmt_ms(ev.result.ms).c_str() : "-", ev.qname.c_str(),
                             ev.result.ok ? dns::rcode_name(ev.result.rcode).c_str() : ev.result.error.c_str());
        }
    };
    bool stopping = false;
    while (bench.running()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        if (g_interrupted && !stopping) {
            std::fprintf(stderr, "\nStopping...\n");
            bench.stop();
            stopping = true;
        }
        drain();
        if (!verbose) std::fprintf(stderr, "\r%d / %d lookups", done, total);
    }
    bench.join();
    drain();
    std::fprintf(stderr, "\n");

    // Rank and print.
    std::vector<Score> scores;
    for (const auto& r : results) scores.push_back(score_server(r, -1));  // once per server
    std::vector<size_t> order(servers.size());
    for (size_t i = 0; i < order.size(); ++i) order[i] = i;
    std::stable_sort(order.begin(), order.end(),
                     [&](size_t a, size_t b) { return score_better(scores[a], scores[b]); });

    std::printf("%-3s %-34s %-7s", "#", "Server", "Source");
    for (Protocol p : kAllProtocols)
        if (cfg.protocols[static_cast<int>(p)]) std::printf(" %9s", protocol_name(p));
    std::printf(" %7s  %s\n", "Loss%", "Best");
    int rank = 0;
    for (size_t i : order) {
        const Server& s = servers[i];
        std::printf("%-3d %-34s %-7s", ++rank, s.label().substr(0, 34).c_str(), source_name(s.source));
        int sent = 0, ok = 0;
        for (Protocol p : kAllProtocols) {
            if (!cfg.protocols[static_cast<int>(p)]) continue;
            Summary sum = results[i].summary(p);
            sent += static_cast<int>(sum.sent);
            ok += static_cast<int>(sum.ok);
            std::printf(" %9s", s.supports(p) ? fmt_ms(sum.median).c_str() : "n/a");
        }
        double loss = sent ? 100.0 * (sent - ok) / sent : 0;
        const Score& sc = scores[i];
        std::printf(" %7.1f  %s\n", loss,
                    sc.has_data ? (std::string(protocol_name(sc.proto)) + " " + fmt_ms(sc.median) + " ms").c_str()
                                : "no answers");
    }
    std::printf("(median ms per protocol; servers with >%.0f%% loss rank last)\n", kMaxHealthyLossPct);

    // Error summary.
    for (size_t i : order)
        for (Protocol p : kAllProtocols)
            for (auto& [err, n] : results[i].proto[static_cast<int>(p)].errors)
                std::printf("  %s %s: %d x %s\n", servers[i].label().c_str(), protocol_name(p), n, err.c_str());
    return 0;
}
