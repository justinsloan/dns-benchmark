#include "system_dns.h"

#include <cstdio>
#include <fstream>
#include <sstream>

std::vector<std::string> parse_resolv_conf(std::istream& in) {
    std::vector<std::string> out;
    std::string line;
    while (std::getline(in, line)) {
        std::istringstream ls(line);
        std::string key, addr;
        if (!(ls >> key) || key != "nameserver" || !(ls >> addr)) continue;
        if (is_valid_ip(addr)) out.push_back(addr);
    }
    return out;
}

std::vector<std::string> parse_resolvectl_dns(const std::string& text) {
    std::vector<std::string> out;
    std::istringstream in(text);
    std::string line;
    while (std::getline(in, line)) {
        // The label ends at the first ": " (IPv6 addresses contain bare ':').
        size_t colon = line.find(": ");
        if (colon == std::string::npos) continue;
        std::istringstream rest(line.substr(colon + 2));
        std::string tok;
        while (rest >> tok) {
            // Strip DoT server names ("1.1.1.1#cloudflare-dns.com") and ports
            // in the "addr:port" / "[v6]:port" forms resolvectl may print.
            if (size_t hash = tok.find('#'); hash != std::string::npos) tok.resize(hash);
            if (!tok.empty() && tok.front() == '[') {
                size_t close = tok.find(']');
                if (close == std::string::npos) continue;
                tok = tok.substr(1, close - 1);
            } else if (tok.find(':') != std::string::npos && tok.find('.') != std::string::npos &&
                       tok.find(':') == tok.rfind(':')) {
                tok.resize(tok.find(':'));  // IPv4 with port
            }
            if (is_valid_ip(tok)) out.push_back(tok);
        }
    }
    return out;
}

bool is_loopback_address(const std::string& ip) {
    return ip.rfind("127.", 0) == 0 || ip == "::1";
}

namespace {

std::vector<std::string> read_resolv_file(const char* path) {
    std::ifstream f(path);
    return f ? parse_resolv_conf(f) : std::vector<std::string>{};
}

std::string run_command(const char* cmd) {
    std::string out;
    FILE* p = popen(cmd, "r");
    if (!p) return out;
    char buf[512];
    size_t n;
    while ((n = fread(buf, 1, sizeof buf, p)) > 0) out.append(buf, n);
    pclose(p);
    return out;
}

}  // namespace

std::vector<Server> discover_system_servers() {
    std::vector<std::string> addrs = read_resolv_file("/etc/resolv.conf");
    bool uses_stub = false;
    for (const auto& a : addrs) uses_stub |= is_loopback_address(a);
    if (uses_stub || addrs.empty()) {
        for (auto& a : read_resolv_file("/run/systemd/resolve/resolv.conf")) addrs.push_back(a);
        for (auto& a : parse_resolvectl_dns(run_command("resolvectl dns 2>/dev/null")))
            addrs.push_back(a);
    }

    std::vector<Server> out;
    for (const auto& a : addrs) {
        bool dup = false;
        for (const auto& s : out) dup |= s.address == a;
        if (dup) continue;
        Server s;
        s.address = a;
        s.source = Source::System;
        if (a == "127.0.0.53" || a == "127.0.0.54")
            s.name = "systemd-resolved";
        else if (is_loopback_address(a))
            s.name = "Local resolver";
        else if (a == "100.100.100.100")
            s.name = "Tailscale";
        else
            s.name = "System";
        out.push_back(std::move(s));
    }
    return out;
}
