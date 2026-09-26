#include "servers.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <sstream>

const char* protocol_name(Protocol p) {
    switch (p) {
        case Protocol::UDP: return "UDP";
        case Protocol::TCP: return "TCP";
        case Protocol::DoT: return "DoT";
        case Protocol::DoH: return "DoH";
    }
    return "?";
}

const char* source_name(Source s) {
    switch (s) {
        case Source::System: return "System";
        case Source::Public: return "Public";
        case Source::Custom: return "Custom";
    }
    return "?";
}

bool Server::supports(Protocol p) const {
    switch (p) {
        case Protocol::UDP:
        case Protocol::TCP: return true;
        case Protocol::DoT: return is_valid_tls_host(tls_host);
        case Protocol::DoH: {
            std::string host, path;
            int port;
            return parse_https_url(doh_url, host, port, path);
        }
    }
    return false;
}

std::string Server::label() const {
    if (name.empty() || name == address) return address;
    return name + " (" + address + ")";
}

bool is_valid_ip(const std::string& s) {
    if (s.empty()) return false;
    // Strict dotted-quad for IPv4: getaddrinfo would also accept inet_aton
    // shorthands such as "1.1.1" (= 1.1.0.1), which is never what a user means.
    if (s.find(':') == std::string::npos) {
        in_addr a4;
        return inet_pton(AF_INET, s.c_str(), &a4) == 1;
    }
    // IPv6 via getaddrinfo so scoped link-local addresses (fe80::1%eth0) work.
    addrinfo hints{};
    hints.ai_flags = AI_NUMERICHOST;
    hints.ai_family = AF_UNSPEC;
    addrinfo* res = nullptr;
    if (getaddrinfo(s.c_str(), nullptr, &hints, &res) != 0) return false;
    freeaddrinfo(res);
    return true;
}

bool is_valid_tls_host(const std::string& s) {
    if (s.empty() || s.size() > 253) return false;
    if (is_valid_ip(s)) return true;
    size_t label = 0;
    for (char c : s) {
        if (c == '.') {
            if (label == 0) return false;  // empty label
            label = 0;
        } else if (std::isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_') {
            if (++label > 63) return false;
        } else {
            return false;
        }
    }
    return true;  // a trailing dot (FQDN) is fine
}

bool parse_https_url(const std::string& url, std::string& host, int& port, std::string& path) {
    const std::string scheme = "https://";
    if (url.compare(0, scheme.size(), scheme) != 0) return false;
    std::string rest = url.substr(scheme.size());
    size_t slash = rest.find('/');
    std::string authority = rest.substr(0, slash);
    path = slash == std::string::npos ? "/dns-query" : rest.substr(slash);
    port = 443;

    std::string port_str;
    bool has_port = false;
    if (!authority.empty() && authority.front() == '[') {  // [v6addr]:port
        size_t close = authority.find(']');
        if (close == std::string::npos) return false;
        host = authority.substr(0, close + 1);  // keep brackets for the Host header
        std::string tail = authority.substr(close + 1);
        if (!tail.empty()) {
            if (tail.front() != ':') return false;
            port_str = tail.substr(1);
            has_port = true;
        }
    } else {
        size_t colon = authority.find(':');
        host = authority.substr(0, colon);
        if (colon != std::string::npos) {
            port_str = authority.substr(colon + 1);
            has_port = true;
        }
    }
    if (has_port) {
        char* end = nullptr;
        long v = std::strtol(port_str.c_str(), &end, 10);
        if (port_str.empty() || *end || v <= 0 || v > 65535) return false;
        port = static_cast<int>(v);
    }
    if (host.empty() || host == "[]" || host.find_first_of(" \t/?#@") != std::string::npos) return false;
    return true;
}

std::vector<Server> public_servers() {
    auto pub = [](std::string name, std::string addr, std::string tls, std::string doh) {
        Server s;
        s.name = std::move(name);
        s.address = std::move(addr);
        s.source = Source::Public;
        s.tls_host = std::move(tls);
        s.doh_url = std::move(doh);
        return s;
    };
    return {
        pub("Cloudflare", "1.1.1.1", "one.one.one.one", "https://cloudflare-dns.com/dns-query"),
        pub("Cloudflare", "1.0.0.1", "one.one.one.one", "https://cloudflare-dns.com/dns-query"),
        pub("Cloudflare Family", "1.1.1.3", "family.cloudflare-dns.com",
            "https://family.cloudflare-dns.com/dns-query"),
        pub("Google", "8.8.8.8", "dns.google", "https://dns.google/dns-query"),
        pub("Google", "8.8.4.4", "dns.google", "https://dns.google/dns-query"),
        pub("Quad9", "9.9.9.9", "dns.quad9.net", "https://dns.quad9.net/dns-query"),
        pub("Quad9", "149.112.112.112", "dns.quad9.net", "https://dns.quad9.net/dns-query"),
        pub("OpenDNS", "208.67.222.222", "dns.opendns.com", "https://doh.opendns.com/dns-query"),
    };
}

std::vector<Server> merge_server_lists(const std::vector<Server>& system,
                                       const std::vector<Server>& pub,
                                       const std::vector<Server>& custom) {
    std::vector<Server> out;
    auto find = [&out](const std::string& addr) {
        return std::find_if(out.begin(), out.end(), [&](const Server& s) { return s.address == addr; });
    };
    for (const auto* list : {&system, &pub})
        for (const auto& s : *list)
            if (find(s.address) == out.end()) out.push_back(s);
    for (const auto& s : custom) {
        auto it = find(s.address);
        if (it == out.end())
            out.push_back(s);
        else if (it->source != Source::Custom)
            *it = s;  // custom settings win; a duplicate custom line is ignored
    }
    return out;
}

void add_or_update_server(std::vector<Server>& list, const Server& s) {
    auto it = std::find_if(list.begin(), list.end(), [&](const Server& x) { return x.address == s.address; });
    if (it == list.end()) {
        list.push_back(s);
        return;
    }
    if (!s.name.empty() && s.name != s.address) it->name = s.name;
    if (!s.tls_host.empty()) it->tls_host = s.tls_host;
    if (!s.doh_url.empty()) it->doh_url = s.doh_url;
}

std::string custom_servers_path() {
    std::string base;
    if (const char* x = std::getenv("XDG_CONFIG_HOME"); x && *x) {
        base = x;
    } else if (const char* h = std::getenv("HOME"); h && *h) {
        base = std::string(h) + "/.config";
    } else {
        base = ".";
    }
    return base + "/dns-benchmark/servers.conf";
}

std::vector<Server> load_custom_servers(const std::string& path) {
    std::vector<Server> out;
    std::ifstream in(path);
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty() || line[0] == '#') continue;
        std::vector<std::string> f;
        std::stringstream ss(line);
        std::string field;
        while (std::getline(ss, field, '\t')) f.push_back(field);
        if (f.empty() || !is_valid_ip(f[0])) continue;
        Server s;
        s.source = Source::Custom;
        s.address = f[0];
        if (f.size() > 1) s.name = f[1];
        if (f.size() > 2) s.tls_host = f[2];
        if (f.size() > 3) s.doh_url = f[3];
        if (f.size() > 4) s.enabled = f[4] != "0";
        out.push_back(std::move(s));
    }
    return out;
}

namespace {
std::string clean(const std::string& s) {
    std::string r;
    for (char c : s) r.push_back(c == '\t' || c == '\n' || c == '\r' ? ' ' : c);
    return r;
}

void make_parent_dirs(const std::string& path) {
    for (size_t pos = path.find('/', 1); pos != std::string::npos; pos = path.find('/', pos + 1))
        mkdir(path.substr(0, pos).c_str(), 0755);  // EEXIST is fine
}
}  // namespace

bool save_custom_servers(const std::string& path, const std::vector<Server>& servers) {
    make_parent_dirs(path);
    std::string tmp = path + ".tmp";
    {
        std::ofstream out(tmp, std::ios::trunc);
        if (!out) return false;
        out << "# dns-benchmark custom servers: address\tname\ttls_host\tdoh_url\tenabled\n";
        for (const auto& s : servers) {
            if (s.source != Source::Custom) continue;
            out << clean(s.address) << '\t' << clean(s.name) << '\t' << clean(s.tls_host) << '\t'
                << clean(s.doh_url) << '\t' << (s.enabled ? 1 : 0) << '\n';
        }
        if (!out) return false;
    }
    return std::rename(tmp.c_str(), path.c_str()) == 0;
}
