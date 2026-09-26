// DNS server descriptions: built-in public resolvers, user-defined servers and
// their persistence.
#pragma once

#include <array>
#include <string>
#include <vector>

enum class Protocol { UDP = 0, TCP, DoT, DoH };
constexpr int kProtocolCount = 4;
constexpr std::array<Protocol, kProtocolCount> kAllProtocols = {
    Protocol::UDP, Protocol::TCP, Protocol::DoT, Protocol::DoH};

const char* protocol_name(Protocol p);  // "UDP", "TCP", "DoT", "DoH"

enum class Source { System, Public, Custom };
const char* source_name(Source s);

struct Server {
    std::string name;
    std::string address;   // numeric IPv4/IPv6 (IPv6 may carry a %scope)
    Source source = Source::Custom;
    std::string tls_host;  // DoT: SNI + certificate name; empty = DoT unsupported
    std::string doh_url;   // DoH: https://host[:port]/path; empty = DoH unsupported
    bool enabled = true;

    // UDP/TCP always; DoT/DoH only with a *valid* tls_host / doh_url, so a
    // bad hand-edited config shows "n/a" instead of 100% failures.
    bool supports(Protocol p) const;
    std::string label() const;  // "Name (address)" or just the address
};

// True for a numeric IPv4 or IPv6 address (IPv6 scope ids such as
// fe80::1%eth0 are accepted).
bool is_valid_ip(const std::string& s);

// A DoT name: a DNS hostname (letters, digits, '-', '.') or an IP literal.
bool is_valid_tls_host(const std::string& s);

// Validates a DoH URL of the form https://host[:port][/path].
bool parse_https_url(const std::string& url, std::string& host, int& port, std::string& path);

std::vector<Server> public_servers();

// Builds the initial server list: system servers, then public ones, skipping
// duplicate addresses. A saved custom server replaces a system/public entry
// with the same address (in place), so its name and DoT/DoH settings are kept
// and it is still written back when custom servers are saved.
std::vector<Server> merge_server_lists(const std::vector<Server>& system,
                                       const std::vector<Server>& pub,
                                       const std::vector<Server>& custom);

// Adds `s` to `list`, or, if its address is already there, fills in that
// entry's name / DoT host / DoH URL from the non-empty fields of `s`.
void add_or_update_server(std::vector<Server>& list, const Server& s);

// ~/.config/dns-benchmark/servers.conf (honours $XDG_CONFIG_HOME).
std::string custom_servers_path();
// One server per line: address<TAB>name<TAB>tls_host<TAB>doh_url<TAB>enabled.
std::vector<Server> load_custom_servers(const std::string& path);
bool save_custom_servers(const std::string& path, const std::vector<Server>& servers);
