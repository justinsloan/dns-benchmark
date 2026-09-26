// Discovery of the DNS servers this machine is configured to use.
#pragma once

#include <istream>
#include <string>
#include <vector>

#include "servers.h"

// Extracts `nameserver` addresses from resolv.conf-formatted text.
std::vector<std::string> parse_resolv_conf(std::istream& in);

// Extracts addresses from `resolvectl dns` output, e.g.
//   Global: 1.1.1.1#cloudflare-dns.com
//   Link 3 (wlp2s0): 10.0.0.1 fe80::1%3
std::vector<std::string> parse_resolvectl_dns(const std::string& text);

bool is_loopback_address(const std::string& ip);

// /etc/resolv.conf, and when that points at the systemd-resolved stub, the
// real upstream servers from /run/systemd/resolve/resolv.conf and resolvectl.
std::vector<Server> discover_system_servers();
