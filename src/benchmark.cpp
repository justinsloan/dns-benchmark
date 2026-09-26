#include "benchmark.h"

#include "dns_message.h"

const std::vector<std::string>& popular_domains() {
    static const std::vector<std::string> d = {
        "google.com",     "youtube.com",   "facebook.com",  "instagram.com", "wikipedia.org",
        "amazon.com",     "apple.com",     "microsoft.com", "netflix.com",   "linkedin.com",
        "reddit.com",     "x.com",         "whatsapp.com",  "yahoo.com",     "bing.com",
        "github.com",     "stackoverflow.com", "office.com", "live.com",     "zoom.us",
        "twitch.tv",      "ebay.com",      "cloudflare.com", "tiktok.com",   "pinterest.com",
        "paypal.com",     "spotify.com",   "adobe.com",     "dropbox.com",   "cnn.com",
        "bbc.co.uk",      "nytimes.com",   "imdb.com",      "wordpress.org", "mozilla.org",
        "ubuntu.com",     "debian.org",    "discord.com",   "openai.com",    "duckduckgo.com",
    };
    return d;
}

namespace {
std::vector<Protocol> protocols_for(const Server& s, const BenchmarkConfig& cfg) {
    std::vector<Protocol> v;
    for (Protocol p : kAllProtocols)
        if (cfg.protocols[static_cast<int>(p)] && s.supports(p)) v.push_back(p);
    return v;
}
}  // namespace

int planned_lookups(const Server& s, const BenchmarkConfig& cfg) {
    return s.enabled ? cfg.lookups * static_cast<int>(protocols_for(s, cfg).size()) : 0;
}

Benchmark::~Benchmark() {
    stop();
    join();
}

void Benchmark::start(const std::vector<Server>& servers, const BenchmarkConfig& cfg, Notify notify) {
    if (running()) return;
    join();  // reap threads from a previous run
    stop_ = false;
    notify_ = std::move(notify);
    {
        std::lock_guard lk(mu_);
        events_.clear();
    }
    auto t0 = Clock::now();
    for (size_t i = 0; i < servers.size(); ++i) {
        if (planned_lookups(servers[i], cfg) == 0) continue;
        ++active_;
        threads_.emplace_back(&Benchmark::worker, this, i, servers[i], cfg, t0);
    }
}

void Benchmark::stop() {
    {
        std::lock_guard lk(mu_);
        stop_ = true;
    }
    cv_.notify_all();
}

void Benchmark::join() {
    for (auto& t : threads_)
        if (t.joinable()) t.join();
    threads_.clear();
}

std::vector<BenchmarkEvent> Benchmark::take_events() {
    std::lock_guard lk(mu_);
    std::vector<BenchmarkEvent> out;
    out.swap(events_);
    return out;
}

bool Benchmark::sleep_until(Clock::time_point t) {
    std::unique_lock lk(mu_);
    return !cv_.wait_until(lk, t, [&] { return stop_.load(); });
}

void Benchmark::push(BenchmarkEvent ev) {
    {
        std::lock_guard lk(mu_);
        events_.push_back(std::move(ev));
    }
    if (notify_) notify_();
}

void Benchmark::worker(size_t index, Server server, BenchmarkConfig cfg, Clock::time_point t0) {
    std::vector<Protocol> protos = protocols_for(server, cfg);
    std::array<std::unique_ptr<Transport>, kProtocolCount> transports;
    for (Protocol p : protos) transports[static_cast<int>(p)] = make_transport(server, p);

    const auto& domains = popular_domains();
    // Offset each server's walk through the domain list so servers are not
    // all asked the same name at the same instant.
    size_t offset = index * 7;
    auto interval = std::chrono::milliseconds(std::max(cfg.interval_ms, 0));
    auto next = Clock::now();

    const size_t np = protos.size();
    for (int i = 0; i < cfg.lookups && !stop_; ++i) {
        // Alternate cached (popular name) and uncached (random subdomain) rounds.
        bool cached = i % 2 == 0;
        for (size_t j = 0; j < np && !stop_; ++j) {
            // Rotate which protocol goes first each round, and give every
            // protocol its own name, so no protocol systematically warms the
            // resolver's cache for the others.
            Protocol p = protos[(static_cast<size_t>(i) + j) % np];
            const std::string& base = domains[(offset + static_cast<size_t>(i / 2) * np + j) % domains.size()];
            if (!sleep_until(next)) break;
            auto slot = Clock::now();
            next = slot + interval;  // at most one lookup per interval per server

            std::string qname = cached ? base : random_label(12) + "." + base;
            BenchmarkEvent ev;
            ev.server = index;
            ev.proto = p;
            ev.qname = qname;
            ev.at_ms = std::chrono::duration<double, std::milli>(slot - t0).count();
            Transport* t = transports[static_cast<int>(p)].get();
            ev.result = t ? t->lookup(qname, dns::kTypeA, cfg.timeout_ms)
                          : LookupResult{false, 0, -1, "unsupported", -1};
            ev.sample = Sample{ev.result.ms, ev.result.ok, cached};
            push(std::move(ev));
        }
    }
    transports = {};  // close connections before announcing completion
    BenchmarkEvent done;
    done.server = index;
    done.server_finished = true;
    push(std::move(done));
    --active_;
}

// ------------------------------------------------------------ results

void ServerResults::add(const BenchmarkEvent& ev) {
    if (ev.server_finished) {
        finished = true;
        return;
    }
    auto& pr = proto[static_cast<int>(ev.proto)];
    pr.samples.push_back(ev.sample);
    if (ev.result.connect_ms >= 0) pr.connect_ms.push_back(ev.result.connect_ms);
    if (!ev.result.ok) pr.errors[ev.result.error.empty() ? "unknown" : ev.result.error]++;
    ++done;
}

namespace {
Score score_protocol(const Summary& sum, Protocol p) {
    Score s;
    s.proto = p;
    if (sum.sent == 0) return s;
    s.loss_pct = sum.loss_pct;
    if (sum.ok == 0) return s;
    s.has_data = true;
    s.median = sum.median;
    s.healthy = sum.loss_pct <= kMaxHealthyLossPct;
    return s;
}
}  // namespace

bool score_better(const Score& a, const Score& b) {
    if (a.has_data != b.has_data) return a.has_data;
    if (!a.has_data) return a.loss_pct < b.loss_pct;
    if (a.healthy != b.healthy) return a.healthy;
    if (!a.healthy && a.loss_pct != b.loss_pct) return a.loss_pct < b.loss_pct;
    return a.median < b.median;
}

Score score_from_summaries(const std::array<Summary, kProtocolCount>& sums, int rank_mode) {
    if (rank_mode >= 0 && rank_mode < kProtocolCount)
        return score_protocol(sums[rank_mode], static_cast<Protocol>(rank_mode));
    Score best;
    bool any = false;
    for (Protocol p : kAllProtocols) {
        const Summary& sum = sums[static_cast<int>(p)];
        if (sum.sent == 0) continue;
        Score s = score_protocol(sum, p);
        if (!any || score_better(s, best)) best = s;
        any = true;
    }
    return best;
}

Score score_server(const ServerResults& r, int rank_mode) {
    std::array<Summary, kProtocolCount> sums;
    for (Protocol p : kAllProtocols) sums[static_cast<int>(p)] = r.summary(p);
    return score_from_summaries(sums, rank_mode);
}
