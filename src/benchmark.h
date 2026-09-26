// Benchmark engine: runs lookups against many servers concurrently while
// limiting each server to one lookup per configured interval.
#pragma once

#include <array>
#include <atomic>
#include <condition_variable>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "net.h"
#include "servers.h"
#include "stats.h"
#include "transport.h"

struct BenchmarkConfig {
    int lookups = 50;          // per protocol, per server
    int interval_ms = 1000;    // minimum gap between lookups to the same server
    int timeout_ms = 2000;
    std::array<bool, kProtocolCount> protocols = {true, true, true, true};
};

// One completed lookup, delivered from a worker thread.
struct BenchmarkEvent {
    size_t server = 0;          // index into the server list given to start()
    Protocol proto = Protocol::UDP;
    std::string qname;
    Sample sample;
    LookupResult result;
    double at_ms = 0;           // start time of the lookup, relative to benchmark start
    bool server_finished = false;  // marker event: no data, worker is done
};

// Popular domains used for "cached" lookups; exposed for tests/UI.
const std::vector<std::string>& popular_domains();

// Number of lookups that will be sent to `s` under `cfg`.
int planned_lookups(const Server& s, const BenchmarkConfig& cfg);

class Benchmark {
public:
    using Notify = std::function<void()>;  // called from worker threads

    ~Benchmark();

    // Starts one worker per enabled server. Ignored if already running.
    void start(const std::vector<Server>& servers, const BenchmarkConfig& cfg, Notify notify = {});
    void stop();  // request cancellation; returns immediately
    void join();  // wait for all workers to exit
    bool running() const { return active_ > 0; }

    std::vector<BenchmarkEvent> take_events();  // drains the queue

private:
    void worker(size_t index, Server server, BenchmarkConfig cfg, Clock::time_point t0);
    bool sleep_until(Clock::time_point t);  // false if stop was requested
    void push(BenchmarkEvent ev);

    std::vector<std::thread> threads_;
    std::atomic<int> active_{0};
    std::atomic<bool> stop_{false};
    std::mutex mu_;
    std::condition_variable cv_;
    std::vector<BenchmarkEvent> events_;
    Notify notify_;
};

// ------------------------------------------------------------ results

struct ProtocolResults {
    std::vector<Sample> samples;
    std::vector<double> connect_ms;
    std::map<std::string, int> errors;
};

struct ServerResults {
    std::array<ProtocolResults, kProtocolCount> proto;
    int done = 0;
    int planned = 0;
    bool finished = false;

    void add(const BenchmarkEvent& ev);
    Summary summary(Protocol p) const { return summarize(proto[static_cast<int>(p)].samples); }
};

// Servers losing more than this share of lookups rank after all healthy ones.
constexpr double kMaxHealthyLossPct = 10.0;

// RankMode: -1 = best protocol of each server, otherwise a Protocol index.
struct Score {
    bool has_data = false;
    bool healthy = false;
    double median = 0;
    double loss_pct = 100;
    Protocol proto = Protocol::UDP;
};
Score score_server(const ServerResults& r, int rank_mode);
// Same, from summaries already computed for each protocol (cheap).
Score score_from_summaries(const std::array<Summary, kProtocolCount>& s, int rank_mode);
// Strict weak ordering: better scores first.
bool score_better(const Score& a, const Score& b);
