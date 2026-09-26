#include "stats.h"

#include <algorithm>
#include <cmath>
#include <limits>

namespace {
constexpr double kNaN = std::numeric_limits<double>::quiet_NaN();
}

Summary::Summary()
    : mean(kNaN), median(kNaN), min(kNaN), max(kNaN), stddev(kNaN),
      median_cached(kNaN), median_uncached(kNaN) {}

double median_of(std::vector<double> v) {
    if (v.empty()) return kNaN;
    size_t mid = v.size() / 2;
    std::nth_element(v.begin(), v.begin() + static_cast<long>(mid), v.end());
    double hi = v[mid];
    if (v.size() % 2) return hi;
    double lo = *std::max_element(v.begin(), v.begin() + static_cast<long>(mid));
    return (lo + hi) / 2;
}

Summary summarize(const std::vector<Sample>& samples) {
    Summary s;
    s.sent = samples.size();
    std::vector<double> all, cached, uncached;
    for (const auto& x : samples) {
        if (!x.ok) continue;
        all.push_back(x.ms);
        (x.cached ? cached : uncached).push_back(x.ms);
    }
    s.ok = all.size();
    s.loss_pct = s.sent ? 100.0 * static_cast<double>(s.sent - s.ok) / static_cast<double>(s.sent) : 0;
    if (all.empty()) return s;

    double sum = 0;
    for (double v : all) sum += v;
    s.mean = sum / static_cast<double>(all.size());
    double var = 0;
    for (double v : all) var += (v - s.mean) * (v - s.mean);
    s.stddev = all.size() > 1 ? std::sqrt(var / static_cast<double>(all.size() - 1)) : 0;
    auto [mn, mx] = std::minmax_element(all.begin(), all.end());
    s.min = *mn;
    s.max = *mx;
    s.median = median_of(all);
    s.median_cached = median_of(cached);
    s.median_uncached = median_of(uncached);
    return s;
}
