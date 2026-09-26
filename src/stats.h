// Latency statistics over a set of lookup samples.
#pragma once

#include <cstddef>
#include <vector>

struct Sample {
    double ms = 0;       // latency; meaningful only when ok
    bool ok = false;
    bool cached = true;  // popular name (likely cached) vs random subdomain
};

// All latency fields are NaN when there are no successful samples.
struct Summary {
    size_t sent = 0;
    size_t ok = 0;
    double loss_pct = 0;
    double mean, median, min, max, stddev;
    double median_cached, median_uncached;
    Summary();
};

double median_of(std::vector<double> values);  // NaN if empty
Summary summarize(const std::vector<Sample>& samples);
