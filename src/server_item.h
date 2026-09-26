// Row model for the server list: a Glib::Object so it can live in a
// Gio::ListStore and back a Gtk::ColumnView.
#pragma once

#include <glibmm/object.h>
#include <sigc++/signal.h>

#include "benchmark.h"
#include "servers.h"

class ServerItem : public Glib::Object {
public:
    static Glib::RefPtr<ServerItem> create(const Server& s) {
        return Glib::make_refptr_for_instance<ServerItem>(new ServerItem(s));
    }

    Server server;
    ServerResults results;
    int rank = 0;  // 1-based position after ranking; 0 = not ranked yet

    // Per-protocol summaries of `results`, recomputed by refresh_stats() once
    // per update so cells and ranking never re-summarize the raw samples.
    std::array<Summary, kProtocolCount> stats;
    size_t sent = 0, ok = 0;  // totals over all protocols

    void refresh_stats() {
        sent = ok = 0;
        for (Protocol p : kAllProtocols) {
            Summary& s = stats[static_cast<int>(p)];
            s = results.summary(p);
            sent += s.sent;
            ok += s.ok;
        }
    }
    Score score(int rank_mode) const { return score_from_summaries(stats, rank_mode); }

    // Emitted (on the GUI thread) whenever anything shown for this row changed.
    sigc::signal<void()> signal_changed;
    void changed() { signal_changed.emit(); }

protected:
    explicit ServerItem(const Server& s) : Glib::ObjectBase(typeid(ServerItem)), server(s) {}
};
