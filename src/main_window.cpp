#include "main_window.h"

#include <algorithm>
#include <cmath>
#include <cstdio>

#include "system_dns.h"

namespace {

constexpr int kRankBest = -1;

Glib::ustring fmt_ms(double v) {
    if (std::isnan(v)) return "–";
    char b[32];
    std::snprintf(b, sizeof b, v < 100 ? "%.1f" : "%.0f", v);
    return b;
}

Glib::ustring fmt_duration(double seconds) {
    long s = std::lround(seconds);
    char b[64];
    if (s >= 3600)
        std::snprintf(b, sizeof b, "%ld h %02ld min", s / 3600, (s % 3600) / 60);
    else if (s >= 60)
        std::snprintf(b, sizeof b, "%ld min %02ld s", s / 60, s % 60);
    else
        std::snprintf(b, sizeof b, "%ld s", s);
    return b;
}

// Text for one protocol's median cell.
Glib::ustring median_cell(const ServerItem& it, Protocol p) {
    if (!it.server.supports(p)) return "<span alpha='50%'>n/a</span>";
    const Summary& s = it.stats[static_cast<int>(p)];
    if (s.sent == 0) return "";
    if (s.ok == 0) return "<span foreground='#c01c28'>fail</span>";
    Glib::ustring txt = fmt_ms(s.median);
    Score best = it.score(kRankBest);
    if (best.has_data && best.proto == p) txt = "<b>" + txt + "</b>";
    if (s.loss_pct > kMaxHealthyLossPct) txt = "<span foreground='#c64600'>" + txt + "</span>";
    return txt;
}

Glib::RefPtr<Gtk::Adjustment> adj(double value, double lo, double hi, double step, double page) {
    return Gtk::Adjustment::create(value, lo, hi, step, page, 0);
}

}  // namespace

MainWindow::MainWindow() {
    set_title("DNS Benchmark");
    set_icon_name("io.github.dns_benchmark");  // matches the .desktop file / app id
    set_default_size(1180, 760);

    start_button_.add_css_class("suggested-action");
    start_button_.signal_clicked().connect(sigc::mem_fun(*this, &MainWindow::on_start_stop));
    header_.pack_start(start_button_);
    set_titlebar(header_);

    root_.set_margin(12);
    set_child(root_);

    build_settings();
    build_add_bar();
    build_list();

    auto status_box = Gtk::make_managed<Gtk::Box>(Gtk::Orientation::HORIZONTAL, 12);
    progress_.set_valign(Gtk::Align::CENTER);
    progress_.set_size_request(220, -1);
    status_label_.set_xalign(0);
    status_label_.set_hexpand(true);
    status_label_.set_ellipsize(Pango::EllipsizeMode::END);
    status_label_.set_selectable(true);
    status_box->append(progress_);
    status_box->append(status_label_);
    root_.append(*status_box);

    dispatcher_.connect(sigc::mem_fun(*this, &MainWindow::on_events));
    signal_close_request().connect(
        [this] {
            bench_.stop();  // workers exit at their next scheduling point
            return false;
        },
        false);

    load_servers();
    update_estimate();
    update_details();
    set_status("Ready. Select servers and press Start.");
}

MainWindow::~MainWindow() {
    tick_conn_.disconnect();
    bench_.stop();
    bench_.join();
}

// ------------------------------------------------------------------ UI

void MainWindow::build_settings() {
    auto row1 = Gtk::make_managed<Gtk::Box>(Gtk::Orientation::HORIZONTAL, 18);
    auto row2 = Gtk::make_managed<Gtk::Box>(Gtk::Orientation::HORIZONTAL, 18);
    Gtk::Box* grid = row1;

    auto labeled = [&](const char* text, Gtk::Widget& w, const char* tooltip) {
        auto box = Gtk::make_managed<Gtk::Box>(Gtk::Orientation::HORIZONTAL, 6);
        auto l = Gtk::make_managed<Gtk::Label>(text);
        box->append(*l);
        box->append(w);
        box->set_tooltip_text(tooltip);
        grid->append(*box);
    };

    lookups_spin_.set_adjustment(adj(50, 1, 10000, 1, 10));
    lookups_spin_.set_numeric(true);
    labeled("Lookups", lookups_spin_, "Number of lookups per protocol for each server");

    interval_spin_.set_adjustment(adj(1000, 50, 60000, 50, 500));
    interval_spin_.set_numeric(true);
    labeled("Interval (ms)", interval_spin_,
            "Minimum time between two lookups to the same server (all protocols combined). "
            "1000 ms = at most one lookup per server per second.");

    timeout_spin_.set_adjustment(adj(2000, 100, 30000, 100, 1000));
    timeout_spin_.set_numeric(true);
    labeled("Timeout (ms)", timeout_spin_, "A lookup that takes longer than this counts as failed");

    rank_drop_.set_model(Gtk::StringList::create({"Best protocol", "UDP", "TCP", "DoT", "DoH"}));
    rank_drop_.set_selected(0);
    rank_drop_.property_selected().signal_changed().connect([this] { rerank(true); });
    labeled("Rank by", rank_drop_, "Which latency decides the ranking: each server's fastest protocol, or one protocol");

    grid = row2;
    auto protos = Gtk::make_managed<Gtk::Box>(Gtk::Orientation::HORIZONTAL, 6);
    protos->append(*Gtk::make_managed<Gtk::Label>("Protocols"));
    const char* tips[kProtocolCount] = {
        "Classic DNS over UDP port 53",
        "Classic DNS over TCP port 53 (connection reused between lookups)",
        "DNS-over-TLS, port 853 (RFC 7858)",
        "DNS-over-HTTPS (RFC 8484), HTTP/2 or HTTP/1.1",
    };
    for (Protocol p : kAllProtocols) {
        auto& cb = proto_checks_[static_cast<int>(p)];
        cb.set_label(protocol_name(p));
        cb.set_active(true);
        cb.set_tooltip_text(tips[static_cast<int>(p)]);
        cb.signal_toggled().connect([this] { update_estimate(); });
        protos->append(cb);
    }
    grid->append(*protos);

    estimate_label_.set_hexpand(true);
    estimate_label_.set_xalign(1);
    estimate_label_.add_css_class("dim-label");
    grid->append(estimate_label_);

    lookups_spin_.signal_value_changed().connect([this] { update_estimate(); });
    interval_spin_.signal_value_changed().connect([this] { update_estimate(); });

    root_.append(*row1);
    root_.append(*row2);
}

void MainWindow::build_add_bar() {
    auto box = Gtk::make_managed<Gtk::Box>(Gtk::Orientation::HORIZONTAL, 6);
    ip_entry_.set_placeholder_text("IP address, e.g. 94.140.14.14");
    ip_entry_.set_width_chars(24);
    name_entry_.set_placeholder_text("Name (optional)");
    name_entry_.set_width_chars(12);
    tls_entry_.set_placeholder_text("DoT hostname (optional)");
    tls_entry_.set_width_chars(18);
    tls_entry_.set_tooltip_text("TLS name for DNS-over-TLS, e.g. dns.adguard-dns.com. Leave empty to skip DoT.");
    doh_entry_.set_placeholder_text("DoH URL (optional)");
    doh_entry_.set_hexpand(true);
    doh_entry_.set_tooltip_text("e.g. https://dns.adguard-dns.com/dns-query. Leave empty to skip DoH.");

    for (auto* e : {&ip_entry_, &name_entry_, &tls_entry_, &doh_entry_}) {
        e->signal_activate().connect(sigc::mem_fun(*this, &MainWindow::on_add_server));
        e->signal_changed().connect([e] { e->remove_css_class("error"); });
        box->append(*e);
    }
    add_button_.signal_clicked().connect(sigc::mem_fun(*this, &MainWindow::on_add_server));
    remove_button_.set_tooltip_text("Remove the selected custom server");
    remove_button_.set_sensitive(false);
    remove_button_.signal_clicked().connect(sigc::mem_fun(*this, &MainWindow::on_remove_server));
    box->append(add_button_);
    box->append(remove_button_);
    root_.append(*box);
}

void MainWindow::build_list() {
    store_ = Gio::ListStore<ServerItem>::create();
    selection_ = Gtk::SingleSelection::create(store_);
    selection_->set_autoselect(false);
    selection_->set_can_unselect(true);
    selection_->signal_selection_changed().connect([this](guint, guint) {
        auto it = selected_item();
        remove_button_.set_sensitive(it && it->server.source == Source::Custom && !running_);
        update_details();
    });
    column_view_.set_model(selection_);
    column_view_.set_show_row_separators(true);
    column_view_.add_css_class("data-table");

    add_label_column("#", [](const ServerItem& it) {
        return it.rank ? Glib::ustring::format(it.rank) : Glib::ustring();
    }, true, false);
    add_enabled_column();
    add_label_column("Name", [](const ServerItem& it) {
        return Glib::Markup::escape_text(it.server.name.empty() ? it.server.address : it.server.name);
    }, false, true, true);
    add_label_column("Address", [](const ServerItem& it) {
        return Glib::ustring(it.server.address);
    }, false, false);
    add_label_column("Source", [](const ServerItem& it) {
        return Glib::ustring(source_name(it.server.source));
    }, false, false);
    for (Protocol p : kAllProtocols) {
        add_label_column(Glib::ustring(protocol_name(p)) + " ms",
                         [p](const ServerItem& it) { return median_cell(it, p); }, true, false, true);
    }
    add_label_column("Loss", [](const ServerItem& it) -> Glib::ustring {
        if (!it.sent) return "";
        char b[16];
        std::snprintf(b, sizeof b, "%.0f%%",
                      100.0 * static_cast<double>(it.sent - it.ok) / static_cast<double>(it.sent));
        return b;
    }, true, false);
    add_label_column("Best", [](const ServerItem& it) -> Glib::ustring {
        Score s = it.score(kRankBest);
        if (!s.has_data) return it.results.done ? "no answers" : "";
        return Glib::ustring(protocol_name(s.proto)) + " " + fmt_ms(s.median) + " ms";
    }, false, false);
    add_progress_column();

    list_scroll_.set_child(column_view_);
    list_scroll_.set_vexpand(true);
    list_scroll_.set_policy(Gtk::PolicyType::AUTOMATIC, Gtk::PolicyType::AUTOMATIC);

    details_view_.set_editable(false);
    details_view_.set_cursor_visible(false);
    details_view_.set_monospace(true);
    details_view_.set_left_margin(8);
    details_view_.set_top_margin(6);
    details_scroll_.set_child(details_view_);
    details_scroll_.set_size_request(-1, 150);

    paned_.set_start_child(list_scroll_);
    paned_.set_end_child(details_scroll_);
    paned_.set_resize_start_child(true);
    paned_.set_shrink_end_child(false);
    paned_.set_position(430);
    paned_.set_vexpand(true);
    root_.append(paned_);
}

void MainWindow::add_label_column(const Glib::ustring& title, TextFn text, bool numeric, bool expand,
                                  bool markup) {
    // Cells are recycled across rows: subscribe to the bound item's change
    // signal on bind and drop the subscription on unbind.
    auto conns = std::make_shared<std::map<Gtk::ListItem*, sigc::connection>>();
    auto factory = Gtk::SignalListItemFactory::create();
    factory->signal_setup().connect([numeric](const Glib::RefPtr<Gtk::ListItem>& li) {
        auto label = Gtk::make_managed<Gtk::Label>();
        label->set_xalign(numeric ? 1.0f : 0.0f);
        label->set_ellipsize(Pango::EllipsizeMode::END);
        if (numeric) label->add_css_class("numeric");
        li->set_child(*label);
    });
    factory->signal_bind().connect([text, markup, conns](const Glib::RefPtr<Gtk::ListItem>& li) {
        auto item = std::dynamic_pointer_cast<ServerItem>(li->get_item());
        auto label = dynamic_cast<Gtk::Label*>(li->get_child());
        if (!item || !label) return;
        auto refresh = [label, text, markup, raw = item.get()] {
            if (markup)
                label->set_markup(text(*raw));
            else
                label->set_text(text(*raw));
        };
        refresh();
        (*conns)[li.get()] = item->signal_changed.connect(refresh);
    });
    factory->signal_unbind().connect([conns](const Glib::RefPtr<Gtk::ListItem>& li) {
        auto it = conns->find(li.get());
        if (it == conns->end()) return;
        it->second.disconnect();
        conns->erase(it);
    });
    auto col = Gtk::ColumnViewColumn::create(title, factory);
    col->set_expand(expand);
    col->set_resizable(true);
    column_view_.append_column(col);
}

void MainWindow::add_enabled_column() {
    auto conns = std::make_shared<std::map<Gtk::ListItem*, std::vector<sigc::connection>>>();
    auto factory = Gtk::SignalListItemFactory::create();
    factory->signal_setup().connect([](const Glib::RefPtr<Gtk::ListItem>& li) {
        auto cb = Gtk::make_managed<Gtk::CheckButton>();
        cb->set_halign(Gtk::Align::CENTER);
        cb->set_tooltip_text("Include this server in the benchmark");
        li->set_child(*cb);
    });
    factory->signal_bind().connect([this, conns](const Glib::RefPtr<Gtk::ListItem>& li) {
        auto item = std::dynamic_pointer_cast<ServerItem>(li->get_item());
        auto cb = dynamic_cast<Gtk::CheckButton*>(li->get_child());
        if (!item || !cb) return;
        cb->set_active(item->server.enabled);
        cb->set_sensitive(!running_);
        auto& c = (*conns)[li.get()];
        c.push_back(cb->signal_toggled().connect([this, cb, raw = item.get()] {
            raw->server.enabled = cb->get_active();
            if (raw->server.source == Source::Custom) save_custom();
            update_estimate();
        }));
        // Checkboxes are locked while a benchmark runs.
        c.push_back(item->signal_changed.connect([this, cb] { cb->set_sensitive(!running_); }));
    });
    factory->signal_unbind().connect([conns](const Glib::RefPtr<Gtk::ListItem>& li) {
        auto it = conns->find(li.get());
        if (it == conns->end()) return;
        for (auto& c : it->second) c.disconnect();
        conns->erase(it);
    });
    auto col = Gtk::ColumnViewColumn::create("Use", factory);
    column_view_.append_column(col);
}

void MainWindow::add_progress_column() {
    auto conns = std::make_shared<std::map<Gtk::ListItem*, sigc::connection>>();
    auto factory = Gtk::SignalListItemFactory::create();
    factory->signal_setup().connect([](const Glib::RefPtr<Gtk::ListItem>& li) {
        auto bar = Gtk::make_managed<Gtk::ProgressBar>();
        bar->set_valign(Gtk::Align::CENTER);
        bar->set_size_request(90, -1);
        li->set_child(*bar);
    });
    factory->signal_bind().connect([conns](const Glib::RefPtr<Gtk::ListItem>& li) {
        auto item = std::dynamic_pointer_cast<ServerItem>(li->get_item());
        auto bar = dynamic_cast<Gtk::ProgressBar*>(li->get_child());
        if (!item || !bar) return;
        auto refresh = [bar, raw = item.get()] {
            const auto& r = raw->results;
            bar->set_fraction(r.planned ? std::min(1.0, static_cast<double>(r.done) / r.planned) : 0.0);
            bar->set_tooltip_text(r.planned ? Glib::ustring::compose("%1 / %2 lookups", r.done, r.planned) : "");
        };
        refresh();
        (*conns)[li.get()] = item->signal_changed.connect(refresh);
    });
    factory->signal_unbind().connect([conns](const Glib::RefPtr<Gtk::ListItem>& li) {
        auto it = conns->find(li.get());
        if (it == conns->end()) return;
        it->second.disconnect();
        conns->erase(it);
    });
    auto col = Gtk::ColumnViewColumn::create("Progress", factory);
    column_view_.append_column(col);
}

// ------------------------------------------------------------- servers

void MainWindow::load_servers() {
    for (const auto& s : merge_server_lists(discover_system_servers(), public_servers(),
                                            load_custom_servers(custom_servers_path())))
        store_->append(ServerItem::create(s));
}

void MainWindow::on_add_server() {
    if (running_) return;
    Server s;
    s.source = Source::Custom;
    s.address = ip_entry_.get_text();
    s.name = name_entry_.get_text();
    s.tls_host = tls_entry_.get_text();
    s.doh_url = doh_entry_.get_text();
    for (auto* str : {&s.address, &s.name, &s.tls_host, &s.doh_url}) {
        size_t a = str->find_first_not_of(" \t"), b = str->find_last_not_of(" \t");
        *str = a == std::string::npos ? "" : str->substr(a, b - a + 1);
    }

    if (!is_valid_ip(s.address)) {
        ip_entry_.add_css_class("error");
        ip_entry_.grab_focus();
        set_status(s.address.empty() ? "Enter the server's IP address."
                                     : "\"" + s.address + "\" is not a valid IPv4 or IPv6 address.",
                   true);
        return;
    }
    std::string host, path;
    int port;
    if (!s.doh_url.empty() && !parse_https_url(s.doh_url, host, port, path)) {
        doh_entry_.add_css_class("error");
        set_status("DoH URL must look like https://host/dns-query", true);
        return;
    }
    if (!s.tls_host.empty() && !is_valid_tls_host(s.tls_host)) {
        tls_entry_.add_css_class("error");
        set_status("DoT hostname must be a plain host name, e.g. dns.example.com", true);
        return;
    }
    for (guint i = 0; i < store_->get_n_items(); ++i) {
        if (store_->get_item(i)->server.address == s.address) {
            ip_entry_.add_css_class("error");
            selection_->set_selected(i);
            set_status(s.address + " is already in the list.", true);
            return;
        }
    }

    store_->append(ServerItem::create(s));
    selection_->set_selected(store_->get_n_items() - 1);
    column_view_.scroll_to(store_->get_n_items() - 1, {}, Gtk::ListScrollFlags::NONE);
    save_custom();
    for (auto* e : {&ip_entry_, &name_entry_, &tls_entry_, &doh_entry_}) e->set_text("");
    update_estimate();
    set_status("Added " + s.label() + ".");
}

void MainWindow::on_remove_server() {
    if (running_) return;
    guint pos = selection_->get_selected();
    auto it = selected_item();
    if (!it || it->server.source != Source::Custom) return;
    std::string label = it->server.label();
    store_->remove(pos);
    save_custom();
    update_estimate();
    set_status("Removed " + label + ".");
}

void MainWindow::save_custom() {
    std::vector<Server> custom;
    for (guint i = 0; i < store_->get_n_items(); ++i)
        if (store_->get_item(i)->server.source == Source::Custom) custom.push_back(store_->get_item(i)->server);
    if (!save_custom_servers(custom_servers_path(), custom))
        set_status("Could not save custom servers to " + custom_servers_path(), true);
}

Glib::RefPtr<ServerItem> MainWindow::selected_item() const {
    return std::dynamic_pointer_cast<ServerItem>(selection_->get_selected_item());
}

// ----------------------------------------------------------- benchmark

BenchmarkConfig MainWindow::current_config() const {
    BenchmarkConfig cfg;
    cfg.lookups = lookups_spin_.get_value_as_int();
    cfg.interval_ms = interval_spin_.get_value_as_int();
    cfg.timeout_ms = timeout_spin_.get_value_as_int();
    for (int i = 0; i < kProtocolCount; ++i) cfg.protocols[i] = proto_checks_[i].get_active();
    return cfg;
}

void MainWindow::update_estimate() {
    BenchmarkConfig cfg = current_config();
    int total = 0, longest = 0, servers = 0;
    for (guint i = 0; i < store_->get_n_items(); ++i) {
        int n = planned_lookups(store_->get_item(i)->server, cfg);
        total += n;
        longest = std::max(longest, n);
        servers += n > 0;
    }
    // Servers run in parallel; each is limited to one lookup per interval.
    // In double: 10000 lookups x 4 protocols x 60000 ms overflows int.
    double secs = longest > 0 ? (longest - 1) * static_cast<double>(cfg.interval_ms) / 1000.0 : 0;
    estimate_label_.set_text(Glib::ustring::compose("%1 servers · %2 lookups · ≈ %3", servers, total,
                                                    fmt_duration(secs)));
    if (!running_) start_button_.set_sensitive(total > 0);
}

void MainWindow::set_running_ui(bool running) {
    running_ = running;
    start_button_.set_label(running ? "Stop" : "Start");
    start_button_.set_sensitive(true);
    if (running) {
        start_button_.remove_css_class("suggested-action");
        start_button_.add_css_class("destructive-action");
    } else {
        start_button_.remove_css_class("destructive-action");
        start_button_.add_css_class("suggested-action");
    }
    for (Gtk::Widget* w : std::initializer_list<Gtk::Widget*>{
             &lookups_spin_, &interval_spin_, &timeout_spin_, &ip_entry_, &name_entry_, &tls_entry_,
             &doh_entry_, &add_button_})
        w->set_sensitive(!running);
    for (auto& cb : proto_checks_) cb.set_sensitive(!running);
    auto it = selected_item();
    remove_button_.set_sensitive(!running && it && it->server.source == Source::Custom);
    // Bound "Use" checkboxes refresh their sensitivity on changed().
    for (guint i = 0; i < store_->get_n_items(); ++i) store_->get_item(i)->changed();
}

void MainWindow::on_start_stop() {
    if (running_) {
        if (!stopping_) {
            stopping_ = true;
            bench_.stop();
            start_button_.set_sensitive(false);
            set_status("Stopping… (waiting for in-flight lookups)");
        }
        return;
    }

    run_cfg_ = current_config();
    std::vector<Server> servers;
    run_items_.clear();
    run_total_ = run_done_ = run_finished_servers_ = run_servers_ = 0;
    for (guint i = 0; i < store_->get_n_items(); ++i) {
        auto it = store_->get_item(i);
        it->results = ServerResults{};
        it->rank = 0;
        it->results.planned = planned_lookups(it->server, run_cfg_);
        it->refresh_stats();
        run_total_ += it->results.planned;
        run_servers_ += it->results.planned > 0;
        servers.push_back(it->server);
        run_items_.push_back(it);
        it->changed();
    }
    if (run_total_ == 0) {
        set_status("Nothing to do: enable at least one server and one protocol.", true);
        return;
    }

    stopping_ = false;
    set_running_ui(true);
    progress_.set_fraction(0);
    set_status(Glib::ustring::compose("Benchmarking %1 servers…", run_servers_));
    bench_.start(servers, run_cfg_, [this] { dispatcher_.emit(); });
    tick_conn_ = Glib::signal_timeout().connect(sigc::mem_fun(*this, &MainWindow::on_tick), 1500);
}

void MainWindow::on_events() {
    std::vector<Glib::RefPtr<ServerItem>> touched;
    for (auto& ev : bench_.take_events()) {
        if (ev.server >= run_items_.size()) continue;
        auto& item = run_items_[ev.server];
        item->results.add(ev);
        if (ev.server_finished)
            ++run_finished_servers_;
        else
            ++run_done_;
        if (std::find(touched.begin(), touched.end(), item) == touched.end()) touched.push_back(item);
    }
    if (touched.empty()) return;
    for (auto& it : touched) {
        it->refresh_stats();  // once per batch, not once per cell
        it->changed();
    }
    order_dirty_ = true;

    if (run_total_) progress_.set_fraction(std::min(1.0, static_cast<double>(run_done_) / run_total_));
    if (!stopping_)
        set_status(Glib::ustring::compose("Benchmarking… %1 / %2 lookups", run_done_, run_total_));
    if (auto sel = selected_item(); sel && std::find(touched.begin(), touched.end(), sel) != touched.end())
        update_details();

    if (run_finished_servers_ >= run_servers_) finish_run(stopping_);
}

bool MainWindow::on_tick() {
    if (!running_) return false;
    rerank(false);
    return true;
}

void MainWindow::finish_run(bool stopped) {
    tick_conn_.disconnect();
    bench_.join();
    set_running_ui(false);
    stopping_ = false;
    rerank(true);
    update_details();

    // Announce the winner.
    Glib::RefPtr<ServerItem> best;
    for (guint i = 0; i < store_->get_n_items(); ++i) {
        auto it = store_->get_item(i);
        if (it->rank == 1) best = it;
    }
    Glib::ustring prefix = stopped ? "Stopped — partial results. " : "Done. ";
    int mode = static_cast<int>(rank_drop_.get_selected()) - 1;
    Score s = best ? best->score(mode) : Score{};
    if (best && s.has_data) {
        set_status(prefix + Glib::ustring::compose("Fastest: %1 via %2 — median %3 ms%4", best->server.label(),
                                                   protocol_name(s.proto), fmt_ms(s.median),
                                                   s.healthy ? "" : " (but unreliable)"));
    } else {
        set_status(prefix + "No server answered.", !stopped);
    }
}

void MainWindow::rerank(bool force) {
    if (!force && !order_dirty_) return;
    order_dirty_ = false;
    guint n = store_->get_n_items();
    if (n == 0) return;
    int mode = static_cast<int>(rank_drop_.get_selected()) - 1;

    // Score every server once, then sort by the cached scores.
    std::vector<Glib::RefPtr<ServerItem>> items;
    std::vector<std::pair<Score, Glib::RefPtr<ServerItem>>> scored;
    for (guint i = 0; i < n; ++i) {
        items.push_back(store_->get_item(i));
        scored.emplace_back(items.back()->score(mode), items.back());
    }
    std::stable_sort(scored.begin(), scored.end(),
                     [](const auto& a, const auto& b) { return score_better(a.first, b.first); });
    std::vector<Glib::RefPtr<ServerItem>> sorted;
    for (auto& [score, item] : scored) sorted.push_back(item);

    bool any_data = false;
    for (size_t i = 0; i < sorted.size(); ++i) {
        bool has = scored[i].first.has_data;
        any_data |= has;
        int rank = has ? static_cast<int>(i) + 1 : 0;
        if (sorted[i]->rank != rank) {
            sorted[i]->rank = rank;
            sorted[i]->changed();
        }
    }
    if (!any_data || sorted == items) return;

    // Reorder the model in one splice, keeping the user's selection.
    auto sel = selected_item();
    store_->splice(0, n, sorted);
    if (sel) {
        for (guint i = 0; i < n; ++i)
            if (store_->get_item(i) == sel) selection_->set_selected(i);
    } else {
        selection_->unselect_all();
    }
}

void MainWindow::update_details() {
    auto buf = details_view_.get_buffer();
    auto it = selected_item();
    if (!it) {
        buf->set_text(
            "Select a server to see detailed statistics.\n\n"
            "Each lookup alternates between a popular (usually cached) domain and a random\n"
            "subdomain that forces the resolver to recurse. Latency excludes connection setup\n"
            "for TCP/DoT/DoH, which reuse one connection per server; setup time is shown separately.");
        return;
    }
    const Server& s = it->server;
    std::string t = s.label() + "   [" + source_name(s.source) + "]";
    if (!s.tls_host.empty()) t += "   DoT: " + s.tls_host;
    if (!s.doh_url.empty()) t += "   DoH: " + s.doh_url;
    t += "\n\n";
    char line[256];
    std::snprintf(line, sizeof line, "%-5s %5s %5s %6s %8s %8s %8s %8s %8s %8s %8s %9s\n", "", "sent", "ok",
                  "loss%", "median", "mean", "min", "max", "stddev", "cached", "uncached", "connect");
    t += line;
    for (Protocol p : kAllProtocols) {
        if (!s.supports(p)) {
            std::snprintf(line, sizeof line, "%-5s not configured for this server\n", protocol_name(p));
            t += line;
            continue;
        }
        const auto& pr = it->results.proto[static_cast<int>(p)];
        const Summary& sum = it->stats[static_cast<int>(p)];
        double connect = median_of(pr.connect_ms);
        std::snprintf(line, sizeof line, "%-5s %5zu %5zu %6.1f %8s %8s %8s %8s %8s %8s %8s %9s\n",
                      protocol_name(p), sum.sent, sum.ok, sum.loss_pct, fmt_ms(sum.median).c_str(),
                      fmt_ms(sum.mean).c_str(), fmt_ms(sum.min).c_str(), fmt_ms(sum.max).c_str(),
                      fmt_ms(sum.stddev).c_str(), fmt_ms(sum.median_cached).c_str(),
                      fmt_ms(sum.median_uncached).c_str(),
                      p == Protocol::UDP ? "–" : fmt_ms(connect).c_str());
        t += line;
    }
    bool header = false;
    for (Protocol p : kAllProtocols) {
        for (const auto& [err, n] : it->results.proto[static_cast<int>(p)].errors) {
            if (!header) t += "\nErrors:\n";
            header = true;
            t += std::string("  ") + protocol_name(p) + ": " + std::to_string(n) + " × " + err + "\n";
        }
    }
    t += "\nAll times in milliseconds. Cached = popular domain, uncached = random subdomain.";
    buf->set_text(t);
}

void MainWindow::set_status(const Glib::ustring& text, bool error) {
    status_label_.set_text(text);
    if (error)
        status_label_.add_css_class("error");
    else
        status_label_.remove_css_class("error");
}
