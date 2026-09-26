// Main application window.
#pragma once

#include <gtkmm.h>

#include <array>
#include <functional>
#include <map>
#include <memory>

#include "benchmark.h"
#include "server_item.h"

class MainWindow : public Gtk::ApplicationWindow {
public:
    MainWindow();
    ~MainWindow() override;

private:
    // UI construction
    void build_settings();
    void build_add_bar();
    void build_list();
    using TextFn = std::function<Glib::ustring(const ServerItem&)>;
    void add_label_column(const Glib::ustring& title, TextFn text, bool numeric, bool expand,
                          bool markup = false);
    void add_enabled_column();
    void add_progress_column();

    // Servers
    void load_servers();
    void on_add_server();
    void on_remove_server();
    void save_custom();
    Glib::RefPtr<ServerItem> selected_item() const;

    // Benchmark
    BenchmarkConfig current_config() const;
    void on_start_stop();
    void on_events();         // Dispatcher: drain worker events (GUI thread)
    bool on_tick();           // periodic re-rank while running
    void finish_run(bool stopped);
    void set_running_ui(bool running);
    void rerank(bool force);
    void update_estimate();
    void update_details();
    void set_status(const Glib::ustring& text, bool error = false);

    // Widgets
    Gtk::HeaderBar header_;
    Gtk::Button start_button_{"Start"};
    Gtk::Box root_{Gtk::Orientation::VERTICAL, 8};

    Gtk::SpinButton lookups_spin_, interval_spin_, timeout_spin_;
    std::array<Gtk::CheckButton, kProtocolCount> proto_checks_;
    Gtk::DropDown rank_drop_;
    Gtk::Label estimate_label_;

    Gtk::Entry ip_entry_, name_entry_, tls_entry_, doh_entry_;
    Gtk::Button add_button_{"Add Server"}, remove_button_{"Remove"};

    Gtk::Paned paned_{Gtk::Orientation::VERTICAL};
    Gtk::ScrolledWindow list_scroll_, details_scroll_;
    Gtk::ColumnView column_view_;
    Gtk::TextView details_view_;

    Gtk::ProgressBar progress_;
    Gtk::Label status_label_;

    // Model
    Glib::RefPtr<Gio::ListStore<ServerItem>> store_;
    Glib::RefPtr<Gtk::SingleSelection> selection_;

    // Benchmark state. The dispatcher must outlive the worker threads, so it
    // is declared before bench_ (members are destroyed in reverse order).
    Glib::Dispatcher dispatcher_;
    Benchmark bench_;
    std::vector<Glib::RefPtr<ServerItem>> run_items_;  // indexed by BenchmarkEvent::server
    BenchmarkConfig run_cfg_;
    int run_total_ = 0, run_done_ = 0, run_finished_servers_ = 0, run_servers_ = 0;
    bool running_ = false, stopping_ = false, order_dirty_ = false;
    sigc::connection tick_conn_;
};
