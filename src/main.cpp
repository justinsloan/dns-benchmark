// DNS Benchmark: GTK 4 front end. `dns-benchmark --cli ...` runs headless.
#include <signal.h>

#include <cstring>

#include "cli.h"
#include "main_window.h"

int main(int argc, char** argv) {
    // A server closing a TLS/TCP connection mid-write must not kill us.
    signal(SIGPIPE, SIG_IGN);

    for (int i = 1; i < argc; ++i)
        if (std::strcmp(argv[i], "--cli") == 0) return run_cli(argc, argv);

    auto app = Gtk::Application::create("io.github.dns_benchmark");
    return app->make_window_and_run<MainWindow>(argc, argv);
}
