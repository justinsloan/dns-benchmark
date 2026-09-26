// Entry point for the GTK-free command-line build (dns-benchmark-cli).
#include <signal.h>

#include "cli.h"

int main(int argc, char** argv) {
    signal(SIGPIPE, SIG_IGN);
    return run_cli(argc, argv);
}
