# DNS Benchmark — GTK 4 (gtkmm-4.0) DNS resolver benchmark.
#
#   make            build the GUI app (./dns-benchmark; also accepts --cli)
#   make cli        build the GTK-free command-line tool (./dns-benchmark-cli)
#   make test       build and run unit tests
#   make run        build and launch the GUI
#   make deps       show the packages needed to build
#   make install-desktop  add a launcher to your app grid that runs this build
#                         (GNOME Files won't start programs on double-click)
#   make install    install binary, launcher and icon under $(PREFIX) (default /usr/local)

CXX      ?= g++
CXXFLAGS ?= -O2 -g
CXXFLAGS += -std=c++20 -Wall -Wextra -pthread -MMD -MP
LDFLAGS  += -pthread
PREFIX   ?= /usr/local
BUILD    := build

PKG_CONFIG ?= pkg-config
SSL_CFLAGS := $(shell $(PKG_CONFIG) --cflags openssl 2>/dev/null)
SSL_LIBS   := $(shell $(PKG_CONFIG) --libs openssl 2>/dev/null || echo -lssl -lcrypto)
GTK_CFLAGS := $(shell $(PKG_CONFIG) --cflags gtkmm-4.0 2>/dev/null)
GTK_LIBS   := $(shell $(PKG_CONFIG) --libs gtkmm-4.0 2>/dev/null)

CORE_SRCS := src/dns_message.cpp src/stats.cpp src/servers.cpp src/system_dns.cpp \
             src/net.cpp src/tls.cpp src/transport.cpp src/benchmark.cpp src/cli.cpp
GUI_SRCS  := src/main.cpp src/main_window.cpp

CORE_OBJS := $(CORE_SRCS:src/%.cpp=$(BUILD)/%.o)
GUI_OBJS  := $(GUI_SRCS:src/%.cpp=$(BUILD)/%.o)
CLI_OBJS  := $(BUILD)/cli_main.o
TEST_OBJS := $(BUILD)/test_core.o

APP  := dns-benchmark
CLI  := dns-benchmark-cli
TEST := $(BUILD)/test_core

APP_ID   := io.github.dns_benchmark
USER_APPS  := $(HOME)/.local/share/applications
USER_ICONS := $(HOME)/.local/share/icons/hicolor/scalable/apps

.PHONY: all cli test run deps install uninstall install-desktop uninstall-desktop clean

# Run inside GUI recipes (not as a phony prerequisite, which would execute on
# every `make` and suppress make's "Nothing to be done" message).
CHECK_GTK = @$(PKG_CONFIG) --exists gtkmm-4.0 || { \
	  echo "gtkmm-4.0 development files not found."; \
	  echo "Install them with:  sudo apt install libgtkmm-4.0-dev libssl-dev pkg-config"; \
	  echo "(or build the GTK-free tool with: make cli)"; exit 1; }

all: $(APP)

cli: $(CLI)

$(APP): $(CORE_OBJS) $(GUI_OBJS)
	$(CHECK_GTK)
	$(CXX) $(LDFLAGS) -o $@ $^ $(GTK_LIBS) $(SSL_LIBS)

$(CLI): $(CORE_OBJS) $(CLI_OBJS)
	$(CXX) $(LDFLAGS) -o $@ $^ $(SSL_LIBS)

$(TEST): $(CORE_OBJS) $(TEST_OBJS)
	$(CXX) $(LDFLAGS) -o $@ $^ $(SSL_LIBS)

test: $(TEST)
	./$(TEST)

run: $(APP)
	./$(APP)

$(BUILD)/%.o: src/%.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) $(SSL_CFLAGS) -c -o $@ $<

$(GUI_OBJS): $(BUILD)/%.o: src/%.cpp | $(BUILD)
	$(CHECK_GTK)
	$(CXX) $(CXXFLAGS) $(GTK_CFLAGS) $(SSL_CFLAGS) -c -o $@ $<

$(BUILD)/test_core.o: tests/test_core.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -Isrc -c -o $@ $<

$(BUILD):
	mkdir -p $@

deps:
	@echo "Debian/Ubuntu:  sudo apt install build-essential pkg-config libgtkmm-4.0-dev libssl-dev"
	@echo "Fedora:         sudo dnf install gcc-c++ pkgconf gtkmm4.0-devel openssl-devel"
	@echo "Arch:           sudo pacman -S base-devel gtkmm-4.0 openssl"

install: $(APP)
	install -Dm755 $(APP) $(DESTDIR)$(PREFIX)/bin/$(APP)
	install -d $(DESTDIR)$(PREFIX)/share/applications
	sed 's|@EXEC@|$(PREFIX)/bin/$(APP)|' data/$(APP_ID).desktop.in > $(DESTDIR)$(PREFIX)/share/applications/$(APP_ID).desktop
	install -Dm644 data/$(APP_ID).svg $(DESTDIR)$(PREFIX)/share/icons/hicolor/scalable/apps/$(APP_ID).svg

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/$(APP) \
	      $(DESTDIR)$(PREFIX)/share/applications/$(APP_ID).desktop \
	      $(DESTDIR)$(PREFIX)/share/icons/hicolor/scalable/apps/$(APP_ID).svg

# Per-user launcher pointing at the binary in this build directory.
install-desktop: $(APP)
	install -d $(USER_APPS)
	sed 's|@EXEC@|$(CURDIR)/$(APP)|' data/$(APP_ID).desktop.in > $(USER_APPS)/$(APP_ID).desktop
	install -Dm644 data/$(APP_ID).svg $(USER_ICONS)/$(APP_ID).svg
	-update-desktop-database -q $(USER_APPS) 2>/dev/null
	@echo "Installed. Launch \"DNS Benchmark\" from Activities / the app grid."

uninstall-desktop:
	rm -f $(USER_APPS)/$(APP_ID).desktop $(USER_ICONS)/$(APP_ID).svg

clean:
	rm -rf $(BUILD) $(APP) $(CLI)

-include $(wildcard $(BUILD)/*.d)
