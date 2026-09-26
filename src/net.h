// Deadline-driven, non-blocking socket helpers shared by all transports.
#pragma once

#include <sys/socket.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>

using Clock = std::chrono::steady_clock;
using Deadline = Clock::time_point;

// Error string used for every deadline expiry, so callers can tell timeouts
// apart from connection failures.
extern const char* const kTimeoutError;

inline Deadline deadline_in_ms(int ms) { return Clock::now() + std::chrono::milliseconds(ms); }
int ms_until(Deadline d);  // clamped to >= 0
double ms_since(Clock::time_point t);

bool make_sockaddr(const std::string& ip, int port, sockaddr_storage& sa, socklen_t& len);

// Waits for `events` (POLLIN/POLLOUT) on fd until the deadline.
bool wait_fd(int fd, short events, Deadline d, std::string& err);

// Non-blocking TCP connect. Returns the (still non-blocking) fd or -1.
int connect_tcp(const std::string& ip, int port, Deadline d, std::string& err);

// Byte-stream abstraction over a plain TCP socket or a TLS session.
class Stream {
public:
    virtual ~Stream() = default;
    virtual bool write_all(const uint8_t* data, size_t len, Deadline d, std::string& err) = 0;
    // Returns bytes read (>0), 0 when the peer closed the stream, -1 on error.
    virtual long read_some(uint8_t* buf, size_t len, Deadline d, std::string& err) = 0;
    // True if an idle keep-alive connection has been closed by the peer.
    virtual bool looks_closed() = 0;
    virtual void close() = 0;
    virtual bool is_open() const = 0;

    bool read_exact(uint8_t* buf, size_t len, Deadline d, std::string& err);
};

class PlainStream : public Stream {
public:
    ~PlainStream() override { close(); }
    bool connect(const std::string& ip, int port, Deadline d, std::string& err);
    bool write_all(const uint8_t* data, size_t len, Deadline d, std::string& err) override;
    long read_some(uint8_t* buf, size_t len, Deadline d, std::string& err) override;
    bool looks_closed() override;
    void close() override;
    bool is_open() const override { return fd_ >= 0; }

private:
    int fd_ = -1;
};
