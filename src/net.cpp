#include "net.h"

#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>

const char* const kTimeoutError = "timeout";

int ms_until(Deadline d) {
    auto left = std::chrono::duration_cast<std::chrono::milliseconds>(d - Clock::now()).count();
    return left > 0 ? static_cast<int>(left) : 0;
}

double ms_since(Clock::time_point t) {
    return std::chrono::duration<double, std::milli>(Clock::now() - t).count();
}

bool make_sockaddr(const std::string& ip, int port, sockaddr_storage& sa, socklen_t& len) {
    addrinfo hints{};
    hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
    hints.ai_family = AF_UNSPEC;
    addrinfo* res = nullptr;
    std::string p = std::to_string(port);
    if (getaddrinfo(ip.c_str(), p.c_str(), &hints, &res) != 0 || !res) return false;
    std::memcpy(&sa, res->ai_addr, res->ai_addrlen);
    len = res->ai_addrlen;
    freeaddrinfo(res);
    return true;
}

bool wait_fd(int fd, short events, Deadline d, std::string& err) {
    while (true) {
        pollfd p{fd, events, 0};
        int left = ms_until(d);
        int r = poll(&p, 1, left);
        if (r > 0) return true;  // readable/writable or error: caller's next syscall reports it
        if (r == 0) {
            err = kTimeoutError;
            return false;
        }
        if (errno != EINTR) {
            err = std::string("poll: ") + std::strerror(errno);
            return false;
        }
    }
}

int connect_tcp(const std::string& ip, int port, Deadline d, std::string& err) {
    sockaddr_storage sa{};
    socklen_t len = 0;
    if (!make_sockaddr(ip, port, sa, len)) {
        err = "bad address";
        return -1;
    }
    int fd = socket(sa.ss_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        err = std::string("socket: ") + std::strerror(errno);
        return -1;
    }
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    if (::connect(fd, reinterpret_cast<sockaddr*>(&sa), len) < 0 && errno != EINPROGRESS) {
        err = std::string("connect: ") + std::strerror(errno);
        ::close(fd);
        return -1;
    }
    if (!wait_fd(fd, POLLOUT, d, err)) {
        if (err == kTimeoutError) err = "connect timeout";
        ::close(fd);
        return -1;
    }
    int soerr = 0;
    socklen_t sl = sizeof soerr;
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &sl);
    if (soerr) {
        err = std::string("connect: ") + std::strerror(soerr);
        ::close(fd);
        return -1;
    }
    return fd;
}

bool Stream::read_exact(uint8_t* buf, size_t len, Deadline d, std::string& err) {
    size_t got = 0;
    while (got < len) {
        long n = read_some(buf + got, len - got, d, err);
        if (n == 0) {
            err = "connection closed";
            return false;
        }
        if (n < 0) return false;
        got += static_cast<size_t>(n);
    }
    return true;
}

bool PlainStream::connect(const std::string& ip, int port, Deadline d, std::string& err) {
    close();
    fd_ = connect_tcp(ip, port, d, err);
    return fd_ >= 0;
}

bool PlainStream::write_all(const uint8_t* data, size_t len, Deadline d, std::string& err) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = ::send(fd_, data + sent, len - sent, MSG_NOSIGNAL);
        if (n > 0) {
            sent += static_cast<size_t>(n);
            continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            if (!wait_fd(fd_, POLLOUT, d, err)) return false;
            continue;
        }
        if (n < 0 && errno == EINTR) continue;
        err = std::string("send: ") + std::strerror(errno);
        return false;
    }
    return true;
}

long PlainStream::read_some(uint8_t* buf, size_t len, Deadline d, std::string& err) {
    while (true) {
        ssize_t n = ::recv(fd_, buf, len, 0);
        if (n >= 0) return static_cast<long>(n);
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            if (!wait_fd(fd_, POLLIN, d, err)) return -1;
            continue;
        }
        if (errno == EINTR) continue;
        err = std::string("recv: ") + std::strerror(errno);
        return -1;
    }
}

bool PlainStream::looks_closed() {
    if (fd_ < 0) return true;
    uint8_t b;
    ssize_t n = ::recv(fd_, &b, 1, MSG_PEEK | MSG_DONTWAIT);
    if (n == 0) return true;  // orderly shutdown by peer
    if (n < 0) return !(errno == EAGAIN || errno == EWOULDBLOCK);
    return false;  // unexpected pending data; stream framing will cope
}

void PlainStream::close() {
    if (fd_ >= 0) ::close(fd_);
    fd_ = -1;
}
