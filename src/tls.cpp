#include "tls.h"

#include <arpa/inet.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <poll.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>

namespace {

SSL_CTX* shared_ctx() {
    // Function-local static: initialised exactly once, thread-safely. SSL_CTX
    // is safe to share between threads once configured.
    static SSL_CTX* ctx = [] {
        SSL_CTX* c = SSL_CTX_new(TLS_client_method());
        if (!c) return c;
        SSL_CTX_set_min_proto_version(c, TLS1_2_VERSION);
        SSL_CTX_set_default_verify_paths(c);
        SSL_CTX_set_verify(c, SSL_VERIFY_PEER, nullptr);
        return c;
    }();
    return ctx;
}

std::string openssl_error(const char* what) {
    unsigned long e = ERR_get_error();
    ERR_clear_error();
    if (!e) return what;
    char buf[256];
    ERR_error_string_n(e, buf, sizeof buf);
    return std::string(what) + ": " + buf;
}

}  // namespace

bool TlsStream::connect(const std::string& ip, int port, const std::string& host,
                        const std::vector<std::string>& alpn, Deadline d, std::string& err) {
    close();
    ERR_clear_error();
    SSL_CTX* ctx = shared_ctx();
    if (!ctx) {
        err = openssl_error("SSL_CTX_new");
        return false;
    }
    fd_ = connect_tcp(ip, port, d, err);
    if (fd_ < 0) return false;

    ssl_ = SSL_new(ctx);
    if (!ssl_) {
        err = openssl_error("SSL_new");
        close();
        return false;
    }
    SSL_set_fd(ssl_, fd_);

    std::string verify_name = host.empty() ? ip : host;
    if (verify_name.size() > 2 && verify_name.front() == '[') verify_name = verify_name.substr(1, verify_name.size() - 2);
    unsigned char probe[16];
    bool is_ip = inet_pton(AF_INET, verify_name.c_str(), probe) == 1 ||
                 inet_pton(AF_INET6, verify_name.c_str(), probe) == 1;
    if (is_ip) {
        X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(ssl_), verify_name.c_str());
    } else {
        SSL_set_tlsext_host_name(ssl_, verify_name.c_str());
        SSL_set1_host(ssl_, verify_name.c_str());
    }
    std::string wire;
    for (const auto& a : alpn) {
        if (a.empty() || a.size() > 255) continue;
        wire.push_back(static_cast<char>(a.size()));
        wire += a;
    }
    if (!wire.empty()) {
        SSL_set_alpn_protos(ssl_, reinterpret_cast<const unsigned char*>(wire.data()),
                            static_cast<unsigned>(wire.size()));
    }

    while (true) {
        // wait_for() consults errno on SSL_ERROR_SYSCALL; clear it so a stale
        // value (e.g. EINPROGRESS from the non-blocking connect) isn't reported.
        errno = 0;
        int r = SSL_connect(ssl_);
        if (r == 1) {
            can_shutdown_ = true;
            return true;
        }
        bool closed = false;
        long verify = SSL_get_verify_result(ssl_);
        if (!wait_for(r, d, err, closed)) {
            if (verify != X509_V_OK)
                err = std::string("certificate: ") + X509_verify_cert_error_string(verify);
            else if (err == kTimeoutError)
                err = "TLS handshake timeout";
            else if (closed)
                err = "TLS handshake: connection closed";
            close();
            return false;
        }
    }
}

std::string TlsStream::alpn_selected() const {
    if (!ssl_) return "";
    const unsigned char* data = nullptr;
    unsigned int len = 0;
    SSL_get0_alpn_selected(ssl_, &data, &len);
    return data ? std::string(reinterpret_cast<const char*>(data), len) : "";
}

bool TlsStream::wait_for(int ssl_ret, Deadline d, std::string& err, bool& closed) {
    int e = SSL_get_error(ssl_, ssl_ret);
    switch (e) {
        case SSL_ERROR_WANT_READ: return wait_fd(fd_, POLLIN, d, err);
        case SSL_ERROR_WANT_WRITE: return wait_fd(fd_, POLLOUT, d, err);
        case SSL_ERROR_ZERO_RETURN:  // peer sent close_notify: answering it is fine
            closed = true;
            err = "connection closed";
            return false;
        case SSL_ERROR_SYSCALL:
            can_shutdown_ = false;
            if (ERR_peek_error() == 0) {
                closed = errno == 0;
                err = closed ? "connection closed" : std::string("TLS I/O: ") + std::strerror(errno);
                return false;
            }
            [[fallthrough]];
        default:
            can_shutdown_ = false;
            err = openssl_error("TLS");
            // OpenSSL 3 reports an unclean EOF as an SSL error.
            if (err.find("unexpected eof") != std::string::npos) closed = true;
            return false;
    }
}

bool TlsStream::write_all(const uint8_t* data, size_t len, Deadline d, std::string& err) {
    size_t sent = 0;
    while (sent < len) {
        size_t n = 0;
        ERR_clear_error();
        errno = 0;
        int r = SSL_write_ex(ssl_, data + sent, len - sent, &n);
        if (r == 1) {
            sent += n;
            continue;
        }
        bool closed = false;
        if (!wait_for(r, d, err, closed)) return false;
    }
    return true;
}

long TlsStream::read_some(uint8_t* buf, size_t len, Deadline d, std::string& err) {
    while (true) {
        size_t n = 0;
        ERR_clear_error();
        errno = 0;
        int r = SSL_read_ex(ssl_, buf, len, &n);
        if (r == 1) return static_cast<long>(n);
        bool closed = false;
        if (!wait_for(r, d, err, closed)) return closed ? 0 : -1;
    }
}

bool TlsStream::looks_closed() {
    if (!ssl_) return true;
    pollfd p{fd_, POLLIN, 0};
    if (poll(&p, 1, 0) <= 0) return false;  // nothing pending: still alive
    // Something arrived while idle. It is usually a TLS 1.3 session ticket
    // (consumed internally, SSL_peek then wants more input) or a close_notify.
    uint8_t b;
    size_t n = 0;
    ERR_clear_error();
    errno = 0;
    int r = SSL_peek_ex(ssl_, &b, 1, &n);
    if (r == 1) return false;
    int e = SSL_get_error(ssl_, r);
    ERR_clear_error();
    if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) return false;
    if (e != SSL_ERROR_ZERO_RETURN) can_shutdown_ = false;
    return true;
}

void TlsStream::close() {
    if (ssl_) {
        if (can_shutdown_) SSL_shutdown(ssl_);  // best effort, non-blocking: sends close_notify
        SSL_free(ssl_);
        ssl_ = nullptr;
    }
    can_shutdown_ = false;
    if (fd_ >= 0) ::close(fd_);
    fd_ = -1;
    ERR_clear_error();
}
