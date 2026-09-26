// TLS client stream on top of OpenSSL, used by DNS-over-TLS and DNS-over-HTTPS.
#pragma once

#include <string>
#include <vector>

#include "net.h"

typedef struct ssl_st SSL;

class TlsStream : public Stream {
public:
    ~TlsStream() override { close(); }

    // Connects to ip:port and performs the handshake. `host` is used for SNI
    // and certificate verification (an IP literal is verified against the
    // certificate's IP SANs instead). `alpn` lists protocol ids to offer, in
    // preference order; alpn_selected() reports what the server chose.
    bool connect(const std::string& ip, int port, const std::string& host,
                 const std::vector<std::string>& alpn, Deadline d, std::string& err);
    std::string alpn_selected() const;

    bool write_all(const uint8_t* data, size_t len, Deadline d, std::string& err) override;
    long read_some(uint8_t* buf, size_t len, Deadline d, std::string& err) override;
    bool looks_closed() override;
    void close() override;
    bool is_open() const override { return ssl_ != nullptr; }

private:
    // Handles SSL_ERROR_WANT_READ/WRITE by polling. Returns true to retry.
    bool wait_for(int ssl_ret, Deadline d, std::string& err, bool& closed);

    int fd_ = -1;
    SSL* ssl_ = nullptr;
    // True once the handshake completed and no fatal error has occurred since.
    // OpenSSL forbids SSL_shutdown() after SSL_ERROR_SYSCALL / SSL_ERROR_SSL.
    bool can_shutdown_ = false;
};
