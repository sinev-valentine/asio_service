
#ifndef ASIO_APP_SHA_WRAP_H
#define ASIO_APP_SHA_WRAP_H

#include <array>
#include <functional>
#include <openssl/evp.h>

namespace asio_app {

template<size_t N>
struct sha_encoder_base {
    template<typename T>
    sha_encoder_base(T p_evp_sha_func)
            :m_evp_sha_func(p_evp_sha_func) {
        ctx = EVP_MD_CTX_create();
    }

    using   result_t = std::array<uint8_t, N>;

    virtual ~sha_encoder_base() {
        EVP_MD_CTX_destroy(ctx);
    }

    void write(const char *d, uint32_t dlen) {
        EVP_DigestUpdate(ctx, d, dlen);
    }

    void put(char c) {
        write(&c, 1);
    }

    result_t result() {
        result_t result;
        unsigned int digest_len;
        int sha_size = EVP_MD_size(m_evp_sha_func());
        if(result.size() != sha_size)
            throw std::runtime_error("sha_encoder_base::result(): Invalid sha hash size");

        EVP_DigestFinal_ex(ctx, result.data(), &digest_len);

        if(digest_len != result.size())
            throw std::runtime_error("sha_encoder_base::result(): Invalid sha hash size has been written");

        return result;
    }

    void result(char *out, uint32_t dlen) {
        unsigned int digest_len;
        int sha_size = EVP_MD_size(m_evp_sha_func());
        if(dlen != sha_size)
            throw std::runtime_error("sha_encoder_base::result(char, uint32_t): Invalid sha hash size");
        EVP_DigestFinal_ex(ctx, (unsigned char *) out, &digest_len);
        if(digest_len != dlen)
            throw std::runtime_error("sha_encoder_base::result(char, uint32_t): Invalid sha hash size has been written");
    }

protected:
    EVP_MD_CTX *ctx;
    std::function<const EVP_MD *(void)> m_evp_sha_func;
};


struct sha1_160_encoder : public sha_encoder_base<20> {
    sha1_160_encoder();
    virtual ~sha1_160_encoder();
};

std::vector<char> sha1_160(const std::vector<char>& src);
std::vector<char> sha1_160(const char *src, uint32_t len);

}

#endif //ASIO_APP_SHA_WRAP_H
