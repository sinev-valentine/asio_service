
#include <vector>
#include "sha_wrapper.hpp"

namespace asio_app {

sha1_160_encoder::sha1_160_encoder()
  : sha_encoder_base(EVP_sha1) {
  EVP_DigestInit_ex(ctx, EVP_sha1(), NULL);
}

sha1_160_encoder::~sha1_160_encoder() {}


std::vector<char> sha1_160(const char *src, uint32_t len){
    std::vector<char> hash(20);
    sha1_160_encoder enc;
    enc.write(src, len);
    enc.result(hash.data(), hash.size());
    return hash;
}

std::vector<char> sha1_160(const std::vector<char>& src) {
        return std::move(sha1_160(src.data(), src.size()));
}
}
