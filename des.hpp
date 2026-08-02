/*
 * SPDX-License-Identifier: Unlicense
 */

#ifndef _DES_HPP_
#define _DES_HPP_

#ifndef __cplusplus
#error Do not include des.hpp in a C project, include des.h instead
#endif

#include <vector>
#include <array>
#include <string>
#include <stdexcept>
#include <cstdint>

extern "C" {
#include "des.h"
}

namespace tiny_des {

/* C++ Wrapper for Single DES */
class DES {
public:
    explicit DES(const std::array<uint8_t, 8>& key) {
        DES_init_ctx(&ctx_, key.data());
    }

    DES(const std::array<uint8_t, 8>& key, const std::array<uint8_t, 8>& iv) {
        DES_init_ctx_iv(&ctx_, key.data(), iv.data());
    }

    void set_iv(const std::array<uint8_t, 8>& iv) {
        DES_ctx_set_iv(&ctx_, iv.data());
    }

    void encrypt_ecb(uint8_t block[8]) const {
        DES_ECB_encrypt(&ctx_, block);
    }

    void decrypt_ecb(uint8_t block[8]) const {
        DES_ECB_decrypt(&ctx_, block);
    }

    void encrypt_cbc(std::vector<uint8_t>& data) {
        if (data.size() % 8 != 0) {
            throw std::invalid_argument("Data size must be a multiple of 8 for CBC mode");
        }
        DES_CBC_encrypt_buffer(&ctx_, data.data(), data.size());
    }

    void decrypt_cbc(std::vector<uint8_t>& data) {
        if (data.size() % 8 != 0) {
            throw std::invalid_argument("Data size must be a multiple of 8 for CBC mode");
        }
        DES_CBC_decrypt_buffer(&ctx_, data.data(), data.size());
    }

    void xcrypt_ctr(std::vector<uint8_t>& data) {
        DES_CTR_xcrypt_buffer(&ctx_, data.data(), data.size());
    }

#if defined(CFB64) && (CFB64 == 1)
    void encrypt_cfb64(std::vector<uint8_t>& data) {
        if (data.size() % 8 != 0) {
            throw std::invalid_argument("Data size must be a multiple of 8 for CFB64 mode");
        }
        DES_CFB64_encrypt_buffer(&ctx_, data.data(), data.size());
    }

    void decrypt_cfb64(std::vector<uint8_t>& data) {
        if (data.size() % 8 != 0) {
            throw std::invalid_argument("Data size must be a multiple of 8 for CFB64 mode");
        }
        DES_CFB64_decrypt_buffer(&ctx_, data.data(), data.size());
    }
#endif /* CFB64 */

#if defined(CFB8) && (CFB8 == 1)
    void encrypt_cfb8(std::vector<uint8_t>& data) {
        DES_CFB8_encrypt_buffer(&ctx_, data.data(), data.size());
    }

    void decrypt_cfb8(std::vector<uint8_t>& data) {
        DES_CFB8_decrypt_buffer(&ctx_, data.data(), data.size());
    }
#endif /* CFB8 */

#if defined(CFB1) && (CFB1 == 1)
    void encrypt_cfb1(std::vector<uint8_t>& data, size_t bit_length) {
        DES_CFB1_encrypt_buffer(&ctx_, data.data(), bit_length);
    }

    void decrypt_cfb1(std::vector<uint8_t>& data, size_t bit_length) {
        DES_CFB1_decrypt_buffer(&ctx_, data.data(), bit_length);
    }
#endif /* CFB1 */

#if defined(OFB) && (OFB == 1)
    void xcrypt_ofb(std::vector<uint8_t>& data) {
        DES_OFB_xcrypt_buffer(&ctx_, data.data(), data.size());
    }
#endif /* OFB */

    const DES_ctx& get_c_ctx() const { return ctx_; }

private:
    DES_ctx ctx_;
};

#if defined(TDES) && (TDES == 1)
/* C++ Wrapper for Triple-DES (3DES / TDES) */
class DES3 {
public:
    DES3(const std::vector<uint8_t>& key) {
        if (key.size() != 16 && key.size() != 24) {
            throw std::invalid_argument("3DES key size must be 16 (2-key) or 24 (3-key) bytes");
        }
        DES3_init_ctx(&ctx_, key.data(), key.size());
    }

    DES3(const std::vector<uint8_t>& key, const std::array<uint8_t, 8>& iv) {
        if (key.size() != 16 && key.size() != 24) {
            throw std::invalid_argument("3DES key size must be 16 (2-key) or 24 (3-key) bytes");
        }
        DES3_init_ctx_iv(&ctx_, key.data(), key.size(), iv.data());
    }

    void set_iv(const std::array<uint8_t, 8>& iv) {
        DES3_ctx_set_iv(&ctx_, iv.data());
    }

    void encrypt_ecb(uint8_t block[8]) const {
        DES3_ECB_encrypt(&ctx_, block);
    }

    void decrypt_ecb(uint8_t block[8]) const {
        DES3_ECB_decrypt(&ctx_, block);
    }

    void encrypt_cbc(std::vector<uint8_t>& data) {
        if (data.size() % 8 != 0) {
            throw std::invalid_argument("Data size must be a multiple of 8 for CBC mode");
        }
        DES3_CBC_encrypt_buffer(&ctx_, data.data(), data.size());
    }

    void decrypt_cbc(std::vector<uint8_t>& data) {
        if (data.size() % 8 != 0) {
            throw std::invalid_argument("Data size must be a multiple of 8 for CBC mode");
        }
        DES3_CBC_decrypt_buffer(&ctx_, data.data(), data.size());
    }

    void xcrypt_ctr(std::vector<uint8_t>& data) {
        DES3_CTR_xcrypt_buffer(&ctx_, data.data(), data.size());
    }

#if defined(CFB64) && (CFB64 == 1)
    void encrypt_cfb64(std::vector<uint8_t>& data) {
        if (data.size() % 8 != 0) {
            throw std::invalid_argument("Data size must be a multiple of 8 for CFB64 mode");
        }
        DES3_CFB64_encrypt_buffer(&ctx_, data.data(), data.size());
    }

    void decrypt_cfb64(std::vector<uint8_t>& data) {
        if (data.size() % 8 != 0) {
            throw std::invalid_argument("Data size must be a multiple of 8 for CFB64 mode");
        }
        DES3_CFB64_decrypt_buffer(&ctx_, data.data(), data.size());
    }
#endif /* CFB64 */

#if defined(CFB8) && (CFB8 == 1)
    void encrypt_cfb8(std::vector<uint8_t>& data) {
        DES3_CFB8_encrypt_buffer(&ctx_, data.data(), data.size());
    }

    void decrypt_cfb8(std::vector<uint8_t>& data) {
        DES3_CFB8_decrypt_buffer(&ctx_, data.data(), data.size());
    }
#endif /* CFB8 */

#if defined(CFB1) && (CFB1 == 1)
    void encrypt_cfb1(std::vector<uint8_t>& data, size_t bit_length) {
        DES3_CFB1_encrypt_buffer(&ctx_, data.data(), bit_length);
    }

    void decrypt_cfb1(std::vector<uint8_t>& data, size_t bit_length) {
        DES3_CFB1_decrypt_buffer(&ctx_, data.data(), bit_length);
    }
#endif /* CFB1 */

#if defined(OFB) && (OFB == 1)
    void xcrypt_ofb(std::vector<uint8_t>& data) {
        DES3_OFB_xcrypt_buffer(&ctx_, data.data(), data.size());
    }
#endif /* OFB */

    const DES3_ctx& get_c_ctx() const { return ctx_; }

private:
    DES3_ctx ctx_;
};
#endif /* TDES */

/* C++ CMAC */
inline std::array<uint8_t, 8> cmac(const std::vector<uint8_t>& key, const std::vector<uint8_t>& message) {
    std::array<uint8_t, 8> out{};
    if (DES_cmac(key.data(), key.size(), message.data(), message.size(), out.data()) != 0) {
        throw std::invalid_argument("Invalid key size for CMAC (must be 8, 16, or 24 bytes)");
    }
    return out;
}

} // namespace tiny_des

#endif /* _DES_HPP_ */
