/*
 * SPDX-License-Identifier: Unlicense
 */

#ifndef _DES_H_
#define _DES_H_

#include <stdint.h>
#include <stddef.h>

/**
 * @file des.h
 * @brief Portable, high-performance C implementation of DES and Triple-DES (3DES / TDES).
 *
 * Designed for microcontrollers and embedded devices.
 * Inspired by kokke's tiny-AES-c.
 */

#ifndef CBC
  #if defined(DES_ENABLE_CBC)
    #define CBC DES_ENABLE_CBC
  #else
    #define CBC 1
  #endif
#endif

#ifndef ECB
  #if defined(DES_ENABLE_ECB)
    #define ECB DES_ENABLE_ECB
  #else
    #define ECB 1
  #endif
#endif

#ifndef CTR
  #if defined(DES_ENABLE_CTR)
    #define CTR DES_ENABLE_CTR
  #else
    #define CTR 1
  #endif
#endif

#ifndef TDES
  #if defined(DES_ENABLE_TDES)
    #define TDES DES_ENABLE_TDES
  #else
    #define TDES 1
  #endif
#endif

#ifndef CFB1
  #if defined(DES_ENABLE_CFB1)
    #define CFB1 DES_ENABLE_CFB1
  #else
    #define CFB1 1
  #endif
#endif

#ifndef CFB8
  #if defined(DES_ENABLE_CFB8)
    #define CFB8 DES_ENABLE_CFB8
  #else
    #define CFB8 1
  #endif
#endif

#ifndef CFB64
  #if defined(DES_ENABLE_CFB64)
    #define CFB64 DES_ENABLE_CFB64
  #else
    #define CFB64 1
  #endif
#endif

#ifndef OFB
  #if defined(DES_ENABLE_OFB)
    #define OFB DES_ENABLE_OFB
  #else
    #define OFB 1
  #endif
#endif

/* Modes that keep chaining state in ctx->Iv */
#if (CBC == 1) || (CTR == 1) || (CFB1 == 1) || (CFB8 == 1) || (CFB64 == 1) || (OFB == 1)
  #define DES_NEEDS_IV 1
#else
  #define DES_NEEDS_IV 0
#endif

#define DES_BLOCKLEN     8  /**< Block length in bytes - DES is a 64-bit (8 bytes) block cipher */
#define DES_KEYLEN       8  /**< Single DES key length in bytes (64 bits total, 56 bits effective) */

#define DES3_KEYLEN_2KEY 16 /**< 2-Key Triple DES key length in bytes (128 bits total, 112 bits effective) */
#define DES3_KEYLEN_3KEY 24 /**< 3-Key Triple DES key length in bytes (192 bits total, 168 bits effective) */

/**
 * @brief Single DES Context Structure
 */
struct DES_ctx
{
  uint32_t Sk[16][2];
#if DES_NEEDS_IV
  uint8_t Iv[DES_BLOCKLEN];
#endif
};

#if defined(TDES) && (TDES == 1)
/**
 * @brief Triple DES (3DES / TDES) Context Structure
 */
struct DES3_ctx
{
  uint32_t Sk[48][2];
#if DES_NEEDS_IV
  uint8_t Iv[DES_BLOCKLEN];
#endif
};
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* --- Single DES API --- */

/**
 * @brief Initialize a Single DES context with key.
 * @param ctx Pointer to Single DES context structure.
 * @param key Pointer to 8-byte key buffer.
 */
void DES_init_ctx(struct DES_ctx* ctx, const uint8_t* key);

#if DES_NEEDS_IV
/**
 * @brief Initialize a Single DES context with key and IV.
 * @param ctx Pointer to Single DES context structure.
 * @param key Pointer to 8-byte key buffer.
 * @param iv Pointer to 8-byte Initialization Vector.
 */
void DES_init_ctx_iv(struct DES_ctx* ctx, const uint8_t* key, const uint8_t* iv);

/**
 * @brief Set or update the Initialization Vector (IV) in Single DES context.
 * @param ctx Pointer to Single DES context structure.
 * @param iv Pointer to 8-byte Initialization Vector.
 */
void DES_ctx_set_iv(struct DES_ctx* ctx, const uint8_t* iv);
#endif

#if defined(ECB) && (ECB == 1)
/**
 * @brief Encrypt an 8-byte block in ECB mode using Single DES.
 * @param ctx Pointer to initialized Single DES context.
 * @param buf Pointer to 8-byte data block (encrypted in-place).
 */
void DES_ECB_encrypt(const struct DES_ctx* ctx, uint8_t* buf);

/**
 * @brief Decrypt an 8-byte block in ECB mode using Single DES.
 * @param ctx Pointer to initialized Single DES context.
 * @param buf Pointer to 8-byte data block (decrypted in-place).
 */
void DES_ECB_decrypt(const struct DES_ctx* ctx, uint8_t* buf);
#endif

#if defined(CBC) && (CBC == 1)
/**
 * @brief Encrypt buffer in CBC mode using Single DES.
 * @param ctx Pointer to initialized Single DES context.
 * @param buf Data buffer (length must be a multiple of 8 bytes). Encrypted in-place.
 * @param length Data length in bytes (must be a multiple of 8).
 */
void DES_CBC_encrypt_buffer(struct DES_ctx* ctx, uint8_t* buf, size_t length);

/**
 * @brief Decrypt buffer in CBC mode using Single DES.
 * @param ctx Pointer to initialized Single DES context.
 * @param buf Data buffer (length must be a multiple of 8 bytes). Decrypted in-place.
 * @param length Data length in bytes (must be a multiple of 8).
 */
void DES_CBC_decrypt_buffer(struct DES_ctx* ctx, uint8_t* buf, size_t length);
#endif

#if defined(CTR) && (CTR == 1)
/**
 * @brief Encrypt/Decrypt buffer in Counter (CTR) stream mode using Single DES.
 * @param ctx Pointer to initialized Single DES context.
 * @param buf Data buffer (arbitrary length). Transformed in-place.
 * @param length Data length in bytes.
 */
void DES_CTR_xcrypt_buffer(struct DES_ctx* ctx, uint8_t* buf, size_t length);
#endif

#if defined(CFB64) && (CFB64 == 1)
/**
 * @brief Encrypt buffer in 64-bit Cipher Feedback (CFB64) mode using Single DES.
 * @param ctx Pointer to initialized Single DES context (IV holds chaining state).
 * @param buf Data buffer (length must be a multiple of 8 bytes). Encrypted in-place.
 * @param length Data length in bytes (must be a multiple of 8).
 */
void DES_CFB64_encrypt_buffer(struct DES_ctx* ctx, uint8_t* buf, size_t length);

/**
 * @brief Decrypt buffer in 64-bit Cipher Feedback (CFB64) mode using Single DES.
 * @param ctx Pointer to initialized Single DES context (IV holds chaining state).
 * @param buf Data buffer (length must be a multiple of 8 bytes). Decrypted in-place.
 * @param length Data length in bytes (must be a multiple of 8).
 */
void DES_CFB64_decrypt_buffer(struct DES_ctx* ctx, uint8_t* buf, size_t length);
#endif

#if defined(CFB8) && (CFB8 == 1)
/**
 * @brief Encrypt buffer in 8-bit Cipher Feedback (CFB8) mode using Single DES.
 * @param ctx Pointer to initialized Single DES context (IV holds chaining state).
 * @param buf Data buffer (arbitrary length). Encrypted in-place.
 * @param length Data length in bytes.
 */
void DES_CFB8_encrypt_buffer(struct DES_ctx* ctx, uint8_t* buf, size_t length);

/**
 * @brief Decrypt buffer in 8-bit Cipher Feedback (CFB8) mode using Single DES.
 * @param ctx Pointer to initialized Single DES context (IV holds chaining state).
 * @param buf Data buffer (arbitrary length). Decrypted in-place.
 * @param length Data length in bytes.
 */
void DES_CFB8_decrypt_buffer(struct DES_ctx* ctx, uint8_t* buf, size_t length);
#endif

#if defined(CFB1) && (CFB1 == 1)
/**
 * @brief Encrypt bits in 1-bit Cipher Feedback (CFB1) mode using Single DES.
 *
 * Bits are packed MSB-first: bit i of the stream is (buf[i/8] >> (7 - i%8)) & 1.
 * Trailing pad bits of the final byte are left unchanged.
 *
 * @param ctx Pointer to initialized Single DES context (IV holds chaining state).
 * @param buf Packed bit buffer. Encrypted in-place.
 * @param bit_length Data length in bits.
 */
void DES_CFB1_encrypt_buffer(struct DES_ctx* ctx, uint8_t* buf, size_t bit_length);

/**
 * @brief Decrypt bits in 1-bit Cipher Feedback (CFB1) mode using Single DES.
 *
 * Bits are packed MSB-first: bit i of the stream is (buf[i/8] >> (7 - i%8)) & 1.
 * Trailing pad bits of the final byte are left unchanged.
 *
 * @param ctx Pointer to initialized Single DES context (IV holds chaining state).
 * @param buf Packed bit buffer. Decrypted in-place.
 * @param bit_length Data length in bits.
 */
void DES_CFB1_decrypt_buffer(struct DES_ctx* ctx, uint8_t* buf, size_t bit_length);
#endif

#if defined(OFB) && (OFB == 1)
/**
 * @brief Encrypt/Decrypt buffer in Output Feedback (OFB) stream mode using Single DES.
 * @param ctx Pointer to initialized Single DES context (IV holds chaining state).
 * @param buf Data buffer (length must be a multiple of 8 bytes). Transformed in-place.
 * @param length Data length in bytes (must be a multiple of 8).
 */
void DES_OFB_xcrypt_buffer(struct DES_ctx* ctx, uint8_t* buf, size_t length);
#endif


/* --- Triple DES (3DES / TDES) API --- */
#if defined(TDES) && (TDES == 1)

/**
 * @brief Initialize a Triple DES (3DES) context with key.
 * @param ctx Pointer to 3DES context structure.
 * @param key Pointer to key buffer (16 bytes for 2-Key 3DES, 24 bytes for 3-Key 3DES).
 * @param keylen Key length in bytes (16 or 24).
 */
void DES3_init_ctx(struct DES3_ctx* ctx, const uint8_t* key, size_t keylen);

#if DES_NEEDS_IV
/**
 * @brief Initialize a Triple DES (3DES) context with key and IV.
 * @param ctx Pointer to 3DES context structure.
 * @param key Pointer to key buffer (16 or 24 bytes).
 * @param keylen Key length in bytes (16 or 24).
 * @param iv Pointer to 8-byte Initialization Vector.
 */
void DES3_init_ctx_iv(struct DES3_ctx* ctx, const uint8_t* key, size_t keylen, const uint8_t* iv);

/**
 * @brief Set or update the Initialization Vector (IV) in 3DES context.
 * @param ctx Pointer to 3DES context structure.
 * @param iv Pointer to 8-byte Initialization Vector.
 */
void DES3_ctx_set_iv(struct DES3_ctx* ctx, const uint8_t* iv);
#endif

#if defined(ECB) && (ECB == 1)
/**
 * @brief Encrypt an 8-byte block in ECB mode using 3DES.
 * @param ctx Pointer to initialized 3DES context.
 * @param buf Pointer to 8-byte data block (encrypted in-place).
 */
void DES3_ECB_encrypt(const struct DES3_ctx* ctx, uint8_t* buf);

/**
 * @brief Decrypt an 8-byte block in ECB mode using 3DES.
 * @param ctx Pointer to initialized 3DES context.
 * @param buf Pointer to 8-byte data block (decrypted in-place).
 */
void DES3_ECB_decrypt(const struct DES3_ctx* ctx, uint8_t* buf);
#endif

#if defined(CBC) && (CBC == 1)
/**
 * @brief Encrypt buffer in CBC mode using 3DES.
 * @param ctx Pointer to initialized 3DES context.
 * @param buf Data buffer (length must be a multiple of 8 bytes). Encrypted in-place.
 * @param length Data length in bytes (must be a multiple of 8).
 */
void DES3_CBC_encrypt_buffer(struct DES3_ctx* ctx, uint8_t* buf, size_t length);

/**
 * @brief Decrypt buffer in CBC mode using 3DES.
 * @param ctx Pointer to initialized 3DES context.
 * @param buf Data buffer (length must be a multiple of 8 bytes). Decrypted in-place.
 * @param length Data length in bytes (must be a multiple of 8).
 */
void DES3_CBC_decrypt_buffer(struct DES3_ctx* ctx, uint8_t* buf, size_t length);
#endif

#if defined(CTR) && (CTR == 1)
/**
 * @brief Encrypt/Decrypt buffer in Counter (CTR) stream mode using 3DES.
 * @param ctx Pointer to initialized 3DES context.
 * @param buf Data buffer (arbitrary length). Transformed in-place.
 * @param length Data length in bytes.
 */
void DES3_CTR_xcrypt_buffer(struct DES3_ctx* ctx, uint8_t* buf, size_t length);
#endif

#if defined(CFB64) && (CFB64 == 1)
/**
 * @brief Encrypt buffer in 64-bit Cipher Feedback (CFB64) mode using 3DES.
 * @param ctx Pointer to initialized 3DES context (IV holds chaining state).
 * @param buf Data buffer (length must be a multiple of 8 bytes). Encrypted in-place.
 * @param length Data length in bytes (must be a multiple of 8).
 */
void DES3_CFB64_encrypt_buffer(struct DES3_ctx* ctx, uint8_t* buf, size_t length);

/**
 * @brief Decrypt buffer in 64-bit Cipher Feedback (CFB64) mode using 3DES.
 * @param ctx Pointer to initialized 3DES context (IV holds chaining state).
 * @param buf Data buffer (length must be a multiple of 8 bytes). Decrypted in-place.
 * @param length Data length in bytes (must be a multiple of 8).
 */
void DES3_CFB64_decrypt_buffer(struct DES3_ctx* ctx, uint8_t* buf, size_t length);
#endif

#if defined(CFB8) && (CFB8 == 1)
/**
 * @brief Encrypt buffer in 8-bit Cipher Feedback (CFB8) mode using 3DES.
 * @param ctx Pointer to initialized 3DES context (IV holds chaining state).
 * @param buf Data buffer (arbitrary length). Encrypted in-place.
 * @param length Data length in bytes.
 */
void DES3_CFB8_encrypt_buffer(struct DES3_ctx* ctx, uint8_t* buf, size_t length);

/**
 * @brief Decrypt buffer in 8-bit Cipher Feedback (CFB8) mode using 3DES.
 * @param ctx Pointer to initialized 3DES context (IV holds chaining state).
 * @param buf Data buffer (arbitrary length). Decrypted in-place.
 * @param length Data length in bytes.
 */
void DES3_CFB8_decrypt_buffer(struct DES3_ctx* ctx, uint8_t* buf, size_t length);
#endif

#if defined(CFB1) && (CFB1 == 1)
/**
 * @brief Encrypt bits in 1-bit Cipher Feedback (CFB1) mode using 3DES.
 *
 * Bits are packed MSB-first: bit i of the stream is (buf[i/8] >> (7 - i%8)) & 1.
 * Trailing pad bits of the final byte are left unchanged.
 *
 * @param ctx Pointer to initialized 3DES context (IV holds chaining state).
 * @param buf Packed bit buffer. Encrypted in-place.
 * @param bit_length Data length in bits.
 */
void DES3_CFB1_encrypt_buffer(struct DES3_ctx* ctx, uint8_t* buf, size_t bit_length);

/**
 * @brief Decrypt bits in 1-bit Cipher Feedback (CFB1) mode using 3DES.
 *
 * Bits are packed MSB-first: bit i of the stream is (buf[i/8] >> (7 - i%8)) & 1.
 * Trailing pad bits of the final byte are left unchanged.
 *
 * @param ctx Pointer to initialized 3DES context (IV holds chaining state).
 * @param buf Packed bit buffer. Decrypted in-place.
 * @param bit_length Data length in bits.
 */
void DES3_CFB1_decrypt_buffer(struct DES3_ctx* ctx, uint8_t* buf, size_t bit_length);
#endif

#if defined(OFB) && (OFB == 1)
/**
 * @brief Encrypt/Decrypt buffer in Output Feedback (OFB) stream mode using 3DES.
 * @param ctx Pointer to initialized 3DES context (IV holds chaining state).
 * @param buf Data buffer (length must be a multiple of 8 bytes). Transformed in-place.
 * @param length Data length in bytes (must be a multiple of 8).
 */
void DES3_OFB_xcrypt_buffer(struct DES3_ctx* ctx, uint8_t* buf, size_t length);
#endif

#endif /* #if defined(TDES) && (TDES == 1) */


/* --- DES / 3DES CMAC (NIST SP 800-38B) --- */

/**
 * @brief Calculate NIST SP 800-38B CMAC tag (Zero IV).
 * @param key Pointer to key buffer (8, 16, or 24 bytes).
 * @param keylen Key length in bytes (8, 16, or 24).
 * @param message Message buffer.
 * @param message_len Message length in bytes.
 * @param cmac_out Output buffer for 8-byte CMAC tag.
 * @return 0 on success, -1 on invalid key length.
 */
int DES_cmac(const uint8_t* key, size_t keylen, const uint8_t* message, size_t message_len, uint8_t* cmac_out);

/**
 * @brief Calculate NIST SP 800-38B CMAC tag with explicit IV.
 * @param key Pointer to key buffer (8, 16, or 24 bytes).
 * @param keylen Key length in bytes (8, 16, or 24).
 * @param message Message buffer.
 * @param message_len Message length in bytes.
 * @param iv Pointer to 8-byte IV (or NULL for zero IV).
 * @param cmac_out Output buffer for 8-byte CMAC tag.
 * @return 0 on success, -1 on invalid key length.
 */
int DES_cmac_with_iv(const uint8_t* key, size_t keylen, const uint8_t* message, size_t message_len, const uint8_t* iv, uint8_t* cmac_out);

#ifdef __cplusplus
}
#endif

#endif /* _DES_H_ */
