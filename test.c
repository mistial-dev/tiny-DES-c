/*
 * SPDX-License-Identifier: Unlicense
 *
 * Unit tests for tiny-DES-c using µunit (munit)
 * https://nemequ.github.io/munit/
 */

#include <stdio.h>
#include <string.h>
#include "munit.h"
#include "des.h"
#include "test_vectors.h"

#if defined(DES_CAVP) && (DES_CAVP == 1) && \
    (ECB == 1) && (CBC == 1) && (CFB1 == 1) && (CFB8 == 1) && \
    (CFB64 == 1) && (OFB == 1) && (TDES == 1)
/* Implemented in cavp.c; runs the full NIST CAVP TDES corpora */
#define DES_CAVP_AVAILABLE 1
MunitResult test_cavp(const MunitParameter params[], void* data);
#else
#define DES_CAVP_AVAILABLE 0
#endif

/* ========================================================================= */
/* Matrix 1: Single DES                                                      */
/* ========================================================================= */

/* 1A. Single DES ECB (KAT Encrypt, KAT Decrypt, & Round-Trip) */
static MunitResult test_des_ecb(const MunitParameter params[], void* data)
{
  (void) params;
  (void) data;

  struct DES_ctx ctx;
  uint8_t buffer[8];

  DES_init_ctx(&ctx, des_test_key);

  /* KAT Encrypt */
  memcpy(buffer, des_test_pt, 8);
  DES_ECB_encrypt(&ctx, buffer);
  munit_assert_memory_equal(8, buffer, des_test_ct);

  /* KAT Decrypt */
  memcpy(buffer, des_test_ct, 8);
  DES_ECB_decrypt(&ctx, buffer);
  munit_assert_memory_equal(8, buffer, des_test_pt);

  /* Round-Trip */
  DES_ECB_encrypt(&ctx, buffer);
  munit_assert_memory_equal(8, buffer, des_test_ct);
  DES_ECB_decrypt(&ctx, buffer);
  munit_assert_memory_equal(8, buffer, des_test_pt);

  return MUNIT_OK;
}

/* 1B. Single DES CBC (KAT Encrypt, KAT Decrypt, & Round-Trip) */
static MunitResult test_des_cbc(const MunitParameter params[], void* data)
{
  (void) params;
  (void) data;

  struct DES_ctx ctx;
  uint8_t buffer[8];

  /* KAT Encrypt */
  DES_init_ctx_iv(&ctx, des_test_key, des_cbc_iv);
  memcpy(buffer, des_test_pt, 8);
  DES_CBC_encrypt_buffer(&ctx, buffer, 8);
  munit_assert_memory_equal(8, buffer, des_cbc_ct);

  /* KAT Decrypt */
  DES_ctx_set_iv(&ctx, des_cbc_iv);
  memcpy(buffer, des_cbc_ct, 8);
  DES_CBC_decrypt_buffer(&ctx, buffer, 8);
  munit_assert_memory_equal(8, buffer, des_test_pt);

  /* Round-Trip */
  DES_ctx_set_iv(&ctx, des_cbc_iv);
  DES_CBC_encrypt_buffer(&ctx, buffer, 8);
  munit_assert_memory_equal(8, buffer, des_cbc_ct);
  DES_ctx_set_iv(&ctx, des_cbc_iv);
  DES_CBC_decrypt_buffer(&ctx, buffer, 8);
  munit_assert_memory_equal(8, buffer, des_test_pt);

  return MUNIT_OK;
}

/* 1C. Single DES CTR Stream Mode */
static MunitResult test_des_ctr(const MunitParameter params[], void* data)
{
  (void) params;
  (void) data;

  struct DES_ctx ctx;
  uint8_t original[20] = "Hello DES CTR Mode!";
  uint8_t buffer[20];

  memcpy(buffer, original, 20);

  /* Encrypt */
  DES_init_ctx_iv(&ctx, des_test_key, des_ctr_iv);
  DES_CTR_xcrypt_buffer(&ctx, buffer, 20);
  munit_assert_memory_not_equal(20, buffer, original);

  /* Decrypt */
  DES_ctx_set_iv(&ctx, des_ctr_iv);
  DES_CTR_xcrypt_buffer(&ctx, buffer, 20);
  munit_assert_memory_equal(20, buffer, original);

  return MUNIT_OK;
}


/* ========================================================================= */
/* Matrix 2: 2-Key 3DES (Triple DES)                                         */
/* ========================================================================= */

/* 2A. 2-Key 3DES ECB (KAT Encrypt, KAT Decrypt, & Round-Trip) */
static MunitResult test_tdes2_ecb(const MunitParameter params[], void* data)
{
  (void) params;
  (void) data;

  struct DES3_ctx ctx;
  uint8_t buffer[16];

  DES3_init_ctx(&ctx, tdes2_key, 16);

  /* KAT Encrypt (2 blocks) */
  memcpy(buffer, tdes2_pt, 16);
  DES3_ECB_encrypt(&ctx, buffer);
  DES3_ECB_encrypt(&ctx, buffer + 8);
  munit_assert_memory_equal(16, buffer, tdes2_ecb_ct);

  /* KAT Decrypt (2 blocks) */
  memcpy(buffer, tdes2_ecb_ct, 16);
  DES3_ECB_decrypt(&ctx, buffer);
  DES3_ECB_decrypt(&ctx, buffer + 8);
  munit_assert_memory_equal(16, buffer, tdes2_pt);

  /* Round-Trip */
  DES3_ECB_encrypt(&ctx, buffer);
  DES3_ECB_encrypt(&ctx, buffer + 8);
  munit_assert_memory_equal(16, buffer, tdes2_ecb_ct);
  DES3_ECB_decrypt(&ctx, buffer);
  DES3_ECB_decrypt(&ctx, buffer + 8);
  munit_assert_memory_equal(16, buffer, tdes2_pt);

  return MUNIT_OK;
}

/* 2B. 2-Key 3DES CBC (KAT Encrypt, KAT Decrypt, & Round-Trip) */
static MunitResult test_tdes2_cbc(const MunitParameter params[], void* data)
{
  (void) params;
  (void) data;

  struct DES3_ctx ctx;
  uint8_t buffer[16];

  /* KAT Encrypt */
  DES3_init_ctx_iv(&ctx, tdes2_key, 16, des_cbc_iv);
  memcpy(buffer, tdes2_pt, 16);
  DES3_CBC_encrypt_buffer(&ctx, buffer, 16);
  munit_assert_memory_equal(16, buffer, tdes2_cbc_ct);

  /* KAT Decrypt */
  DES3_ctx_set_iv(&ctx, des_cbc_iv);
  memcpy(buffer, tdes2_cbc_ct, 16);
  DES3_CBC_decrypt_buffer(&ctx, buffer, 16);
  munit_assert_memory_equal(16, buffer, tdes2_pt);

  /* Round-Trip */
  DES3_ctx_set_iv(&ctx, des_cbc_iv);
  DES3_CBC_encrypt_buffer(&ctx, buffer, 16);
  munit_assert_memory_equal(16, buffer, tdes2_cbc_ct);
  DES3_ctx_set_iv(&ctx, des_cbc_iv);
  DES3_CBC_decrypt_buffer(&ctx, buffer, 16);
  munit_assert_memory_equal(16, buffer, tdes2_pt);

  return MUNIT_OK;
}

/* 2C. 2-Key 3DES CTR Stream Mode */
static MunitResult test_tdes2_ctr(const MunitParameter params[], void* data)
{
  (void) params;
  (void) data;

  struct DES3_ctx ctx;
  uint8_t original[24] = "Stream 2-Key 3DES Test!";
  uint8_t buffer[24];

  memcpy(buffer, original, 24);

  DES3_init_ctx_iv(&ctx, tdes2_key, 16, des_ctr_iv);
  DES3_CTR_xcrypt_buffer(&ctx, buffer, 24);
  munit_assert_memory_not_equal(24, buffer, original);

  DES3_ctx_set_iv(&ctx, des_ctr_iv);
  DES3_CTR_xcrypt_buffer(&ctx, buffer, 24);
  munit_assert_memory_equal(24, buffer, original);

  return MUNIT_OK;
}


/* ========================================================================= */
/* Matrix 3: 3-Key 3DES (Triple DES)                                         */
/* ========================================================================= */

/* 3A. 3-Key 3DES ECB (KAT Encrypt, KAT Decrypt, & Round-Trip) */
static MunitResult test_tdes3_ecb(const MunitParameter params[], void* data)
{
  (void) params;
  (void) data;

  struct DES3_ctx ctx;
  uint8_t buffer[16];

  DES3_init_ctx(&ctx, tdes3_key, 24);

  /* KAT Encrypt (2 blocks) */
  memcpy(buffer, tdes3_pt, 16);
  DES3_ECB_encrypt(&ctx, buffer);
  DES3_ECB_encrypt(&ctx, buffer + 8);
  munit_assert_memory_equal(16, buffer, tdes3_ecb_ct);

  /* KAT Decrypt (2 blocks) */
  memcpy(buffer, tdes3_ecb_ct, 16);
  DES3_ECB_decrypt(&ctx, buffer);
  DES3_ECB_decrypt(&ctx, buffer + 8);
  munit_assert_memory_equal(16, buffer, tdes3_pt);

  /* Round-Trip */
  DES3_ECB_encrypt(&ctx, buffer);
  DES3_ECB_encrypt(&ctx, buffer + 8);
  munit_assert_memory_equal(16, buffer, tdes3_ecb_ct);
  DES3_ECB_decrypt(&ctx, buffer);
  DES3_ECB_decrypt(&ctx, buffer + 8);
  munit_assert_memory_equal(16, buffer, tdes3_pt);

  return MUNIT_OK;
}

/* 3B. 3-Key 3DES CBC (KAT Encrypt, KAT Decrypt, & Round-Trip) */
static MunitResult test_tdes3_cbc(const MunitParameter params[], void* data)
{
  (void) params;
  (void) data;

  struct DES3_ctx ctx;
  uint8_t buffer[16];

  /* KAT Encrypt */
  DES3_init_ctx_iv(&ctx, tdes3_key, 24, des_cbc_iv);
  memcpy(buffer, tdes3_pt, 16);
  DES3_CBC_encrypt_buffer(&ctx, buffer, 16);
  munit_assert_memory_equal(16, buffer, tdes3_cbc_ct);

  /* KAT Decrypt */
  DES3_ctx_set_iv(&ctx, des_cbc_iv);
  memcpy(buffer, tdes3_cbc_ct, 16);
  DES3_CBC_decrypt_buffer(&ctx, buffer, 16);
  munit_assert_memory_equal(16, buffer, tdes3_pt);

  /* Round-Trip */
  DES3_ctx_set_iv(&ctx, des_cbc_iv);
  DES3_CBC_encrypt_buffer(&ctx, buffer, 16);
  munit_assert_memory_equal(16, buffer, tdes3_cbc_ct);
  DES3_ctx_set_iv(&ctx, des_cbc_iv);
  DES3_CBC_decrypt_buffer(&ctx, buffer, 16);
  munit_assert_memory_equal(16, buffer, tdes3_pt);

  return MUNIT_OK;
}

/* 3C. 3-Key 3DES CTR Stream Mode */
static MunitResult test_tdes3_ctr(const MunitParameter params[], void* data)
{
  (void) params;
  (void) data;

  struct DES3_ctx ctx;
  uint8_t original[32] = "Stream 3-Key Triple-DES Test!12";
  uint8_t buffer[32];

  memcpy(buffer, original, 32);

  DES3_init_ctx_iv(&ctx, tdes3_key, 24, des_ctr_iv);
  DES3_CTR_xcrypt_buffer(&ctx, buffer, 32);
  munit_assert_memory_not_equal(32, buffer, original);

  DES3_ctx_set_iv(&ctx, des_ctr_iv);
  DES3_CTR_xcrypt_buffer(&ctx, buffer, 32);
  munit_assert_memory_equal(32, buffer, original);

  return MUNIT_OK;
}


/* ========================================================================= */
/* Matrix 4: CFB / OFB Feedback Modes                                        */
/* ========================================================================= */

/* 4A. Single DES OFB (KAT, Decrypt symmetry, Cross-call chaining) */
static MunitResult test_des_ofb(const MunitParameter params[], void* data)
{
  (void) params;
  (void) data;

  struct DES_ctx ctx;
  uint8_t buffer[8];

  /* KAT Encrypt */
  DES_init_ctx_iv(&ctx, des_test_key, des_cbc_iv);
  memcpy(buffer, des_test_pt, 8);
  DES_OFB_xcrypt_buffer(&ctx, buffer, 8);
  munit_assert_memory_equal(8, buffer, des_ofb_ct);

  /* Decrypt is the same operation */
  DES_ctx_set_iv(&ctx, des_cbc_iv);
  DES_OFB_xcrypt_buffer(&ctx, buffer, 8);
  munit_assert_memory_equal(8, buffer, des_test_pt);

  return MUNIT_OK;
}

/* 4B. Single DES CFB64 (KAT Encrypt, KAT Decrypt) */
static MunitResult test_des_cfb64(const MunitParameter params[], void* data)
{
  (void) params;
  (void) data;

  struct DES_ctx ctx;
  uint8_t buffer[8];

  DES_init_ctx_iv(&ctx, des_test_key, des_cbc_iv);
  memcpy(buffer, des_test_pt, 8);
  DES_CFB64_encrypt_buffer(&ctx, buffer, 8);
  munit_assert_memory_equal(8, buffer, des_cfb64_ct);

  DES_ctx_set_iv(&ctx, des_cbc_iv);
  DES_CFB64_decrypt_buffer(&ctx, buffer, 8);
  munit_assert_memory_equal(8, buffer, des_test_pt);

  return MUNIT_OK;
}

/* 4C. Single DES CFB8 (KAT Encrypt, KAT Decrypt) */
static MunitResult test_des_cfb8(const MunitParameter params[], void* data)
{
  (void) params;
  (void) data;

  struct DES_ctx ctx;
  uint8_t buffer[8];

  DES_init_ctx_iv(&ctx, des_test_key, des_cbc_iv);
  memcpy(buffer, des_test_pt, 8);
  DES_CFB8_encrypt_buffer(&ctx, buffer, 8);
  munit_assert_memory_equal(8, buffer, des_cfb8_ct);

  DES_ctx_set_iv(&ctx, des_cbc_iv);
  DES_CFB8_decrypt_buffer(&ctx, buffer, 8);
  munit_assert_memory_equal(8, buffer, des_test_pt);

  return MUNIT_OK;
}

/* 4D. Single DES CFB1: NIST CAVP TCFB1vartext.rsp single-bit cases + roundtrip */
static MunitResult test_des_cfb1(const MunitParameter params[], void* data)
{
  (void) params;
  (void) data;

  struct DES_ctx ctx;

  /* TCFB1vartext.rsp COUNT 0: KEYs=0101010101010101 IV=8000000000000000 PT=0 -> CT=1 */
  const uint8_t weak_key[8] = {0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
  const uint8_t iv0[8] = {0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  const uint8_t iv2[8] = {0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  uint8_t bits[1];

  bits[0] = 0x00;
  DES_init_ctx_iv(&ctx, weak_key, iv0);
  DES_CFB1_encrypt_buffer(&ctx, bits, 1);
  munit_assert_uint8(bits[0] >> 7, ==, 1);

  /* COUNT 2: IV=2000000000000000 PT=0 -> CT=0 */
  bits[0] = 0x00;
  DES_ctx_set_iv(&ctx, iv2);
  DES_CFB1_encrypt_buffer(&ctx, bits, 1);
  munit_assert_uint8(bits[0] >> 7, ==, 0);

  /* Multi-bit roundtrip with an arbitrary key */
  uint8_t stream[3] = {0xa5, 0x3c, 0x80};
  uint8_t original[3];
  memcpy(original, stream, 3);
  DES_init_ctx_iv(&ctx, des_test_key, des_cbc_iv);
  DES_CFB1_encrypt_buffer(&ctx, stream, 17);
  munit_assert_memory_not_equal(3, stream, original);
  DES_ctx_set_iv(&ctx, des_cbc_iv);
  DES_CFB1_decrypt_buffer(&ctx, stream, 17);
  munit_assert_memory_equal(3, stream, original);

  return MUNIT_OK;
}

/* 4E. 3-Key 3DES OFB / CFB64 / CFB8 (KAT + Decrypt) */
static MunitResult test_tdes3_feedback_modes(const MunitParameter params[], void* data)
{
  (void) params;
  (void) data;

  struct DES3_ctx ctx;
  uint8_t buffer[16];

  /* OFB */
  DES3_init_ctx_iv(&ctx, tdes3_key, 24, des_cbc_iv);
  memcpy(buffer, tdes3_pt, 16);
  DES3_OFB_xcrypt_buffer(&ctx, buffer, 16);
  munit_assert_memory_equal(16, buffer, tdes3_ofb_ct);
  DES3_ctx_set_iv(&ctx, des_cbc_iv);
  DES3_OFB_xcrypt_buffer(&ctx, buffer, 16);
  munit_assert_memory_equal(16, buffer, tdes3_pt);

  /* CFB64 */
  DES3_ctx_set_iv(&ctx, des_cbc_iv);
  DES3_CFB64_encrypt_buffer(&ctx, buffer, 16);
  munit_assert_memory_equal(16, buffer, tdes3_cfb64_ct);
  DES3_ctx_set_iv(&ctx, des_cbc_iv);
  DES3_CFB64_decrypt_buffer(&ctx, buffer, 16);
  munit_assert_memory_equal(16, buffer, tdes3_pt);

  /* CFB8 */
  DES3_ctx_set_iv(&ctx, des_cbc_iv);
  DES3_CFB8_encrypt_buffer(&ctx, buffer, 16);
  munit_assert_memory_equal(16, buffer, tdes3_cfb8_ct);
  DES3_ctx_set_iv(&ctx, des_cbc_iv);
  DES3_CFB8_decrypt_buffer(&ctx, buffer, 16);
  munit_assert_memory_equal(16, buffer, tdes3_pt);

  /* CFB1 roundtrip (no host-generated KAT available; CAVP files cover KAT) */
  uint8_t stream[2] = {0x5a, 0xc0};
  uint8_t original[2];
  memcpy(original, stream, 2);
  DES3_ctx_set_iv(&ctx, des_cbc_iv);
  DES3_CFB1_encrypt_buffer(&ctx, stream, 10);
  DES3_ctx_set_iv(&ctx, des_cbc_iv);
  DES3_CFB1_decrypt_buffer(&ctx, stream, 10);
  munit_assert_memory_equal(2, stream, original);

  return MUNIT_OK;
}

/* 4F. Cross-call chaining: split calls must equal one-shot output */
static MunitResult test_feedback_mode_chaining(const MunitParameter params[], void* data)
{
  (void) params;
  (void) data;

  struct DES3_ctx ctx;
  uint8_t oneshot[16];
  uint8_t split[16];

  /* CFB64 */
  memcpy(oneshot, tdes3_pt, 16);
  memcpy(split, tdes3_pt, 16);
  DES3_init_ctx_iv(&ctx, tdes3_key, 24, des_cbc_iv);
  DES3_CFB64_encrypt_buffer(&ctx, oneshot, 16);
  DES3_ctx_set_iv(&ctx, des_cbc_iv);
  DES3_CFB64_encrypt_buffer(&ctx, split, 8);
  DES3_CFB64_encrypt_buffer(&ctx, split + 8, 8);
  munit_assert_memory_equal(16, split, oneshot);

  /* CFB8 */
  memcpy(oneshot, tdes3_pt, 16);
  memcpy(split, tdes3_pt, 16);
  DES3_ctx_set_iv(&ctx, des_cbc_iv);
  DES3_CFB8_encrypt_buffer(&ctx, oneshot, 16);
  DES3_ctx_set_iv(&ctx, des_cbc_iv);
  DES3_CFB8_encrypt_buffer(&ctx, split, 5);
  DES3_CFB8_encrypt_buffer(&ctx, split + 5, 11);
  munit_assert_memory_equal(16, split, oneshot);

  /* OFB */
  memcpy(oneshot, tdes3_pt, 16);
  memcpy(split, tdes3_pt, 16);
  DES3_ctx_set_iv(&ctx, des_cbc_iv);
  DES3_OFB_xcrypt_buffer(&ctx, oneshot, 16);
  DES3_ctx_set_iv(&ctx, des_cbc_iv);
  DES3_OFB_xcrypt_buffer(&ctx, split, 8);
  DES3_OFB_xcrypt_buffer(&ctx, split + 8, 8);
  munit_assert_memory_equal(16, split, oneshot);

  /* CFB1: 16 bits one-shot vs two 8-bit calls (split only on byte boundaries) */
  uint8_t bits_oneshot[2] = {0x96, 0x3d};
  uint8_t bits_split[2] = {0x96, 0x3d};
  DES3_ctx_set_iv(&ctx, des_cbc_iv);
  DES3_CFB1_encrypt_buffer(&ctx, bits_oneshot, 16);
  DES3_ctx_set_iv(&ctx, des_cbc_iv);
  DES3_CFB1_encrypt_buffer(&ctx, bits_split, 8);
  DES3_CFB1_encrypt_buffer(&ctx, bits_split + 1, 8);
  munit_assert_memory_equal(2, bits_split, bits_oneshot);

  return MUNIT_OK;
}


/* ========================================================================= */
/* Additional Cryptographic & Protocol Tests                                 */
/* ========================================================================= */

/* Equivalence Test: 3DES with K1=K2=K3 equals Single DES */
static MunitResult test_tdes_single_des_equivalence(const MunitParameter params[], void* data)
{
  (void) params;
  (void) data;

  struct DES_ctx single_ctx;
  struct DES3_ctx tdes_ctx;

  uint8_t key3[24];
  memcpy(key3, des_test_key, 8);
  memcpy(key3 + 8, des_test_key, 8);
  memcpy(key3 + 16, des_test_key, 8);

  DES_init_ctx(&single_ctx, des_test_key);
  DES3_init_ctx(&tdes_ctx, key3, 24);

  uint8_t buf_single[8];
  uint8_t buf_tdes[8];

  memcpy(buf_single, des_test_pt, 8);
  memcpy(buf_tdes, des_test_pt, 8);

  DES_ECB_encrypt(&single_ctx, buf_single);
  DES3_ECB_encrypt(&tdes_ctx, buf_tdes);

  munit_assert_memory_equal(8, buf_single, buf_tdes);
  munit_assert_memory_equal(8, buf_single, des_test_ct);

  /* Decryption Equivalence */
  DES_ECB_decrypt(&single_ctx, buf_single);
  DES3_ECB_decrypt(&tdes_ctx, buf_tdes);
  munit_assert_memory_equal(8, buf_single, buf_tdes);
  munit_assert_memory_equal(8, buf_single, des_test_pt);

  return MUNIT_OK;
}

/* CMAC Tests (NIST SP 800-38B) */
static MunitResult test_des_cmac(const MunitParameter params[], void* data)
{
  (void) params;
  (void) data;

  uint8_t cmac1[8], cmac2[8], cmac3[8], cmac_empty[8], cmac_null_iv[8];
  const uint8_t message[] = "tiny-DES-c CMAC Test!";
  size_t msglen = sizeof(message) - 1;

  /* Single DES CMAC */
  munit_assert_int(0, ==, DES_cmac(des_test_key, 8, message, msglen, cmac1));

  /* 2-Key 3DES CMAC */
  munit_assert_int(0, ==, DES_cmac(tdes2_key, 16, message, msglen, cmac2));

  /* 3-Key 3DES CMAC */
  munit_assert_int(0, ==, DES_cmac(tdes3_key, 24, message, msglen, cmac3));

  /* Zero-length message test */
  munit_assert_int(0, ==, DES_cmac(tdes2_key, 16, NULL, 0, cmac_empty));

  /* NULL IV test matches zero-IV */
  munit_assert_int(0, ==, DES_cmac_with_iv(tdes2_key, 16, message, msglen, NULL, cmac_null_iv));
  munit_assert_memory_equal(8, cmac_null_iv, cmac2);

  /* Non-empty & non-equal results */
  munit_assert_memory_not_equal(8, cmac1, cmac2);
  munit_assert_memory_not_equal(8, cmac2, cmac3);

  /* Invalid key length error check */
  munit_assert_int(-1, ==, DES_cmac(des_test_key, 10, message, msglen, cmac1));

  return MUNIT_OK;
}

/* Degenerate Single-DES key (8 bytes) == 2-Key 3DES key with K1=K2 */
static MunitResult test_des_cmac_single_des_matches_2k3des_degenerate(const MunitParameter params[], void* data)
{
  (void) params;
  (void) data;

  uint8_t key8[8] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
  uint8_t key16[16] = {
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88
  };
  uint8_t message[8] = {0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33};

  uint8_t mac8[8], mac16[8];
  munit_assert_int(0, ==, DES_cmac(key8, sizeof(key8), message, sizeof(message), mac8));
  munit_assert_int(0, ==, DES_cmac(key16, sizeof(key16), message, sizeof(message), mac16));
  munit_assert_memory_equal(8, mac8, mac16);

  return MUNIT_OK;
}


/* --- Test Suite Setup --- */

static MunitTest test_suite_tests[] = {
  { "/des_ecb",                           test_des_ecb,                           NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { "/des_cbc",                           test_des_cbc,                           NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { "/des_ctr",                           test_des_ctr,                           NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { "/tdes2_ecb",                         test_tdes2_ecb,                         NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { "/tdes2_cbc",                         test_tdes2_cbc,                         NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { "/tdes2_ctr",                         test_tdes2_ctr,                         NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { "/tdes3_ecb",                         test_tdes3_ecb,                         NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { "/tdes3_cbc",                         test_tdes3_cbc,                         NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { "/tdes3_ctr",                         test_tdes3_ctr,                         NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { "/des_ofb",                           test_des_ofb,                           NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { "/des_cfb64",                         test_des_cfb64,                         NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { "/des_cfb8",                          test_des_cfb8,                          NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { "/des_cfb1",                          test_des_cfb1,                          NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { "/tdes3_feedback_modes",              test_tdes3_feedback_modes,              NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { "/feedback_mode_chaining",            test_feedback_mode_chaining,            NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { "/tdes_single_des_equiv",            test_tdes_single_des_equivalence,        NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { "/des_cmac",                          test_des_cmac,                          NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { "/des_cmac_single_des_degenerate",    test_des_cmac_single_des_matches_2k3des_degenerate, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
#if DES_CAVP_AVAILABLE
  { "/cavp",                              test_cavp,                              NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
#endif
  { NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL }
};

static const MunitSuite test_suite = {
  "/tiny-des-c",
  test_suite_tests,
  NULL,
  1,
  MUNIT_SUITE_OPTION_NONE
};

int main(int argc, char* argv[])
{
  return munit_suite_main(&test_suite, NULL, argc, argv);
}
