/*
 * SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: Unlicense
 *
 * Minimal PlatformIO / Arduino-style smoke: DES-CTR encrypt then decrypt.
 */

#include "des.h"
#include <string.h>

int main(void)
{
  struct DES_ctx ctx;
  uint8_t key[8] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
  uint8_t iv[8] = {0};
  uint8_t buf[16] = "hello DES CTR!!";
  uint8_t orig[16];

  memcpy(orig, buf, sizeof(buf));
  DES_init_ctx_iv(&ctx, key, iv);
  if (DES_CTR_crypt(&ctx, buf, sizeof(buf)) != DES_OK)
    return 1;
  DES_ctx_set_iv(&ctx, iv);
  if (DES_CTR_crypt(&ctx, buf, sizeof(buf)) != DES_OK)
    return 1;
  DES_ctx_clear(&ctx);
  return memcmp(buf, orig, sizeof(buf)) == 0 ? 0 : 1;
}
