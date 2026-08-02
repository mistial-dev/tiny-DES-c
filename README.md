### Tiny DES and Triple-DES (3DES) Cryptographic Engine in C / C++

[![License: Unlicense](https://img.shields.io/badge/license-Unlicense-blue.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/tests-100%25%20passing-brightgreen.svg)](test.c)

This is a small, fast, portable, and zero-dependency implementation of **DES**, **Triple-DES (3DES / TDES)**, and **NIST SP 800-38B CMAC** written in C99 and C++11.

This project is directly inspired by and crafted in the architectural style of [kokke/tiny-AES-c](https://github.com/kokke/tiny-AES-c).

It is designed as a drop-in cryptographic engine for embedded applications and microcontrollers.

---

### Features & Highlights
* **Zero Dynamic Dependencies**: Standard C99 / C++11 (`<stdint.h>`, `<stddef.h>`, `<string.h>`). No dynamic memory allocation (`malloc`).
* **First-Class C++ Support**: [`des.hpp`](des.hpp) provides idiomatic C++ RAII classes (`tiny_des::DES`, `tiny_des::DES3`) with `std::vector` and `std::array` integration.
* **CMake & Makefile Support**: Out-of-the-box support for CMake (`add_subdirectory` / `find_package`) and classical `Makefile`.
* **Single DES & Triple-DES Support**:
  * Single DES (64-bit key / 56-bit effective key)
  * 2-Key 3DES (128-bit key / 112-bit effective key: K1, K2, K1)
  * 3-Key 3DES (192-bit key / 168-bit effective key: K1, K2, K3)
* **Modes of Operation**: ECB, CBC, CTR, CFB1, CFB8, CFB64, and OFB modes (can be individually enabled/disabled at compile time).
* **NIST SP 800-38B CMAC Engine**:
  * Supports Single DES, 2-Key 3DES, and 3-Key 3DES CMAC subkey generation and message authentication.

---

### C API Overview (`des.h`)

```c
#include "des.h"

/* --- Single DES (8-byte block, 8-byte key) --- */
void DES_init_ctx(struct DES_ctx* ctx, const uint8_t* key);
void DES_init_ctx_iv(struct DES_ctx* ctx, const uint8_t* key, const uint8_t* iv);
void DES_ctx_set_iv(struct DES_ctx* ctx, const uint8_t* iv);

void DES_ECB_encrypt(const struct DES_ctx* ctx, uint8_t* buf);
void DES_ECB_decrypt(const struct DES_ctx* ctx, uint8_t* buf);

void DES_CBC_encrypt_buffer(struct DES_ctx* ctx, uint8_t* buf, size_t length);
void DES_CBC_decrypt_buffer(struct DES_ctx* ctx, uint8_t* buf, size_t length);

void DES_CTR_xcrypt_buffer(struct DES_ctx* ctx, uint8_t* buf, size_t length);

void DES_CFB64_encrypt_buffer(struct DES_ctx* ctx, uint8_t* buf, size_t length);
void DES_CFB64_decrypt_buffer(struct DES_ctx* ctx, uint8_t* buf, size_t length);
void DES_CFB8_encrypt_buffer(struct DES_ctx* ctx, uint8_t* buf, size_t length);
void DES_CFB8_decrypt_buffer(struct DES_ctx* ctx, uint8_t* buf, size_t length);
void DES_CFB1_encrypt_buffer(struct DES_ctx* ctx, uint8_t* buf, size_t bit_length);
void DES_CFB1_decrypt_buffer(struct DES_ctx* ctx, uint8_t* buf, size_t bit_length);
void DES_OFB_xcrypt_buffer(struct DES_ctx* ctx, uint8_t* buf, size_t length);

/* --- Triple DES (3DES / TDES) --- */
void DES3_init_ctx(struct DES3_ctx* ctx, const uint8_t* key, size_t keylen);
void DES3_init_ctx_iv(struct DES3_ctx* ctx, const uint8_t* key, size_t keylen, const uint8_t* iv);
void DES3_ctx_set_iv(struct DES3_ctx* ctx, const uint8_t* iv);

void DES3_ECB_encrypt(const struct DES3_ctx* ctx, uint8_t* buf);
void DES3_ECB_decrypt(const struct DES3_ctx* ctx, uint8_t* buf);

void DES3_CBC_encrypt_buffer(struct DES3_ctx* ctx, uint8_t* buf, size_t length);
void DES3_CBC_decrypt_buffer(struct DES3_ctx* ctx, uint8_t* buf, size_t length);

void DES3_CTR_xcrypt_buffer(struct DES3_ctx* ctx, uint8_t* buf, size_t length);

void DES3_CFB64_encrypt_buffer(struct DES3_ctx* ctx, uint8_t* buf, size_t length);
void DES3_CFB64_decrypt_buffer(struct DES3_ctx* ctx, uint8_t* buf, size_t length);
void DES3_CFB8_encrypt_buffer(struct DES3_ctx* ctx, uint8_t* buf, size_t length);
void DES3_CFB8_decrypt_buffer(struct DES3_ctx* ctx, uint8_t* buf, size_t length);
void DES3_CFB1_encrypt_buffer(struct DES3_ctx* ctx, uint8_t* buf, size_t bit_length);
void DES3_CFB1_decrypt_buffer(struct DES3_ctx* ctx, uint8_t* buf, size_t bit_length);
void DES3_OFB_xcrypt_buffer(struct DES3_ctx* ctx, uint8_t* buf, size_t length);

/* --- CMAC --- */
int  DES_cmac(const uint8_t* key, size_t keylen, const uint8_t* message, size_t message_len, uint8_t* cmac_out);
int  DES_cmac_with_iv(const uint8_t* key, size_t keylen, const uint8_t* message, size_t message_len, const uint8_t* iv, uint8_t* cmac_out);
```

---

### C++ Usage Example (`des.hpp`)

```cpp
#include "des.hpp"

// Single DES ECB
std::array<uint8_t, 8> key = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
tiny_des::DES des(key);

uint8_t block[8] = {0x4e, 0x6f, 0x77, 0x20, 0x69, 0x73, 0x20, 0x74};
des.encrypt_ecb(block);
des.decrypt_ecb(block);

// 2-Key or 3-Key 3DES CBC
std::vector<uint8_t> key2k = { /* 16 or 24 bytes */ };
std::array<uint8_t, 8> iv = { /* 8 bytes */ };
tiny_des::DES3 des3(key2k, iv);

std::vector<uint8_t> data = { /* multiple of 8 bytes */ };
des3.encrypt_cbc(data);
des3.decrypt_cbc(data);
```

---

### Building with CMake

```bash
mkdir build && cd build
cmake ..
make
ctest --output-on-failure
```

To include `tiny-DES-c` in your own CMake project:

```cmake
add_subdirectory(path/to/tiny-DES-c)
target_link_libraries(your_target PRIVATE tiny-des-c)
```

---

### Unit Testing & Coverage

Unit tests are written using [µunit (munit)](https://nemequ.github.io/munit/) in [`test.c`](test.c) and C++ integration tests in [`test_cpp.cpp`](test_cpp.cpp).

```bash
# Normal test run
make test

# Rebuild from a clean tree
make clean && make test
```

Outputs:
```text
Running test suite with seed 0x91623758...
/tiny-des-c/des_ecb                           [ OK    ]
/tiny-des-c/des_cbc                           [ OK    ]
/tiny-des-c/des_ctr                           [ OK    ]
/tiny-des-c/tdes2_ecb                         [ OK    ]
/tiny-des-c/tdes2_cbc                         [ OK    ]
/tiny-des-c/tdes2_ctr                         [ OK    ]
/tiny-des-c/tdes3_ecb                         [ OK    ]
/tiny-des-c/tdes3_cbc                         [ OK    ]
/tiny-des-c/tdes3_ctr                         [ OK    ]
/tiny-des-c/des_ofb                           [ OK    ]
/tiny-des-c/des_cfb64                         [ OK    ]
/tiny-des-c/des_cfb8                          [ OK    ]
/tiny-des-c/des_cfb1                          [ OK    ]
/tiny-des-c/tdes3_feedback_modes              [ OK    ]
/tiny-des-c/feedback_mode_chaining            [ OK    ]
/tiny-des-c/tdes_single_des_equiv             [ OK    ]
/tiny-des-c/des_cmac                          [ OK    ]
/tiny-des-c/des_cmac_single_des_degenerate    [ OK    ]
19 of 19 (100%) tests successful, 0 (0%) test skipped.
```

---

### Wycheproof-Style Edge-Case Vectors

[`test_vectors/edge_cases.json`](test_vectors/edge_cases.json) contains 16
valid DES/3DES edge cases in a Wycheproof-style JSON format. It covers weak
and parity-variant keys, 2-key and 3-key TDES, unusual IVs, non-block-aligned
streams, and partial-bit CFB1 inputs. The native test suite executes the same
cases through the C API using the generated [`edge_vectors.h`](edge_vectors.h).

The generator cross-checks byte-oriented ciphertexts with PyCA
`cryptography` and OpenSSL. Recreate both checked-in artifacts with:

```bash
python3 generate_edge_vectors.py
```

---

### NIST CAVP Validation

The complete [NIST CAVP](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/block-ciphers) TDES response-file corpora are checked in under [`test_vectors/cavp/`](test_vectors/cavp/) and executed by an opt-in test ([`cavp.c`](cavp.c)):

| Directory | Contents | Source archive |
|---|---|---|
| `kat/` | Known Answer Tests (invperm, permop, subtab, varkey, vartext) for TECB, TCBC, TCFB1, TCFB8, TCFB64, TOFB | `KAT_TDES.zip` |
| `mmt/` | Multi-block Message Tests, keying options 2 and 3 | `tdesmmt.zip` |
| `mct/` | Monte Carlo Tests per NIST SP 800-20 (400 rounds × 10,000 iterations), keying options 2 and 3 | `tdesmct.zip` |
| `mct_intermediate/` | MCT intermediate-values files (debugging aid, not executed) | `tdesmct_intermediate.zip` |

All archives come from the [CAVP block-ciphers page](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/block-ciphers) (`.../documents/des/`). The interleaved/pipelined variants (`TCBCI*`, `TOFBI*`, `TCFBP*`) target multi-engine implementations and are out of scope.

The Monte Carlo driver validates the full chain: at every one of the 400 rounds it checks the computed keys, IV, and text against the recorded values before comparing the round result, so any drift in the SP 800-20 key-update or feedback rules fails immediately with a diagnostic.

```bash
# Makefile
make clean && make DES_CAVP=1 test

# CMake (CI runs this on Linux/macOS/Windows)
cmake -B build -DTINY_DES_CAVP=ON
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

The CAVP run adds a single `/cavp` munit test (~15 s at `-O2`; the MCT files dominate). The default build stays dependency-free and fast: `DES_CAVP` is off unless requested.

---

### Credits & Acknowledgments

* Directly inspired by [tiny-AES-c](https://github.com/kokke/tiny-AES-c) by kokke.
* Unit testing framework: [µunit (munit)](https://nemequ.github.io/munit/).

---

### License

This software is released into the **Public Domain** under the terms of [The Unlicense](LICENSE).
