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
* **Modes of Operation**: ECB, CBC, and CTR modes (can be individually enabled/disabled at compile time).
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

/* --- Triple DES (3DES / TDES) --- */
void DES3_init_ctx(struct DES3_ctx* ctx, const uint8_t* key, size_t keylen);
void DES3_init_ctx_iv(struct DES3_ctx* ctx, const uint8_t* key, size_t keylen, const uint8_t* iv);
void DES3_ctx_set_iv(struct DES3_ctx* ctx, const uint8_t* iv);

void DES3_ECB_encrypt(const struct DES3_ctx* ctx, uint8_t* buf);
void DES3_ECB_decrypt(const struct DES3_ctx* ctx, uint8_t* buf);

void DES3_CBC_encrypt_buffer(struct DES3_ctx* ctx, uint8_t* buf, size_t length);
void DES3_CBC_decrypt_buffer(struct DES3_ctx* ctx, uint8_t* buf, size_t length);

void DES3_CTR_xcrypt_buffer(struct DES3_ctx* ctx, uint8_t* buf, size_t length);

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
/tiny-des-c/tdes_single_des_equiv             [ OK    ]
/tiny-des-c/des_cmac                          [ OK    ]
/tiny-des-c/des_cmac_single_des_degenerate    [ OK    ]
/tiny-des-c/protocol_utilities                [ OK    ]
13 of 13 (100%) tests successful, 0 (0%) test skipped.
```

The suite includes NIST reference vectors embedded in [`test.c`](test.c):

* Eight TDES variable-plaintext basis vectors from the CAVP `TECBvartext.rsp` set, exercised through ECB and zero-IV CBC.
* Corrected TDEA CMAC examples 13–20 from [NIST SP 800-38B, Appendix D](https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-38b.pdf), covering two-key and three-key TDEA with empty, complete, partial, and multi-block messages.

To download the complete NIST CAVP TDES archive for additional manual/reference testing:

```bash
curl -L https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/des/KAT_TDES.zip -o /tmp/KAT_TDES.zip
unzip -q /tmp/KAT_TDES.zip -d /tmp/KAT_TDES
```

The archive contains the full ECB and CBC KAT sets, including variable-key, permutation, inverse-permutation, and substitution-table tests. The checked-in suite uses a small source-level subset so `make test` remains dependency-free.

---

### Credits & Acknowledgments

* Directly inspired by [tiny-AES-c](https://github.com/kokke/tiny-AES-c) by kokke.
* Unit testing framework: [µunit (munit)](https://nemequ.github.io/munit/).

---

### License

This software is released into the **Public Domain** under the terms of [The Unlicense](LICENSE).
