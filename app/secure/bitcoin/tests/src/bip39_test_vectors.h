// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef BIP39_TEST_VECTORS_H
#define BIP39_TEST_VECTORS_H

#include <stdint.h>
#include <stddef.h>

#define BIP39_TEST_VECTOR_COUNT 24

typedef struct {
    const char *mnemonic;
    uint8_t entropy[32];
    size_t entropy_size;
    uint8_t seed[64];
    size_t seed_size;
} bip39_test_vector_t;

extern const bip39_test_vector_t bip39_test_vectors[BIP39_TEST_VECTOR_COUNT];

#endif // BIP39_TEST_VECTORS_H
