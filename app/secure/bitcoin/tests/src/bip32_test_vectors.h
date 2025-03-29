// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stddef.h>
#include <stdint.h>

#define BIP32_TEST_VECTOR_COUNT 17
#define BIP32_INVALID_TEST_VECTOR_COUNT 14

typedef struct {
    const uint8_t *seed;
    size_t seed_size;
    const char *path;
    const char *xprv;
    const char *xpub;
} bip32_test_vector_t;

typedef struct {
    const char *xprv;        // NULL if not provided
    const char *xpub;        // NULL if not provided
    const char *description; // description of the invalid test vector
} bip32_invalid_test_vector_t;

extern const bip32_test_vector_t bip32_test_vectors[BIP32_TEST_VECTOR_COUNT];
extern const bip32_invalid_test_vector_t
    bip32_invalid_test_vectors[BIP32_INVALID_TEST_VECTOR_COUNT];
