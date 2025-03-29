// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <psa/crypto.h>
#include <stddef.h>
#include <stdint.h>

psa_status_t hash_sha256(const uint8_t *input, size_t input_size, uint8_t *hash_out,
                         size_t hash_out_size);
psa_status_t hash_doubleSha256(const uint8_t *input, size_t input_size, uint8_t *hash_out,
                               size_t hash_out_size);
psa_status_t hash_ripemd160(const uint8_t *input, size_t input_size, uint8_t *hash_out,
                            size_t hash_out_size);
psa_status_t hash_pbkdf2_hmac_sha512(const uint8_t *password, size_t password_len,
                                     const uint8_t *salt, size_t salt_len, uint32_t iterations,
                                     uint8_t *output, size_t output_size);
psa_status_t hash_hmac_sha512(const uint8_t *key, size_t key_len, const uint8_t *input,
                              size_t input_len, uint8_t *output, size_t output_size);
