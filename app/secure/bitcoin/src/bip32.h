// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <psa/crypto.h>
#include <stddef.h>
#include <stdint.h>

#define BIP32_MAX_SERIALIZED_SIZE 113 // Base58 encoded extended key max length
#define BIP32_FINGERPRINT_SIZE 4
#define BIP32_MAX_PATH_LENGTH 256
#define BIP32_MAX_DEPTH 10

typedef struct {
    uint8_t private_key[32];
    uint8_t chain_code[32];
    uint8_t depth;
    uint32_t child_number;
    uint8_t parent_fingerprint[BIP32_FINGERPRINT_SIZE];
} bip32_extended_privkey_t;

psa_status_t bip32_seed_to_master_privkey(const uint8_t *seed, size_t seed_size,
                                          bip32_extended_privkey_t *master_key);
psa_status_t bip32_extended_privkey_derive_from_path(const bip32_extended_privkey_t *master_key,
                                                     const char *path_str,
                                                     bip32_extended_privkey_t *derived_key);
psa_status_t bip32_extended_privkey_serialize(const bip32_extended_privkey_t *key, uint32_t version,
                                              char *output, size_t *output_size);
psa_status_t bip32_extended_privkey_deserialize(const char *input, uint32_t expected_version,
                                                bip32_extended_privkey_t *key);

typedef struct {
    uint8_t pubkey[33];
    uint8_t chain_code[32];
    uint8_t depth;
    uint32_t child_number;
    uint8_t parent_fingerprint[BIP32_FINGERPRINT_SIZE];
} bip32_extended_pubkey_t;

psa_status_t bip32_extended_pubkey_from_privkey(const bip32_extended_privkey_t *privkey,
                                                bip32_extended_pubkey_t *out_pubkey);
psa_status_t bip32_extended_pubkey_serialize(const bip32_extended_pubkey_t *key, uint32_t version,
                                             char *output, size_t *output_size);
psa_status_t bip32_extended_pubkey_deserialize(const char *input, uint32_t expected_version,
                                               bip32_extended_pubkey_t *key);
psa_status_t bip32_extended_pubkey_get_fingerprint(const bip32_extended_pubkey_t *key,
                                                   uint8_t *fingerprint);
