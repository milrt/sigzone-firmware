// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <psa/crypto.h>
#include <stddef.h>
#include <stdint.h>

#define BIP39_MAX_MNEMONIC_LEN 256

psa_status_t bip39_entropy_to_mnemonic(const uint8_t *entropy, size_t entropy_size,
                                       char *mnemonic_out, size_t mnemonic_out_size);
psa_status_t bip39_validate_mnemonic(const char *mnemonic);
psa_status_t bip39_mnemonic_to_entropy(const char *mnemonic, uint8_t *entropy_out,
                                       size_t *entropy_out_size);
psa_status_t bip39_mnemonic_to_seed(const char *mnemonic, const char *passphrase, uint8_t *seed_out,
                                    size_t *seed_size_in_out);
