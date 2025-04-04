// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once
#include <psa/crypto.h>
#include <stddef.h>

psa_status_t bitcoin_core_status(void);

psa_status_t bitcoin_core_create(size_t entropy_size);
psa_status_t bitcoin_core_recover(const char *mnemonic);
psa_status_t bitcoin_core_destroy(const char *pin);

psa_status_t bitcoin_core_verify(char *mnemonic, size_t mnemonic_size);
psa_status_t bitcoin_core_confirm(const char *pin, const char *mnemonic);

psa_status_t bitcoin_core_open(const char *pin, const char *passphrase);
psa_status_t bitcoin_core_close(void);

psa_status_t bitcoin_core_get_pubkey(const char *derivation_path, uint32_t version, uint8_t *pubkey,
                                     size_t *pubkey_size, char *xpub, size_t xpub_size);
psa_status_t bitcoin_core_sign_hash(const char *derivation_path, const uint8_t *hash,
                                    size_t hash_size, uint8_t *signature, size_t *signature_size);
psa_status_t bitcoin_core_get_fingerprint(uint8_t *fingerprint, size_t *fingerprint_size);
