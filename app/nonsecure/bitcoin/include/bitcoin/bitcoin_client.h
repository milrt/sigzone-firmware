// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <psa/crypto.h>
#include <stddef.h>

psa_status_t bitcoin_client_status(void);
psa_status_t bitcoin_client_create(size_t entropy_size);
psa_status_t bitcoin_client_recover(const char *mnemonic);
psa_status_t bitcoin_client_verify(char *mnemonic_out, size_t *mnemonic_out_len);
psa_status_t bitcoin_client_confirm(const char *pin, const char *mnemonic);

psa_status_t bitcoin_client_destroy(const char *pin);
psa_status_t bitcoin_client_open(const char *pin, const char *passphrase);
psa_status_t bitcoin_client_close(void);
psa_status_t bitcoin_client_get_pubkey(const char *derivation_path, uint32_t version,
                                       uint8_t *pubkey_out, size_t *pubkey_size, char *xpub_out,
                                       size_t *xpub_size);
psa_status_t bitcoin_client_sign_hash(const char *derivation_path, const uint8_t *hash32,
                                      size_t hash_size, uint8_t *signature_der,
                                      size_t *signature_size);
psa_status_t bitcoin_client_get_fingerprint(uint8_t *fingerprint);

psa_status_t bitcoin_client_test_run_all(void);
