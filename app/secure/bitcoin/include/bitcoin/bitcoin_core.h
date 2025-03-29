// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once
#include <psa/crypto.h>
#include <stddef.h>

typedef void (*write_buf_callback_t)(void *handle, const uint8_t *buf, size_t buf_size);
typedef void (*write_string_callback_t)(void *handle, const char *str, size_t str_size);
typedef size_t (*read_buf_callback_t)(void *handle, uint8_t *buf, size_t buf_size);

psa_status_t bitcoin_core_status(void);

psa_status_t bitcoin_core_create(size_t entropy_size);
psa_status_t bitcoin_core_recover(const char *mnemonic);
psa_status_t bitcoin_core_destroy(const char *pin);

psa_status_t bitcoin_core_verify(write_string_callback_t write_mnemonic_callback,
                                 void *callback_handle);
psa_status_t bitcoin_core_confirm(const char *pin, const char *mnemonic);

psa_status_t bitcoin_core_open(const char *pin, const char *passphrase);
psa_status_t bitcoin_core_close(void);

psa_status_t bitcoin_core_get_pubkey(const char *derivation_path, size_t *pubkey_size,
                                     write_buf_callback_t write_pubkey_callback,
                                     write_string_callback_t write_xpub_callback,
                                     void *callback_handle);
psa_status_t bitcoin_core_sign_hash(const char *derivation_path,
                                    read_buf_callback_t read_hash_callback, size_t *signature_size,
                                    write_buf_callback_t write_signature_callback,
                                    void *callback_handle);
