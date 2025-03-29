// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <psa/crypto.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t version;
    size_t entropy_size;
    uint8_t entropy[32];
    uint8_t reserved[128];
} magic_internet_key_t;

psa_status_t key_storage_store(const magic_internet_key_t *keys, const char *pin);
psa_status_t key_storage_load(const char *pin, magic_internet_key_t *keys);
psa_status_t key_storage_get_fail_count(uint32_t *fail_count);
psa_status_t key_storage_reset_fail_count(void);
psa_status_t key_storage_exists(bool *exists);
psa_status_t key_storage_wipe(void);
