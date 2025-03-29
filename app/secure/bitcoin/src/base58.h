// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <psa/crypto.h>

#define BASE58_ENCODE_MAX_DATA_SIZE 128

psa_status_t base58_check_encode(const uint8_t *data, size_t data_size, char *str, size_t str_size);
psa_status_t base58_check_decode(const char *str, uint8_t *data, size_t *data_size);
