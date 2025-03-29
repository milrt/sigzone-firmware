// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <psa/crypto.h>
#include <stddef.h>

#define SEGWIT_ADDR_MAX_ADDRESS_LEN 90

psa_status_t segwit_addr_encode(const char *hrp, size_t hrp_len, uint8_t witness_ver,
                                const uint8_t *witness_prog, size_t wp_len, char *out_addr,
                                size_t *out_size);
psa_status_t segwit_addr_decode(const char *addr, char *out_hrp, size_t *out_hrp_len,
                                uint8_t *witness_ver, uint8_t *witness_prog, size_t *wp_size);
