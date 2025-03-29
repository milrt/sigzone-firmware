// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <psa/crypto.h>

#define MAX_ADDRESS_LEN 90
#define MAX_SCRIPT_LEN 40

typedef enum { BITCOIN_MAINNET, BITCOIN_TESTNET } network_type_t;

void set_bitcoin_network(network_type_t network);
network_type_t get_bitcoin_network(void);

psa_status_t pubkey_to_script(const uint8_t *pubkey, size_t pubkey_len, uint8_t *script_out,
                              size_t *script_size);
psa_status_t script_to_address(const uint8_t *script, size_t script_len, char *address_out,
                               size_t *addr_size);
