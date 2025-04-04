// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <psa/crypto.h>

#define MAX_ADDRESS_LEN 90
#define MAX_SCRIPT_LEN 40

typedef enum { BITCOIN_MAINNET, BITCOIN_TESTNET } network_type_t;

void chains_set_network(network_type_t network);
network_type_t chains_get_network(void);

psa_status_t chains_pubkey_to_script(const uint8_t *pubkey, size_t pubkey_len, uint8_t *script_out,
                                     size_t *script_size);
psa_status_t chains_script_to_address(const uint8_t *script, size_t script_len, char *address_out,
                                      size_t *addr_size);
uint32_t chains_get_bip32_pub_version(void);
