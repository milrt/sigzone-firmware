// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "bitcoin/chains.h"
#include "bitcoin/segwit_addr.h"
#include "shared/hash.h"
#include <string.h>

typedef enum {
    ADDR_TYPE_UNKNOWN,
    ADDR_TYPE_P2PKH,  // Legacy Base58 (1...)
    ADDR_TYPE_P2SH,   // Wrapped SegWit Base58 (3...)
    ADDR_TYPE_P2WPKH, // Native SegWit Bech32 (bc1q...)
    ADDR_TYPE_P2TR    // Taproot Bech32m (bc1p...)
} address_type_t;

typedef struct {
    address_type_t type;
    const char *hrp;
    uint32_t bip32_pub_version;
} address_format_t;

static network_type_t current_network = BITCOIN_MAINNET;

static const address_format_t MAINNET_P2WPKH = {
    .type = ADDR_TYPE_P2WPKH,
    .hrp = "bc",
    .bip32_pub_version = 0x0488B21E,
};

static const address_format_t TESTNET_P2WPKH = {
    .type = ADDR_TYPE_P2WPKH,
    .hrp = "tb",
    .bip32_pub_version = 0x043587CF,
};

static const address_format_t *get_default_address_format(void)
{
    return (current_network == BITCOIN_MAINNET) ? &MAINNET_P2WPKH : &TESTNET_P2WPKH;
}

void chains_set_network(network_type_t network)
{
    current_network = network;
}

network_type_t chains_get_network(void)
{
    return current_network;
}

uint32_t chains_get_bip32_pub_version(void)
{
    return get_default_address_format()->bip32_pub_version;
}

psa_status_t chains_pubkey_to_script(const uint8_t *pubkey, size_t pubkey_len, uint8_t *script_out,
                                     size_t *script_size)
{
    if (!pubkey || pubkey_len != 33 || !script_out || !script_size ||
        *script_size < MAX_SCRIPT_LEN) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    uint8_t sha256[32];
    uint8_t ripemd160[20];
    psa_status_t status = hash_sha256(pubkey, pubkey_len, sha256, sizeof(sha256));
    if (status != PSA_SUCCESS) {
        return status;
    }
    status = hash_ripemd160(sha256, sizeof(sha256), ripemd160, sizeof(ripemd160));
    if (status != PSA_SUCCESS) {
        return status;
    }

    if (get_default_address_format()->type == ADDR_TYPE_P2WPKH) {
        // Construct P2WPKH scriptPubKey: OP_0 <20-byte hash>
        script_out[0] = 0x00; // OP_0
        script_out[1] = 0x14; // Push 20 bytes
        memcpy(script_out + 2, ripemd160, 20);
        *script_size = 22;
        return PSA_SUCCESS;
    }

    return PSA_ERROR_INVALID_ARGUMENT;
}

psa_status_t chains_script_to_address(const uint8_t *script, size_t script_len, char *address_out,
                                      size_t *addr_size)
{
    if (!script || script_len == 0 || !address_out || !addr_size || *addr_size < MAX_ADDRESS_LEN) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    // Get the correct HRP for the current network
    const address_format_t *addr_format = get_default_address_format();

    // Detect P2WPKH (SegWit v0, 20-byte witness program)
    if (script_len == 22 && script[0] == 0x00 && script[1] == 0x14) {
        return segwit_addr_encode(addr_format->hrp, strlen(addr_format->hrp), 0, script + 2, 20,
                                  address_out, addr_size);
    }

    return PSA_ERROR_INVALID_ARGUMENT; // Unsupported scriptPubKey format
}
