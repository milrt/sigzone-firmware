// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "bitcoin/psbt_validator.h"
#include "bitcoin/bitcoin_client.h"
#include "bitcoin/chains.h"
#include "bitcoin/psbt.h"
#include "bitcoin/psbt_tx.h"
#include "psbt_compactsize.h"
#include "psbt_heap.h"
#include "shared/hash.h"
#include <string.h>
#include <sys/_stdint.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/byteorder.h>

LOG_MODULE_REGISTER(psbt_validator);

static psa_status_t get_wallet_fingerprint(uint8_t *fingerprint)
{
    uint8_t pubkey[33];
    size_t pubkey_size = sizeof(pubkey);
    char xpub[128];
    size_t xpub_size = sizeof(xpub);

    psa_status_t status = bitcoin_client_get_pubkey("m", pubkey, &pubkey_size, xpub, &xpub_size);
    if (status != PSA_SUCCESS) {
        return status;
    }

    uint8_t sha256[32];
    uint8_t ripemd160[20];
    status = hash_sha256(pubkey, pubkey_size, sha256, sizeof(sha256));
    if (status != PSA_SUCCESS) {
        return status;
    }
    status = hash_ripemd160(sha256, sizeof(sha256), ripemd160, sizeof(ripemd160));
    if (status != PSA_SUCCESS) {
        return status;
    }

    memcpy(fingerprint, ripemd160, 4);
    return PSA_SUCCESS;
}

// TODO: parse derivation path and check is address matches.
static bool is_change_output(psbt_map_t *output, uint8_t wallet_fingerprint[4])
{
    psbt_kv_t *bip32_deriv = psbt_find_kv(output, PSBT_OUT_BIP32_DERIVATION);
    if (!bip32_deriv || bip32_deriv->value_data_len < 4) {
        return false;
    }

    return memcmp(bip32_deriv->value_data, wallet_fingerprint, 4) == 0;
}

psbt_result_t psbt_validate(psbt_t *psbt, psbt_validation_t *validation)
{
    memset(validation, 0, sizeof(*validation));
    sys_slist_init(&validation->entries);

    // Get wallet fingerprint for change detection
    uint8_t wallet_fingerprint[4];
    if (get_wallet_fingerprint(wallet_fingerprint) != PSA_SUCCESS) {
        LOG_ERR("PSBT validate failed. Failed to get fingerprint");
        return PSBT_OOB_WRITE;
    }

    // Parse unsigned transaction
    psbt_kv_t *unsigned_tx = psbt_find_kv(&psbt->global, PSBT_GLOBAL_UNSIGNED_TX);
    if (!unsigned_tx) {
        LOG_ERR("PSBT validate failed. Failed to get unsigned transaction");
        return PSBT_READ_ERROR;
    }

    psbt_tx_t tx;
    psbt_result_t res =
        psbt_tx_create_from_bin(&tx, unsigned_tx->value_data, unsigned_tx->value_data_len);
    if (res != PSBT_OK) {
        LOG_ERR("PSBT validate failed. Failed to create tx from bin (%d)", res);
        return res;
    }

    // Process inputs
    for (size_t i = 0; i < psbt->num_inputs; i++) {
        psbt_map_t *input = &psbt->inputs[i];
        // psbt_txin_t *txin = &tx.inputs[i];

        // Get UTXO value
        uint64_t amount = 0;
        psbt_kv_t *witness_utxo = psbt_find_kv(input, PSBT_IN_WITNESS_UTXO);
        if (witness_utxo && witness_utxo->value_data_len >= 8) {
            amount = sys_get_le64(witness_utxo->value_data);
        }

        // Get address
        char address[MAX_ADDRESS_LEN] = {0};
        if (witness_utxo && witness_utxo->value_data_len > 8) {
            // compactsize
            const uint8_t *data = witness_utxo->value_data + 8;
            size_t remaining = witness_utxo->value_data_len - 8;
            compactsize_data_t script_data;
            compactsize_read_with_data(&data, &remaining, &script_data);

            size_t addr_len = sizeof(address);
            script_to_address(script_data.data, script_data.size, address, &addr_len);
        }

        // Create entry
        psbt_validation_entry_t *entry =
            k_heap_alloc(&psbt_heap, sizeof(psbt_validation_entry_t), K_NO_WAIT);
        if (!entry) {
            psbt_tx_free(&tx);
            LOG_ERR("PSBT validate failed. Failed to allocate heap for input entry");
            return PSBT_OOB_WRITE;
        }

        entry->description = "Input";
        entry->address = k_heap_alloc(&psbt_heap, strlen(address) + 1, K_NO_WAIT);
        if (!entry->address) {
            k_heap_free(&psbt_heap, entry);
            psbt_tx_free(&tx);
            LOG_ERR("PSBT validate failed. Failed to allocate heap for address");
            return PSBT_OOB_WRITE;
        }
        strcpy((char *)entry->address, address);
        entry->amount_sats = amount;
        entry->is_change = false;

        sys_slist_append(&validation->entries, &entry->node);
        validation->total_input += amount;
    }

    // Process outputs
    for (size_t i = 0; i < psbt->num_outputs; i++) {
        psbt_map_t *output = &psbt->outputs[i];
        psbt_txout_t *txout = &tx.outputs[i];

        // Get address
        char address[MAX_ADDRESS_LEN] = {0};
        size_t addr_len = sizeof(address);
        script_to_address(txout->script, txout->script_len, address, &addr_len);

        // Create entry
        psbt_validation_entry_t *entry =
            k_heap_alloc(&psbt_heap, sizeof(psbt_validation_entry_t), K_NO_WAIT);
        if (!entry) {
            psbt_tx_free(&tx);
            LOG_ERR("PSBT validate failed. Failed to allocate heap for output entry");
            return PSBT_OOB_WRITE;
        }

        entry->description = "Output";
        entry->address = k_heap_alloc(&psbt_heap, strlen(address) + 1, K_NO_WAIT);
        if (!entry->address) {
            k_heap_free(&psbt_heap, entry);
            psbt_tx_free(&tx);
            LOG_ERR("PSBT validate failed. Failed to allocate heap for output address");
            return PSBT_OOB_WRITE;
        }
        strcpy((char *)entry->address, address);
        entry->amount_sats = txout->amount;
        entry->is_change = is_change_output(output, wallet_fingerprint);

        sys_slist_append(&validation->entries, &entry->node);
        validation->total_output += txout->amount;
    }

    // Calculate fee
    if (validation->total_input >= validation->total_output) {
        validation->fee = validation->total_input - validation->total_output;
        validation->is_valid = true;
    } else {
        validation->is_valid = false;
    }

    psbt_tx_free(&tx);
    return PSBT_OK;
}

void psbt_validation_free(psbt_validation_t *validation)
{
    psbt_validation_entry_t *entry, *tmp;
    SYS_SLIST_FOR_EACH_CONTAINER_SAFE(&validation->entries, entry, tmp, node)
    {
        sys_slist_remove(&validation->entries, NULL, &entry->node);
        k_heap_free(&psbt_heap, (void *)entry->address);
        k_heap_free(&psbt_heap, entry);
    }
}
