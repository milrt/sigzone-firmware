// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include "psbt_result.h"
#include <zephyr/kernel.h>

typedef struct {
    uint8_t *txid;
    uint32_t index;
    uint8_t *script;
    uint32_t script_len;
    uint32_t sequence;
} psbt_txin_t;

typedef struct {
    uint64_t amount;
    uint8_t *script;
    uint32_t script_len;
} psbt_txout_t;

typedef struct {
    uint8_t **witness_data;
    uint32_t *witness_len;
    uint32_t witness_count;
} psbt_witness_item_t;

typedef struct {
    uint32_t version;
    uint32_t lock_time;
    psbt_txin_t *inputs;
    size_t num_inputs;
    psbt_txout_t *outputs;
    size_t num_outputs;
    psbt_witness_item_t *witnesses;
    size_t num_witnesses;
} psbt_tx_t;

psbt_result_t psbt_tx_create_from_bin(psbt_tx_t *tx, const uint8_t *data, size_t data_len);
void psbt_tx_free(psbt_tx_t *tx);
