// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include "psbt_result.h"
#include <zephyr/kernel.h>
#include <zephyr/sys/slist.h>

#define PSBT_GLOBAL_UNSIGNED_TX 0x00
#define PSBT_IN_WITNESS_UTXO 0x01
#define PSBT_IN_BIP32_DERIVATION 0x06
#define PSBT_IN_FINAL_SCRIPTWITNESS 0x08
#define PSBT_IN_PARTIAL_SIG 0x02
#define PSBT_IN_SIGHASH_TYPE 0x03
#define PSBT_OUT_BIP32_DERIVATION 0x02

typedef struct psbt_kv {
    uint8_t key_type;
    uint8_t *key_data;
    size_t key_data_len;
    uint8_t *value_data;
    size_t value_data_len;
    sys_snode_t node;
} psbt_kv_t;

typedef struct psbt_map {
    sys_slist_t kv_list;
} psbt_map_t;

typedef struct psbt {
    psbt_map_t global;
    psbt_map_t *inputs;
    size_t num_inputs;
    psbt_map_t *outputs;
    size_t num_outputs;
} psbt_t;

psbt_result_t psbt_create_from_bin(psbt_t *psbt, const uint8_t *data, size_t data_len);
psbt_kv_t *psbt_find_kv(psbt_map_t *map, uint8_t key_type);
void psbt_free(psbt_t *psbt);

psbt_result_t psbt_to_bin(psbt_t *psbt, uint8_t *out_buf, size_t *out_len);
psbt_result_t psbt_get_summary(psbt_t *psbt, char *str_out, size_t buf_size);
