// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "bitcoin/psbt_tx.h"
#include "psbt_compactsize.h"
#include "psbt_heap.h"
#include <zephyr/logging/log.h>
#include <zephyr/sys/byteorder.h>

LOG_MODULE_REGISTER(psbt_tx);

static inline void *psbt_alloc(size_t size)
{
    return k_heap_alloc(&psbt_heap, size, K_NO_WAIT);
}

static inline bool psbt_read(const uint8_t **p, size_t *remaining, void *dest, size_t len)
{
    if (*remaining < len) {
        return false;
    }
    memcpy(dest, *p, len);
    *p += len;
    *remaining -= len;
    return true;
}

static inline bool psbt_read_le32(const uint8_t **p, size_t *remaining, uint32_t *val)
{
    return psbt_read(p, remaining, val, 4) ? (*val = sys_get_le32((const uint8_t *)val), true)
                                           : false;
}

static inline bool psbt_read_le64(const uint8_t **p, size_t *remaining, uint64_t *val)
{
    return psbt_read(p, remaining, val, 8) ? (*val = sys_get_le64((const uint8_t *)val), true)
                                           : false;
}

static bool psbt_read_script(const uint8_t **p, size_t *remaining, uint8_t **script,
                             uint32_t *script_len)
{
    uint64_t len;
    if (!compactsize_read(p, remaining, &len) || len > *remaining) {
        return false;
    }
    *script_len = len;
    if (len > 0) {
        *script = psbt_alloc(len);
        if (!*script) {
            return false;
        }
        memcpy(*script, *p, len);
        *p += len;
        *remaining -= len;
    }
    return true;
}

static bool psbt_parse_inputs(psbt_tx_t *tx, const uint8_t **p, size_t *remaining)
{
    uint64_t num_inputs;
    if (!compactsize_read(p, remaining, &num_inputs)) {
        return false;
    }

    tx->num_inputs = num_inputs;
    if (!(tx->inputs = psbt_alloc(num_inputs * sizeof(psbt_txin_t)))) {
        return false;
    }

    memset(tx->inputs, 0, num_inputs * sizeof(psbt_txin_t));

    for (size_t i = 0; i < num_inputs; i++) {
        psbt_txin_t *in = &tx->inputs[i];

        if (!(in->txid = psbt_alloc(32)) || !psbt_read(p, remaining, in->txid, 32) ||
            !psbt_read_le32(p, remaining, &in->index) ||
            !psbt_read_script(p, remaining, &in->script, &in->script_len) ||
            !psbt_read_le32(p, remaining, &in->sequence)) {
            return false;
        }
    }
    return true;
}

static bool psbt_parse_outputs(psbt_tx_t *tx, const uint8_t **p, size_t *remaining)
{
    uint64_t num_outputs;
    if (!compactsize_read(p, remaining, &num_outputs)) {
        return false;
    }

    tx->num_outputs = num_outputs;
    if (!(tx->outputs = psbt_alloc(num_outputs * sizeof(psbt_txout_t)))) {
        return false;
    }

    memset(tx->outputs, 0, num_outputs * sizeof(psbt_txout_t));

    for (size_t i = 0; i < num_outputs; i++) {
        psbt_txout_t *out = &tx->outputs[i];

        if (!psbt_read_le64(p, remaining, &out->amount) ||
            !psbt_read_script(p, remaining, &out->script, &out->script_len)) {
            return false;
        }
    }
    return true;
}

static bool psbt_parse_witnesses(psbt_tx_t *tx, const uint8_t **p, size_t *remaining)
{
    tx->num_witnesses = tx->num_inputs;
    if (!(tx->witnesses = psbt_alloc(tx->num_witnesses * sizeof(psbt_witness_item_t)))) {
        return false;
    }

    memset(tx->witnesses, 0, tx->num_witnesses * sizeof(psbt_witness_item_t));

    for (size_t i = 0; i < tx->num_inputs; i++) {
        psbt_witness_item_t *wit = &tx->witnesses[i];
        uint64_t witness_count;

        if (!compactsize_read(p, remaining, &witness_count)) {
            return false;
        }

        wit->witness_count = witness_count;

        if (!(wit->witness_data = psbt_alloc(witness_count * sizeof(uint8_t *))) ||
            !(wit->witness_len = psbt_alloc(witness_count * sizeof(uint32_t)))) {
            return false;
        }

        for (uint32_t j = 0; j < witness_count; j++) {
            uint64_t item_len;
            if (!compactsize_read(p, remaining, &item_len) || item_len > *remaining) {
                return false;
            }

            wit->witness_len[j] = item_len;
            if (!(wit->witness_data[j] = psbt_alloc(item_len)) ||
                !psbt_read(p, remaining, wit->witness_data[j], item_len)) {
                return false;
            }
        }
    }
    return true;
}

psbt_result_t psbt_tx_create_from_bin(psbt_tx_t *tx, const uint8_t *data, size_t data_len)
{
    if (!tx || !data) {
        return PSBT_OOB_WRITE;
    }

    memset(tx, 0, sizeof(psbt_tx_t));
    const uint8_t *p = data;
    size_t remaining = data_len;

    if (!psbt_read_le32(&p, &remaining, &tx->version)) {
        return PSBT_READ_ERROR;
    }

    int has_witness = (remaining >= 2 && p[0] == 0x00 && p[1] == 0x01);
    if (has_witness) {
        p += 2;
        remaining -= 2;
    }

    if (!psbt_parse_inputs(tx, &p, &remaining) || !psbt_parse_outputs(tx, &p, &remaining) ||
        (has_witness && !psbt_parse_witnesses(tx, &p, &remaining)) ||
        !psbt_read_le32(&p, &remaining, &tx->lock_time) || remaining != 0) {
        goto error;
    }

    return PSBT_OK;

error:
    psbt_tx_free(tx);
    return PSBT_READ_ERROR;
}

void psbt_tx_free(psbt_tx_t *tx)
{
    if (!tx) {
        return;
    }

    for (size_t i = 0; i < tx->num_inputs; i++) {
        k_heap_free(&psbt_heap, tx->inputs[i].txid);
        k_heap_free(&psbt_heap, tx->inputs[i].script);
    }
    k_heap_free(&psbt_heap, tx->inputs);

    for (size_t i = 0; i < tx->num_outputs; i++) {
        k_heap_free(&psbt_heap, tx->outputs[i].script);
    }
    k_heap_free(&psbt_heap, tx->outputs);

    for (size_t i = 0; i < tx->num_witnesses; i++) {
        for (uint32_t j = 0; j < tx->witnesses[i].witness_count; j++) {
            k_heap_free(&psbt_heap, tx->witnesses[i].witness_data[j]);
        }

        k_heap_free(&psbt_heap, tx->witnesses[i].witness_data);
        k_heap_free(&psbt_heap, tx->witnesses[i].witness_len);
    }
    k_heap_free(&psbt_heap, tx->witnesses);
}
