// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "bitcoin/psbt.h"
#include "bitcoin/psbt_tx.h"
#include "psbt_compactsize.h"
#include "psbt_heap.h"
#include <string.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/sys/util.h>

LOG_MODULE_REGISTER(psbt);

/* Free a single key-value pair */
static inline void free_kv(psbt_kv_t *kv)
{
    if (!kv) {
        return;
    }
    k_heap_free(&psbt_heap, kv->key_data);
    k_heap_free(&psbt_heap, kv->value_data);
    k_heap_free(&psbt_heap, kv);
}

/* Free all key-value pairs in a map */
static inline void free_map(psbt_map_t *map)
{
    psbt_kv_t *kv, *tmp;
    SYS_SLIST_FOR_EACH_CONTAINER_SAFE(&map->kv_list, kv, tmp, node)
    {
        sys_slist_remove(&map->kv_list, NULL, &kv->node);
        free_kv(kv);
    }
}

/* Free an array of maps and reset count */
static inline void free_maps(psbt_map_t **maps, size_t *num)
{
    if (*maps) {
        for (size_t i = 0; i < *num; i++) {
            free_map(&(*maps)[i]);
        }
        k_heap_free(&psbt_heap, *maps);
        *maps = NULL;
        *num = 0;
    }
}

void psbt_free(psbt_t *psbt)
{
    free_map(&psbt->global);
    free_maps(&psbt->inputs, &psbt->num_inputs);
    free_maps(&psbt->outputs, &psbt->num_outputs);
}

psbt_kv_t *psbt_find_kv(psbt_map_t *map, uint8_t key_type)
{
    psbt_kv_t *kv;
    SYS_SLIST_FOR_EACH_CONTAINER(&map->kv_list, kv, node)
    {
        if (kv->key_type == key_type) {
            return kv;
        }
    }
    return NULL;
}

/*
 * Read key/value pairs into a map.
 * Advances *data_ptr and decreases *remaining_ptr accordingly.
 */
static psbt_result_t parse_map(const uint8_t **data_ptr, size_t *remaining_ptr, psbt_map_t *map)
{
    while (*remaining_ptr > 0) {
        compactsize_data_t key_data;
        if (!compactsize_read_with_data(data_ptr, remaining_ptr, &key_data)) {
            return PSBT_READ_ERROR;
        }
        if (key_data.size == 0) {
            break;
        }

        compactsize_data_t value_data;
        if (!compactsize_read_with_data(data_ptr, remaining_ptr, &value_data)) {
            return PSBT_READ_ERROR;
        }

        psbt_kv_t *kv = k_heap_alloc(&psbt_heap, sizeof(*kv), K_NO_WAIT);
        if (!kv) {
            return PSBT_OOB_WRITE;
        }

        kv->key_type = key_data.data[0];
        kv->key_data_len = key_data.size - 1;
        if (kv->key_data_len) {
            kv->key_data = k_heap_alloc(&psbt_heap, kv->key_data_len, K_NO_WAIT);
            if (!kv->key_data) {
                k_heap_free(&psbt_heap, kv);
                return PSBT_OOB_WRITE;
            }
            memcpy(kv->key_data, key_data.data + 1, kv->key_data_len);
        } else {
            kv->key_data = NULL;
        }

        kv->value_data_len = value_data.size;
        kv->value_data = k_heap_alloc(&psbt_heap, value_data.size, K_NO_WAIT);
        if (!kv->value_data) {
            k_heap_free(&psbt_heap, kv->key_data);
            k_heap_free(&psbt_heap, kv);
            return PSBT_OOB_WRITE;
        }
        memcpy(kv->value_data, value_data.data, value_data.size);

        sys_slist_append(&map->kv_list, &kv->node);
    }

    return PSBT_OK;
}

psbt_result_t psbt_create_from_bin(psbt_t *psbt, const uint8_t *data, size_t data_len)
{
    const uint8_t *cur = data;
    size_t rem = data_len;
    psbt_result_t res;

    /* Initialize PSBT structure */
    sys_slist_init(&psbt->global.kv_list);
    psbt->inputs = psbt->outputs = NULL;
    psbt->num_inputs = psbt->num_outputs = 0;

    /* Check signature */
    if (rem < 5 || memcmp(cur, "\x70\x73\x62\x74\xFF", 5) != 0) {
        return PSBT_READ_ERROR;
    }
    cur += 5;
    rem -= 5;

    /* Parse global map */
    res = parse_map(&cur, &rem, &psbt->global);
    if (res != PSBT_OK) {
        return res;
    }

    /* Ensure unsigned tx exists */
    psbt_kv_t *utxokv = psbt_find_kv(&psbt->global, PSBT_GLOBAL_UNSIGNED_TX);
    if (!utxokv || !utxokv->value_data) {
        return PSBT_READ_ERROR;
    }

    /* Get counts from unsigned transaction */
    psbt_tx_t tx;
    res = psbt_tx_create_from_bin(&tx, utxokv->value_data, utxokv->value_data_len);
    if (res != PSBT_OK) {
        return res;
    }
    psbt->num_inputs = tx.num_inputs;
    psbt->num_outputs = tx.num_outputs;
    psbt_tx_free(&tx);

    /* Allocate and parse input maps */
    psbt->inputs = k_heap_alloc(&psbt_heap, psbt->num_inputs * sizeof(psbt_map_t), K_NO_WAIT);
    if (!psbt->inputs) {
        return PSBT_OOB_WRITE;
    }
    for (size_t i = 0; i < psbt->num_inputs; i++) {
        sys_slist_init(&psbt->inputs[i].kv_list);
        res = parse_map(&cur, &rem, &psbt->inputs[i]);
        if (res != PSBT_OK) {
            psbt_free(psbt);
            return res;
        }
    }

    /* Allocate and parse output maps */
    psbt->outputs = k_heap_alloc(&psbt_heap, psbt->num_outputs * sizeof(psbt_map_t), K_NO_WAIT);
    if (!psbt->outputs) {
        psbt_free(psbt);
        return PSBT_OOB_WRITE;
    }
    for (size_t i = 0; i < psbt->num_outputs; i++) {
        sys_slist_init(&psbt->outputs[i].kv_list);
        res = parse_map(&cur, &rem, &psbt->outputs[i]);
        if (res != PSBT_OK) {
            psbt_free(psbt);
            return res;
        }
    }

    if (rem != 0) {
        psbt_free(psbt);
        return PSBT_READ_ERROR;
    }

    return PSBT_OK;
}

static size_t calculate_map_size(psbt_map_t *map)
{
    size_t size = 0;
    psbt_kv_t *kv;

    SYS_SLIST_FOR_EACH_CONTAINER(&map->kv_list, kv, node)
    {
        /* Size of compactsize(key_length) + key header + compactsize(value_length) + value */
        size += compactsize_length(1 + kv->key_data_len) + (1 + kv->key_data_len) +
                compactsize_length(kv->value_data_len) + kv->value_data_len;
    }
    return size + 1; /* Separator */
}

/*
 * Write the map into the destination buffer.
 * Writes each key/value pair and then the final separator (0x00).
 */
static psbt_result_t write_map(psbt_map_t *map, uint8_t **dest_ptr, size_t *remaining_ptr)
{
    psbt_kv_t *kv;

    SYS_SLIST_FOR_EACH_CONTAINER(&map->kv_list, kv, node)
    {
        size_t key_len = 1 + kv->key_data_len;
        /* Allocate temporary buffer to hold key header */
        uint8_t *key_buf = k_heap_alloc(&psbt_heap, key_len, K_NO_WAIT);
        if (!key_buf) {
            return PSBT_OOB_WRITE;
        }
        key_buf[0] = kv->key_type;
        if (kv->key_data_len) {
            memcpy(key_buf + 1, kv->key_data, kv->key_data_len);
        }

        compactsize_data_t key_write_data = {.size = key_len, .data = key_buf};
        if (!compactsize_write_with_data(dest_ptr, remaining_ptr, &key_write_data)) {
            k_heap_free(&psbt_heap, key_buf);
            return PSBT_OOB_WRITE;
        }
        k_heap_free(&psbt_heap, key_buf);

        compactsize_data_t value_write_data = {.size = kv->value_data_len, .data = kv->value_data};
        if (!compactsize_write_with_data(dest_ptr, remaining_ptr, &value_write_data)) {
            return PSBT_OOB_WRITE;
        }
    }

    if (*remaining_ptr < 1) {
        return PSBT_OOB_WRITE;
    }
    *(*dest_ptr)++ = 0x00;
    (*remaining_ptr)--;
    return PSBT_OK;
}

psbt_result_t psbt_to_bin(psbt_t *psbt, uint8_t *out_buf, size_t *out_len)
{
    size_t required = 5 + calculate_map_size(&psbt->global);

    for (size_t i = 0; i < psbt->num_inputs; i++) {
        required += calculate_map_size(&psbt->inputs[i]);
    }
    for (size_t i = 0; i < psbt->num_outputs; i++) {
        required += calculate_map_size(&psbt->outputs[i]);
    }

    if (*out_len < required) {
        *out_len = required;
        return PSBT_OOB_WRITE;
    }

    uint8_t *dest = out_buf;
    size_t remaining = *out_len;

    memcpy(dest, "\x70\x73\x62\x74\xFF", 5);
    dest += 5;
    remaining -= 5;

    psbt_result_t res = write_map(&psbt->global, &dest, &remaining);
    if (res != PSBT_OK) {
        return res;
    }

    for (size_t i = 0; i < psbt->num_inputs; i++) {
        res = write_map(&psbt->inputs[i], &dest, &remaining);
        if (res != PSBT_OK) {
            return res;
        }
    }

    for (size_t i = 0; i < psbt->num_outputs; i++) {
        res = write_map(&psbt->outputs[i], &dest, &remaining);
        if (res != PSBT_OK) {
            return res;
        }
    }

    *out_len = dest - out_buf;
    return PSBT_OK;
}
