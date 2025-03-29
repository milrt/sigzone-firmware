// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "psbt_compactsize.h"
#include <string.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/byteorder.h>

LOG_MODULE_REGISTER(psbt_compactsize);

uint32_t compactsize_length(uint64_t size)
{
    return (size < 253) ? 1 : (size <= 0xFFFF) ? 3 : (size <= 0xFFFFFFFF) ? 5 : 9;
}

static inline bool check_bounds(const uint8_t **data, size_t *remaining, size_t needed)
{
    if (*remaining < needed) {
        LOG_ERR("Buffer underflow (need %zu, have %zu)", needed, *remaining);
        return false;
    }
    return true;
}

bool compactsize_read(const uint8_t **data, size_t *remaining, uint64_t *out)
{
    if (!data || !*data || !remaining || !out) {
        LOG_ERR("Null pointer in compactsize_read");
        return false;
    }

    if (!check_bounds(data, remaining, 1)) {
        return false;
    }

    uint8_t header = *(*data)++;
    uint32_t needed = 1;
    uint64_t result = header;

    if (header >= 253) {
        needed = (header == 253) ? 3 : (header == 254) ? 5 : 9;
        if (!check_bounds(data, remaining, needed - 1)) {
            return false;
        }

        if (header == 253) {
            result = sys_get_le16(*data);
        } else if (header == 254) {
            result = sys_get_le32(*data);
        } else {
            result = sys_get_le64(*data);
        }

        if ((header == 253 && result < 253) || (header == 254 && result <= 0xFFFF) ||
            (header == 255 && result <= 0xFFFFFFFF)) {
            LOG_ERR("Non-canonical compactsize %llu", result);
            return false;
        }
    }

    *data += needed - 1;
    *remaining -= needed;
    *out = result;
    return true;
}

bool compactsize_write(uint8_t **dest, size_t *remaining, uint64_t size)
{
    if (!dest || !*dest || !remaining) {
        LOG_ERR("Null pointer in compactsize_write");
        return false;
    }

    uint32_t needed = compactsize_length(size);
    if (!check_bounds((const uint8_t **)dest, remaining, needed)) {
        return false;
    }

    uint8_t *p = *dest;
    *p = (size < 253) ? size : (size <= 0xFFFF) ? 253 : (size <= 0xFFFFFFFF) ? 254 : 255;

    if (size >= 253) {
        if (size <= 0xFFFF) {
            sys_put_le16(size, p + 1);
        } else if (size <= 0xFFFFFFFF) {
            sys_put_le32(size, p + 1);
        } else {
            sys_put_le64(size, p + 1);
        }
    }

    *dest += needed;
    *remaining -= needed;
    return true;
}

bool compactsize_write_with_data(uint8_t **dest, size_t *remaining, const compactsize_data_t *data)
{
    if (!compactsize_write(dest, remaining, data->size)) {
        return false;
    }
    if (!check_bounds((const uint8_t **)dest, remaining, data->size)) {
        return false;
    }

    memcpy(*dest, data->data, data->size);
    *dest += data->size;
    *remaining -= data->size;
    return true;
}

bool compactsize_read_with_data(const uint8_t **data, size_t *remaining, compactsize_data_t *out)
{
    if (!compactsize_read(data, remaining, &out->size)) {
        return false;
    }
    if (!check_bounds(data, remaining, out->size)) {
        return false;
    }

    out->data = *data;
    *data += out->size;
    *remaining -= out->size;
    return true;
}
