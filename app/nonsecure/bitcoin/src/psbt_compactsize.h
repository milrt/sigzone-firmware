// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint64_t size;
    const uint8_t *data;
} compactsize_data_t;

uint32_t compactsize_length(uint64_t size);
bool compactsize_read(const uint8_t **data, size_t *remaining, uint64_t *out);
bool compactsize_write(uint8_t **dest, size_t *remaining, uint64_t size);

bool compactsize_read_with_data(const uint8_t **data_ptr, size_t *remaining_ptr,
                                compactsize_data_t *out);
bool compactsize_write_with_data(uint8_t **dest_ptr, size_t *remaining_ptr,
                                 const compactsize_data_t *write_data);
