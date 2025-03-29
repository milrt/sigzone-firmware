// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include "psbt.h"
#include "psbt_result.h"

typedef struct psbt_validation_entry {
    const char *description; // "Input" or "Output"
    const char *address;
    uint64_t amount_sats;
    bool is_change;
    sys_snode_t node;
} psbt_validation_entry_t;

typedef struct {
    sys_slist_t entries;
    uint64_t total_input;
    uint64_t total_output;
    uint64_t fee;
    bool is_valid;
} psbt_validation_t;

void psbt_validation_free(psbt_validation_t *validation);
psbt_result_t psbt_validate(psbt_t *psbt, psbt_validation_t *validation);
