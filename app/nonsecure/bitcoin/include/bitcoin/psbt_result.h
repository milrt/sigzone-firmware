// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

typedef enum {
    PSBT_OK,
    PSBT_COMPACT_READ_ERROR,
    PSBT_READ_ERROR,
    PSBT_WRITE_ERROR,
    PSBT_INVALID_STATE,
    PSBT_NOT_IMPLEMENTED,
    PSBT_OOB_WRITE
} psbt_result_t;
