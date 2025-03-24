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
