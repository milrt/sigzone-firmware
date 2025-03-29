// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "base58.h"
#include "libbase58.h"
#include "shared/hash.h"

static bool sha256_wrapper(void *digest, const void *data, size_t datasz)
{
    return hash_sha256(data, datasz, (uint8_t *)digest, 32) == PSA_SUCCESS;
}

// Set the base58 library's SHA-256 function at startup.
__attribute__((constructor)) static void init_base58_sha256()
{
    b58_sha256_impl = sha256_wrapper;
}

psa_status_t base58_check_encode(const uint8_t *data, size_t data_size, char *str, size_t str_size)
{
    if (!data || (data_size == 0) || !str) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (data_size + 4 > BASE58_ENCODE_MAX_DATA_SIZE) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    uint8_t buf[BASE58_ENCODE_MAX_DATA_SIZE];
    memcpy(buf, data, data_size);

    uint8_t hash[32];
    psa_status_t status = hash_doubleSha256(data, data_size, hash, sizeof(hash));
    if (status != PSA_SUCCESS) {
        return status;
    }
    memcpy(buf + data_size, hash, 4);

    size_t total_size = data_size + 4;
    size_t encoded_size = str_size;
    bool ok = b58enc(str, &encoded_size, buf, total_size);
    if (!ok) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }
    return PSA_SUCCESS;
}

psa_status_t base58_check_decode(const char *str, uint8_t *data, size_t *data_size)
{
    if (!str || !data || !data_size) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    size_t str_len = strlen(str);
    bool ok = b58tobin(data, data_size, str, str_len);
    if (!ok) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (*data_size < 4) {
        return PSA_ERROR_INVALID_SIGNATURE;
    }

    int check = b58check(data, *data_size, str, str_len);
    if (check < 0) {
        return PSA_ERROR_INVALID_SIGNATURE;
    }

    *data_size -= 4;
    return PSA_SUCCESS;
}
