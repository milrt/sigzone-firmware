// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "shared/hash.h"
#include <mbedtls/md.h>
#include <mbedtls/pkcs5.h>

psa_status_t hash_sha256(const uint8_t *input, size_t input_size, uint8_t *hash_out,
                         size_t hash_out_size)
{
    if (!input || input_size == 0 || hash_out_size < 32) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    psa_status_t status;
    psa_hash_operation_t op = PSA_HASH_OPERATION_INIT;

    status = psa_hash_setup(&op, PSA_ALG_SHA_256);
    if (status != PSA_SUCCESS) {
        return status;
    }

    status = psa_hash_update(&op, input, input_size);
    if (status != PSA_SUCCESS) {
        psa_hash_abort(&op);
        return status;
    }

    size_t hash_size = 0;
    status = psa_hash_finish(&op, hash_out, 32, &hash_size);
    if (hash_size != 32) {
        psa_hash_abort(&op);
        return PSA_ERROR_GENERIC_ERROR;
    }
    if (status != PSA_SUCCESS) {
        psa_hash_abort(&op);
        return status;
    }

    return PSA_SUCCESS;
}

psa_status_t hash_doubleSha256(const uint8_t *input, size_t input_size, uint8_t *hash_out,
                               size_t hash_out_size)
{
    if (!input || (input_size == 0) || !hash_out || hash_out_size < 32) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    uint8_t first_hash[32];
    psa_status_t status = hash_sha256(input, input_size, first_hash, sizeof(first_hash));
    if (status != PSA_SUCCESS) {
        return status;
    }
    return hash_sha256(first_hash, sizeof(first_hash), hash_out, hash_out_size);
}

psa_status_t hash_ripemd160(const uint8_t *input, size_t input_size, uint8_t *hash_out,
                            size_t hash_out_size)
{
    if (!input || input_size == 0 || hash_out_size < 20) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    psa_status_t status;
    psa_hash_operation_t op = PSA_HASH_OPERATION_INIT;

    status = psa_hash_setup(&op, PSA_ALG_RIPEMD160);
    if (status != PSA_SUCCESS) {
        return status;
    }

    status = psa_hash_update(&op, input, input_size);
    if (status != PSA_SUCCESS) {
        psa_hash_abort(&op);
        return status;
    }

    size_t hash_size = 0;
    status = psa_hash_finish(&op, hash_out, 20, &hash_size);
    if (status != PSA_SUCCESS || hash_size != 20) {
        psa_hash_abort(&op);
        return PSA_ERROR_GENERIC_ERROR;
    }

    return PSA_SUCCESS;
}

// TODO: use PSA Crypto API as soon as it's supported.
psa_status_t hash_pbkdf2_hmac_sha512(const uint8_t *password, size_t password_len,
                                     const uint8_t *salt, size_t salt_len, uint32_t iterations,
                                     uint8_t *output, size_t output_size)
{
    if (!output || output_size < 64) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if ((password_len > 0 && !password) || (salt_len > 0 && !salt)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    const int ret = mbedtls_pkcs5_pbkdf2_hmac_ext(MBEDTLS_MD_SHA512, password, password_len, salt,
                                                  salt_len, iterations, 64, output);

    return (ret == 0) ? PSA_SUCCESS : PSA_ERROR_GENERIC_ERROR;
}

psa_status_t hash_hmac_sha512(const uint8_t *key, size_t key_len, const uint8_t *input,
                              size_t input_len, uint8_t *output, size_t output_size)
{
    if (!key || key_len == 0 || !input || !output || output_size < 64) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    psa_status_t status;
    psa_key_handle_t key_handle;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH);
    psa_set_key_algorithm(&attributes, PSA_ALG_HMAC(PSA_ALG_SHA_512));
    psa_set_key_type(&attributes, PSA_KEY_TYPE_HMAC);

    status = psa_import_key(&attributes, key, key_len, &key_handle);
    psa_reset_key_attributes(&attributes); // Clean up key attributes
    if (status != PSA_SUCCESS) {
        return status;
    }

    size_t mac_length = 0;
    status = psa_mac_compute(key_handle, PSA_ALG_HMAC(PSA_ALG_SHA_512), input, input_len, output,
                             output_size, &mac_length);

    psa_destroy_key(key_handle);

    if (status != PSA_SUCCESS || mac_length != 64) {
        return PSA_ERROR_GENERIC_ERROR;
    }

    return PSA_SUCCESS;
}
