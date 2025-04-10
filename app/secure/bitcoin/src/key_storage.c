// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "key_storage.h"
#include "nv_counter.h"
#include "psa/crypto.h"
#include "psa/crypto_types.h"
#include "psa/crypto_values.h"
#include "psa/error.h"
#include "tfm_crypto_defs.h"
#include <mbedtls/gcm.h>
#include <mbedtls/platform_util.h>
#include "psa/protected_storage.h"
#include <psa/storage_common.h>
#include <stdbool.h>
#include <string.h>

#define KEY_STORAGE_UID (0x10010010UL)
#define KEY_STORAGE_FAIL_COUNT_UID (0x10010011UL)
#define KEY_STORAGE_MAX_FAILS (10)

#define SALT_SIZE (16)
#define DERIVED_KEY_SIZE (32)
#define IV_SIZE (12)
#define TAG_SIZE (16)

typedef struct {
    uint8_t salt[SALT_SIZE];
    uint8_t iv[IV_SIZE];
    uint8_t tag[TAG_SIZE];
    uint8_t ciphertext[sizeof(magic_internet_key_t)];
} key_storage_data_t;

static psa_status_t derive_key_from_pin_and_huk(const char *pin, size_t pin_len,
                                                const uint8_t *salt, size_t salt_len,
                                                psa_key_id_t *enc_key, psa_key_usage_t usage)
{
    psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_status_t status;

    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attributes, 256);
    psa_set_key_usage_flags(&attributes, usage);
    psa_set_key_algorithm(&attributes, PSA_ALG_GCM);

    status = psa_key_derivation_setup(&op, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    if (status != PSA_SUCCESS) {
        return status;
    }

    status = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SALT, salt, salt_len);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    status =
        psa_key_derivation_input_key(&op, PSA_KEY_DERIVATION_INPUT_SECRET, TFM_BUILTIN_KEY_ID_HUK);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    status = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_INFO,
                                            (const uint8_t *)pin, pin_len);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    status = psa_key_derivation_output_key(&attributes, &op, enc_key);

cleanup:
    psa_key_derivation_abort(&op);
    return status;
}

static psa_status_t encrypt_data(psa_key_id_t enc_key, const uint8_t *iv, const void *plaintext,
                                 size_t plaintext_len, uint8_t *ciphertext, uint8_t *tag)
{
    size_t out_len;
    uint8_t local_out[sizeof(magic_internet_key_t) + TAG_SIZE];

    psa_status_t status = psa_aead_encrypt(enc_key, PSA_ALG_GCM, iv, IV_SIZE, NULL, 0, plaintext,
                                           plaintext_len, local_out, sizeof(local_out), &out_len);
    if (status != PSA_SUCCESS) {
        return status;
    }

    if (out_len != plaintext_len + TAG_SIZE) {
        return PSA_ERROR_GENERIC_ERROR;
    }

    memcpy(ciphertext, local_out, plaintext_len);
    memcpy(tag, local_out + plaintext_len, TAG_SIZE);
    return PSA_SUCCESS;
}

static psa_status_t decrypt_data(psa_key_id_t enc_key, const uint8_t *iv, const uint8_t *ciphertext,
                                 size_t ciphertext_len, const uint8_t *tag, void *plaintext)
{
    size_t out_len;
    uint8_t local_in[sizeof(magic_internet_key_t) + TAG_SIZE];

    if (ciphertext_len > sizeof(magic_internet_key_t)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    memcpy(local_in, ciphertext, ciphertext_len);
    memcpy(local_in + ciphertext_len, tag, TAG_SIZE);

    return psa_aead_decrypt(enc_key, PSA_ALG_GCM, iv, IV_SIZE, NULL, 0, local_in,
                            ciphertext_len + TAG_SIZE, plaintext, ciphertext_len, &out_len);
}

static psa_status_t load_ps_data(key_storage_data_t *data, bool *exist)
{
    if (!data || !exist) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    psa_status_t st = key_storage_exists(exist);
    if (st != PSA_SUCCESS) {
        return st;
    }

    size_t bytes_read = 0;
    st = psa_ps_get(KEY_STORAGE_UID, 0, sizeof(key_storage_data_t), data, &bytes_read);
    if (st == PSA_SUCCESS && bytes_read == sizeof(key_storage_data_t)) {
        *exist = true;
    } else {
        *exist = false;
    }
    return PSA_SUCCESS;
}

static psa_status_t store_ps_data(const key_storage_data_t *data)
{
    if (!data) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    return psa_ps_set(KEY_STORAGE_UID, sizeof(key_storage_data_t), data, PSA_STORAGE_FLAG_NONE);
}

psa_status_t key_storage_store(const magic_internet_key_t *keys, const char *pin)
{
    if (!keys || !pin) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    psa_status_t status = PSA_ERROR_PROGRAMMER_ERROR;
    key_storage_data_t data;
    memset(&data, 0, sizeof(data));

    status = psa_generate_random(data.salt, SALT_SIZE);
    if (status != PSA_SUCCESS) {
        return status;
    }
    status = psa_generate_random(data.iv, IV_SIZE);
    if (status != PSA_SUCCESS) {
        return status;
    }

    status = nvc_create(KEY_STORAGE_FAIL_COUNT_UID);
    if (status != PSA_SUCCESS) {
        return status;
    }

    psa_key_id_t enc_key;
    status = derive_key_from_pin_and_huk(pin, strlen(pin), data.salt, SALT_SIZE, &enc_key,
                                         PSA_KEY_USAGE_ENCRYPT);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    status = encrypt_data(enc_key, data.iv, keys, sizeof(*keys), data.ciphertext, data.tag);
    psa_destroy_key(enc_key);

    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    status = store_ps_data(&data);

cleanup:
    mbedtls_platform_zeroize(&data, sizeof(data));
    return status;
}

psa_status_t key_storage_load(const char *pin, magic_internet_key_t *keys)
{
    if (!pin || !keys) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    key_storage_data_t data;
    bool exist = false;

    status = load_ps_data(&data, &exist);
    if (status != PSA_SUCCESS) {
        return status;
    }
    if (!exist) {
        return PSA_ERROR_DOES_NOT_EXIST;
    }

    status = nvc_validate(KEY_STORAGE_FAIL_COUNT_UID);
    if (status != PSA_SUCCESS) {
        psa_ps_remove(KEY_STORAGE_UID);
        nvc_destroy(KEY_STORAGE_FAIL_COUNT_UID);
        return status;
    }

    uint32_t fail_count;
    status = nvc_get_value(KEY_STORAGE_FAIL_COUNT_UID, &fail_count);
    if (status != PSA_SUCCESS) {
        return status;
    }

    if (fail_count >= KEY_STORAGE_MAX_FAILS) {
        return PSA_ERROR_NOT_PERMITTED;
    }

    psa_key_id_t enc_key;
    status = derive_key_from_pin_and_huk(pin, strlen(pin), data.salt, SALT_SIZE, &enc_key,
                                         PSA_KEY_USAGE_DECRYPT);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    status =
        decrypt_data(enc_key, data.iv, data.ciphertext, sizeof(data.ciphertext), data.tag, keys);
    psa_destroy_key(enc_key);

    if (status == PSA_SUCCESS) {
        nvc_reset(KEY_STORAGE_FAIL_COUNT_UID);
        goto cleanup;
    }

    if (status != PSA_ERROR_INVALID_SIGNATURE) {
        goto cleanup;
    }

    // Invalid signature
    nvc_increment(KEY_STORAGE_FAIL_COUNT_UID);
    nvc_get_value(KEY_STORAGE_FAIL_COUNT_UID, &fail_count);

    if (fail_count < KEY_STORAGE_MAX_FAILS) {
        goto cleanup;
    }

    // Exceeded max fails.
    psa_ps_remove(KEY_STORAGE_UID);
    nvc_destroy(KEY_STORAGE_FAIL_COUNT_UID);

cleanup:
    mbedtls_platform_zeroize(&data, sizeof(data));
    return status;
}

psa_status_t key_storage_get_fail_count(uint32_t *fail_count)
{
    return nvc_get_value(KEY_STORAGE_FAIL_COUNT_UID, fail_count);
}

psa_status_t key_storage_reset_fail_count(void)
{
    return nvc_reset(KEY_STORAGE_FAIL_COUNT_UID);
}

psa_status_t key_storage_exists(bool *exists)
{
    struct psa_storage_info_t info;
    psa_status_t status = psa_ps_get_info(KEY_STORAGE_UID, &info);
    if (status == PSA_ERROR_DOES_NOT_EXIST) {
        *exists = false;
        return PSA_SUCCESS;
    } else if (status != PSA_SUCCESS) {
        return status;
    }
    *exists = (info.size == sizeof(key_storage_data_t));
    return PSA_SUCCESS;
}

psa_status_t key_storage_wipe(void)
{
    return psa_ps_remove(KEY_STORAGE_UID);
}
