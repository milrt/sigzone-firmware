// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "key_storage.h"
#include "psa/crypto.h"
#include "psa/crypto_types.h"
#include "psa/crypto_values.h"
#include "psa/error.h"
#include "shared/hash.h"
#include <mbedtls/gcm.h>
#include <mbedtls/platform_util.h>
#include <psa/internal_trusted_storage.h>
#include <psa/storage_common.h>
#include <stdbool.h>
#include <string.h>

#define KEY_STORAGE_ITS_UID (0x10010010UL)
#define KEY_STORAGE_MAX_FAILS (10)

#define PBKDF2_ITERATIONS (10000)
#define PBKDF2_KEY_SIZE (32)
#define SALT_SIZE (16)
#define IV_SIZE (12)
#define TAG_SIZE (16)

typedef struct {
    uint8_t salt[SALT_SIZE];
    uint8_t iv[IV_SIZE];
    uint8_t tag[TAG_SIZE];
    uint8_t ciphertext[sizeof(magic_internet_key_t)];
    uint32_t fail_count; // TODO: must be tamperevident
} key_storage_data_t;

static psa_status_t derive_key_from_pin(const char *pin, size_t pin_len, const uint8_t *salt,
                                        size_t salt_len, uint8_t derived_key[PBKDF2_KEY_SIZE])
{
    if (!pin || !salt || !derived_key) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    uint8_t tmp[64];
    memset(tmp, 0, sizeof(tmp));

    psa_status_t status = hash_pbkdf2_hmac_sha512((const uint8_t *)pin, pin_len, salt, salt_len,
                                                  PBKDF2_ITERATIONS, tmp, sizeof(tmp));
    if (status != PSA_SUCCESS) {
        mbedtls_platform_zeroize(tmp, sizeof(tmp));
        return status;
    }

    memcpy(derived_key, tmp, PBKDF2_KEY_SIZE);

    mbedtls_platform_zeroize(tmp, sizeof(tmp));
    return PSA_SUCCESS;
}

static psa_status_t encrypt_data(const uint8_t *derived_key, const uint8_t *iv,
                                 const void *plaintext, size_t plaintext_len, uint8_t *ciphertext,
                                 uint8_t *tag)
{
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id = 0;
    size_t out_len = 0;

    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attributes, 256);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attributes, PSA_ALG_GCM);

    status = psa_import_key(&attributes, derived_key, PBKDF2_KEY_SIZE, &key_id);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    // We will receive ciphertext + tag in a single buffer from psa_aead_encrypt
    // and then split them into separate buffers (ciphertext, tag).
    uint8_t local_out[sizeof(magic_internet_key_t) + TAG_SIZE];
    if (plaintext_len + TAG_SIZE > sizeof(local_out)) {
        status = PSA_ERROR_BUFFER_TOO_SMALL;
        goto cleanup;
    }

    status = psa_aead_encrypt(key_id, PSA_ALG_GCM, iv, IV_SIZE, NULL, 0, plaintext, plaintext_len,
                              local_out, sizeof(local_out), &out_len);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    // The result (ciphertext||tag) should be plaintext_len + TAG_SIZE bytes
    if (out_len != plaintext_len + TAG_SIZE) {
        status = PSA_ERROR_GENERIC_ERROR;
        goto cleanup;
    }

    // Split out the ciphertext and tag
    memcpy(ciphertext, local_out, plaintext_len);
    memcpy(tag, local_out + plaintext_len, TAG_SIZE);

cleanup:
    psa_destroy_key(key_id);
    mbedtls_platform_zeroize((void *)local_out, sizeof(local_out));
    return status;
}

static psa_status_t decrypt_data(const uint8_t *derived_key, const uint8_t *iv,
                                 const uint8_t *ciphertext, size_t ciphertext_len,
                                 const uint8_t *tag, void *plaintext)
{
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id = 0;
    size_t out_len = 0;
    uint8_t local_in[sizeof(magic_internet_key_t) + TAG_SIZE];

    if (ciphertext_len > sizeof(magic_internet_key_t)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attributes, 256);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attributes, PSA_ALG_GCM);

    status = psa_import_key(&attributes, derived_key, PBKDF2_KEY_SIZE, &key_id);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    // We'll combine (ciphertext + tag) into a single buffer for psa_aead_decrypt.
    if (ciphertext_len + TAG_SIZE > sizeof(local_in)) {
        status = PSA_ERROR_BUFFER_TOO_SMALL;
        goto cleanup;
    }

    memcpy(local_in, ciphertext, ciphertext_len);
    memcpy(local_in + ciphertext_len, tag, TAG_SIZE);

    status = psa_aead_decrypt(key_id, PSA_ALG_GCM, iv, IV_SIZE, NULL, 0, local_in, sizeof(local_in),
                              plaintext, ciphertext_len, &out_len);
    if (status == PSA_SUCCESS) {
        if (out_len != ciphertext_len) {
            status = PSA_ERROR_GENERIC_ERROR;
        }
    }
    // If status == PSA_ERROR_INVALID_SIGNATURE -> "invalid tag" (i.e., wrong PIN)

cleanup:
    psa_destroy_key(key_id);
    return status;
}

static psa_status_t load_its_data(key_storage_data_t *data, bool *exist)
{
    if (!data || !exist) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    psa_status_t st = key_storage_exists(exist);
    if (st != PSA_SUCCESS) {
        return st;
    }

    size_t bytes_read = 0;
    st = psa_its_get(KEY_STORAGE_ITS_UID, 0, sizeof(key_storage_data_t), data, &bytes_read);
    if (st == PSA_SUCCESS && bytes_read == sizeof(key_storage_data_t)) {
        *exist = true;
    } else {
        *exist = false;
    }
    return PSA_SUCCESS;
}

static psa_status_t store_its_data(const key_storage_data_t *data)
{
    if (!data) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    return psa_its_set(KEY_STORAGE_ITS_UID, sizeof(key_storage_data_t), data,
                       PSA_STORAGE_FLAG_NONE);
}

static psa_status_t wipe_its_data(void)
{
    return psa_its_remove(KEY_STORAGE_ITS_UID);
}

psa_status_t key_storage_store(const magic_internet_key_t *keys, const char *pin)
{
    if (!keys || !pin) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    psa_status_t status = PSA_ERROR_PROGRAMMER_ERROR;
    key_storage_data_t data;
    memset(&data, 0, sizeof(data));

    // 1) Generate salt + IV
    status = psa_generate_random(data.salt, SALT_SIZE);
    if (status != PSA_SUCCESS) {
        return status;
    }
    status = psa_generate_random(data.iv, IV_SIZE);
    if (status != PSA_SUCCESS) {
        return status;
    }

    // 2) Derive key from PIN
    uint8_t derived_key[PBKDF2_KEY_SIZE];
    memset(derived_key, 0, sizeof(derived_key));

    size_t pin_len = strlen(pin);
    status = derive_key_from_pin(pin, pin_len, data.salt, SALT_SIZE, derived_key);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    // 3) Encrypt the keys structure
    status = encrypt_data(derived_key, data.iv, keys, sizeof(*keys), data.ciphertext, data.tag);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    // 4) Reset fail_count
    data.fail_count = 0;

    // 5) Store in ITS
    status = store_its_data(&data);

cleanup:
    mbedtls_platform_zeroize(derived_key, sizeof(derived_key));
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

    // 1) Load from ITS
    status = load_its_data(&data, &exist);
    if (status != PSA_SUCCESS) {
        return status;
    }
    if (!exist) {
        return PSA_ERROR_DOES_NOT_EXIST; // no keys stored
    }

    // 2) If fail_count >= KEY_STORAGE_MAX_FAILS, locked
    if (data.fail_count >= KEY_STORAGE_MAX_FAILS) {
        return PSA_ERROR_NOT_PERMITTED;
    }

    // 3) Derive key from PIN
    uint8_t derived_key[PBKDF2_KEY_SIZE];
    memset(derived_key, 0, sizeof(derived_key));
    size_t pin_len = strlen(pin);

    status = derive_key_from_pin(pin, pin_len, data.salt, SALT_SIZE, derived_key);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    // 4) Decrypt
    status = decrypt_data(derived_key, data.iv, data.ciphertext, sizeof(data.ciphertext), data.tag,
                          keys);
    if (status == PSA_SUCCESS) {
        // Good PIN => reset fail_count
        data.fail_count = 0;
        psa_status_t st2 = store_its_data(&data);
        (void)st2; // best effort
    } else if (status == PSA_ERROR_INVALID_SIGNATURE) {
        // Wrong PIN => increment fail_count
        data.fail_count++;
        if (data.fail_count >= KEY_STORAGE_MAX_FAILS) {
            // Wipe data
            psa_status_t st2 = wipe_its_data();
            (void)st2;
        } else {
            // Save updated fail_count
            psa_status_t st2 = store_its_data(&data);
            (void)st2;
        }
    }

cleanup:
    mbedtls_platform_zeroize(derived_key, sizeof(derived_key));
    mbedtls_platform_zeroize(&data, sizeof(data));
    return status;
}

psa_status_t key_storage_get_fail_count(uint32_t *fail_count)
{
    if (!fail_count) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    key_storage_data_t data;
    bool exist = false;
    psa_status_t st = load_its_data(&data, &exist);
    if (st != PSA_SUCCESS) {
        return st;
    }
    if (!exist) {
        *fail_count = 0; // no data => no fails
        return PSA_SUCCESS;
    }
    *fail_count = data.fail_count;
    return PSA_SUCCESS;
}

psa_status_t key_storage_reset_fail_count(void)
{
    key_storage_data_t data;
    bool exist = false;
    psa_status_t st = load_its_data(&data, &exist);
    if (st != PSA_SUCCESS) {
        return st;
    }
    if (!exist) {
        return PSA_ERROR_DOES_NOT_EXIST;
    }

    data.fail_count = 0;
    return store_its_data(&data);
}

psa_status_t key_storage_exists(bool *exists)
{
    struct psa_storage_info_t info;
    psa_status_t status = psa_its_get_info(KEY_STORAGE_ITS_UID, &info);
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
    return psa_its_remove(KEY_STORAGE_ITS_UID);
}
