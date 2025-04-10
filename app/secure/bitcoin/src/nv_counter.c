// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "nv_counter.h"
#include "psa/crypto.h"
#include "psa/crypto_values.h"
#include "psa/protected_storage.h"
#include "tfm_crypto_defs.h"

#define NV_COUNTER_SALT_SIZE 16
#define NV_COUNTER_HASH_SIZE 32

typedef struct {
    uint32_t uid;
    uint32_t current_count;
    uint8_t salt[NV_COUNTER_SALT_SIZE];
    uint8_t current_hash[NV_COUNTER_HASH_SIZE];
} nvc_internal_t;

static psa_status_t load_counter(uint32_t uid, nvc_internal_t *counter)
{
    size_t bytes_read;
    psa_status_t status = psa_ps_get(uid, 0, sizeof(*counter), counter, &bytes_read);

    if (status == PSA_SUCCESS && bytes_read == sizeof(*counter)) {
        return PSA_SUCCESS;
    }
    return status;
}

static psa_status_t save_counter(const nvc_internal_t *counter)
{
    return psa_ps_set(counter->uid, sizeof(*counter), counter, PSA_STORAGE_FLAG_NONE);
}

static psa_status_t derive_hmac_key(const nvc_internal_t *counter, psa_key_id_t *hmac_key)
{
    psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_status_t status;

    psa_set_key_type(&attributes, PSA_KEY_TYPE_HMAC);
    psa_set_key_bits(&attributes, 256);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attributes, PSA_ALG_HMAC(PSA_ALG_SHA_256));

    status = psa_key_derivation_setup(&op, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    if (status != PSA_SUCCESS) {
        return status;
    }

    status = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SALT, counter->salt,
                                            NV_COUNTER_SALT_SIZE);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    status =
        psa_key_derivation_input_key(&op, PSA_KEY_DERIVATION_INPUT_SECRET, TFM_BUILTIN_KEY_ID_HUK);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    const char *info = "nv_counter";
    status = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_INFO,
                                            (const uint8_t *)info, strlen(info));
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    status = psa_key_derivation_output_key(&attributes, &op, hmac_key);

cleanup:
    psa_key_derivation_abort(&op);
    return status;
}

static psa_status_t compute_hmac(psa_key_id_t hmac_key, const uint8_t *prev_hash, uint32_t count,
                                 uint8_t *output)
{
    psa_mac_operation_t op = PSA_MAC_OPERATION_INIT;
    size_t mac_length;
    psa_status_t status;

    status = psa_mac_sign_setup(&op, hmac_key, PSA_ALG_HMAC(PSA_ALG_SHA_256));
    if (status != PSA_SUCCESS) {
        return status;
    }

    status = psa_mac_update(&op, prev_hash, NV_COUNTER_HASH_SIZE);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    status = psa_mac_update(&op, (const uint8_t *)&count, sizeof(count));
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    status = psa_mac_sign_finish(&op, output, NV_COUNTER_HASH_SIZE, &mac_length);

cleanup:
    psa_mac_abort(&op);
    return (status == PSA_SUCCESS && mac_length == NV_COUNTER_HASH_SIZE) ? PSA_SUCCESS
                                                                         : PSA_ERROR_GENERIC_ERROR;
}

psa_status_t nvc_create(uint32_t uid)
{
    nvc_internal_t counter = {0};
    counter.uid = uid;
    counter.current_count = 0;

    psa_status_t status = psa_generate_random(counter.salt, NV_COUNTER_SALT_SIZE);
    if (status != PSA_SUCCESS) {
        return status;
    }

    psa_key_id_t hmac_key;
    status = derive_hmac_key(&counter, &hmac_key);
    if (status != PSA_SUCCESS) {
        return status;
    }

    // Initialize hash chain with all zeros
    uint8_t initial_hash[NV_COUNTER_HASH_SIZE] = {0};
    status = compute_hmac(hmac_key, initial_hash, 0, counter.current_hash);
    psa_destroy_key(hmac_key);
    if (status != PSA_SUCCESS) {
        return status;
    }

    return save_counter(&counter);
}

psa_status_t nvc_increment(uint32_t uid)
{
    nvc_internal_t counter;
    psa_status_t status = load_counter(uid, &counter);
    if (status != PSA_SUCCESS) {
        return status;
    }

    psa_key_id_t hmac_key;
    status = derive_hmac_key(&counter, &hmac_key);
    if (status != PSA_SUCCESS) {
        return status;
    }

    uint32_t new_count = counter.current_count + 1;
    uint8_t new_hash[NV_COUNTER_HASH_SIZE];

    status = compute_hmac(hmac_key, counter.current_hash, new_count, new_hash);
    psa_destroy_key(hmac_key);

    if (status != PSA_SUCCESS) {
        return status;
    }

    counter.current_count = new_count;
    memcpy(counter.current_hash, new_hash, NV_COUNTER_HASH_SIZE);
    return save_counter(&counter);
}

psa_status_t nvc_reset(uint32_t uid)
{
    nvc_internal_t counter;
    psa_status_t status = load_counter(uid, &counter);
    if (status != PSA_SUCCESS) {
        return status;
    }

    status = psa_generate_random(counter.salt, NV_COUNTER_SALT_SIZE);
    if (status != PSA_SUCCESS) {
        return status;
    }

    psa_key_id_t hmac_key;
    status = derive_hmac_key(&counter, &hmac_key);
    if (status != PSA_SUCCESS) {
        return status;
    }

    // Reset hash chain
    uint8_t initial_hash[NV_COUNTER_HASH_SIZE] = {0};
    status = compute_hmac(hmac_key, initial_hash, 0, counter.current_hash);
    psa_destroy_key(hmac_key);

    if (status != PSA_SUCCESS) {
        return status;
    }

    counter.current_count = 0;

    return save_counter(&counter);
}

psa_status_t nvc_validate(uint32_t uid)
{
    nvc_internal_t stored;
    psa_status_t status = load_counter(uid, &stored);
    if (status != PSA_SUCCESS) {
        return PSA_ERROR_DOES_NOT_EXIST;
    }

    psa_key_id_t hmac_key;
    status = derive_hmac_key(&stored, &hmac_key);
    if (status != PSA_SUCCESS) {
        return status;
    }

    uint8_t computed_hash[NV_COUNTER_HASH_SIZE];
    uint8_t current_hash[NV_COUNTER_HASH_SIZE] = {0};

    for (uint32_t i = 0; i <= stored.current_count; i++) {
        status = compute_hmac(hmac_key, current_hash, i, computed_hash);
        if (status != PSA_SUCCESS) {
            break;
        }
        memcpy(current_hash, computed_hash, NV_COUNTER_HASH_SIZE);
    }

    psa_destroy_key(hmac_key);
    return (status == PSA_SUCCESS &&
            memcmp(current_hash, stored.current_hash, NV_COUNTER_HASH_SIZE) == 0)
               ? PSA_SUCCESS
               : PSA_ERROR_CORRUPTION_DETECTED;
}

psa_status_t nvc_get_value(uint32_t uid, uint32_t *value)
{
    if (!value) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    nvc_internal_t stored;
    psa_status_t status = load_counter(uid, &stored);
    if (status != PSA_SUCCESS) {
        return status;
    }

    *value = stored.current_count;
    return PSA_SUCCESS;
}

psa_status_t nvc_destroy(uint32_t uid)
{
    return psa_ps_remove(uid);
}
