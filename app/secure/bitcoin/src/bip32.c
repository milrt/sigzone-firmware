// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "bip32.h"
#include "base58.h"
#include "secp256k1_context.h"
#include "shared/hash.h"
#include "utils.h"
#include <mbedtls/platform_util.h>
#include <secp256k1.h>
#include <secp256k1_preallocated.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#define BIP32_SERIALIZED_SIZE 78

// Hardened child index bit
#define BIP32_HARDENED 0x80000000

static psa_status_t privkey_to_pubkey(const uint8_t *privkey, uint8_t *out_pubkey33)
{
    uint8_t ctx_mem[secp256k1_get_context_size()];
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    secp256k1_context *ctx = secp256k1_create_randomized_context(ctx_mem);
    if (!ctx) {
        goto cleanup;
    }

    secp256k1_pubkey pub;
    if (!secp256k1_ec_pubkey_create(ctx, &pub, privkey)) {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto cleanup;
    }

    size_t pub_len = 33;
    if (!secp256k1_ec_pubkey_serialize(ctx, out_pubkey33, &pub_len, &pub,
                                       SECP256K1_EC_COMPRESSED)) {
        status = PSA_ERROR_GENERIC_ERROR;
        goto cleanup;
    }

    status = PSA_SUCCESS;

cleanup:
    if (ctx) {
        secp256k1_context_preallocated_destroy(ctx);
    }
    mbedtls_platform_zeroize(ctx_mem, sizeof(ctx_mem));
    return status;
}

static psa_status_t get_fingerprint(const uint8_t *pubkey, uint8_t fingerprint[4])
{
    if (!pubkey || !fingerprint) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    psa_status_t status;
    uint8_t sha256[32] = {0};
    uint8_t ripemd160[20] = {0};

    // Step 1: SHA256(pubkey)
    status = hash_sha256(pubkey, 33, sha256, sizeof(sha256));
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    // Step 2: RIPEMD160(SHA256(pubkey))
    status = hash_ripemd160(sha256, sizeof(sha256), ripemd160, sizeof(ripemd160));
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    // Step 3: First 4 bytes = fingerprint
    memcpy(fingerprint, ripemd160, 4);

cleanup:
    mbedtls_platform_zeroize(sha256, sizeof(sha256));
    mbedtls_platform_zeroize(ripemd160, sizeof(ripemd160));
    return status;
}

static psa_status_t get_fingerprint_from_privkey(const uint8_t *privkey, uint8_t fingerprint[4])
{
    if (!privkey || !fingerprint) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    psa_status_t status;
    uint8_t pubkey[33] = {0};

    status = privkey_to_pubkey(privkey, pubkey);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    status = get_fingerprint(pubkey, fingerprint);

cleanup:
    mbedtls_platform_zeroize(pubkey, sizeof(pubkey));
    return status;
}

psa_status_t bip32_seed_to_master_privkey(const uint8_t *seed, size_t seed_size,
                                          bip32_extended_privkey_t *master_key)
{
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    uint8_t hmac[64] = {0};
    uint8_t ctx_mem[secp256k1_get_context_size()];
    secp256k1_context *ctx = NULL;

    if (!seed || seed_size < 16 || seed_size > 64 || !master_key) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    // 1) HMAC-SHA512("Bitcoin seed", seed)
    const char *key = "Bitcoin seed";
    status =
        hash_hmac_sha512((const uint8_t *)key, strlen(key), seed, seed_size, hmac, sizeof(hmac));
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    // 2) Check whether the first 32 bytes is a valid secp256k1 private key
    ctx = secp256k1_create_randomized_context(ctx_mem);
    if (!ctx) {
        status = PSA_ERROR_GENERIC_ERROR;
        goto cleanup;
    }

    if (!secp256k1_ec_seckey_verify(ctx, hmac)) {
        // invalid private key
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto cleanup;
    }

    // 3) Fill out the structure
    memcpy(master_key->private_key, hmac, 32);
    memcpy(master_key->chain_code, hmac + 32, 32);
    master_key->depth = 0;
    master_key->child_number = 0;
    memset(master_key->parent_fingerprint, 0, BIP32_FINGERPRINT_SIZE);

    status = PSA_SUCCESS;

cleanup:
    if (ctx) {
        secp256k1_context_preallocated_destroy(ctx);
    }
    mbedtls_platform_zeroize(ctx_mem, sizeof(ctx_mem));
    mbedtls_platform_zeroize(hmac, sizeof(hmac));
    return status;
}

static psa_status_t derive_child_privkey(const bip32_extended_privkey_t *parent_key,
                                         uint32_t child_index, bip32_extended_privkey_t *child_key)
{
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    bool hardened = (child_index & BIP32_HARDENED) != 0;

    uint8_t data[37] = {0};
    uint8_t hmac[64] = {0};
    uint8_t ctx_mem[secp256k1_get_context_size()];
    secp256k1_context *ctx = NULL;
    uint8_t parent_pubkey[33] = {0};
    uint8_t tweak[32] = {0};
    uint8_t child_privkey[32] = {0};

    if (!parent_key || !child_key) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    // 1) Construct data for HMAC: either [0x00 + parent_privkey] (hardened)
    //    or [parent_pubkey] (non-hardened), plus child_index (big-endian).
    if (hardened) {
        data[0] = 0x00;
        memcpy(&data[1], parent_key->private_key, 32);
    } else {
        status = privkey_to_pubkey(parent_key->private_key, parent_pubkey);
        if (status != PSA_SUCCESS) {
            goto cleanup;
        }
        memcpy(data, parent_pubkey, 33);
    }
    // Append child index
    data[33] = (child_index >> 24) & 0xFF;
    data[34] = (child_index >> 16) & 0xFF;
    data[35] = (child_index >> 8) & 0xFF;
    data[36] = (child_index) & 0xFF;

    // 2) HMAC-SHA512(chain_code, data)
    status = hash_hmac_sha512(parent_key->chain_code, 32, data, sizeof(data), hmac, sizeof(hmac));
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    // 3) Tweak-add the left 32 bytes to the parent private key
    ctx = secp256k1_create_randomized_context(ctx_mem);
    if (!ctx) {
        status = PSA_ERROR_GENERIC_ERROR;
        goto cleanup;
    }

    memcpy(tweak, hmac, 32);
    memcpy(child_privkey, parent_key->private_key, 32);

    if (!secp256k1_ec_seckey_tweak_add(ctx, child_privkey, tweak)) {
        // means invalid or overflow
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto cleanup;
    }

    // Check if valid
    if (!secp256k1_ec_seckey_verify(ctx, child_privkey)) {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto cleanup;
    }

    // 4) Fill out child structure
    memcpy(child_key->private_key, child_privkey, 32);
    memcpy(child_key->chain_code, hmac + 32, 32);
    child_key->depth = parent_key->depth + 1;
    child_key->child_number = child_index;

    // The parent's fingerprint
    status = get_fingerprint_from_privkey(parent_key->private_key, child_key->parent_fingerprint);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    status = PSA_SUCCESS;

cleanup:
    if (ctx) {
        secp256k1_context_preallocated_destroy(ctx);
    }
    mbedtls_platform_zeroize(ctx_mem, sizeof(ctx_mem));
    mbedtls_platform_zeroize(data, sizeof(data));
    mbedtls_platform_zeroize(hmac, sizeof(hmac));
    mbedtls_platform_zeroize(parent_pubkey, sizeof(parent_pubkey));
    mbedtls_platform_zeroize(tweak, sizeof(tweak));
    mbedtls_platform_zeroize(child_privkey, sizeof(child_privkey));
    return status;
}

static psa_status_t derive_path_privkey(const bip32_extended_privkey_t *master_key,
                                        const uint32_t *path, size_t path_length,
                                        bip32_extended_privkey_t *derived_key)
{
    bip32_extended_privkey_t current = *master_key;
    psa_status_t status = PSA_SUCCESS;

    for (size_t i = 0; i < path_length; i++) {
        status = derive_child_privkey(&current, path[i], derived_key);
        if (status != PSA_SUCCESS) {
            break;
        }
        current = *derived_key; // carry forward
    }

    return status;
}

psa_status_t bip32_extended_privkey_derive_from_path(const bip32_extended_privkey_t *master_key,
                                                     const char *path_str,
                                                     bip32_extended_privkey_t *derived_key)
{
    if (!master_key || !path_str || !derived_key) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    char path_copy[BIP32_MAX_PATH_LENGTH];
    uint32_t indices[BIP32_MAX_DEPTH];
    size_t depth = 0;
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;

    // 1) Copy path_str to local buffer for parsing
    size_t path_len = strlen(path_str);
    if (path_len >= sizeof(path_copy)) {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto cleanup;
    }
    strcpy(path_copy, path_str);

    // 2) Check if "m" or "m/..."
    if (strncmp(path_copy, "m/", 2) != 0) {
        if (strcmp(path_copy, "m") == 0) {
            // Just the master
            *derived_key = *master_key;
            status = PSA_SUCCESS;
            goto cleanup;
        }
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto cleanup;
    }

    // 3) Tokenize path components after "m/"
    char *saveptr = NULL;
    char *token = get_token(path_copy + 2, "/", &saveptr);
    while (token && depth < BIP32_MAX_DEPTH) {
        int hardened = 0;
        size_t token_len = strlen(token);
        if (token_len == 0) {
            status = PSA_ERROR_INVALID_ARGUMENT;
            goto cleanup;
        }

        // Check for hardened marker
        char last_char = token[token_len - 1];
        if (last_char == '\'' || last_char == 'h' || last_char == 'H') {
            hardened = 1;
            token[token_len - 1] = '\0';
        }

        // Parse index
        char *endptr = NULL;
        unsigned long val = strtoul(token, &endptr, 10);
        if (*endptr != '\0' || val > 0x7FFFFFFF) {
            status = PSA_ERROR_INVALID_ARGUMENT;
            goto cleanup;
        }

        indices[depth++] = (uint32_t)val | (hardened ? BIP32_HARDENED : 0);
        token = get_token(NULL, "/", &saveptr);
    }

    if (token != NULL) {
        // Path too long
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto cleanup;
    }

    // 4) Derive
    status = derive_path_privkey(master_key, indices, depth, derived_key);

cleanup:
    mbedtls_platform_zeroize(path_copy, sizeof(path_copy));
    mbedtls_platform_zeroize(indices, sizeof(indices));
    return status;
}

psa_status_t bip32_extended_privkey_serialize(const bip32_extended_privkey_t *key, uint32_t version,
                                              char *output, size_t *output_size)
{
    if (!key || !output || !output_size || *output_size < BIP32_MAX_SERIALIZED_SIZE) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    // We will build a buffer of 78 bytes + 4 bytes checksum = 82 total.
    uint8_t data[BIP32_SERIALIZED_SIZE + 4] = {0};
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;

    // 1) 4-byte version
    data[0] = (version >> 24) & 0xFF;
    data[1] = (version >> 16) & 0xFF;
    data[2] = (version >> 8) & 0xFF;
    data[3] = (version) & 0xFF;

    // 2) depth
    data[4] = key->depth;

    // 3) parent fingerprint
    memcpy(&data[5], key->parent_fingerprint, 4);

    // 4) child number
    data[9] = (key->child_number >> 24) & 0xFF;
    data[10] = (key->child_number >> 16) & 0xFF;
    data[11] = (key->child_number >> 8) & 0xFF;
    data[12] = (key->child_number) & 0xFF;

    // 5) chain code
    memcpy(&data[13], key->chain_code, 32);

    // 6) 0x00 + private_key
    data[45] = 0x00;
    memcpy(&data[46], key->private_key, 32);

    // 7) Base58 encode with check.
    status = base58_check_encode(data, BIP32_SERIALIZED_SIZE, output, *output_size);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    *output_size = strlen(output) + 1;

    status = PSA_SUCCESS;

cleanup:
    mbedtls_platform_zeroize(data, sizeof(data));
    return status;
}

psa_status_t bip32_extended_privkey_deserialize(const char *input, uint32_t expected_version,
                                                bip32_extended_privkey_t *key)
{
    if (!input || !key) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    uint8_t data[BIP32_SERIALIZED_SIZE + 4] = {0};
    size_t data_len = sizeof(data); // 82
    psa_status_t status;

    // 1) Base58 decode with check.
    status = base58_check_decode(input, data, &data_len);
    if (status != PSA_SUCCESS) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (data_len != BIP32_SERIALIZED_SIZE) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    // Parse version
    uint32_t ver = ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) |
                   ((uint32_t)data[2] << 8) | (uint32_t)data[3];

    if (ver != expected_version) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    // depth
    key->depth = data[4];

    // parent fingerprint
    memcpy(key->parent_fingerprint, &data[5], 4);

    // child number
    key->child_number = ((uint32_t)data[9] << 24) | ((uint32_t)data[10] << 16) |
                        ((uint32_t)data[11] << 8) | ((uint32_t)data[12]);

    if (key->depth == 0) {
        uint8_t zero_fpr[4] = {0};
        if (memcmp(&data[5], zero_fpr, 4) != 0 || key->child_number != 0) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
    }

    // chain code
    memcpy(key->chain_code, &data[13], 32);

    // check the marker
    if (data[45] != 0x00) {
        return PSA_ERROR_INVALID_ARGUMENT; // indicates not a private key
    }
    memcpy(key->private_key, &data[46], 32);

    // Validate private key
    uint8_t ctx_mem[secp256k1_get_context_size()];
    secp256k1_context *ctx = secp256k1_create_randomized_context(ctx_mem);
    if (!ctx) {
        return PSA_ERROR_GENERIC_ERROR;
    }
    bool valid = secp256k1_ec_seckey_verify(ctx, key->private_key);
    secp256k1_context_preallocated_destroy(ctx);
    mbedtls_platform_zeroize(ctx_mem, sizeof(ctx_mem));

    return valid ? PSA_SUCCESS : PSA_ERROR_INVALID_ARGUMENT;
}

psa_status_t bip32_extended_pubkey_from_privkey(const bip32_extended_privkey_t *privkey,
                                                bip32_extended_pubkey_t *out_pubkey)
{
    if (!privkey || !out_pubkey) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    psa_status_t status = privkey_to_pubkey(privkey->private_key, out_pubkey->pubkey);
    if (status != PSA_SUCCESS) {
        return status;
    }

    // Copy common fields
    memcpy(out_pubkey->chain_code, privkey->chain_code, 32);
    out_pubkey->depth = privkey->depth;
    out_pubkey->child_number = privkey->child_number;
    memcpy(out_pubkey->parent_fingerprint, privkey->parent_fingerprint, BIP32_FINGERPRINT_SIZE);

    return PSA_SUCCESS;
}

psa_status_t bip32_extended_pubkey_serialize(const bip32_extended_pubkey_t *key, uint32_t version,
                                             char *output, size_t *output_size)
{
    if (!key || !output || !output_size || *output_size < BIP32_MAX_SERIALIZED_SIZE) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    uint8_t data[BIP32_SERIALIZED_SIZE + 4] = {0};

    // 1) 4-byte version
    data[0] = (version >> 24) & 0xFF;
    data[1] = (version >> 16) & 0xFF;
    data[2] = (version >> 8) & 0xFF;
    data[3] = (version) & 0xFF;

    // 2) depth
    data[4] = key->depth;

    // 3) parent fingerprint
    memcpy(&data[5], key->parent_fingerprint, 4);

    // 4) child number
    data[9] = (key->child_number >> 24) & 0xFF;
    data[10] = (key->child_number >> 16) & 0xFF;
    data[11] = (key->child_number >> 8) & 0xFF;
    data[12] = (key->child_number) & 0xFF;

    // 5) chain code
    memcpy(&data[13], key->chain_code, 32);

    // 6) pubkey (33 bytes)
    memcpy(&data[45], key->pubkey, 33);

    // 7) Base58 encode with check.
    status = base58_check_encode(data, BIP32_SERIALIZED_SIZE, output, *output_size);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }
    *output_size = strlen(output) + 1;
    status = PSA_SUCCESS;

cleanup:
    mbedtls_platform_zeroize(data, sizeof(data));
    return status;
}

psa_status_t bip32_extended_pubkey_deserialize(const char *input, uint32_t expected_version,
                                               bip32_extended_pubkey_t *key)
{
    if (!input || !key) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    uint8_t data[BIP32_SERIALIZED_SIZE + 4] = {0};
    size_t data_len = sizeof(data);

    // 1) Base58 decode with check.
    status = base58_check_decode(input, data, &data_len);
    if (status != PSA_SUCCESS) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (data_len != BIP32_SERIALIZED_SIZE) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    // Parse version
    uint32_t ver = ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) |
                   ((uint32_t)data[2] << 8) | (uint32_t)data[3];
    if (ver != expected_version) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    // depth
    key->depth = data[4];

    // parent fingerprint
    memcpy(key->parent_fingerprint, &data[5], 4);

    // child number
    key->child_number = ((uint32_t)data[9] << 24) | ((uint32_t)data[10] << 16) |
                        ((uint32_t)data[11] << 8) | ((uint32_t)data[12]);

    if (key->depth == 0) {
        uint8_t zero_fpr[4] = {0};
        if (memcmp(&data[5], zero_fpr, 4) != 0 || key->child_number != 0) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
    }

    // chain code
    memcpy(key->chain_code, &data[13], 32);

    // pubkey (33 bytes)
    memcpy(key->pubkey, &data[45], 33);

    // (Optional) we could validate that the pubkey is a valid secp256k1 public key
    {
        uint8_t ctx_mem[secp256k1_get_context_size()];
        secp256k1_context *ctx = secp256k1_create_randomized_context(ctx_mem);
        if (!ctx) {
            status = PSA_ERROR_GENERIC_ERROR;
            goto cleanup;
        }

        secp256k1_pubkey pub;
        if (!secp256k1_ec_pubkey_parse(ctx, &pub, key->pubkey, 33)) {
            // invalid pubkey
            secp256k1_context_preallocated_destroy(ctx);
            mbedtls_platform_zeroize(ctx_mem, sizeof(ctx_mem));
            status = PSA_ERROR_INVALID_ARGUMENT;
            goto cleanup;
        }

        secp256k1_context_preallocated_destroy(ctx);
        mbedtls_platform_zeroize(ctx_mem, sizeof(ctx_mem));
    }

    status = PSA_SUCCESS;

cleanup:
    mbedtls_platform_zeroize(data, sizeof(data));
    return status;
}

psa_status_t bip32_extended_pubkey_get_fingerprint(const bip32_extended_pubkey_t *key,
                                                   uint8_t *fingerprint)
{
    if (!key || !fingerprint) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    psa_status_t status = get_fingerprint(key->pubkey, fingerprint);
    if (status != PSA_SUCCESS) {
        return status;
    }

    return PSA_SUCCESS;
}
