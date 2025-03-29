// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "bitcoin/bitcoin_core.h"
#include "bip32.h"
#include "bip39.h"
#include "key_storage.h"
#include "psa/crypto.h"
#include "psa/crypto_values.h"
#include "secp256k1_context.h"
#include <mbedtls/platform_util.h>
#include <secp256k1.h>
#include <secp256k1_preallocated.h>
#include <string.h>

typedef enum {
    WALLET_SESSION_NONE,
    WALLET_SESSION_VERIFYING,
    WALLET_SESSION_CONFIRMING,
    WALLET_SESSION_ACTIVE,
} wallet_session_state_t;

typedef struct {
    uint8_t entropy[32];
    size_t entropy_size;
    char mnemonic[256];
} wallet_verification_context_t;

typedef struct {
    bip32_extended_privkey_t master_key;
} wallet_opened_context_t;

typedef union {
    wallet_verification_context_t verification;
    wallet_opened_context_t opened;
} wallet_session_union_t;

typedef struct {
    wallet_session_state_t state;
    wallet_session_union_t data;
} wallet_session_t;

static wallet_session_t s_wallet;

static void clear_session_data(void)
{
    mbedtls_platform_zeroize(&s_wallet.data, sizeof(s_wallet.data));
    s_wallet.state = WALLET_SESSION_NONE;
}

psa_status_t bitcoin_core_status(void)
{
    bool exists = false;
    psa_status_t status = key_storage_exists(&exists);
    return (status == PSA_SUCCESS && exists) ? PSA_SUCCESS : PSA_ERROR_DOES_NOT_EXIST;
}

psa_status_t bitcoin_core_destroy(const char *pin)
{
    magic_internet_key_t keys;
    psa_status_t status = key_storage_load(pin, &keys);
    if (status != PSA_SUCCESS) {
        return status;
    }
    return key_storage_wipe();
}

psa_status_t bitcoin_core_create(size_t entropy_size)
{
    bool exists = false;
    psa_status_t status = key_storage_exists(&exists);
    if (status != PSA_SUCCESS) {
        return status;
    }
    if (exists) {
        return PSA_ERROR_ALREADY_EXISTS;
    }
    if (s_wallet.state != WALLET_SESSION_NONE) {
        return PSA_ERROR_BAD_STATE;
    }

    wallet_verification_context_t *verification = &s_wallet.data.verification;

    verification->entropy_size = entropy_size;
    status = psa_generate_random(verification->entropy, verification->entropy_size);
    if (status != PSA_SUCCESS) {
        clear_session_data();
        return status;
    }

    memset(verification->mnemonic, 0, sizeof(verification->mnemonic));
    status = bip39_entropy_to_mnemonic(verification->entropy, verification->entropy_size,
                                       verification->mnemonic, sizeof(verification->mnemonic));
    if (status != PSA_SUCCESS) {
        clear_session_data();
        return status;
    }

    s_wallet.state = WALLET_SESSION_VERIFYING;
    return PSA_SUCCESS;
}

psa_status_t bitcoin_core_recover(const char *mnemonic)
{
    bool exists = false;
    psa_status_t status = key_storage_exists(&exists);
    if (status != PSA_SUCCESS) {
        return status;
    }
    if (exists) {
        return PSA_ERROR_ALREADY_EXISTS;
    }
    if (s_wallet.state != WALLET_SESSION_NONE) {
        return PSA_ERROR_BAD_STATE;
    }

    wallet_verification_context_t *verification = &s_wallet.data.verification;

    memset(verification->entropy, 0, sizeof(verification->entropy));
    verification->entropy_size = sizeof(verification->entropy);
    status =
        bip39_mnemonic_to_entropy(mnemonic, verification->entropy, &verification->entropy_size);
    if (status != PSA_SUCCESS) {
        clear_session_data();
        return status;
    }

    memset(verification->mnemonic, 0, sizeof(verification->mnemonic));
    strncpy(verification->mnemonic, mnemonic, sizeof(verification->mnemonic) - 1);

    s_wallet.state = WALLET_SESSION_VERIFYING;
    return PSA_SUCCESS;
}

psa_status_t bitcoin_core_verify(write_string_callback_t write_mnemonic_callback,
                                 void *callback_handle)
{
    if (s_wallet.state != WALLET_SESSION_VERIFYING) {
        return PSA_ERROR_BAD_STATE;
    }

    wallet_verification_context_t *verification = &s_wallet.data.verification;

    if (write_mnemonic_callback) {
        write_mnemonic_callback(callback_handle, verification->mnemonic,
                                sizeof(verification->mnemonic));
    }

    s_wallet.state = WALLET_SESSION_CONFIRMING;
    return PSA_SUCCESS;
}

psa_status_t bitcoin_core_confirm(const char *pin, const char *mnemonic)
{
    if (s_wallet.state != WALLET_SESSION_CONFIRMING) {
        return PSA_ERROR_BAD_STATE;
    }

    wallet_verification_context_t *verification = &s_wallet.data.verification;

    if (strncmp(mnemonic, verification->mnemonic, sizeof(verification->mnemonic)) != 0) {
        clear_session_data();
        return PSA_ERROR_INVALID_SIGNATURE;
    }

    magic_internet_key_t keys = {.version = 1, .entropy_size = verification->entropy_size};
    memcpy(keys.entropy, verification->entropy, verification->entropy_size);

    psa_status_t status = key_storage_store(&keys, pin);

    mbedtls_platform_zeroize(&keys, sizeof(keys));

    if (status != PSA_SUCCESS) {
        clear_session_data();
        return status;
    }

    clear_session_data();
    return PSA_SUCCESS;
}

psa_status_t bitcoin_core_open(const char *pin, const char *passphrase)
{
    if (s_wallet.state != WALLET_SESSION_NONE) {
        return PSA_ERROR_BAD_STATE;
    }

    magic_internet_key_t keys;
    psa_status_t status = key_storage_load(pin, &keys);
    if (status != PSA_SUCCESS) {
        return status;
    }

    char mnemonic[256];
    status = bip39_entropy_to_mnemonic(keys.entropy, keys.entropy_size, mnemonic, sizeof(mnemonic));
    if (status != PSA_SUCCESS) {
        return status;
    }

    uint8_t seed[64];
    size_t seed_size = sizeof(seed);
    status = bip39_mnemonic_to_seed(mnemonic, passphrase, seed, &seed_size);
    mbedtls_platform_zeroize(mnemonic, sizeof(mnemonic));
    if (status != PSA_SUCCESS) {
        return status;
    }

    wallet_opened_context_t *opened = &s_wallet.data.opened;

    status = bip32_seed_to_master_privkey(seed, seed_size, &opened->master_key);
    mbedtls_platform_zeroize(seed, sizeof(seed));
    if (status != PSA_SUCCESS) {
        clear_session_data();
        return status;
    }

    s_wallet.state = WALLET_SESSION_ACTIVE;
    return PSA_SUCCESS;
}

psa_status_t bitcoin_core_close(void)
{
    if (s_wallet.state != WALLET_SESSION_ACTIVE) {
        return PSA_ERROR_BAD_STATE;
    }

    clear_session_data();
    return PSA_SUCCESS;
}

psa_status_t bitcoin_core_get_pubkey(const char *derivation_path, size_t *pubkey_size,
                                     write_buf_callback_t write_pubkey_callback,
                                     write_string_callback_t write_xpub_callback,
                                     void *callback_handle)
{
    if (s_wallet.state != WALLET_SESSION_ACTIVE) {
        return PSA_ERROR_BAD_STATE;
    }

    wallet_opened_context_t *opened = &s_wallet.data.opened;

    bip32_extended_privkey_t derived_key;
    psa_status_t status =
        bip32_extended_privkey_derive_from_path(&opened->master_key, derivation_path, &derived_key);
    if (status != PSA_SUCCESS) {
        return status;
    }

    bip32_extended_pubkey_t pubkey;
    status = bip32_extended_pubkey_from_privkey(&derived_key, &pubkey);
    if (status != PSA_SUCCESS) {
        return status;
    }

    if (write_pubkey_callback) {
        write_pubkey_callback(callback_handle, pubkey.pubkey, sizeof(pubkey.pubkey));
    }

    if (write_xpub_callback) {
        char xpub[BIP32_MAX_SERIALIZED_SIZE];
        size_t xpub_size = sizeof(xpub);
        bip32_extended_pubkey_serialize(&pubkey, xpub, &xpub_size);
        write_xpub_callback(callback_handle, xpub, xpub_size);
    }

    *pubkey_size = sizeof(pubkey.pubkey);
    return PSA_SUCCESS;
}

psa_status_t bitcoin_core_sign_hash(const char *derivation_path,
                                    read_buf_callback_t read_hash_callback, size_t *signature_size,
                                    write_buf_callback_t write_signature_callback,
                                    void *callback_handle)
{
    if (s_wallet.state != WALLET_SESSION_ACTIVE) {
        return PSA_ERROR_BAD_STATE;
    }

    wallet_opened_context_t *opened = &s_wallet.data.opened;

    bip32_extended_privkey_t derived_key;
    psa_status_t status =
        bip32_extended_privkey_derive_from_path(&opened->master_key, derivation_path, &derived_key);
    if (status != PSA_SUCCESS) {
        return status;
    }

    uint8_t hash[32];
    size_t bytes_read = read_hash_callback(callback_handle, hash, sizeof(hash));
    if (bytes_read != sizeof(hash)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    uint8_t context_mem[secp256k1_get_context_size()];
    secp256k1_context *ctx = secp256k1_create_randomized_context(context_mem);
    secp256k1_ecdsa_signature sig;
    if (!secp256k1_ecdsa_sign(ctx, &sig, hash, derived_key.private_key, NULL, NULL)) {
        return PSA_ERROR_GENERIC_ERROR;
    }

    uint8_t der[72];
    if (!secp256k1_ecdsa_signature_serialize_der(ctx, der, signature_size, &sig)) {
        return PSA_ERROR_GENERIC_ERROR;
    }

    write_signature_callback(callback_handle, der, *signature_size);
    return PSA_SUCCESS;
}
