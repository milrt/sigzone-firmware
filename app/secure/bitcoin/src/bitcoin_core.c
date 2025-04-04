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
    magic_internet_key_t keys = {0};
    psa_status_t status = key_storage_load(pin, &keys);

    mbedtls_platform_zeroize(&keys, sizeof(keys));

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
    verification->mnemonic[sizeof(verification->mnemonic) - 1] = '\0';

    s_wallet.state = WALLET_SESSION_VERIFYING;
    return PSA_SUCCESS;
}

psa_status_t bitcoin_core_verify(char *mnemonic, size_t mnemonic_size)
{
    if (s_wallet.state != WALLET_SESSION_VERIFYING) {
        return PSA_ERROR_BAD_STATE;
    }

    wallet_verification_context_t *verification = &s_wallet.data.verification;
    size_t needed_size = strlen(verification->mnemonic) + 1;

    if (mnemonic_size < needed_size) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    strcpy(mnemonic, verification->mnemonic);

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

    magic_internet_key_t keys = {0};
    psa_status_t status = key_storage_load(pin, &keys);
    if (status != PSA_SUCCESS) {
        mbedtls_platform_zeroize(&keys, sizeof(keys));
        return status;
    }

    char mnemonic[256];
    status = bip39_entropy_to_mnemonic(keys.entropy, keys.entropy_size, mnemonic, sizeof(mnemonic));

    mbedtls_platform_zeroize(&keys, sizeof(keys));

    if (status != PSA_SUCCESS) {
        mbedtls_platform_zeroize(mnemonic, sizeof(mnemonic));
        return status;
    }

    uint8_t seed[64];
    size_t seed_size = sizeof(seed);
    status = bip39_mnemonic_to_seed(mnemonic, passphrase, seed, &seed_size);
    mbedtls_platform_zeroize(mnemonic, sizeof(mnemonic));
    if (status != PSA_SUCCESS) {
        mbedtls_platform_zeroize(seed, sizeof(seed));
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

psa_status_t bitcoin_core_get_pubkey(const char *derivation_path, uint32_t version, uint8_t *pubkey,
                                     size_t *pubkey_size, char *xpub, size_t xpub_size)
{
    if (s_wallet.state != WALLET_SESSION_ACTIVE) {
        return PSA_ERROR_BAD_STATE;
    }

    wallet_opened_context_t *opened = &s_wallet.data.opened;

    bip32_extended_privkey_t derived_key;
    psa_status_t status =
        bip32_extended_privkey_derive_from_path(&opened->master_key, derivation_path, &derived_key);
    if (status != PSA_SUCCESS) {
        mbedtls_platform_zeroize(&derived_key, sizeof(derived_key));
        return status;
    }

    bip32_extended_pubkey_t ext_pubkey;
    status = bip32_extended_pubkey_from_privkey(&derived_key, &ext_pubkey);

    mbedtls_platform_zeroize(&derived_key, sizeof(derived_key));

    if (status != PSA_SUCCESS) {
        mbedtls_platform_zeroize(&ext_pubkey, sizeof(ext_pubkey));
        return status;
    }

    if (*pubkey_size < sizeof(ext_pubkey.pubkey)) {
        mbedtls_platform_zeroize(&ext_pubkey, sizeof(ext_pubkey));
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    memcpy(pubkey, ext_pubkey.pubkey, sizeof(ext_pubkey.pubkey));
    *pubkey_size = sizeof(ext_pubkey.pubkey);

    size_t xpub_serialized_size = xpub_size;
    status = bip32_extended_pubkey_serialize(&ext_pubkey, version, xpub, &xpub_serialized_size);

    mbedtls_platform_zeroize(&ext_pubkey, sizeof(ext_pubkey));

    if (status != PSA_SUCCESS) {
        return status;
    }

    return PSA_SUCCESS;
}

psa_status_t bitcoin_core_sign_hash(const char *derivation_path, const uint8_t *hash,
                                    size_t hash_size, uint8_t *signature, size_t *signature_size)
{
    if (s_wallet.state != WALLET_SESSION_ACTIVE) {
        return PSA_ERROR_BAD_STATE;
    }

    if (hash_size != 32) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    wallet_opened_context_t *opened = &s_wallet.data.opened;

    bip32_extended_privkey_t derived_key;
    psa_status_t status =
        bip32_extended_privkey_derive_from_path(&opened->master_key, derivation_path, &derived_key);
    if (status != PSA_SUCCESS) {
        mbedtls_platform_zeroize(&derived_key, sizeof(derived_key));
        return status;
    }

    uint8_t context_mem[secp256k1_get_context_size()];
    secp256k1_context *ctx = secp256k1_create_randomized_context(context_mem);
    secp256k1_ecdsa_signature sig;

    int res = secp256k1_ecdsa_sign(ctx, &sig, hash, derived_key.private_key, NULL, NULL);

    mbedtls_platform_zeroize(&derived_key, sizeof(derived_key));

    if (!res) {
        secp256k1_context_preallocated_destroy(ctx);
        return PSA_ERROR_GENERIC_ERROR;
    }

    if (!secp256k1_ecdsa_signature_serialize_der(ctx, signature, signature_size, &sig)) {
        secp256k1_context_preallocated_destroy(ctx);
        return PSA_ERROR_GENERIC_ERROR;
    }

    secp256k1_context_preallocated_destroy(ctx);

    return PSA_SUCCESS;
}

psa_status_t bitcoin_core_get_fingerprint(uint8_t *fingerprint, size_t *fingerprint_size)
{
    if (s_wallet.state != WALLET_SESSION_ACTIVE) {
        return PSA_ERROR_BAD_STATE;
    }
    if (*fingerprint_size < 4) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    wallet_opened_context_t *opened = &s_wallet.data.opened;

    bip32_extended_pubkey_t ext_pubkey;
    psa_status_t status = bip32_extended_pubkey_from_privkey(&opened->master_key, &ext_pubkey);
    if (status != PSA_SUCCESS) {
        mbedtls_platform_zeroize(&ext_pubkey, sizeof(ext_pubkey));
        return status;
    }

    status = bip32_extended_pubkey_get_fingerprint(&ext_pubkey, fingerprint);

    mbedtls_platform_zeroize(&ext_pubkey, sizeof(ext_pubkey));

    if (status != PSA_SUCCESS) {
        return status;
    }

    *fingerprint_size = 4;
    return PSA_SUCCESS;
}
