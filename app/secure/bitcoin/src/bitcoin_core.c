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

static bip32_extended_privkey_t s_master_key;
static bool s_wallet_open = false;

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

psa_status_t bitcoin_core_create(const char *pin)
{
    bool exists = false;
    key_storage_exists(&exists);
    if (exists) {
        return PSA_ERROR_ALREADY_EXISTS;
    }

    uint8_t entropy[32];
    psa_status_t status = psa_generate_random(entropy, sizeof(entropy));
    if (status != PSA_SUCCESS) {
        return status;
    }

    magic_internet_key_t keys = {
        .version = 1,
        .entropy_size = sizeof(entropy),
    };
    memcpy(keys.entropy, entropy, sizeof(entropy));

    status = key_storage_store(&keys, pin);
    mbedtls_platform_zeroize(entropy, sizeof(entropy));
    mbedtls_platform_zeroize(&keys, sizeof(keys));
    return status;
}

psa_status_t bitcoin_core_recover(const char *pin, const char *mnemonic)
{
    bool exists = false;
    key_storage_exists(&exists);
    if (exists) {
        return PSA_ERROR_ALREADY_EXISTS;
    }

    uint8_t entropy[32];
    size_t entropy_size = sizeof(entropy);
    psa_status_t status = bip39_mnemonic_to_entropy(mnemonic, entropy, &entropy_size);
    if (status != PSA_SUCCESS) {
        return status;
    }

    magic_internet_key_t keys = {
        .version = 1,
        .entropy_size = entropy_size,
    };
    memcpy(keys.entropy, entropy, sizeof(entropy));

    status = key_storage_store(&keys, pin);
    mbedtls_platform_zeroize(entropy, sizeof(entropy));
    mbedtls_platform_zeroize(&keys, sizeof(keys));
    return status;
}

psa_status_t bitcoin_core_open(const char *pin, const char *passphrase)
{
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
    if (status != PSA_SUCCESS) {
        return status;
    }

    status = bip32_seed_to_master_privkey(seed, seed_size, &s_master_key);
    mbedtls_platform_zeroize(seed, sizeof(seed));
    if (status != PSA_SUCCESS) {
        return status;
    }

    s_wallet_open = true;
    return PSA_SUCCESS;
}

psa_status_t bitcoin_core_close(void)
{
    if (!s_wallet_open) {
        return PSA_ERROR_BAD_STATE;
    }
    mbedtls_platform_zeroize(&s_master_key, sizeof(s_master_key));
    s_wallet_open = false;
    return PSA_SUCCESS;
}

psa_status_t bitcoin_core_get_pubkey(const char *derivation_path, size_t *pubkey_size,
                                     write_buf_callback_t write_pubkey_callback,
                                     write_string_callback_t write_xpub_callback,
                                     void *callback_handle)
{
    if (!s_wallet_open) {
        return PSA_ERROR_BAD_STATE;
    }

    bip32_extended_privkey_t derived_key;
    psa_status_t status =
        bip32_extended_privkey_derive_from_path(&s_master_key, derivation_path, &derived_key);
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
    if (!s_wallet_open) {
        return PSA_ERROR_BAD_STATE;
    }

    bip32_extended_privkey_t derived_key;
    psa_status_t status =
        bip32_extended_privkey_derive_from_path(&s_master_key, derivation_path, &derived_key);
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
