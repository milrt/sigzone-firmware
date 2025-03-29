// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "bip32.h"
#include "bip32_test_vectors.h"
#include "psa/crypto_types.h"
#include "shared/test_util.h"
#include "tfm_sp_log.h"
#include <string.h>

static void test_valid_vectors(void)
{
    for (size_t i = 0; i < BIP32_TEST_VECTOR_COUNT; i++) {
        const bip32_test_vector_t *vec = &bip32_test_vectors[i];

        // Derive master key
        bip32_extended_privkey_t key;
        TEST_ASSERT_EQUAL(PSA_SUCCESS,
                          bip32_seed_to_master_privkey(vec->seed, vec->seed_size, &key));

        TEST_ASSERT_EQUAL(PSA_SUCCESS,
                          bip32_extended_privkey_derive_from_path(&key, vec->path, &key));

        // Test serialization
        char serialized[BIP32_MAX_SERIALIZED_SIZE];
        size_t serialized_size = sizeof(serialized);
        TEST_ASSERT_EQUAL(PSA_SUCCESS,
                          bip32_extended_privkey_serialize(&key, serialized, &serialized_size));
        TEST_ASSERT_STR_EQUAL(serialized, vec->xprv);

        // Test deserialization
        bip32_extended_privkey_t deserialized;
        TEST_ASSERT_EQUAL(PSA_SUCCESS,
                          bip32_extended_privkey_deserialize(vec->xprv, &deserialized));
        TEST_ASSERT_ARRAY_EQUAL(key.private_key, deserialized.private_key, 32);
        TEST_ASSERT_ARRAY_EQUAL(key.chain_code, deserialized.chain_code, 32);

        // Test privkey to pubkey
        bip32_extended_pubkey_t pubkey;
        TEST_ASSERT_EQUAL(PSA_SUCCESS, bip32_extended_pubkey_from_privkey(&key, &pubkey));

        // Test pubkey serialization
        serialized_size = sizeof(serialized);
        TEST_ASSERT_EQUAL(PSA_SUCCESS,
                          bip32_extended_pubkey_serialize(&pubkey, serialized, &serialized_size));
        TEST_ASSERT_STR_EQUAL(serialized, vec->xpub);

        // Test pubkey deserialization
        bip32_extended_pubkey_t deserialized_pubkey;
        TEST_ASSERT_EQUAL(PSA_SUCCESS,
                          bip32_extended_pubkey_deserialize(vec->xpub, &deserialized_pubkey));
        TEST_ASSERT_ARRAY_EQUAL(pubkey.pubkey, deserialized_pubkey.pubkey, 33);
        TEST_ASSERT_ARRAY_EQUAL(pubkey.chain_code, deserialized_pubkey.chain_code, 32);
    }
}

static void test_invalid_vectors(void)
{
    for (size_t i = 0; i < BIP32_INVALID_TEST_VECTOR_COUNT; i++) {
        const bip32_invalid_test_vector_t *vec = &bip32_invalid_test_vectors[i];

        if (vec->xprv) {
            bip32_extended_privkey_t deserialized;
            psa_status_t status = bip32_extended_privkey_deserialize(vec->xprv, &deserialized);
            if (status == PSA_SUCCESS) {
                LOG_ERRFMT("Test %d failed description: %s\n", i, vec->description);
            }
            TEST_ASSERT_NOT_EQUAL(PSA_SUCCESS, status);
        }

        if (vec->xpub) {
            bip32_extended_pubkey_t deserialized;
            psa_status_t status = bip32_extended_pubkey_deserialize(vec->xpub, &deserialized);
            if (status == PSA_SUCCESS) {
                LOG_ERRFMT("Test %d failed description: %s\n", i, vec->description);
            }
            TEST_ASSERT_NOT_EQUAL(PSA_SUCCESS, status);
        }
    }
}

static void test_key_serialization_roundtrip(void)
{
    const char *test_xprv =
        "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3"
        "TGtRBeJgk33yuGBxrMPHi";

    bip32_extended_privkey_t key;
    // Unit-test: Success
    TEST_ASSERT_EQUAL(PSA_SUCCESS, bip32_extended_privkey_deserialize(test_xprv, &key));

    char serialized[BIP32_MAX_SERIALIZED_SIZE];
    size_t serialized_size = sizeof(serialized);
    // Unit-test: Fails here
    TEST_ASSERT_EQUAL(
        PSA_SUCCESS, bip32_extended_privkey_serialize(&key, serialized, &serialized_size)); // Fails
    // Unit-test: Fails here
    TEST_ASSERT_STR_EQUAL(test_xprv, serialized); // Fails
}

void bip32_test_run_all(void)
{
    test_valid_vectors();
    test_invalid_vectors();
    test_key_serialization_roundtrip();
}
