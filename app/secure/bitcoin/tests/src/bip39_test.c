// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "bip39.h"
#include "bip39_test_vectors.h"
#include "shared/test_util.h"
#include <psa/crypto.h>
#include <string.h>

static const uint8_t entropy_128[] = {0x0c, 0x1e, 0x24, 0xe5, 0x91, 0x77, 0x79, 0xd2,
                                      0x97, 0xe1, 0x4d, 0x45, 0xf1, 0x4e, 0x1a, 0x1a};
static const char mnemonic_128[] =
    "army van defense carry jealous true garbage claim echo media make crunch";

static void test_bip39_entropy_to_mnemonic(void)
{
    char mnemonic_out[256] = {0};

    // Test valid entropy
    psa_status_t status = bip39_entropy_to_mnemonic(entropy_128, sizeof(entropy_128), mnemonic_out,
                                                    sizeof(mnemonic_out));
    TEST_ASSERT_EQUAL(status, PSA_SUCCESS);
    TEST_ASSERT_STR_EQUAL(mnemonic_out, mnemonic_128);

    // Test invalid entropy size
    uint8_t invalid_entropy[10] = {0};
    status = bip39_entropy_to_mnemonic(invalid_entropy, sizeof(invalid_entropy), mnemonic_out,
                                       sizeof(mnemonic_out));
    TEST_ASSERT_EQUAL(status, PSA_ERROR_INVALID_ARGUMENT);
}

static void test_bip39_validate_mnemonic(void)
{
    // Test valid mnemonic
    psa_status_t status = bip39_validate_mnemonic(mnemonic_128);
    TEST_ASSERT_EQUAL(status, PSA_SUCCESS);

    // Test invalid mnemonic (word not in wordlist)
    const char *invalid_mnemonic =
        "army van defense carry jealous true garbage claim echo media make invalidword";
    status = bip39_validate_mnemonic(invalid_mnemonic);
    TEST_ASSERT_EQUAL(status, PSA_ERROR_INVALID_ARGUMENT);

    // Test invalid mnemonic (incorrect checksum)
    const char *invalid_checksum_mnemonic =
        "army van defense carry jealous true garbage claim echo media make crunches";
    status = bip39_validate_mnemonic(invalid_checksum_mnemonic);
    TEST_ASSERT_EQUAL(status, PSA_ERROR_INVALID_ARGUMENT);
}

static void test_bip39_test_vectors(void)
{
    char mnemonic_out[256] = {0};
    uint8_t seed[64];
    size_t seed_size;

    for (size_t i = 0; i < BIP39_TEST_VECTOR_COUNT; i++) {
        const bip39_test_vector_t *vector = &bip39_test_vectors[i];

        // Test entropy to mnemonic conversion
        psa_status_t status = bip39_entropy_to_mnemonic(vector->entropy, vector->entropy_size,
                                                        mnemonic_out, sizeof(mnemonic_out));
        TEST_ASSERT_EQUAL(status, PSA_SUCCESS);
        TEST_ASSERT_STR_EQUAL(mnemonic_out, vector->mnemonic);

        // Test mnemonic validation
        status = bip39_validate_mnemonic(vector->mnemonic);
        TEST_ASSERT_EQUAL(status, PSA_SUCCESS);

        // Test mnemonic to seed conversion
        seed_size = sizeof(seed);
        status = bip39_mnemonic_to_seed(vector->mnemonic, "TREZOR", seed, &seed_size);
        TEST_ASSERT_EQUAL(status, PSA_SUCCESS);
        TEST_ASSERT_EQUAL(seed_size, vector->seed_size);
        TEST_ASSERT_ARRAY_EQUAL(seed, vector->seed, vector->seed_size);
    }
}

void bip39_test_run_all(void)
{
    test_bip39_entropy_to_mnemonic();
    test_bip39_validate_mnemonic();
    test_bip39_test_vectors();
}
