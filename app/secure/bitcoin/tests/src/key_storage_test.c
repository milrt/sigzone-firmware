// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "key_storage_test.h"
#include "key_storage.h"
#include "psa/crypto_types.h"
#include "shared/test_util.h"
#include <string.h>

static magic_internet_key_t make_sample_keys(uint32_t version, const uint8_t *entropy,
                                             size_t entropy_len)
{
    magic_internet_key_t keys;
    memset(&keys, 0, sizeof(keys));
    keys.version = version;
    keys.entropy_size = entropy_len;
    if (entropy_len > sizeof(keys.entropy)) {
        entropy_len = sizeof(keys.entropy);
    }
    memcpy(keys.entropy, entropy, entropy_len);
    return keys;
}

static void test_store_load_correct_pin(void)
{
    const uint8_t sample_entropy[32] = {
        0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE,
        0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD,
        0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
    };
    magic_internet_key_t keys_out = make_sample_keys(42, sample_entropy, 32);

    // Store them with a known PIN
    const char *pin = "123456";
    psa_status_t st = key_storage_store(&keys_out, pin);
    TEST_ASSERT_EQUAL(PSA_SUCCESS, st);
    TEST_ASSERT_EQUAL(PSA_SUCCESS, st);

    // Now load them back with correct pin
    magic_internet_key_t loaded;
    memset(&loaded, 0, sizeof(loaded));
    st = key_storage_load(pin, &loaded);
    TEST_ASSERT_EQUAL(PSA_SUCCESS, st);
    TEST_ASSERT_EQUAL(42, loaded.version);
    TEST_ASSERT_EQUAL(32, loaded.entropy_size);
    TEST_ASSERT_ARRAY_EQUAL(keys_out.entropy, loaded.entropy, 32);

    // Check fail_count remains 0
    uint32_t fails = 999;
    st = key_storage_get_fail_count(&fails);
    TEST_ASSERT_EQUAL(PSA_SUCCESS, st);
    TEST_ASSERT_EQUAL(0, fails);
}

static void test_load_wrong_pin(void)
{
    const char *correct_pin = "123456";
    const char *wrong_pin = "000000";

    // Make sure we can still load with correct pin
    magic_internet_key_t loaded;
    memset(&loaded, 0, sizeof(loaded));
    psa_status_t st = key_storage_load(correct_pin, &loaded);
    TEST_ASSERT_EQUAL(PSA_SUCCESS, st);

    // Now load with wrong pin => expect PSA_ERROR_INVALID_SIGNATURE
    memset(&loaded, 0, sizeof(loaded));
    st = key_storage_load(wrong_pin, &loaded);
    TEST_ASSERT_EQUAL(PSA_ERROR_INVALID_SIGNATURE, st);

    // Verify fail_count == 1
    uint32_t fails = 999;
    st = key_storage_get_fail_count(&fails);
    TEST_ASSERT_EQUAL(PSA_SUCCESS, st);
    TEST_ASSERT_EQUAL(1, fails);

    // Use correct pin again => should succeed + reset fail_count
    memset(&loaded, 0, sizeof(loaded));
    st = key_storage_load(correct_pin, &loaded);
    TEST_ASSERT_EQUAL(PSA_SUCCESS, st);

    // fail_count should be 0 again
    fails = 999;
    st = key_storage_get_fail_count(&fails);
    TEST_ASSERT_EQUAL(PSA_SUCCESS, st);
    TEST_ASSERT_EQUAL(0, fails);
}

/**
 * Test scenario: exceed fail_count => data wiped => subsequent load => not exist
 */
static void test_fail_count_wipe(void)
{
    // We'll store a new set of keys so we don't break other tests
    const uint8_t data[32] = {0xAA, 0xBB, 0xCC};
    magic_internet_key_t keys_out = make_sample_keys(777, data, 32);
    const char *pin = "mypin";
    psa_status_t st = key_storage_store(&keys_out, pin);
    TEST_ASSERT_EQUAL(PSA_SUCCESS, st);

    // We'll intentionally fail multiple times
    const uint32_t MAX_FAILS = 10;
    for (uint32_t i = 0; i < MAX_FAILS; i++) {
        magic_internet_key_t loaded;
        memset(&loaded, 0, sizeof(loaded));
        // wrong pin => fail
        st = key_storage_load("wrong", &loaded);
        // The final iteration might wipe the data
        // So we expect PSA_ERROR_INVALID_SIGNATURE for the first (MAX_FAILS-1) times
        // and might see a different code if it was wiped on the last attempt
    }

    // Now the data should be wiped, so a load with correct pin => PSA_ERROR_DOES_NOT_EXIST
    magic_internet_key_t loaded;
    memset(&loaded, 0, sizeof(loaded));
    st = key_storage_load(pin, &loaded);
    TEST_ASSERT_EQUAL(PSA_ERROR_DOES_NOT_EXIST, st);
}

static void test_reset_fail_count(void)
{
    // store something
    const uint8_t data[32] = {0x99, 0x88};
    magic_internet_key_t keys_out = make_sample_keys(123, data, 32);
    const char *pin = "asdfgh";
    psa_status_t st = key_storage_store(&keys_out, pin);
    TEST_ASSERT_EQUAL(PSA_SUCCESS, st);

    // cause 2 fails
    for (int i = 0; i < 2; i++) {
        magic_internet_key_t loaded;
        memset(&loaded, 0, sizeof(loaded));
        st = key_storage_load("nonsense", &loaded);
        TEST_ASSERT_EQUAL(PSA_ERROR_INVALID_SIGNATURE, st);
    }
    // check fail_count = 2
    uint32_t fails = 999;
    st = key_storage_get_fail_count(&fails);
    TEST_ASSERT_EQUAL(2, fails);

    // call key_storage_reset_fail_count()
    st = key_storage_reset_fail_count();
    TEST_ASSERT_EQUAL(PSA_SUCCESS, st);

    // verify fail_count = 0
    fails = 999;
    st = key_storage_get_fail_count(&fails);
    TEST_ASSERT_EQUAL(PSA_SUCCESS, st);
    TEST_ASSERT_EQUAL(0, fails);
}

void key_storage_test_run_all(void)
{
    test_store_load_correct_pin();
    test_load_wrong_pin();
    test_fail_count_wipe();
    test_reset_fail_count();
    key_storage_wipe();
}
