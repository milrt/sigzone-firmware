// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "psa/crypto.h"
#include "shared/hash.h"
#include "shared/test_util.h"

static void test_hash_sha256(void)
{
    const uint8_t input[] = "abc";
    uint8_t hash[32];
    psa_status_t status;
    const uint8_t expected[] = {0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40,
                                0xde, 0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17,
                                0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};

    // Test successful hash
    status = hash_sha256(input, sizeof(input) - 1, hash, sizeof(hash));
    TEST_ASSERT_EQUAL(status, PSA_SUCCESS);

    // Verify hash contents
    TEST_ASSERT_ARRAY_EQUAL(hash, expected, sizeof(expected));

    // Test invalid input (NULL input should fail)
    status = hash_sha256(NULL, 32, hash, sizeof(hash));
    TEST_ASSERT_EQUAL(status, PSA_ERROR_INVALID_ARGUMENT);

    // Test buffer too small
    uint8_t small_buf[16];
    status = hash_sha256(input, sizeof(input) - 1, small_buf, sizeof(small_buf));
    TEST_ASSERT_EQUAL(status, PSA_ERROR_INVALID_ARGUMENT);
}

void hash_test_run_all(void)
{
    test_hash_sha256();
}
