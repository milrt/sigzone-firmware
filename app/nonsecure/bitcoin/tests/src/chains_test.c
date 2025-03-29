// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "bitcoin/chains.h"
#include "shared/test_util.h"
#include <string.h>
#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(chains_test);

static void test_set_get_network(void)
{
    // Default should be mainnet
    TEST_ASSERT_EQUAL(get_bitcoin_network(), BITCOIN_MAINNET);

    // Change to testnet
    set_bitcoin_network(BITCOIN_TESTNET);
    TEST_ASSERT_EQUAL(get_bitcoin_network(), BITCOIN_TESTNET);

    // Change back to mainnet
    set_bitcoin_network(BITCOIN_MAINNET);
    TEST_ASSERT_EQUAL(get_bitcoin_network(), BITCOIN_MAINNET);
}

static void test_pubkey_to_script(void)
{
    set_bitcoin_network(BITCOIN_MAINNET);

    uint8_t pubkey[33] = {0x02, 0x1e, 0x99, 0x32, 0x9b, 0xa0, 0x0c, 0x4e, 0x9a, 0x30, 0xc2,
                          0x04, 0xa1, 0x4c, 0x4b, 0x0a, 0x64, 0x40, 0xf5, 0xe6, 0x61, 0xc0,
                          0xb4, 0x7a, 0x10, 0x17, 0xa1, 0xb1, 0xf7, 0xf0, 0xe2, 0x9d, 0x2f};

    uint8_t expectedScript[] = {0x00, 0x14, 0x91, 0x99, 0xb5, 0x50, 0xad, 0x90, 0x82, 0xed, 0x89,
                                0x52, 0x76, 0x41, 0xe0, 0x65, 0x3a, 0x2b, 0x2f, 0x1e, 0x91, 0x31};

    uint8_t script[MAX_SCRIPT_LEN] = {0};
    size_t script_size = MAX_SCRIPT_LEN;
    psa_status_t status;

    // Valid case
    status = pubkey_to_script(pubkey, sizeof(pubkey), script, &script_size);
    TEST_ASSERT_EQUAL(status, PSA_SUCCESS);
    TEST_ASSERT_EQUAL(script_size, 22); // P2WPKH script should be 22 bytes
    TEST_ASSERT_ARRAY_EQUAL(expectedScript, script, script_size);

    // Invalid: NULL pubkey
    status = pubkey_to_script(NULL, sizeof(pubkey), script, &script_size);
    TEST_ASSERT_EQUAL(status, PSA_ERROR_INVALID_ARGUMENT);

    // Invalid: Wrong pubkey length
    status = pubkey_to_script(pubkey, 31, script, &script_size);
    TEST_ASSERT_EQUAL(status, PSA_ERROR_INVALID_ARGUMENT);

    // Invalid: NULL output script buffer
    status = pubkey_to_script(pubkey, sizeof(pubkey), NULL, &script_size);
    TEST_ASSERT_EQUAL(status, PSA_ERROR_INVALID_ARGUMENT);

    // Invalid: Small output buffer
    size_t small_size = 10;
    status = pubkey_to_script(pubkey, sizeof(pubkey), script, &small_size);
    TEST_ASSERT_EQUAL(status, PSA_ERROR_INVALID_ARGUMENT);
}

static void test_script_to_address(void)
{
    uint8_t script[] = {0x00, 0x14, 0x85, 0x3e, 0xc3, 0x16, 0x68, 0x60, 0x37, 0x1e, 0xe6,
                        0x7b, 0x77, 0x54, 0xff, 0x85, 0xe1, 0x3d, 0x7a, 0x0d, 0x66, 0x98};

    char address[MAX_ADDRESS_LEN] = {0};
    size_t addr_size = MAX_ADDRESS_LEN;
    psa_status_t status;

    // Test on mainnet
    set_bitcoin_network(BITCOIN_MAINNET);
    status = script_to_address(script, sizeof(script), address, &addr_size);
    TEST_ASSERT_EQUAL(status, PSA_SUCCESS);
    TEST_ASSERT_NOT_NULL(address);
    TEST_ASSERT_STR_EQUAL(address, "bc1qs5lvx9ngvqm3aenmwa20lp0p84aq6e5cuayqcp");

    // Test on testnet
    set_bitcoin_network(BITCOIN_TESTNET);
    addr_size = MAX_ADDRESS_LEN;
    status = script_to_address(script, sizeof(script), address, &addr_size);
    TEST_ASSERT_EQUAL(status, PSA_SUCCESS);
    TEST_ASSERT_NOT_NULL(address);
    TEST_ASSERT_STR_EQUAL(address, "tb1qs5lvx9ngvqm3aenmwa20lp0p84aq6e5ckmlnrj");

    // Invalid: NULL script
    status = script_to_address(NULL, sizeof(script), address, &addr_size);
    TEST_ASSERT_EQUAL(status, PSA_ERROR_INVALID_ARGUMENT);

    // Invalid: Small address buffer
    size_t small_addr_size = 10;
    status = script_to_address(script, sizeof(script), address, &small_addr_size);
    TEST_ASSERT_EQUAL(status, PSA_ERROR_INVALID_ARGUMENT);

    // Invalid: Wrong script length
    status = script_to_address(script, 10, address, &addr_size);
    TEST_ASSERT_EQUAL(status, PSA_ERROR_INVALID_ARGUMENT);
}

void chains_test_run_all(void)
{
    test_set_get_network();
    test_pubkey_to_script();
    test_script_to_address();
}
