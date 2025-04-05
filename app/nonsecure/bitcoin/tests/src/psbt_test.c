// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "psbt_test.h"
#include "bitcoin/bitcoin_client.h"
#include "bitcoin/chains.h"
#include "bitcoin/psbt.h"
#include "bitcoin/psbt_result.h"
#include "bitcoin/psbt_signer.h"
#include "bitcoin/psbt_validator.h"
#include "shared/test_util.h"
#include <zephyr/sys/base64.h>

static const char *psbt_base64 =
    "cHNidP8BAHECAAAAAQmRtjBtG4pseYo9aWA6Cjst0E5db1QhSAHBSovQGSk5AQAAAAD9////"
    "Apg6AAAAAAAAFgAUAhwwpCAd2VHnZbXafW/"
    "XWEH7pE9eDQAAAAAAABYAFGfHzVm5AeAEX4fdTMHZJTsp7hveVS4+AE8BBDWHzwMuRF/cgAAAAPxf6XMnS+a0/"
    "RiSUycEy0ViWsmgCXTApwTTC+jLPvCuA92ijp/"
    "z7HQvP2n4wSfUgxF8wHpvxvmq9vv6l7VFm6hPECSzBqZUAACAAQAAgAAAAIAAAQBxAgAAAAGQAc+"
    "Te355UKXIGBOKqY73StyP0fM22HfTSHmabnhMSQEAAAAA/f///wKIt6a4AAAAABYAFC+ZDeVXFudqnD5unvRE/"
    "0KdgpjE6kkAAAAAAAAWABRj6rseiCYoo9BQ9u8rupAw/r4X3UAuPgABAR/"
    "qSQAAAAAAABYAFGPqux6IJiij0FD27yu6kDD+vhfdAQMEAQAAACIGAi+NVo70FI76y2NOK7wqU1IAMfZ+"
    "fw9PPSwyaO248d6nGCSzBqZUAACAAQAAgAAAAIAAAAAAAAAAAAAAIgIDit7wwrlz/"
    "pHLR2CmBQkUgmtqorsaQxWTOnCrejidFiQYJLMGplQAAIABAACAAAAAgAEAAAAAAAAAAA==";

static uint8_t psbt_raw[4096];
static size_t psbt_raw_size = 0;

static void open_wallet()
{
    char mnemonic[256];
    size_t mnemonic_size = sizeof(mnemonic);

    psa_status_t status;
    status = bitcoin_client_recover(
        "guess nuclear width pave clap crumble rain dance nurse bind parrot yellow");
    TEST_ASSERT_EQUAL(PSA_SUCCESS, status);
    status = bitcoin_client_verify(mnemonic, &mnemonic_size);
    TEST_ASSERT_EQUAL(PSA_SUCCESS, status);
    status = bitcoin_client_confirm("1", mnemonic);
    TEST_ASSERT_EQUAL(PSA_SUCCESS, status);
    status = bitcoin_client_open("1", "sigzone");
    TEST_ASSERT_EQUAL(PSA_SUCCESS, status);
}

static void destroy_wallet()
{
    bitcoin_client_close();
    bitcoin_client_destroy("1");
}

static void test_serialize_deserialize()
{
    // Serialize
    psbt_t psbt = {0};
    psbt_result_t result = psbt_create_from_bin(&psbt, psbt_raw, psbt_raw_size);
    TEST_ASSERT_EQUAL(PSBT_OK, result);

    // Deserialize
    uint8_t psbt_raw_deserialized[4096];
    size_t psbt_raw__deserialized_size = sizeof(psbt_raw_deserialized);
    result = psbt_to_bin(&psbt, psbt_raw_deserialized, &psbt_raw__deserialized_size);
    TEST_ASSERT_EQUAL(PSBT_OK, result);

    char psbt_base64_deserialized[4096 * 2];
    size_t psbt_base64_len_deserialized;
    int res = base64_encode(psbt_base64_deserialized, sizeof(psbt_base64_deserialized),
                            &psbt_base64_len_deserialized, psbt_raw_deserialized,
                            psbt_raw__deserialized_size);
    TEST_ASSERT_EQUAL(0, res);

    TEST_ASSERT_STR_EQUAL(psbt_base64, psbt_base64_deserialized);
    psbt_free(&psbt);
}

static void test_validator()
{
    open_wallet();

    psbt_t psbt = {0};
    psbt_result_t result = psbt_create_from_bin(&psbt, psbt_raw, psbt_raw_size);
    TEST_ASSERT_EQUAL(PSBT_OK, result);

    psbt_validation_t validation;
    result = psbt_validate(&psbt, &validation);
    TEST_ASSERT_EQUAL(PSBT_OK, result);

    TEST_ASSERT_EQUAL(18922, validation.total_input);
    TEST_ASSERT_EQUAL(18422, validation.total_output);
    TEST_ASSERT_EQUAL(500, validation.fee);
    TEST_ASSERT_TRUE(validation.is_valid);

    psbt_validation_entry_t *entry;
    uint32_t count = 0;
    SYS_SLIST_FOR_EACH_CONTAINER(&validation.entries, entry, node)
    {
        switch (count) {
        case 0:
            TEST_ASSERT_STR_EQUAL("Input", entry->description);
            TEST_ASSERT_STR_EQUAL("tb1qv04tk85gyc5285zs7mhjhw5sxrltu97aunastm", entry->address);
            TEST_ASSERT_EQUAL(18922, entry->amount_sats);
            TEST_ASSERT_FALSE(entry->is_change);
            break;
        case 1:
            TEST_ASSERT_STR_EQUAL("Output", entry->description);
            TEST_ASSERT_STR_EQUAL("tb1qqgwrpfpqrhv4rem9khd86m7htpqlhfz0g9pzqj", entry->address);
            TEST_ASSERT_EQUAL(15000, entry->amount_sats);
            TEST_ASSERT_FALSE(entry->is_change);
            break;
        case 2:
            TEST_ASSERT_STR_EQUAL("Output", entry->description);
            TEST_ASSERT_STR_EQUAL("tb1qvlru6kdeq8sqghu8m4xvrkf98v57ux77gjx8xc", entry->address);
            TEST_ASSERT_EQUAL(3422, entry->amount_sats);
            TEST_ASSERT_TRUE(entry->is_change);
            break;
        default:
            TEST_ASSERT_TRUE(false);
        }
        count++;
    }

    psbt_validation_free(&validation);
    psbt_free(&psbt);

    destroy_wallet();
}

static void test_signer()
{
    const char *expected_signed_base64 =
        "cHNidP8BAHECAAAAAQmRtjBtG4pseYo9aWA6Cjst0E5db1QhSAHBSovQGSk5AQAAAAD9////"
        "Apg6AAAAAAAAFgAUAhwwpCAd2VHnZbXafW/"
        "XWEH7pE9eDQAAAAAAABYAFGfHzVm5AeAEX4fdTMHZJTsp7hveVS4+AE8BBDWHzwMuRF/cgAAAAPxf6XMnS+a0/"
        "RiSUycEy0ViWsmgCXTApwTTC+jLPvCuA92ijp/"
        "z7HQvP2n4wSfUgxF8wHpvxvmq9vv6l7VFm6hPECSzBqZUAACAAQAAgAAAAIAAAQBxAgAAAAGQAc+"
        "Te355UKXIGBOKqY73StyP0fM22HfTSHmabnhMSQEAAAAA/f///wKIt6a4AAAAABYAFC+ZDeVXFudqnD5unvRE/"
        "0KdgpjE6kkAAAAAAAAWABRj6rseiCYoo9BQ9u8rupAw/r4X3UAuPgABAR/"
        "qSQAAAAAAABYAFGPqux6IJiij0FD27yu6kDD+vhfdAQMEAQAAACIGAi+NVo70FI76y2NOK7wqU1IAMfZ+"
        "fw9PPSwyaO248d6nGCSzBqZUAACAAQAAgAAAAIAAAAAAAAAAACICAi+NVo70FI76y2NOK7wqU1IAMfZ+"
        "fw9PPSwyaO248d6nRzBEAiAjhEP70ON9ZRRut/X3650qfBIswfkTatUb8rBRfkfSaAIgcpr42du1SEXd3Ug/"
        "FipiUD0WBDIYgzR/iQnqh/"
        "9cm4gBAAAiAgOK3vDCuXP+"
        "kctHYKYFCRSCa2qiuxpDFZM6cKt6OJ0WJBgkswamVAAAgAEAAIAAAACAAQAAAAAAAAAA";

    open_wallet();

    psbt_t psbt = {0};
    psbt_result_t result = psbt_create_from_bin(&psbt, psbt_raw, psbt_raw_size);
    TEST_ASSERT_EQUAL(PSBT_OK, result);

    result = psbt_sign(&psbt);
    TEST_ASSERT_EQUAL(PSBT_OK, result);

    // Deserialize
    uint8_t psbt_raw_deserialized[4096];
    size_t psbt_raw__deserialized_size = sizeof(psbt_raw_deserialized);
    result = psbt_to_bin(&psbt, psbt_raw_deserialized, &psbt_raw__deserialized_size);
    TEST_ASSERT_EQUAL(PSBT_OK, result);

    char psbt_base64_deserialized[4096 * 2];
    size_t psbt_base64_len_deserialized;
    int res = base64_encode(psbt_base64_deserialized, sizeof(psbt_base64_deserialized),
                            &psbt_base64_len_deserialized, psbt_raw_deserialized,
                            psbt_raw__deserialized_size);
    TEST_ASSERT_EQUAL(0, res);

    TEST_ASSERT_STR_EQUAL(expected_signed_base64, psbt_base64_deserialized);

    psbt_free(&psbt);

    destroy_wallet();
}

static void init()
{
    int res =
        base64_decode(psbt_raw, sizeof(psbt_raw), &psbt_raw_size, psbt_base64, strlen(psbt_base64));
    TEST_ASSERT_EQUAL(0, res);
    chains_set_network(BITCOIN_TESTNET);
}

void psbt_test_run_all(void)
{
    init();
    test_serialize_deserialize();
    test_validator();
    test_signer();
}
