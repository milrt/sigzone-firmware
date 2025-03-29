// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "bitcoin/secure_bitcoin_test.h"
#include "bip32_test.h"
#include "bip39_test.h"
#include "key_storage_test.h"
#include "shared/shared_test.h"
#include "shared/test_util.h"
#include "tfm_sp_log.h"

psa_status_t secure_bitcoin_test_run_all(void)
{
    test_assert_init();

    // TEST RUNS
    shared_test_run_all();
    bip39_test_run_all();
    bip32_test_run_all();
    key_storage_test_run_all();
    //  TEST RUNS

    test_assert_results_t *results = test_assert_get_results();

    LOG_INFFMT("Test Summary secure parition:\n");
    LOG_INFFMT("Total Tests Run: %u\n", results->total);
    LOG_INFFMT("Tests Passed:    %u\n", results->passed);
    LOG_INFFMT("Tests Failed:    %u\n", results->failure_count);

    if (results->failure_count > 0) {
        LOG_INFFMT("\nFailed Test Details:\n");
        for (uint32_t i = 0; i < results->failure_count; i++) {
            test_assert_failure_t *f = &results->failures[i];
            LOG_INFFMT("%u) %s:%u: %s\n", i + 1, f->file, f->line, f->message);
        }
    }

    return (results->failure_count == 0) ? PSA_SUCCESS : PSA_ERROR_GENERIC_ERROR;
}
