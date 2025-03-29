// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "shared/test_util.h"
#ifdef __ZEPHYR__
#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(test_assert);
#else
#include "tfm_sp_log.h"
#endif

static test_assert_results_t test_assert_results = {0};

void test_assert_init(void)
{
    memset(&test_assert_results, 0, sizeof(test_assert_results));
    test_assert_results.failure_count = 0;
}

test_assert_results_t *test_assert_get_results(void)
{
    return &test_assert_results;
}

void test_assert_record_failure(const char *file, uint32_t line, const char *message)
{
    if (test_assert_results.failure_count < TEST_ASSERT_MAX_FAILURES) {
        test_assert_failure_t *f =
            &test_assert_results.failures[test_assert_results.failure_count++];
        strncpy(f->file, file, TEST_ASSERT_MAX_FILE_LEN - 1);
        f->file[TEST_ASSERT_MAX_FILE_LEN - 1] = '\0';
        f->line = line;
        if (message) {
            strncpy(f->message, message, TEST_ASSERT_MAX_MSG_LEN - 1);
            f->message[TEST_ASSERT_MAX_MSG_LEN - 1] = '\0';
        } else {
            f->message[0] = '\0';
        }
    }
#ifdef __ZEPHYR__
    LOG_ERR("Test failed in %s at line %u: %s", file, line, message ? message : "No message");
#else
    LOG_ERRFMT("Test failed in %s at line %u: %s\n", file, line, message ? message : "No message");
#endif
}

void test_assert_increment_total(void)
{
    test_assert_results.total++;
}
void test_assert_increment_passed(void)
{
    test_assert_results.passed++;
}
