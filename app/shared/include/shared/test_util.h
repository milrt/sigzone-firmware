// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once
#include <psa/crypto.h>
#include <stdio.h>
#include <string.h>

#define TEST_ASSERT_MAX_FAILURES 20
#define TEST_ASSERT_MAX_FILE_LEN 50
#define TEST_ASSERT_MAX_MSG_LEN 50

typedef struct {
    char file[TEST_ASSERT_MAX_FILE_LEN];
    uint32_t line;
    char message[TEST_ASSERT_MAX_MSG_LEN];
} test_assert_failure_t;

typedef struct {
    uint32_t total;
    uint32_t passed;
    test_assert_failure_t failures[TEST_ASSERT_MAX_FAILURES];
    uint32_t failure_count;
} test_assert_results_t;

test_assert_results_t *test_assert_get_results(void);
void test_assert_init(void);
void test_assert_record_failure(const char *file, uint32_t line, const char *message);
void test_assert_increment_total(void);
void test_assert_increment_passed(void);

#define TEST_ASSERT(test, ...)                                                                     \
    do {                                                                                           \
        test_assert_increment_total();                                                             \
        if (!(test)) {                                                                             \
            test_assert_record_failure(__FILE_NAME__, __LINE__,                                    \
                                       (__VA_ARGS__[0] ? __VA_ARGS__ : NULL));                     \
        } else {                                                                                   \
            test_assert_increment_passed();                                                        \
        }                                                                                          \
    } while (0)

#define TEST_ASSERT_NO_MSG(test) TEST_ASSERT(test, "")

#define TEST_ASSERT_EQUAL(a, b) TEST_ASSERT((a) == (b), "Expected " #a " == " #b)

#define TEST_ASSERT_NOT_EQUAL(a, b) TEST_ASSERT((a) != (b), "Expected " #a " != " #b)

#define TEST_ASSERT_TRUE(cond) TEST_ASSERT((cond), #cond " is false")

#define TEST_ASSERT_FALSE(cond) TEST_ASSERT(!(cond), #cond " is true")

#define TEST_ASSERT_NULL(ptr) TEST_ASSERT((ptr) == NULL, #ptr " is not NULL")

#define TEST_ASSERT_NOT_NULL(ptr) TEST_ASSERT((ptr) != NULL, #ptr " is NULL")

#define TEST_ASSERT_WITHIN(a, b, d)                                                                \
    TEST_ASSERT(((a) >= ((b) - (d))) && ((a) <= ((b) + (d))), #a " not within " #b " +/- " #d)

#define TEST_ASSERT_STR_EQUAL(s1, s2) TEST_ASSERT(strcmp(s1, s2) == 0, #s1 " not equal to " #s2)

#define TEST_ASSERT_STR_NOT_EQUAL(s1, s2) TEST_ASSERT(strcmp(s1, s2) != 0, #s1 " equal to " #s2)

#define TEST_ASSERT_ARRAY_EQUAL(arr1, arr2, size)                                                  \
    TEST_ASSERT(memcmp(arr1, arr2, size) == 0, #arr1 " not equal to " #arr2)

#define TEST_ASSERT_ARRAY_NOT_EQUAL(arr1, arr2, size)                                              \
    TEST_ASSERT(memcmp(arr1, arr2, size) != 0, #arr1 " equal to " #arr2)
