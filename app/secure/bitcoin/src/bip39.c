// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "bip39.h"
#include "bip39_wordlist.h"
#include "psa/error.h"
#include "shared/hash.h"
#include <mbedtls/constant_time.h>
#include <psa/crypto.h>
#include <string.h>

#define BIP39_ENTROPY_LEN_128 16
#define BIP39_ENTROPY_LEN_160 20
#define BIP39_ENTROPY_LEN_192 24
#define BIP39_ENTROPY_LEN_224 28
#define BIP39_ENTROPY_LEN_256 32

#define BIP39_WORD_COUNT_12 12
#define BIP39_WORD_COUNT_24 24
#define BIP39_BITS_PER_WORD 11
#define BIP39_CHECKSUM_BITS_128 4

#define BIP39_MAX_SALT_LEN 1024

#define BITS_PER_BYTE 8
#define BYTE_INDEX(pos) ((pos) / BITS_PER_BYTE)
#define BIT_INDEX(pos) (7 - ((pos) % BITS_PER_BYTE))

static size_t size_to_mask(size_t entropy_size)
{
    switch (entropy_size) {
    case BIP39_ENTROPY_LEN_128:
        return 0xF0;
    case BIP39_ENTROPY_LEN_160:
        return 0xF8;
    case BIP39_ENTROPY_LEN_192:
        return 0xFC;
    case BIP39_ENTROPY_LEN_224:
        return 0xFE;
    case BIP39_ENTROPY_LEN_256:
        return 0xFF;
    default:
        return 0;
    }
}

static int binary_search_wordlist(const char *word, const char **wordlist, size_t wordlist_size)
{
    for (size_t low = 0, high = wordlist_size - 1; low <= high;) {
        size_t mid = low + (high - low) / 2;
        int cmp = strcmp(word, wordlist[mid]);
        if (cmp == 0) {
            return mid;
        }
        cmp < 0 ? (high = mid - 1) : (low = mid + 1);
    }
    return -1;
}

static void set_bit(uint8_t *bits, size_t pos, uint8_t val)
{
    bits[BYTE_INDEX(pos)] |= (val & 1) << BIT_INDEX(pos);
}
static uint8_t get_bit(const uint8_t *bits, size_t pos)
{
    return (bits[BYTE_INDEX(pos)] >> BIT_INDEX(pos)) & 1;
}

static uint16_t extract_index(const uint8_t *bits, size_t n)
{
    uint16_t index = 0;
    size_t start = n * BIP39_BITS_PER_WORD;
    for (size_t i = 0; i < BIP39_BITS_PER_WORD; i++) {
        index = (index << 1) | get_bit(bits, start + i);
    }
    return index;
}

static void store_index(uint8_t *bits, size_t n, uint16_t index)
{
    size_t start = n * BIP39_BITS_PER_WORD;
    for (size_t i = 0; i < BIP39_BITS_PER_WORD; i++) {
        set_bit(bits, start + i, (index >> (10 - i)) & 1);
    }
}

psa_status_t bip39_mnemonic_to_entropy(const char *mnemonic, uint8_t *entropy_out,
                                       size_t *entropy_out_size)
{
    if (!mnemonic || !entropy_out) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    psa_status_t status = PSA_ERROR_PROGRAMMER_ERROR;
    char local_copy[BIP39_MAX_MNEMONIC_LEN] = {0};
    uint8_t bits[34] = {0};
    uint8_t hash[32] = {0};

    const size_t mnemonic_len = strlen(mnemonic);
    if (mnemonic_len >= sizeof(local_copy)) {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto cleanup;
    }

    strncpy(local_copy, mnemonic, sizeof(local_copy) - 1);
    local_copy[sizeof(local_copy) - 1] = '\0';

    char *words[BIP39_WORD_COUNT_24] = {0};
    size_t word_count = 0;
    char *start = local_copy;

    for (word_count = 0; word_count < BIP39_WORD_COUNT_24; word_count++) {
        char *end = strchr(start, ' ');
        if (end) {
            *end = '\0';
        }
        words[word_count] = start;
        if (!end) {
            break;
        }
        start = end + 1;
    }
    word_count++; // Account for last word

    const size_t entropy_len = (word_count * BIP39_BITS_PER_WORD - word_count / 3) / BITS_PER_BYTE;
    if (!size_to_mask(entropy_len) || *entropy_out_size < entropy_len) {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto cleanup;
    }

    for (size_t i = 0; i < word_count; i++) {
        int index = binary_search_wordlist(words[i], bip39_wordlist_en, BIP39_WORDLIST_EN_SIZE);
        if (index < 0) {
            status = PSA_ERROR_INVALID_ARGUMENT;
            goto cleanup;
        }
        store_index(bits, i, (uint16_t)index);
    }

    status = hash_sha256(bits, entropy_len, hash, sizeof(hash));
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    const uint8_t expected_checksum = bits[entropy_len] & size_to_mask(entropy_len);
    const uint8_t calculated_checksum = hash[0] & size_to_mask(entropy_len);

    if (mbedtls_ct_memcmp(&expected_checksum, &calculated_checksum, 1) != 0) {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto cleanup;
    }

    memcpy(entropy_out, bits, entropy_len);
    *entropy_out_size = entropy_len;
    status = PSA_SUCCESS;

cleanup:
    mbedtls_platform_zeroize(local_copy, sizeof(local_copy));
    mbedtls_platform_zeroize(bits, sizeof(bits));
    mbedtls_platform_zeroize(hash, sizeof(hash));
    return status;
}

psa_status_t bip39_entropy_to_mnemonic(const uint8_t *entropy, size_t entropy_len,
                                       char *mnemonic_out, size_t mnemonic_out_size)
{
    if (!entropy || !mnemonic_out || !size_to_mask(entropy_len)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    psa_status_t status = PSA_ERROR_PROGRAMMER_ERROR;

    const size_t checksum_bits = entropy_len * BITS_PER_BYTE / 32;
    const size_t total_bits = entropy_len * BITS_PER_BYTE + checksum_bits;
    const size_t word_count = total_bits / BIP39_BITS_PER_WORD;

    // Pre-calculate required buffer size
    size_t required_size = 0;
    for (size_t i = 0; i < word_count; i++) {
        uint16_t index = extract_index(entropy, i);
        required_size += strlen(bip39_wordlist_en[index]) + 1; // Word + space
    }
    if (required_size > mnemonic_out_size) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    uint8_t bits[34] = {0};
    uint8_t hash[32] = {0};

    memcpy(bits, entropy, entropy_len);
    status = hash_sha256(entropy, entropy_len, hash, sizeof(hash));
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    bits[entropy_len] = hash[0] & size_to_mask(entropy_len);

    char *ptr = mnemonic_out;
    for (size_t i = 0; i < word_count; i++) {
        const uint16_t index = extract_index(bits, i);
        if (index >= BIP39_WORDLIST_EN_SIZE) {
            status = PSA_ERROR_DATA_CORRUPT;
            goto cleanup;
        }

        const char *word = bip39_wordlist_en[index];
        const size_t word_len = strlen(word);
        memcpy(ptr, word, word_len);
        ptr += word_len;
        *ptr++ = ' ';
    }
    if (word_count > 0) {
        ptr--; // Remove trailing space
    }
    *ptr = '\0';

    status = PSA_SUCCESS;

cleanup:
    mbedtls_platform_zeroize(bits, sizeof(bits));
    mbedtls_platform_zeroize(hash, sizeof(hash));
    return status;
}

psa_status_t bip39_validate_mnemonic(const char *mnemonic)
{
    if (!mnemonic) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    uint8_t entropy[32] = {0};
    size_t entropy_size = sizeof(entropy);
    psa_status_t status = bip39_mnemonic_to_entropy(mnemonic, entropy, &entropy_size);

    mbedtls_platform_zeroize(entropy, sizeof(entropy));
    return status;
}

psa_status_t bip39_mnemonic_to_seed(const char *mnemonic, const char *passphrase, uint8_t *seed_out,
                                    size_t *seed_size_in_out)
{
    if (!mnemonic || !seed_out || !seed_size_in_out || *seed_size_in_out < 64) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    const char *passphrase_clean = passphrase ? passphrase : "";
    const char *salt_preface = "mnemonic";
    const size_t salt_preface_len = strlen(salt_preface);
    const size_t passphrase_len = strlen(passphrase_clean);
    const size_t salt_len = salt_preface_len + passphrase_len;

    if (salt_len > BIP39_MAX_SALT_LEN) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    psa_status_t status = PSA_ERROR_PROGRAMMER_ERROR;
    uint8_t salt[BIP39_MAX_SALT_LEN] = {0};

    memcpy(salt, salt_preface, salt_preface_len);
    memcpy(salt + salt_preface_len, passphrase_clean, passphrase_len);

    const size_t mnemonic_len = strlen(mnemonic);

    status = hash_pbkdf2_hmac_sha512((const uint8_t *)mnemonic, mnemonic_len, salt, salt_len, 2048,
                                     seed_out, 64);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    *seed_size_in_out = 64;
    status = PSA_SUCCESS;

cleanup:
    mbedtls_platform_zeroize(salt, sizeof(salt));
    return status;
}
