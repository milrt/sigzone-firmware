// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "bitcoin/segwit_addr.h"
#include <ctype.h> // for tolower
#include <mbedtls/platform_util.h>
#include <stdbool.h>
#include <string.h>

/*
 * Note on checksum constants:
 *   - For witness version 0, use Bech32 constant 1.
 *   - For version >= 1, use Bech32m constant 0x2bc830a3.
 */
static inline uint32_t bech32_const_for_version(uint8_t witness_ver)
{
    return (witness_ver == 0) ? 0x1 : 0x2bc830a3;
}

static const char *CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
static int8_t charset_rev[128];
static bool g_charset_rev_init;

static void init_charset_rev(void)
{
    memset(charset_rev, -1, sizeof(charset_rev));
    for (int i = 0; i < 32; i++) {
        charset_rev[(int)CHARSET[i]] = (int8_t)i;
    }
    g_charset_rev_init = true;
}

static const uint32_t GEN[5] = {0x3b6a57b2UL, 0x26508e6dUL, 0x1ea119faUL, 0x3d4233ddUL,
                                0x2a1462b3UL};

static uint32_t polymod(const uint8_t *values, size_t values_len)
{
    uint32_t chk = 1;
    for (size_t i = 0; i < values_len; i++) {
        uint8_t top = chk >> 25;
        chk = ((chk & 0x1FFFFFF) << 5) ^ values[i];
        for (int j = 0; j < 5; j++) {
            if ((top >> j) & 1) {
                chk ^= GEN[j];
            }
        }
    }
    return chk;
}

/* Expand HRP for checksum calculation.
 * out must have room for (2 * hrp_len + 1) bytes.
 */
static size_t hrp_expand(const char *hrp, size_t hrp_len, uint8_t *out)
{
    for (size_t i = 0; i < hrp_len; i++) {
        out[i] = (uint8_t)(hrp[i] >> 5);
    }
    out[hrp_len] = 0;
    for (size_t i = 0; i < hrp_len; i++) {
        out[hrp_len + 1 + i] = (uint8_t)(hrp[i] & 0x1F);
    }
    return hrp_len * 2 + 1;
}

/* Convert bits from in_width to out_width. */
static bool convert_bits(uint8_t *out, size_t *outlen, int out_width, const uint8_t *in,
                         size_t inlen, int in_width, bool pad)
{
    uint32_t acc = 0;
    int bits = 0;
    size_t pos = 0;
    uint32_t maxv = (1U << out_width) - 1;
    for (size_t i = 0; i < inlen; i++) {
        uint32_t value = in[i];
        if (value >> in_width) {
            return false;
        }
        acc = (acc << in_width) | value;
        bits += in_width;
        while (bits >= out_width) {
            bits -= out_width;
            out[pos++] = (acc >> bits) & maxv;
        }
    }
    if (pad) {
        if (bits) {
            out[pos++] = (acc << (out_width - bits)) & maxv;
        }
    } else if (bits >= in_width || ((acc << (out_width - bits)) & maxv)) {
        return false;
    }
    *outlen = pos;
    return true;
}

/* Append a 6-digit checksum to the data in values. */
static void create_checksum(const char *hrp, size_t hrp_len, uint8_t *values, size_t values_len,
                            uint32_t bech32_const)
{
    uint8_t buf[2 * 83 + 1 + 90 + 6] = {0};
    size_t e_len = hrp_expand(hrp, hrp_len, buf);
    memcpy(buf + e_len, values, values_len);
    memset(buf + e_len + values_len, 0, 6);
    uint32_t mod = polymod(buf, e_len + values_len + 6) ^ bech32_const;
    for (int i = 0; i < 6; i++) {
        values[values_len + i] = (mod >> (5 * (5 - i))) & 0x1F;
    }
}

psa_status_t segwit_addr_encode(const char *hrp, size_t hrp_len, uint8_t witness_ver,
                                const uint8_t *witness_prog, size_t wp_len, char *out_addr,
                                size_t *out_size)
{
    if (!hrp || !witness_prog || !out_addr || !out_size || hrp_len == 0 || wp_len == 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (*out_size < SEGWIT_ADDR_MAX_ADDRESS_LEN) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }
    if (!g_charset_rev_init) {
        init_charset_rev();
    }

    /* Prepare data: version + converted witness program */
    uint8_t tmp[128] = {0};
    size_t tmp_len = 0;
    tmp[tmp_len++] = witness_ver & 0x1F;

    size_t conv_len = sizeof(tmp) - tmp_len - 6; /* Reserve space for checksum */
    if (!convert_bits(&tmp[tmp_len], &conv_len, 5, witness_prog, wp_len, 8, true)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    tmp_len += conv_len;

    /* Append checksum */
    create_checksum(hrp, hrp_len, tmp, tmp_len, bech32_const_for_version(witness_ver));
    tmp_len += 6;

    /* Build final address: HRP + separator + data */
    size_t offset = 0;
    memcpy(out_addr, hrp, hrp_len);
    offset += hrp_len;
    out_addr[offset++] = '1';
    for (size_t i = 0; i < tmp_len; i++) {
        if (tmp[i] > 31) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        out_addr[offset++] = CHARSET[tmp[i]];
    }
    out_addr[offset] = '\0';
    *out_size = offset;
    return PSA_SUCCESS;
}

psa_status_t segwit_addr_decode(const char *addr, char *out_hrp, size_t *out_hrp_len,
                                uint8_t *witness_ver, uint8_t *witness_prog, size_t *wp_size)
{
    if (!addr || !out_hrp || !out_hrp_len || !witness_ver || !witness_prog || !wp_size) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (!g_charset_rev_init) {
        init_charset_rev();
    }

    size_t addr_len = strlen(addr);
    if (addr_len < 8) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    /* Use standard library call to find last '1' separator */
    const char *sep = strrchr(addr, '1');
    if (!sep || sep == addr) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    size_t hrp_len_local = sep - addr;
    if (hrp_len_local > *out_hrp_len - 1) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }
    memcpy(out_hrp, addr, hrp_len_local);
    out_hrp[hrp_len_local] = '\0';
    *out_hrp_len = hrp_len_local;

    size_t data_len = addr_len - hrp_len_local - 1;
    if (data_len < 6) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    uint8_t data[90] = {0};
    for (size_t i = 0; i < data_len; i++) {
        char c = addr[hrp_len_local + 1 + i];
        /* Optional: enforce lowercase by converting uppercase letters */
        if (c >= 'A' && c <= 'Z') {
            c = (char)tolower(c);
        }
        if (c < 33 || c > 126) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        int8_t v = charset_rev[(int)c];
        if (v < 0) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        data[i] = (uint8_t)v;
    }

    uint8_t hrp_expanded[2 * 83 + 1] = {0};
    size_t e_len = hrp_expand(out_hrp, hrp_len_local, hrp_expanded);

    uint8_t buf[2 * 83 + 1 + 90];
    memcpy(buf, hrp_expanded, e_len);
    memcpy(buf + e_len, data, data_len);
    uint32_t pm = polymod(buf, e_len + data_len);
    bool is_bech32 = (pm == 1);
    bool is_bech32m = (pm == 0x2bc830a3);
    if (!is_bech32 && !is_bech32m) {
        return PSA_ERROR_INVALID_SIGNATURE;
    }

    size_t payload_len = data_len - 6;
    if (payload_len == 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    uint8_t ver = data[0];
    if (ver > 16) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    *witness_ver = ver;
    if ((ver == 0 && !is_bech32) || (ver > 0 && !is_bech32m)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    size_t conv_len = *wp_size;
    if (!convert_bits(witness_prog, &conv_len, 8, &data[1], payload_len - 1, 5, false)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    *wp_size = conv_len;
    return PSA_SUCCESS;
}
