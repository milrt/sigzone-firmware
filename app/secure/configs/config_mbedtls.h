// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

// For PBKDF2-HMAC-SHA512 in hash.c
#define MBEDTLS_PKCS5_C
#define MBEDTLS_MD_CAN_SHA512

#define MBEDTLS_RIPEMD160_C
#define MBEDTLS_AES_C
#define MBEDTLS_GCM_C
