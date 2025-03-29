// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once
#include <stdint.h>

static inline uint32_t htonl(uint32_t hostlong)
{
    return ((hostlong & 0x000000FFU) << 24) | ((hostlong & 0x0000FF00U) << 8) |
           ((hostlong & 0x00FF0000U) >> 8) | ((hostlong & 0xFF000000U) >> 24);
}

static inline uint16_t htons(uint16_t hostshort)
{
    return (uint16_t)(((hostshort & 0x00FFU) << 8) | ((hostshort & 0xFF00U) >> 8));
}

static inline uint32_t ntohl(uint32_t netlong)
{
    return htonl(netlong);
}
static inline uint16_t ntohs(uint16_t netshort)
{
    return htons(netshort);
}
