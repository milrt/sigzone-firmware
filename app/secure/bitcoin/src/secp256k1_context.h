// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <secp256k1.h>
#include <stdint.h>

size_t secp256k1_get_context_size();
secp256k1_context *secp256k1_create_randomized_context(uint8_t *context_memory);
