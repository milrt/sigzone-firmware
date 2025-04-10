// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <psa/error.h>
#include <stdint.h>

psa_status_t nvc_create(uint32_t uid);
psa_status_t nvc_increment(uint32_t uid);
psa_status_t nvc_reset(uint32_t uid);
psa_status_t nvc_validate(uint32_t uid);
psa_status_t nvc_get_value(uint32_t uid, uint32_t *value);
psa_status_t nvc_destroy(uint32_t uid);
