// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include "psbt.h"
#include "psbt_result.h"

psbt_result_t psbt_sign(psbt_t *psbt);
