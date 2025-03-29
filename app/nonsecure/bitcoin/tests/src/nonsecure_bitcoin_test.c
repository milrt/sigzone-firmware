// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "bitcoin/nonsecure_bitcoin_test.h"
#include "chains_test.h"
#include "psbt_test.h"

void nonsecure_bitcoin_test_run_all(void)
{
    chains_test_run_all();
    psbt_test_run_all();
}
