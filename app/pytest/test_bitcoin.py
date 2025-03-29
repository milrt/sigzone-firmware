# Copyright (C) 2025 milrt <milrt@proton.me>
# SPDX-License-Identifier: GPL-3.0-or-later

from twister_harness import DeviceAdapter
import time

def test_bitcoin_test_secure(dut: DeviceAdapter):
    dut.launch()
    time.sleep(3)
    dut.write(b"bitcoin test_secure\n")

    lines = dut.readlines_until(regex=r"(PASSED|FAILED)", timeout=30)

    assert any("PASSED" in line for line in lines), "Test run failed or did not complete"
    assert not any("FAILED" in line for line in lines), "One or more tests failed"

def test_bitcoin_test_nonsecure(dut: DeviceAdapter):
    dut.launch()
    time.sleep(3)
    dut.write(b"bitcoin test_nonsecure\n")

    lines = dut.readlines_until(regex=r"(PASSED|FAILED)", timeout=30)

    assert any("PASSED" in line for line in lines), "Test run failed or did not complete"
    assert not any("FAILED" in line for line in lines), "One or more tests failed"
