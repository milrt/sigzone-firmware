<div align="center">

# sigzone

Bitcoin hardware wallet firmware based on Zephyr RTOS and Trusted Firmware-M (TF-M)

[![Test](https://github.com/milrt/sigzone-firmware/actions/workflows/test.yml/badge.svg)](https://github.com/milrt/sigzone-firmware/actions/workflows/test.yml)

</div>

---

> ⚠️ **WIP Warning**
>
> sigzone is still in early development.
> **Don't trust it with your sats**
>
> Runs on QEMU (ARM Cortex M33 `mps2/an521`) — hardware is in the works.

## Setup

1. **Install Zephyr SDK and prerequisites**

   Follow the official [Zephyr Getting Started Guide](https://docs.zephyrproject.org/latest/develop/getting_started/index.html) to set up your build environment.

2. **Initialize workspace with west**
```sh
mkdir sigzone && cd sigzone
west init -m https://github.com/milrt/sigzone-firmware
cd sigzone-firmware
west update
west zephyr-export
```

## Build & Run

From the sigzone-firmware/app directory, run:
```sh
west build -b mps2/an521/cpu0/ns -p auto -t run
```

## Test

Unit and integration tests can be run with:
```sh
west twister -T .
```

## Shell
https://github.com/user-attachments/assets/1d8ab99f-acc1-493f-974d-9b9c33006e87
