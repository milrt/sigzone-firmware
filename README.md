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

sigzone includes a built-in Zephyr shell interface for interacting with the wallet firmware.

You can:

- Create, recover, open, and destroy wallets
- Load from mnemonic phrases
- Derive and view public keys + Bitcoin addresses
- Sign raw hashes or complete PSBTs
- Parse and validate PSBTs
- Switch between mainnet and testnet
- Run unit tests from both the secure and non-secure environments

Example Commands
```
sigzone:~$ bitcoin create 1234
Wallet created
sigzone:~$ bitcoin open 1234 mypassphrase
Wallet opened
sigzone:~$ bitcoin get_pubkey m/84h/1h/0h/0/0
Public Key (33 bytes): 03c09c8b9cda47d68d12fea3fc7b6a60951ed0405b491f963e135c9e4fcc3083df
xpub: xpub6FXdWkBQJGJb4CdMcLoA9WKfdssp7WcENbzzdokB7ufxp1HiFWWom5JWYW1q4qXTq42AjueFNqJ22ye13wpWvcTavGxzfMEULwgYEbecm2c
Bitcoin Address: bc1qt3zhj6lcvxmey68w5sw6h65f327vz8x4ygks0q
```
