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
sigzone:~$ bitcoin create 16
Wallet in verifying state.
sigzone:~$ bitcoin verify
Mnemonic: hint erupt enrich scale radio scout assault debate forest hotel upon course
Wallet in confirming state.
sigzone:~$ bitcoin confirm 1234 "hint erupt enrich scale radio scout assault debate forest hotel upon course"
Confirmed and stored.
sigzone:~$ bitcoin open 1234 "passphrase"
Wallet opened
bitcoin get_pubkey m/84h/0h/0h/0/0
Public Key (33 bytes): 02cdf39e4393e4d82a1ad985cbcf5ecfe94e392c8df3aea11c68c00eaca44146d6
xpub: xpub6FmSxutVLKCcUA6gWXUof4xhk77j68U2FfMQqSFCMeS4cwTbcuruaKGpkpQLcpPRV8HQauuSfUo1cYJ4i17vqVgEQg67Kane2gj7AYbWcyK
Bitcoin Address: bc1q6tazls7z6sv77wg2pr0j9h0nfsqwtlz3f0k9q4
```
