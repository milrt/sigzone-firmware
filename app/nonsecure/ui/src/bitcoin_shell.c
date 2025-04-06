// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "bitcoin/bitcoin_client.h"
#include "bitcoin/chains.h"
#include "bitcoin/nonsecure_bitcoin_test.h"
#include "bitcoin/psbt.h"
#include "bitcoin/psbt_result.h"
#include "bitcoin/psbt_signer.h"
#include "bitcoin/psbt_validator.h"
#include "shared/test_util.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <zephyr/logging/log.h>
#include <zephyr/shell/shell.h>
#include <zephyr/sys/base64.h>
#include <zephyr/sys/byteorder.h>

LOG_MODULE_REGISTER(bitcoin_shell);

static const char *psa_strerror(psa_status_t status);

static void print_hex_string(const struct shell *shell, const char *label, const uint8_t *data,
                             size_t len)
{
    if (!data || len == 0) {
        shell_print(shell, "%s: (empty or null)", label);
        return;
    }
    char hex_str[4096];
    memset(hex_str, 0, sizeof(hex_str));
    if (len * 2 + 1 > sizeof(hex_str)) {
        shell_error(shell, "%s: (buffer too big)", label);
        return;
    }
    for (size_t i = 0; i < len; i++) {
        snprintf(&hex_str[i * 2], 3, "%02x", data[i]);
    }
    shell_print(shell, "%s (%d bytes): %s", label, len, hex_str);
}

static int hex_str_to_bytes(const char *hex_str, uint8_t *bytes, size_t bytes_len)
{
    size_t hex_len = strlen(hex_str);
    if (hex_len != bytes_len * 2) {
        return -1;
    }
    for (size_t i = 0; i < bytes_len; i++) {
        if (sscanf(hex_str + 2 * i, "%2hhx", &bytes[i]) != 1) {
            return -1;
        }
    }
    return 0;
}

static int cmd_status(const struct shell *shell, size_t argc, char **argv)
{
    psa_status_t status = bitcoin_client_status();
    if (status == PSA_SUCCESS) {
        shell_print(shell, "Wallet exists");
    } else if (status == PSA_ERROR_DOES_NOT_EXIST) {
        shell_print(shell, "No wallet found");
    } else {
        shell_error(shell, "Error: %s", psa_strerror(status));
        return -EIO;
    }
    return 0;
}

static int cmd_create(const struct shell *shell, size_t argc, char **argv)
{
    if (argc != 2) {
        shell_error(shell, "Usage: create <entropy_size>");
        return -EINVAL;
    }

    size_t entropy_size = strtoul(argv[1], NULL, 10);

    psa_status_t status = bitcoin_client_create(entropy_size);
    if (status != PSA_SUCCESS) {
        shell_error(shell, "Create failed: %s", psa_strerror(status));
        return -EIO;
    }
    shell_print(shell, "Wallet in verifying state.");
    return 0;
}

static int cmd_recover(const struct shell *shell, size_t argc, char **argv)
{
    if (argc != 2) {
        shell_error(shell, "Usage: recover <mnemonic>");
        return -EINVAL;
    }
    const char *mnemonic = argv[1];

    psa_status_t status = bitcoin_client_recover(mnemonic);
    if (status != PSA_SUCCESS) {
        shell_error(shell, "Recover failed: %s", psa_strerror(status));
        return -EIO;
    }

    shell_print(shell, "Wallet in verifying state.");
    return 0;
}

static int cmd_verify(const struct shell *shell, size_t argc, char **argv)
{
    (void)argc;
    (void)argv;

    char mnemonic[256];
    memset(mnemonic, 0, sizeof(mnemonic));
    size_t mnemonic_len = sizeof(mnemonic);

    psa_status_t status = bitcoin_client_verify(mnemonic, &mnemonic_len);
    if (status != PSA_SUCCESS) {
        shell_error(shell, "verify failed: %s", psa_strerror(status));
        return -EIO;
    }
    shell_print(shell, "Mnemonic: %s", mnemonic);
    shell_print(shell, "Wallet in confirming state.");

    return 0;
}

static int cmd_confirm(const struct shell *shell, size_t argc, char **argv)
{
    if (argc != 3) {
        shell_error(shell, "Usage: confirm <pin> <mnemonic>");
        return -EINVAL;
    }

    const char *pin = argv[1];
    const char *mnemonic = argv[2];

    psa_status_t status = bitcoin_client_confirm(pin, mnemonic);
    if (status != PSA_SUCCESS) {
        shell_error(shell, "confirm failed: %s", psa_strerror(status));
        return -EIO;
    }
    shell_print(shell, "Confirmed and stored.");
    return 0;
}

static int cmd_destroy(const struct shell *shell, size_t argc, char **argv)
{
    if (argc != 2) {
        shell_error(shell, "Usage: destroy <pin>");
        return -EINVAL;
    }
    psa_status_t status = bitcoin_client_destroy(argv[1]);
    if (status != PSA_SUCCESS) {
        shell_error(shell, "Destroy failed: %s", psa_strerror(status));
        return -EIO;
    }
    shell_print(shell, "Wallet destroyed");
    return 0;
}

static int cmd_open(const struct shell *shell, size_t argc, char **argv)
{
    if (argc != 3) {
        shell_error(shell, "Usage: open <pin> <passphrase>");
        return -EINVAL;
    }
    psa_status_t status = bitcoin_client_open(argv[1], argv[2]);
    if (status != PSA_SUCCESS) {
        shell_error(shell, "Open failed: %s", psa_strerror(status));
        return -EIO;
    }
    shell_print(shell, "Wallet opened");
    return 0;
}

static int cmd_close(const struct shell *shell, size_t argc, char **argv)
{
    psa_status_t status = bitcoin_client_close();
    if (status != PSA_SUCCESS) {
        shell_error(shell, "Close failed: %s", psa_strerror(status));
        return -EIO;
    }
    shell_print(shell, "Wallet closed");
    return 0;
}

static int cmd_get_pubkey(const struct shell *shell, size_t argc, char **argv)
{
    if (argc != 2) {
        shell_error(shell, "Usage: get_pubkey <derivation_path>");
        return -EINVAL;
    }
    const char *path = argv[1];

    uint8_t pubkey[33];
    size_t pubkey_size = sizeof(pubkey);
    char xpub[128];
    size_t xpub_size = sizeof(xpub);

    psa_status_t status = bitcoin_client_get_pubkey(path, chains_get_bip32_pub_version(), pubkey,
                                                    &pubkey_size, xpub, &xpub_size);

    if (status != PSA_SUCCESS) {
        shell_error(shell, "Get pubkey failed: %s", psa_strerror(status));
        return -EIO;
    }

    print_hex_string(shell, "Public Key", pubkey, pubkey_size);
    shell_print(shell, "xpub: %s", xpub);

    uint8_t script[MAX_SCRIPT_LEN];
    size_t script_size = sizeof(script);

    status = chains_pubkey_to_script(pubkey, pubkey_size, script, &script_size);
    if (status != PSA_SUCCESS) {
        shell_error(shell, "Script generation failed: %s", psa_strerror(status));
        return -EIO;
    }

    char address[MAX_ADDRESS_LEN];
    size_t addr_size = sizeof(address);

    status = chains_script_to_address(script, script_size, address, &addr_size);
    if (status == PSA_SUCCESS) {
        shell_print(shell, "Bitcoin Address: %s", address);
    } else {
        shell_error(shell, "Address generation failed: %s", psa_strerror(status));
    }

    return 0;
}

static int cmd_get_fingerprint(const struct shell *shell, size_t argc, char **argv)
{
    uint8_t fingerprint[4];

    psa_status_t status = bitcoin_client_get_fingerprint(fingerprint);

    if (status != PSA_SUCCESS) {
        shell_error(shell, "Get fingerprint failed: %s", psa_strerror(status));
        return -EIO;
    }

    shell_print(shell, "Fingerprint: %02x%02x%02x%02x", fingerprint[0], fingerprint[1],
                fingerprint[2], fingerprint[3]);
    return 0;
}

static int cmd_sign_hash(const struct shell *shell, size_t argc, char **argv)
{
    if (argc != 3) {
        shell_error(shell, "Usage: sign_hash <path> <hash_hex>");
        return -EINVAL;
    }
    const char *path = argv[1];
    const char *hash_hex = argv[2];

    uint8_t hash[32];
    if (hex_str_to_bytes(hash_hex, hash, sizeof(hash))) {
        shell_error(shell, "Invalid hash (64 hex chars required)");
        return -EINVAL;
    }

    uint8_t signature[72];
    size_t sig_size = sizeof(signature);

    psa_status_t status = bitcoin_client_sign_hash(path, hash, sizeof(hash), signature, &sig_size);

    if (status != PSA_SUCCESS) {
        shell_error(shell, "Sign failed: %s", psa_strerror(status));
        return -EIO;
    }

    print_hex_string(shell, "Signature", signature, sig_size);
    return 0;
}

static int cmd_test_secure(const struct shell *shell, size_t argc, char **argv)
{
    psa_status_t status = bitcoin_client_test_run_all();
    if (status != PSA_SUCCESS) {
        shell_error(shell, "FAILED");
        return -EIO;
    }

    shell_info(shell, "PASSED");

    return 0;
}

static int cmd_test_nonsecure(const struct shell *shell, size_t argc, char **argv)
{
    test_assert_init();

    nonsecure_bitcoin_test_run_all();

    test_assert_results_t *results = test_assert_get_results();
    if (results->failure_count > 0) {
        shell_error(shell, "FAILED");
        return -EIO;
    }

    shell_info(shell, "PASSED");

    return 0;
}

static int cmd_psbt_show(const struct shell *shell, size_t argc, char **argv)
{
    if (argc != 2) {
        shell_error(shell, "Usage: psbt_show <psbt_base64>");
        return -EINVAL;
    }

    const char *psbt_base64 = argv[1];
    uint8_t psbt_raw[4096];
    size_t psbt_raw_size = 0;

    if (base64_decode(psbt_raw, sizeof(psbt_raw), &psbt_raw_size, psbt_base64,
                      strlen(psbt_base64)) != 0) {
        shell_error(shell, "Base64 decoding failed");
        return -EIO;
    }

    psbt_t psbt;
    psbt_result_t result = psbt_create_from_bin(&psbt, psbt_raw, psbt_raw_size);
    if (result != PSBT_OK) {
        shell_error(shell, "Failed to load PSBT from bin");
        return -EIO;
    }

    psbt_validation_t validation;
    if (psbt_validate(&psbt, &validation) == PSBT_OK) {
        shell_print(shell, "\nTransaction Summary:");
        shell_print(shell, "Total Input:  %llu sats", validation.total_input);
        shell_print(shell, "Total Output: %llu sats", validation.total_output);
        shell_print(shell, "Fee:          %llu sats", validation.fee);
        shell_print(shell, "Valid:        %s", validation.is_valid ? "Yes" : "No");

        psbt_validation_entry_t *entry;
        SYS_SLIST_FOR_EACH_CONTAINER(&validation.entries, entry, node)
        {
            shell_print(shell, "%s %-8s %-40s %llu sats", entry->description,
                        entry->is_change ? "[change]" : "", entry->address, entry->amount_sats);
        }
    }

    psbt_validation_free(&validation);
    psbt_free(&psbt);

    return 0;
}

static int cmd_psbt_sign(const struct shell *shell, size_t argc, char **argv)
{
    if (argc != 2) {
        shell_error(shell, "Usage: psbt_sign <psbt_base64>");
        return -EINVAL;
    }

    const char *psbt_base64 = argv[1];
    uint8_t psbt_raw[4096];
    size_t psbt_raw_size = 0;

    if (base64_decode(psbt_raw, sizeof(psbt_raw), &psbt_raw_size, psbt_base64,
                      strlen(psbt_base64)) != 0) {
        shell_error(shell, "Base64 decoding failed");
        return -EIO;
    }

    psbt_t psbt;
    psbt_result_t result = psbt_create_from_bin(&psbt, psbt_raw, psbt_raw_size);
    if (result != PSBT_OK) {
        shell_error(shell, "Failed to load PSBT from bin");
        return -EIO;
    }
    // Sign the PSBT
    psbt_result_t res = psbt_sign(&psbt);
    if (res != PSBT_OK) {
        shell_error(shell, "Signing failed");
        psbt_free(&psbt);
        return -EIO;
    }

    // Convert back to binary
    size_t psbt_size = sizeof(psbt_raw);
    if (psbt_to_bin(&psbt, psbt_raw, &psbt_size) != PSBT_OK) {
        shell_error(shell, "Failed to serialize signed PSBT");
        psbt_free(&psbt);
        return -EIO;
    }

    // Base64 encode and show result
    char b64[4096 * 2];
    size_t b64_len;
    if (base64_encode(b64, sizeof(b64), &b64_len, psbt_raw, psbt_size) != 0) {
        shell_error(shell, "Base64 encoding failed");
        psbt_free(&psbt);
        return -EIO;
    }
    shell_print(shell, "Signed PSBT: %s", b64);

    psbt_free(&psbt);
    return 0;
}

static int cmd_set_network(const struct shell *shell, size_t argc, char **argv)
{
    if (argc != 2) {
        shell_error(shell, "Usage: set_network <mainnet|testnet>");
        return -EINVAL;
    }
    if (strcmp(argv[1], "mainnet") == 0) {
        chains_set_network(BITCOIN_MAINNET);
        shell_print(shell, "Network set to Bitcoin Mainnet.");
    } else if (strcmp(argv[1], "testnet") == 0) {
        chains_set_network(BITCOIN_TESTNET);
        shell_print(shell, "Network set to Bitcoin Testnet.");
    } else {
        shell_error(shell, "Invalid network. Use 'mainnet' or 'testnet'.");
        return -EINVAL;
    }
    return 0;
}

SHELL_STATIC_SUBCMD_SET_CREATE(
    bitcoin_subcmds, SHELL_CMD_ARG(status, NULL, "Check wallet status", cmd_status, 1, 0),
    SHELL_CMD_ARG(psbt_show, NULL, "Psbt show <psbt_base64>", cmd_psbt_show, 2, 0),
    SHELL_CMD_ARG(psbt_sign, NULL, "Sign PSBT <psbt_base64>", cmd_psbt_sign, 2, 0),
    SHELL_CMD_ARG(create, NULL, "Create new wallet with <entropy_size>", cmd_create, 2, 0),
    SHELL_CMD_ARG(recover, NULL, "Recover wallet from <mnemonic>", cmd_recover, 2, 0),
    SHELL_CMD_ARG(verify, NULL, "Verify", cmd_verify, 1, 0),
    SHELL_CMD_ARG(confirm, NULL, "Confirm <pin> <mnemonic>", cmd_confirm, 3, 0),
    SHELL_CMD_ARG(destroy, NULL, "Destroy wallet <pin>", cmd_destroy, 2, 0),
    SHELL_CMD_ARG(open, NULL, "Open wallet <pin> <passphrase>", cmd_open, 3, 0),
    SHELL_CMD_ARG(close, NULL, "Close wallet", cmd_close, 1, 0),
    SHELL_CMD_ARG(get_pubkey, NULL, "Get pubkey <derivation_path>", cmd_get_pubkey, 2, 0),
    SHELL_CMD_ARG(get_fingerprint, NULL, "Get fingerprint", cmd_get_fingerprint, 1, 0),
    SHELL_CMD_ARG(sign_hash, NULL, "Sign hash <derivation_path> <hash_hex>", cmd_sign_hash, 3, 0),
    SHELL_CMD_ARG(set_network, NULL, "Set Bitcoin network <mainnet|testnet>", cmd_set_network, 2,
                  0),
    SHELL_CMD_ARG(test_secure, NULL, "Run secure tests", cmd_test_secure, 1, 0),
    SHELL_CMD_ARG(test_nonsecure, NULL, "Run non-secure tests", cmd_test_nonsecure, 1, 0),
    SHELL_SUBCMD_SET_END);

SHELL_CMD_REGISTER(bitcoin, &bitcoin_subcmds, "Bitcoin Hardware Wallet Commands", NULL);

static const char *psa_strerror(psa_status_t status)
{
    switch (status) {
    case PSA_ERROR_ALREADY_EXISTS:
        return "PSA_ERROR_ALREADY_EXISTS";
    case PSA_ERROR_BAD_STATE:
        return "PSA_ERROR_BAD_STATE";
    case PSA_ERROR_BUFFER_TOO_SMALL:
        return "PSA_ERROR_BUFFER_TOO_SMALL";
    case PSA_ERROR_COMMUNICATION_FAILURE:
        return "PSA_ERROR_COMMUNICATION_FAILURE";
    case PSA_ERROR_CORRUPTION_DETECTED:
        return "PSA_ERROR_CORRUPTION_DETECTED";
    case PSA_ERROR_DATA_CORRUPT:
        return "PSA_ERROR_DATA_CORRUPT";
    case PSA_ERROR_DATA_INVALID:
        return "PSA_ERROR_DATA_INVALID";
    case PSA_ERROR_DOES_NOT_EXIST:
        return "PSA_ERROR_DOES_NOT_EXIST";
    case PSA_ERROR_GENERIC_ERROR:
        return "PSA_ERROR_GENERIC_ERROR";
    case PSA_ERROR_HARDWARE_FAILURE:
        return "PSA_ERROR_HARDWARE_FAILURE";
    case PSA_ERROR_INSUFFICIENT_DATA:
        return "PSA_ERROR_INSUFFICIENT_DATA";
    case PSA_ERROR_INSUFFICIENT_ENTROPY:
        return "PSA_ERROR_INSUFFICIENT_ENTROPY";
    case PSA_ERROR_INSUFFICIENT_MEMORY:
        return "PSA_ERROR_INSUFFICIENT_MEMORY";
    case PSA_ERROR_INSUFFICIENT_STORAGE:
        return "PSA_ERROR_INSUFFICIENT_STORAGE";
    case PSA_ERROR_INVALID_ARGUMENT:
        return "PSA_ERROR_INVALID_ARGUMENT";
    case PSA_ERROR_INVALID_HANDLE:
        return "PSA_ERROR_INVALID_HANDLE";
    case PSA_ERROR_INVALID_PADDING:
        return "PSA_ERROR_INVALID_PADDING";
    case PSA_ERROR_INVALID_SIGNATURE:
        return "PSA_ERROR_INVALID_SIGNATURE";
    case PSA_ERROR_NOT_PERMITTED:
        return "PSA_ERROR_NOT_PERMITTED";
    case PSA_ERROR_NOT_SUPPORTED:
        return "PSA_ERROR_NOT_SUPPORTED";
    case PSA_ERROR_SERVICE_FAILURE:
        return "PSA_ERROR_SERVICE_FAILURE";
    case PSA_ERROR_STORAGE_FAILURE:
        return "PSA_ERROR_STORAGE_FAILURE";
    case PSA_SUCCESS:
        return "PSA_SUCCESS";
    default:
        return NULL;
    }
}
