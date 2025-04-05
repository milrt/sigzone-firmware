// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "bitcoin/bitcoin_core.h"
#include "bitcoin/secure_bitcoin_test.h"
#include "shared/bitcoin_service_defs.h"
#include <psa/service.h>
#include <psa_manifest/tfm_bitcoin_partition.h>

// sbrk workaround for secp256k1
void *_sbrk(ptrdiff_t incr)
{
    return NULL;
}

static void read_string_arg(psa_msg_t *msg, uint32_t index, char *out_buf, size_t out_buf_size)
{
    size_t bytes_read = psa_read(msg->handle, index, out_buf, out_buf_size - 1);
    out_buf[bytes_read] = '\0';
}

static psa_status_t tfm_bitcoin_status_ipc(psa_msg_t *msg)
{
    (void)msg;
    return bitcoin_core_status();
}

static psa_status_t tfm_bitcoin_create_ipc(psa_msg_t *msg)
{
    size_t entropy_size = 0;

    if (psa_read(msg->handle, 0, &entropy_size, sizeof(entropy_size)) != sizeof(entropy_size)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    return bitcoin_core_create(entropy_size);
}

static psa_status_t tfm_bitcoin_recover_ipc(psa_msg_t *msg)
{
    char mnemonic_buf[256] = {0};

    read_string_arg(msg, 0, mnemonic_buf, sizeof(mnemonic_buf));
    psa_status_t status = bitcoin_core_recover(mnemonic_buf);

    mbedtls_platform_zeroize(mnemonic_buf, sizeof(mnemonic_buf));
    return status;
}

static psa_status_t tfm_bitcoin_verify_mnemonic_ipc(psa_msg_t *msg)
{
    char mnemonic[256] = {0};
    const size_t out_size = msg->out_size[0];
    psa_status_t status;

    status = bitcoin_core_verify(mnemonic, sizeof(mnemonic));
    if (status != PSA_SUCCESS) {
        mbedtls_platform_zeroize(mnemonic, sizeof(mnemonic));
        return status;
    }

    const size_t mnemonic_len = strlen(mnemonic) + 1;
    if (out_size < mnemonic_len) {
        mbedtls_platform_zeroize(mnemonic, sizeof(mnemonic));
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    psa_write(msg->handle, 0, mnemonic, mnemonic_len);

    mbedtls_platform_zeroize(mnemonic, sizeof(mnemonic));
    return PSA_SUCCESS;
}

static psa_status_t tfm_bitcoin_confirm_mnemonic_ipc(psa_msg_t *msg)
{
    char pin_buf[64] = {0};
    char mnemonic_buf[256] = {0};

    read_string_arg(msg, 0, pin_buf, sizeof(pin_buf));
    read_string_arg(msg, 1, mnemonic_buf, sizeof(mnemonic_buf));

    psa_status_t status = bitcoin_core_confirm(pin_buf, mnemonic_buf);

    mbedtls_platform_zeroize(pin_buf, sizeof(pin_buf));
    mbedtls_platform_zeroize(mnemonic_buf, sizeof(mnemonic_buf));
    return status;
}

static psa_status_t tfm_bitcoin_get_pubkey_ipc(psa_msg_t *msg)
{
    char path_buf[128] = {0};
    uint32_t version = 0;
    uint8_t pubkey[33] = {0};
    char xpub[113] = {0};
    size_t pubkey_size = sizeof(pubkey);
    const size_t xpub_size = sizeof(xpub);

    // Read inputs
    psa_read(msg->handle, 0, path_buf, sizeof(path_buf));
    psa_read(msg->handle, 1, &version, sizeof(version));

    // Get pubkeys
    psa_status_t status =
        bitcoin_core_get_pubkey(path_buf, version, pubkey, &pubkey_size, xpub, xpub_size);

    mbedtls_platform_zeroize(path_buf, sizeof(path_buf));

    if (status != PSA_SUCCESS) {
        mbedtls_platform_zeroize(pubkey, sizeof(pubkey));
        mbedtls_platform_zeroize(xpub, sizeof(xpub));
        return status;
    }

    // Write outputs
    if (msg->out_size[0] < pubkey_size) {
        mbedtls_platform_zeroize(pubkey, sizeof(pubkey));
        mbedtls_platform_zeroize(xpub, sizeof(xpub));
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }
    psa_write(msg->handle, 0, pubkey, pubkey_size);

    const size_t xpub_len = strlen(xpub) + 1;
    if (msg->out_size[1] < xpub_len) {
        mbedtls_platform_zeroize(pubkey, sizeof(pubkey));
        mbedtls_platform_zeroize(xpub, sizeof(xpub));
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }
    psa_write(msg->handle, 1, xpub, xpub_len);

    mbedtls_platform_zeroize(pubkey, sizeof(pubkey));
    mbedtls_platform_zeroize(xpub, sizeof(xpub));
    return PSA_SUCCESS;
}

static psa_status_t tfm_bitcoin_destroy_ipc(psa_msg_t *msg)
{
    char pin_buf[64] = {0};
    read_string_arg(msg, 0, pin_buf, sizeof(pin_buf));

    psa_status_t status = bitcoin_core_destroy(pin_buf);

    mbedtls_platform_zeroize(pin_buf, sizeof(pin_buf));
    return status;
}

static psa_status_t tfm_bitcoin_open_ipc(psa_msg_t *msg)
{
    char pin_buf[64] = {0}, passphrase_buf[128] = {0};
    read_string_arg(msg, 0, pin_buf, sizeof(pin_buf));
    read_string_arg(msg, 1, passphrase_buf, sizeof(passphrase_buf));

    psa_status_t status = bitcoin_core_open(pin_buf, passphrase_buf);

    mbedtls_platform_zeroize(pin_buf, sizeof(pin_buf));
    mbedtls_platform_zeroize(passphrase_buf, sizeof(passphrase_buf));
    return status;
}

static psa_status_t tfm_bitcoin_close_ipc(psa_msg_t *msg)
{
    (void)msg;
    return bitcoin_core_close();
}

static psa_status_t tfm_bitcoin_sign_hash_ipc(psa_msg_t *msg)
{
    char path_buf[128] = {0};
    uint8_t hash[32] = {0};
    uint8_t signature[72] = {0};
    size_t signature_size = sizeof(signature);

    // Read inputs
    psa_read(msg->handle, 0, path_buf, sizeof(path_buf));
    if (psa_read(msg->handle, 1, hash, sizeof(hash)) != sizeof(hash)) {
        mbedtls_platform_zeroize(hash, sizeof(hash));
        mbedtls_platform_zeroize(path_buf, sizeof(path_buf));
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    // Sign hash
    psa_status_t status =
        bitcoin_core_sign_hash(path_buf, hash, sizeof(hash), signature, &signature_size);

    mbedtls_platform_zeroize(hash, sizeof(hash));
    mbedtls_platform_zeroize(path_buf, sizeof(path_buf));

    if (status != PSA_SUCCESS) {
        mbedtls_platform_zeroize(signature, sizeof(signature));
        return status;
    }

    // Write output
    if (msg->out_size[0] < signature_size) {
        mbedtls_platform_zeroize(signature, sizeof(signature));
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }
    psa_write(msg->handle, 0, signature, signature_size);

    mbedtls_platform_zeroize(signature, sizeof(signature));
    return PSA_SUCCESS;
}

static psa_status_t tfm_bitcoin_get_fingerprint_ipc(psa_msg_t *msg)
{
    uint8_t fingerprint[4] = {0};
    size_t fingerprint_size = sizeof(fingerprint);

    psa_status_t status = bitcoin_core_get_fingerprint(fingerprint, &fingerprint_size);
    if (status != PSA_SUCCESS) {
        return status;
    }

    if (msg->out_size[0] < fingerprint_size) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }
    psa_write(msg->handle, 0, fingerprint, fingerprint_size);
    return PSA_SUCCESS;
}

static psa_status_t tfm_bitcoin_test_run_ipc(psa_msg_t *msg)
{
    (void)msg;
    return secure_bitcoin_test_run_all();
}

static void handle_bitcoin_signal(psa_msg_t *msg)
{
    psa_status_t rc;
    switch (msg->type) {
    case PSA_IPC_CONNECT:
        psa_reply(msg->handle, PSA_SUCCESS);
        break;
    case TFM_BITCOIN_STATUS:
        rc = tfm_bitcoin_status_ipc(msg);
        psa_reply(msg->handle, rc);
        break;
    case TFM_BITCOIN_CREATE:
        rc = tfm_bitcoin_create_ipc(msg);
        psa_reply(msg->handle, rc);
        break;
    case TFM_BITCOIN_DESTROY:
        rc = tfm_bitcoin_destroy_ipc(msg);
        psa_reply(msg->handle, rc);
        break;
    case TFM_BITCOIN_OPEN:
        rc = tfm_bitcoin_open_ipc(msg);
        psa_reply(msg->handle, rc);
        break;
    case TFM_BITCOIN_CLOSE:
        rc = tfm_bitcoin_close_ipc(msg);
        psa_reply(msg->handle, rc);
        break;
    case TFM_BITCOIN_GET_PUBKEY:
        rc = tfm_bitcoin_get_pubkey_ipc(msg);
        psa_reply(msg->handle, rc);
        break;
    case TFM_BITCOIN_SIGN_HASH:
        rc = tfm_bitcoin_sign_hash_ipc(msg);
        psa_reply(msg->handle, rc);
        break;
    case TFM_BITCOIN_RECOVER:
        rc = tfm_bitcoin_recover_ipc(msg);
        psa_reply(msg->handle, rc);
        break;
    case TFM_BITCOIN_VERIFY:
        rc = tfm_bitcoin_verify_mnemonic_ipc(msg);
        psa_reply(msg->handle, rc);
        break;
    case TFM_BITCOIN_CONFIRM:
        rc = tfm_bitcoin_confirm_mnemonic_ipc(msg);
        psa_reply(msg->handle, rc);
        break;
    case TFM_BITCOIN_GET_FINGERPRINT:
        rc = tfm_bitcoin_get_fingerprint_ipc(msg);
        psa_reply(msg->handle, rc);
        break;
    case PSA_IPC_DISCONNECT:
        psa_reply(msg->handle, PSA_SUCCESS);
        break;
    default:
        psa_panic();
        break;
    }
}

static void handle_bitcoin_test_signal(psa_msg_t *msg)
{
    psa_status_t rc;
    switch (msg->type) {
    case PSA_IPC_CONNECT:
        psa_reply(msg->handle, PSA_SUCCESS);
        break;
    case TFM_BITCOIN_TEST_RUN:
        rc = tfm_bitcoin_test_run_ipc(msg);
        psa_reply(msg->handle, rc);
        break;
    case PSA_IPC_DISCONNECT:
        psa_reply(msg->handle, PSA_SUCCESS);
        break;
    default:
        psa_panic();
        break;
    }
}

void tfm_bitcoin_init(void)
{
    while (1) {
        psa_signal_t signal = psa_wait(PSA_WAIT_ANY, PSA_BLOCK);
        psa_msg_t msg;
        if (signal & TFM_BITCOIN_SIGNAL) {
            if (psa_get(TFM_BITCOIN_SIGNAL, &msg) != PSA_SUCCESS) {
                psa_panic();
            }
            handle_bitcoin_signal(&msg);
        } else if (signal & TFM_BITCOIN_TEST_SIGNAL) {
            if (psa_get(TFM_BITCOIN_TEST_SIGNAL, &msg) != PSA_SUCCESS) {
                psa_panic();
            }
            handle_bitcoin_test_signal(&msg);
        } else {
            psa_panic();
        }
    }
}
