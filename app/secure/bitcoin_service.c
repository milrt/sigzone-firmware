// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "bitcoin/bitcoin_core.h"
#include "bitcoin/secure_bitcoin_test.h"
#include "shared/bitcoin_service_defs.h"
#include <psa/service.h>
#include <psa_manifest/tfm_bitcoin_partition.h>

// Minimal sbrk workaround for secp256k1
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
    return bitcoin_core_recover(mnemonic_buf);
}

struct verify_mnemonic_ctx {
    char *out;
    size_t out_buf_size;
    size_t actual_size;
};

static void verify_mnemonic_writer(void *h, const char *str, size_t str_size)
{
    struct verify_mnemonic_ctx *ctx = (struct verify_mnemonic_ctx *)h;
    if (str_size <= ctx->out_buf_size) {
        memcpy(ctx->out, str, str_size);
        ctx->actual_size = str_size;
    }
}

static psa_status_t tfm_bitcoin_verify_mnemonic_ipc(psa_msg_t *msg)
{
    size_t out_size = msg->out_size[0];
    char local_buf[256] = {0};

    struct verify_mnemonic_ctx ctx = {
        .out = local_buf, .out_buf_size = sizeof(local_buf), .actual_size = 0};

    psa_status_t status = bitcoin_core_verify(verify_mnemonic_writer, &ctx);
    if (status != PSA_SUCCESS) {
        return status;
    }

    if (ctx.actual_size > out_size) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    psa_write(msg->handle, 0, local_buf, ctx.actual_size);
    return PSA_SUCCESS;
}

static psa_status_t tfm_bitcoin_confirm_mnemonic_ipc(psa_msg_t *msg)
{
    char pin_buf[64] = {0};
    char mnemonic_buf[256] = {0};

    read_string_arg(msg, 0, pin_buf, sizeof(pin_buf));
    read_string_arg(msg, 1, mnemonic_buf, sizeof(mnemonic_buf));

    return bitcoin_core_confirm(pin_buf, mnemonic_buf);
}

static psa_status_t tfm_bitcoin_destroy_ipc(psa_msg_t *msg)
{
    char pin_buf[64] = {0};
    read_string_arg(msg, 0, pin_buf, sizeof(pin_buf));
    return bitcoin_core_destroy(pin_buf);
}

static psa_status_t tfm_bitcoin_open_ipc(psa_msg_t *msg)
{
    char pin_buf[64] = {0}, passphrase_buf[128] = {0};
    read_string_arg(msg, 0, pin_buf, sizeof(pin_buf));
    read_string_arg(msg, 1, passphrase_buf, sizeof(passphrase_buf));
    return bitcoin_core_open(pin_buf, passphrase_buf);
}

static psa_status_t tfm_bitcoin_close_ipc(psa_msg_t *msg)
{
    (void)msg;
    return bitcoin_core_close();
}

struct get_pubkey_ctx {
    uint8_t *pubkey;
    size_t pubkey_buf_size;
    size_t actual_pubkey_size;
    char *xpub;
    size_t xpub_buf_size;
    size_t actual_xpub_len;
};

static void pubkey_writer(void *h, const uint8_t *buf, size_t size)
{
    struct get_pubkey_ctx *ctx = h;
    if (size <= ctx->pubkey_buf_size) {
        memcpy(ctx->pubkey, buf, size);
        ctx->actual_pubkey_size = size;
    }
}

static void xpub_writer(void *h, const char *str, size_t str_size)
{
    struct get_pubkey_ctx *ctx = h;
    if (str_size <= ctx->xpub_buf_size) {
        memcpy(ctx->xpub, str, str_size);
        ctx->actual_xpub_len = str_size;
    }
}

static psa_status_t tfm_bitcoin_get_pubkey_ipc(psa_msg_t *msg)
{
    char path_buf[128] = {0};
    psa_read(msg->handle, 0, path_buf, sizeof(path_buf) - 1);

    size_t pubkey_size = msg->out_size[0];
    size_t xpub_buf_size = msg->out_size[1];

    uint8_t pubkey_local[64] = {0};
    char xpub_local[128] = {0};

    struct get_pubkey_ctx ctx = {0};
    ctx.pubkey = pubkey_local;
    ctx.pubkey_buf_size = sizeof(pubkey_local);
    ctx.xpub = xpub_local;
    ctx.xpub_buf_size = sizeof(xpub_local);

    psa_status_t status = bitcoin_core_get_pubkey(path_buf, &ctx.actual_pubkey_size, pubkey_writer,
                                                  xpub_writer, &ctx);
    if (status != PSA_SUCCESS) {
        return status;
    }

    if (ctx.actual_pubkey_size > pubkey_size) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }
    psa_write(msg->handle, 0, pubkey_local, ctx.actual_pubkey_size);

    if (ctx.actual_xpub_len == 0) {
        ctx.actual_xpub_len = strlen(xpub_local) + 1;
    }
    if (ctx.actual_xpub_len > xpub_buf_size) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }
    psa_write(msg->handle, 1, xpub_local, ctx.actual_xpub_len);

    return PSA_SUCCESS;
}

struct sign_hash_ctx {
    uint8_t *hash_ptr;
    size_t hash_len;
    uint8_t *der_ptr;
    size_t der_buf_size;
    size_t actual_sig_size;
};

static size_t signhash_read_hash(void *h, uint8_t *out, size_t out_size)
{
    struct sign_hash_ctx *ctx = h;
    if (out_size >= ctx->hash_len) {
        memcpy(out, ctx->hash_ptr, ctx->hash_len);
        return ctx->hash_len;
    }
    return 0;
}

static void signhash_write_sig(void *h, const uint8_t *buf, size_t size)
{
    struct sign_hash_ctx *ctx = h;
    if (size <= ctx->der_buf_size) {
        memcpy(ctx->der_ptr, buf, size);
        ctx->actual_sig_size = size;
    }
}

static psa_status_t tfm_bitcoin_sign_hash_ipc(psa_msg_t *msg)
{
    char path_buf[128] = {0};
    psa_read(msg->handle, 0, path_buf, sizeof(path_buf) - 1);

    uint8_t hash_buf[32] = {0};
    if (psa_read(msg->handle, 1, hash_buf, sizeof(hash_buf)) != 32) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    uint8_t der_local[80] = {0};
    size_t der_buf_size = msg->out_size[0];

    struct sign_hash_ctx ctx = {0};
    ctx.hash_ptr = hash_buf;
    ctx.hash_len = 32;
    ctx.der_ptr = der_local;
    ctx.der_buf_size = sizeof(der_local);
    ctx.actual_sig_size = sizeof(der_local);

    psa_status_t status = bitcoin_core_sign_hash(path_buf, signhash_read_hash, &ctx.actual_sig_size,
                                                 signhash_write_sig, &ctx);
    if (status != PSA_SUCCESS) {
        return status;
    }
    if (ctx.actual_sig_size > der_buf_size) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }
    psa_write(msg->handle, 0, der_local, ctx.actual_sig_size);
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
