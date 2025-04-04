// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "bitcoin/bitcoin_client.h"
#include "psa_manifest/sid.h"
#include "shared/bitcoin_service_defs.h"
#include <psa/client.h>
#include <string.h>

psa_status_t bitcoin_client_status(void)
{
    psa_handle_t handle = psa_connect(TFM_BITCOIN_SID, TFM_BITCOIN_VERSION);
    if (!PSA_HANDLE_IS_VALID(handle)) {
        return PSA_ERROR_GENERIC_ERROR;
    }

    psa_status_t status = psa_call(handle, TFM_BITCOIN_STATUS, NULL, 0, NULL, 0);
    psa_close(handle);
    return status;
}

psa_status_t bitcoin_client_create(size_t entropy_size)
{
    psa_handle_t handle = psa_connect(TFM_BITCOIN_SID, TFM_BITCOIN_VERSION);
    if (!PSA_HANDLE_IS_VALID(handle)) {
        return PSA_ERROR_GENERIC_ERROR;
    }

    psa_invec in_vec[] = {{.base = &entropy_size, .len = sizeof(entropy_size)}};

    psa_status_t status = psa_call(handle, TFM_BITCOIN_CREATE, in_vec, IOVEC_LEN(in_vec), NULL, 0);

    psa_close(handle);
    return status;
}

psa_status_t bitcoin_client_recover(const char *mnemonic)
{
    psa_handle_t handle = psa_connect(TFM_BITCOIN_SID, TFM_BITCOIN_VERSION);
    if (!PSA_HANDLE_IS_VALID(handle)) {
        return PSA_ERROR_GENERIC_ERROR;
    }

    psa_invec in_vec[] = {{.base = mnemonic, .len = (mnemonic == NULL ? 0 : strlen(mnemonic) + 1)}};

    psa_status_t status = psa_call(handle, TFM_BITCOIN_RECOVER, in_vec, IOVEC_LEN(in_vec), NULL, 0);

    psa_close(handle);
    return status;
}

psa_status_t bitcoin_client_verify(char *mnemonic_out, size_t *mnemonic_out_len)
{
    if (!mnemonic_out || !mnemonic_out_len || *mnemonic_out_len == 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    psa_handle_t handle = psa_connect(TFM_BITCOIN_SID, TFM_BITCOIN_VERSION);
    if (!PSA_HANDLE_IS_VALID(handle)) {
        return PSA_ERROR_GENERIC_ERROR;
    }

    psa_invec in_vec[] = {};
    psa_outvec out_vec[] = {{.base = mnemonic_out, .len = *mnemonic_out_len}};

    psa_status_t status =
        psa_call(handle, TFM_BITCOIN_VERIFY, in_vec, 0, out_vec, IOVEC_LEN(out_vec));

    if (status == PSA_SUCCESS) {
        *mnemonic_out_len = out_vec[0].len;
    }
    psa_close(handle);
    return status;
}

psa_status_t bitcoin_client_confirm(const char *pin, const char *mnemonic)
{
    if (!pin || !mnemonic) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    psa_handle_t handle = psa_connect(TFM_BITCOIN_SID, TFM_BITCOIN_VERSION);
    if (!PSA_HANDLE_IS_VALID(handle)) {
        return PSA_ERROR_GENERIC_ERROR;
    }

    psa_invec in_vec[] = {
        {.base = pin, .len = strlen(pin) + 1},
        {.base = mnemonic, .len = strlen(mnemonic) + 1},
    };

    psa_status_t status = psa_call(handle, TFM_BITCOIN_CONFIRM, in_vec, IOVEC_LEN(in_vec), NULL, 0);

    psa_close(handle);
    return status;
}

psa_status_t bitcoin_client_destroy(const char *pin)
{
    psa_handle_t handle = psa_connect(TFM_BITCOIN_SID, TFM_BITCOIN_VERSION);
    if (!PSA_HANDLE_IS_VALID(handle)) {
        return PSA_ERROR_GENERIC_ERROR;
    }

    psa_invec in_vec[] = {
        {.base = pin, .len = (pin == NULL ? 0 : strlen(pin) + 1)},
    };

    psa_status_t status = psa_call(handle, TFM_BITCOIN_DESTROY, in_vec, IOVEC_LEN(in_vec), NULL, 0);
    psa_close(handle);
    return status;
}

psa_status_t bitcoin_client_open(const char *pin, const char *passphrase)
{
    psa_handle_t handle = psa_connect(TFM_BITCOIN_SID, TFM_BITCOIN_VERSION);
    if (!PSA_HANDLE_IS_VALID(handle)) {
        return PSA_ERROR_GENERIC_ERROR;
    }

    psa_invec in_vec[] = {
        {.base = pin, .len = (pin ? strlen(pin) + 1 : 0)},
        {.base = passphrase, .len = (passphrase ? strlen(passphrase) + 1 : 0)},
    };

    psa_status_t status = psa_call(handle, TFM_BITCOIN_OPEN, in_vec, IOVEC_LEN(in_vec), NULL, 0);
    psa_close(handle);
    return status;
}

psa_status_t bitcoin_client_close(void)
{
    psa_handle_t handle = psa_connect(TFM_BITCOIN_SID, TFM_BITCOIN_VERSION);
    if (!PSA_HANDLE_IS_VALID(handle)) {
        return PSA_ERROR_GENERIC_ERROR;
    }

    psa_status_t status = psa_call(handle, TFM_BITCOIN_CLOSE, NULL, 0, NULL, 0);
    psa_close(handle);
    return status;
}

psa_status_t bitcoin_client_get_pubkey(const char *derivation_path, uint32_t version,
                                       uint8_t *pubkey_out, size_t *pubkey_size, char *xpub_out,
                                       size_t *xpub_size)
{
    if (!pubkey_out || !pubkey_size || !xpub_out || !xpub_size) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    psa_handle_t handle = psa_connect(TFM_BITCOIN_SID, TFM_BITCOIN_VERSION);
    if (!PSA_HANDLE_IS_VALID(handle)) {
        return PSA_ERROR_GENERIC_ERROR;
    }

    psa_invec in_vec[] = {
        {.base = derivation_path, .len = (derivation_path ? strlen(derivation_path) + 1 : 0)},
        {.base = &version, .len = sizeof(version)},
    };

    psa_outvec out_vec[] = {
        {.base = pubkey_out, .len = *pubkey_size},
        {.base = xpub_out, .len = *xpub_size},
    };

    psa_status_t status = psa_call(handle, TFM_BITCOIN_GET_PUBKEY, in_vec, IOVEC_LEN(in_vec),
                                   out_vec, IOVEC_LEN(out_vec));

    // Update returned sizes
    *pubkey_size = out_vec[0].len;
    *xpub_size = out_vec[1].len;

    psa_close(handle);
    return status;
}

psa_status_t bitcoin_client_sign_hash(const char *derivation_path, const uint8_t *hash32,
                                      size_t hash_size, uint8_t *signature_der,
                                      size_t *signature_size)
{
    if (!derivation_path || !hash32 || hash_size != 32 || !signature_der || !signature_size) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    psa_handle_t handle = psa_connect(TFM_BITCOIN_SID, TFM_BITCOIN_VERSION);
    if (!PSA_HANDLE_IS_VALID(handle)) {
        return PSA_ERROR_GENERIC_ERROR;
    }

    psa_invec in_vec[] = {
        {.base = derivation_path, .len = strlen(derivation_path) + 1},
        {.base = hash32, .len = hash_size},
    };

    psa_outvec out_vec[] = {
        {.base = signature_der, .len = *signature_size},
    };

    psa_status_t status = psa_call(handle, TFM_BITCOIN_SIGN_HASH, in_vec, IOVEC_LEN(in_vec),
                                   out_vec, IOVEC_LEN(out_vec));

    *signature_size = out_vec[0].len;

    psa_close(handle);
    return status;
}

psa_status_t bitcoin_client_get_fingerprint(uint8_t *fingerprint)
{
    if (!fingerprint) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    psa_handle_t handle = psa_connect(TFM_BITCOIN_SID, TFM_BITCOIN_VERSION);
    if (!PSA_HANDLE_IS_VALID(handle)) {
        return PSA_ERROR_GENERIC_ERROR;
    }

    psa_invec in_vec[] = {};
    psa_outvec out_vec[] = {
        {.base = fingerprint, .len = 4},
    };

    psa_status_t status = psa_call(handle, TFM_BITCOIN_GET_FINGERPRINT, in_vec, 0, out_vec, 1);

    psa_close(handle);
    return status;
}

psa_status_t bitcoin_client_test_run_all(void)
{
    psa_handle_t handle = psa_connect(TFM_BITCOIN_TEST_SID, TFM_BITCOIN_TEST_VERSION);
    if (!PSA_HANDLE_IS_VALID(handle)) {
        return PSA_ERROR_GENERIC_ERROR;
    }

    psa_status_t status = psa_call(handle, TFM_BITCOIN_TEST_RUN, NULL, 0, NULL, 0);
    psa_close(handle);
    return status;
}
