// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "bitcoin/psbt_signer.h"
#include "bitcoin/bitcoin_client.h"
#include "bitcoin/psbt.h"
#include "bitcoin/psbt_result.h"
#include "bitcoin/psbt_tx.h"
#include "psbt_compactsize.h"
#include "psbt_heap.h"
#include "shared/hash.h"
#include <psa/crypto.h>
#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/byteorder.h>

LOG_MODULE_REGISTER(psbt_signer);

#define SIGHASH_ALL 0x01
#define SIGHASH_NONE 0x02
#define SIGHASH_SINGLE 0x03
#define SIGHASH_ANYONECANPAY 0x80
#define MAX_INPUTS 5

/* Parse BIP32 derivation path and format as a string (e.g. "m/44'/0'/0'/0") */
static psbt_result_t parse_derivation_path(const uint8_t *value_data, size_t value_len,
                                           char *path_str, size_t path_size)
{
    if (value_len < 4 || ((value_len - 4) % 4 != 0)) {
        return PSBT_READ_ERROR;
    }

    const uint8_t *ptr = value_data + 4;
    size_t num_elements = (value_len - 4) / 4;
    char *p = path_str;
    size_t remaining = path_size;
    int written = snprintf(p, remaining, "m");
    if (written < 0 || (size_t)written >= remaining) {
        return PSBT_OOB_WRITE;
    }

    p += written;
    remaining -= written;
    for (size_t i = 0; i < num_elements; i++) {
        uint32_t num = sys_get_le32(ptr);
        ptr += 4;
        written = snprintf(p, remaining, "/%u%s", num & 0x7FFFFFFF, (num & 0x80000000) ? "'" : "");
        if (written < 0 || (size_t)written >= remaining) {
            return PSBT_OOB_WRITE;
        }
        p += written;
        remaining -= written;
    }
    return PSBT_OK;
}

/* Helper: Compute double SHA256 over previous outputs */
static psbt_result_t calc_hash_prevouts(const psbt_tx_t *tx, uint8_t *hash_prevouts)
{
    uint8_t buffer[36 * MAX_INPUTS];
    uint8_t *p = buffer;

    for (size_t i = 0; i < tx->num_inputs; i++) {
        const psbt_txin_t *in = &tx->inputs[i];
        if (!in || !in->txid) {
            LOG_ERR("Invalid transaction input or missing txid");
            return PSBT_OOB_WRITE;
        }
        memcpy(p, in->txid, 32);
        p += 32;
        sys_put_le32(in->index, p);
        p += 4;
    }

    if (hash_doubleSha256(buffer, p - buffer, hash_prevouts, 32) != PSA_SUCCESS) {
        return PSBT_OOB_WRITE;
    }
    return PSBT_OK;
}

/* Helper: Compute double SHA256 over input sequences */
static psbt_result_t calc_hash_sequence(const psbt_tx_t *tx, uint8_t *hash_sequence)
{
    uint8_t buffer[4 * MAX_INPUTS];
    uint8_t *p = buffer;

    for (size_t i = 0; i < tx->num_inputs; i++) {
        sys_put_le32(tx->inputs[i].sequence, p);
        p += 4;
    }

    if (hash_doubleSha256(buffer, p - buffer, hash_sequence, 32) != PSA_SUCCESS) {
        return PSBT_OOB_WRITE;
    }
    return PSBT_OK;
}

/* Helper: Compute double SHA256 over transaction outputs */
static psbt_result_t calc_hash_outputs(const psbt_tx_t *tx, uint8_t *hash_outputs)
{
    uint8_t buffer[1024];
    uint8_t *p = buffer;
    size_t remaining = sizeof(buffer);

    for (size_t i = 0; i < tx->num_outputs; i++) {
        const psbt_txout_t *out = &tx->outputs[i];
        sys_put_le64(out->amount, p);
        p += 8;
        remaining -= 8;

        compactsize_data_t script = {.size = out->script_len, .data = out->script};
        if (!compactsize_write_with_data(&p, &remaining, &script)) {
            return PSBT_OOB_WRITE;
        }
    }

    if (hash_doubleSha256(buffer, p - buffer, hash_outputs, 32) != PSA_SUCCESS) {
        return PSBT_OOB_WRITE;
    }
    return PSBT_OK;
}

/* Compute the sighash for a given input following BIP143 */
static psbt_result_t compute_sighash(const psbt_tx_t *tx, size_t input_index,
                                     const uint8_t *script_code, size_t script_code_len,
                                     uint64_t amount, uint32_t sighash_type, uint8_t *sighash_out)
{
    uint8_t hash_prevouts[32] = {0};
    uint8_t hash_sequence[32] = {0};
    uint8_t hash_outputs[32] = {0};

    if ((sighash_type & SIGHASH_ANYONECANPAY) == 0) {
        psbt_result_t res = calc_hash_prevouts(tx, hash_prevouts);
        if (res != PSBT_OK) {
            return res;
        }
    }

    if ((sighash_type & SIGHASH_ANYONECANPAY) == 0 && (sighash_type & 0x1f) != SIGHASH_SINGLE &&
        (sighash_type & 0x1f) != SIGHASH_NONE) {
        psbt_result_t res = calc_hash_sequence(tx, hash_sequence);
        if (res != PSBT_OK) {
            return res;
        }
    }

    if ((sighash_type & 0x1f) == SIGHASH_ALL) {
        psbt_result_t res = calc_hash_outputs(tx, hash_outputs);
        if (res != PSBT_OK) {
            return res;
        }
    } else if ((sighash_type & 0x1f) == SIGHASH_SINGLE && input_index < tx->num_outputs) {
        /* SINGLE case handling omitted for brevity */
    }

    uint8_t buffer[1024];
    uint8_t *dest = buffer;
    size_t remaining = sizeof(buffer);

    sys_put_le32(tx->version, dest);
    dest += 4;
    remaining -= 4;

    memcpy(dest, hash_prevouts, 32);
    dest += 32;
    remaining -= 32;

    memcpy(dest, hash_sequence, 32);
    dest += 32;
    remaining -= 32;

    const psbt_txin_t *in = &tx->inputs[input_index];
    memcpy(dest, in->txid, 32);
    dest += 32;
    remaining -= 32;

    sys_put_le32(in->index, dest);
    dest += 4;
    remaining -= 4;

    compactsize_data_t sc_data = {.size = script_code_len, .data = script_code};
    if (!compactsize_write_with_data(&dest, &remaining, &sc_data)) {
        LOG_ERR("Failed to write scriptCode with compactsize");
        return PSBT_OOB_WRITE;
    }

    sys_put_le64(amount, dest);
    dest += 8;
    remaining -= 8;

    sys_put_le32(in->sequence, dest);
    dest += 4;
    remaining -= 4;

    memcpy(dest, hash_outputs, 32);
    dest += 32;
    remaining -= 32;

    sys_put_le32(tx->lock_time, dest);
    dest += 4;
    remaining -= 4;

    sys_put_le32(sighash_type, dest);
    dest += 4;
    remaining -= 4;

    if (hash_doubleSha256(buffer, dest - buffer, sighash_out, 32) != PSA_SUCCESS) {
        return PSBT_OOB_WRITE;
    }

    return PSBT_OK;
}

/* Process one PSBT input: validate the UTXO, derivation, compute sighash, sign and add the partial
 * signature */
static psbt_result_t process_input(const psbt_tx_t *tx, size_t index, psbt_map_t *input,
                                   const uint8_t *wallet_fingerprint)
{
    psbt_kv_t *witness_utxo = psbt_find_kv(input, PSBT_IN_WITNESS_UTXO);
    if (!witness_utxo || witness_utxo->value_data_len < 8) {
        LOG_INF("Input %zu: Missing valid witness UTXO", index);
        return PSBT_OK;
    }

    uint64_t amount = sys_get_le64(witness_utxo->value_data);
    const uint8_t *script_ptr = witness_utxo->value_data + 8;
    size_t script_remaining = witness_utxo->value_data_len - 8;
    compactsize_data_t script_data;
    if (!compactsize_read_with_data(&script_ptr, &script_remaining, &script_data)) {
        LOG_INF("Input %zu: Invalid script length encoding", index);
        return PSBT_OK;
    }

    if (script_data.size != 22 || script_data.data[0] != 0x00 || script_data.data[1] != 0x14) {
        LOG_INF("Input %zu: Invalid witness script", index);
        return PSBT_OK;
    }

    psbt_kv_t *bip32_deriv = psbt_find_kv(input, PSBT_IN_BIP32_DERIVATION);
    if (!bip32_deriv || bip32_deriv->value_data_len < 4) {
        LOG_INF("Input %zu: Missing derivation path", index);
        return PSBT_OK;
    }

    if (memcmp(bip32_deriv->value_data, wallet_fingerprint, 4) != 0) {
        LOG_INF("Input %zu: Foreign fingerprint", index);
        return PSBT_OK;
    }

    char path_str[128];
    if (parse_derivation_path(bip32_deriv->value_data, bip32_deriv->value_data_len, path_str,
                              sizeof(path_str)) != PSBT_OK) {
        LOG_INF("Input %zu: Invalid derivation path", index);
        return PSBT_OK;
    }

    const uint8_t *pubkey = bip32_deriv->key_data;
    uint8_t sha256[32], pubkey_hash[20];
    psa_status_t status = hash_sha256(pubkey, bip32_deriv->key_data_len, sha256, sizeof(sha256));
    if (status != PSA_SUCCESS) {
        LOG_INF("Input %zu: Failed to hash sha256", index);
        return PSBT_OK;
    }
    status = hash_ripemd160(sha256, sizeof(sha256), pubkey_hash, sizeof(pubkey_hash));
    if (status != PSA_SUCCESS) {
        LOG_INF("Input %zu: Failed to hash ripemd160", index);
        return PSBT_OK;
    }
    if (memcmp(pubkey_hash, script_data.data + 2, 20) != 0) {
        LOG_INF("Input %zu: Pubkey mismatch", index);
        return PSBT_OK;
    }

    uint32_t sighash_type = SIGHASH_ALL;
    psbt_kv_t *sighash_kv = psbt_find_kv(input, PSBT_IN_SIGHASH_TYPE);
    if (sighash_kv && sighash_kv->value_data_len == 4) {
        sighash_type = sys_get_le32(sighash_kv->value_data);
    }

    /* Build BIP143 scriptCode for P2WPKH:
       OP_DUP OP_HASH160 0x14 <20-byte pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG */
    uint8_t script_code[25];
    script_code[0] = 0x76; /* OP_DUP */
    script_code[1] = 0xa9; /* OP_HASH160 */
    script_code[2] = 0x14; /* PUSH 20 bytes */
    memcpy(script_code + 3, pubkey_hash, 20);
    script_code[23] = 0x88; /* OP_EQUALVERIFY */
    script_code[24] = 0xac; /* OP_CHECKSIG */

    uint8_t sighash[32];
    psbt_result_t res =
        compute_sighash(tx, index, script_code, sizeof(script_code), amount, sighash_type, sighash);
    if (res != PSBT_OK) {
        LOG_INF("Input %zu: Sighash computation failed", index);
        return PSBT_OK;
    }

    uint8_t signature[72];
    size_t sig_size = sizeof(signature);
    status = bitcoin_client_sign_hash(path_str, sighash, sizeof(sighash), signature, &sig_size);
    if (status != PSA_SUCCESS) {
        LOG_INF("Input %zu: Signing failed", index);
        return PSBT_OK;
    }

    psbt_kv_t *partial_sig = k_heap_alloc(&psbt_heap, sizeof(psbt_kv_t), K_NO_WAIT);
    if (!partial_sig) {
        return PSBT_OOB_WRITE;
    }

    partial_sig->key_type = PSBT_IN_PARTIAL_SIG;
    partial_sig->key_data = k_heap_alloc(&psbt_heap, bip32_deriv->key_data_len, K_NO_WAIT);
    if (!partial_sig->key_data) {
        k_heap_free(&psbt_heap, partial_sig);
        return PSBT_OOB_WRITE;
    }
    memcpy(partial_sig->key_data, pubkey, bip32_deriv->key_data_len);
    partial_sig->key_data_len = bip32_deriv->key_data_len;

    uint8_t final_signature[73];
    memcpy(final_signature, signature, sig_size);
    final_signature[sig_size] = sighash_type;

    partial_sig->value_data = k_heap_alloc(&psbt_heap, sig_size + 1, K_NO_WAIT);
    if (!partial_sig->value_data) {
        k_heap_free(&psbt_heap, partial_sig->key_data);
        k_heap_free(&psbt_heap, partial_sig);
        return PSBT_OOB_WRITE;
    }
    memcpy(partial_sig->value_data, final_signature, sig_size + 1);
    partial_sig->value_data_len = sig_size + 1;

    sys_slist_append(&input->kv_list, &partial_sig->node);
    return PSBT_OK;
}

/* Main PSBT signing function */
psbt_result_t psbt_sign(psbt_t *psbt)
{
    psbt_kv_t *unsigned_tx = psbt_find_kv(&psbt->global, PSBT_GLOBAL_UNSIGNED_TX);
    if (!unsigned_tx || !unsigned_tx->value_data) {
        return PSBT_READ_ERROR;
    }

    psbt_tx_t tx;
    psbt_result_t res =
        psbt_tx_create_from_bin(&tx, unsigned_tx->value_data, unsigned_tx->value_data_len);
    if (res != PSBT_OK) {
        return res;
    }

    uint8_t wallet_fingerprint[4];
    psa_status_t status = bitcoin_client_get_fingerprint(wallet_fingerprint);
    if (status != PSA_SUCCESS) {
        psbt_tx_free(&tx);
        return PSBT_OOB_WRITE;
    }

    for (size_t i = 0; i < psbt->num_inputs; i++) {
        res = process_input(&tx, i, &psbt->inputs[i], wallet_fingerprint);
        if (res != PSBT_OK) {
            break;
        }
    }

    psbt_tx_free(&tx);
    return res;
}
