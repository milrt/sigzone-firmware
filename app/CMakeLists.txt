# Copyright (C) 2025 milrt <milrt@proton.me>
# SPDX-License-Identifier: GPL-3.0-or-later

cmake_minimum_required(VERSION 3.20)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})

get_target_property(TFM_BINARY_DIR tfm TFM_BINARY_DIR)
configure_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/secure/tfm_manifest_list.yaml.in
  ${CMAKE_CURRENT_BINARY_DIR}/secure/tfm_manifest_list.yaml
)

get_filename_component(SECP256K1_DIR "${ZEPHYR_BASE}/../libs/secp256k1" ABSOLUTE)
get_filename_component(BIPS_DIR "${ZEPHYR_BASE}/../libs/bips" ABSOLUTE)
get_filename_component(LIBBASE58_DIR "${ZEPHYR_BASE}/../libs/libbase58" ABSOLUTE)
get_filename_component(SHARED_DIR "${ZEPHYR_BASE}/../sigzone-firmware/app/shared" ABSOLUTE)

set_property(TARGET zephyr_property_target
  APPEND PROPERTY TFM_CMAKE_OPTIONS
  -DTFM_EXTRA_MANIFEST_LIST_FILES=${CMAKE_CURRENT_BINARY_DIR}/secure/tfm_manifest_list.yaml
  -DTFM_EXTRA_PARTITION_PATHS=${CMAKE_CURRENT_SOURCE_DIR}/secure
  -DSECP256K1_DIR=${SECP256K1_DIR}
  -DBIPS_DIR=${BIPS_DIR}
  -DLIBBASE58_DIR=${LIBBASE58_DIR}
  -DSHARED_DIR=${SHARED_DIR}
  -DPROJECT_CONFIG_HEADER_FILE=${CMAKE_CURRENT_SOURCE_DIR}/secure/configs/config_mbedtls.h
)

project(sigzone LANGUAGES C)

target_sources(app PRIVATE ${ZEPHYR_BASE}/misc/empty_file.c
    nonsecure/main.c
    nonsecure/bitcoin/src/bitcoin_client.c
    nonsecure/bitcoin/src/psbt.c
    nonsecure/bitcoin/src/psbt_compactsize.c
    nonsecure/bitcoin/src/psbt_tx.c
    nonsecure/bitcoin/src/psbt_heap.c
    nonsecure/bitcoin/src/psbt_signer.c
    nonsecure/bitcoin/src/psbt_validator.c
    nonsecure/bitcoin/src/segwit_addr.c
    nonsecure/bitcoin/src/chains.c
    nonsecure/ui/src/bitcoin_shell.c
    shared/src/hash.c
    shared/src/test_util.c

    # Tests
    nonsecure/bitcoin/tests/src/nonsecure_bitcoin_test.c
    nonsecure/bitcoin/tests/src/chains_test.c
    nonsecure/bitcoin/tests/src/psbt_test.c
)

target_include_directories(app PRIVATE
  $<TARGET_PROPERTY:tfm,TFM_BINARY_DIR>/api_ns/interface/include
  nonsecure/bitcoin/include
  nonsecure/bitcoin/tests/include
  shared/tests/include
  shared/include
)

target_compile_definitions(app PRIVATE
  TFM_PARTITION_BITCOIN
)
