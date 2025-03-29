# Copyright (C) 2025 milrt <milrt@proton.me>
# SPDX-License-Identifier: GPL-3.0-or-later

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_library(tfm_app_rot_partition_bitcoin STATIC)

add_subdirectory(bitcoin)

target_include_directories(tfm_app_rot_partition_bitcoin
  INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
  PRIVATE
    ${CMAKE_BINARY_DIR}/bitcoin_partition
    ../shared/include
)

target_include_directories(tfm_partitions
    INTERFACE
        ${CMAKE_BINARY_DIR}/bitcoin_partition
)

target_sources(tfm_app_rot_partition_bitcoin PRIVATE
  bitcoin_service.c
)

# Generated sources from manifest
target_sources(tfm_app_rot_partition_bitcoin PRIVATE
  ${CMAKE_BINARY_DIR}/bitcoin_partition/auto_generated/intermedia_tfm_bitcoin_partition.c
)
target_sources(tfm_partitions
    INTERFACE
        ${CMAKE_BINARY_DIR}/bitcoin_partition/auto_generated/load_info_tfm_bitcoin_partition.c
)

target_link_libraries(tfm_app_rot_partition_bitcoin PRIVATE
  bitcoin
  tfm_sprt
  psa_crypto_config
)

# Link to TFM core
target_link_libraries(tfm_spm PRIVATE
  tfm_app_rot_partition_bitcoin
)

target_link_libraries(tfm_partitions
    INTERFACE
        tfm_app_rot_partition_bitcoin
)

# Partition definitions
target_compile_definitions(tfm_config INTERFACE
  TFM_PARTITION_BITCOIN
)
