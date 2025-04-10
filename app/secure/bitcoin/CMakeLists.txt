cmake_minimum_required(VERSION 3.20)

include(cmake/bip39_wordlist.cmake)
include(cmake/secp256k1-config.cmake)

add_subdirectory(${SECP256K1_DIR} ${CMAKE_BINARY_DIR}/secp256k1)

add_library(bitcoin STATIC
    ${LIBBASE58_DIR}/base58.c
    ${SHARED_DIR}/src/hash.c
    ${SHARED_DIR}/src/test_util.c
    src/bitcoin_core.c
    src/base58.c
    src/utils.c
    src/bip39.c
    src/bip32.c
    src/key_storage.c
    src/nv_counter.c
    src/secp256k1_context.c

    # Tests
    ${SHARED_DIR}/tests/src/hash_test.c
    ${SHARED_DIR}/tests/src/shared_test.c
    tests/src/secure_bitcoin_test.c
    tests/src/bip39_test.c
    tests/src/bip39_test_vectors.c
    tests/src/bip32_test_vectors.c
    tests/src/bip32_test.c
    tests/src/key_storage_test.c
)

target_include_directories(bitcoin PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/include
)

target_include_directories(bitcoin PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${LIBBASE58_DIR}
    ${SHARED_DIR}/include
    ${SHARED_DIR}/tests/include
)

target_link_libraries(bitcoin PRIVATE
    bip39_wordlist
    secp256k1
    psa_crypto_config
    tfm_sprt
)
