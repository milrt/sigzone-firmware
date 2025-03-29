# Copyright (C) 2025 milrt <milrt@proton.me>
# SPDX-License-Identifier: GPL-3.0-or-later

set(INPUT_WORDLIST ${BIPS_DIR}/bip-0039/english.txt)

set(WORDLIST_OUTPUT_DIR ${CMAKE_BINARY_DIR}/bip39_wordlist)
file(MAKE_DIRECTORY ${WORDLIST_OUTPUT_DIR})

file(READ ${INPUT_WORDLIST} WORDLIST_CONTENTS)
string(REPLACE "\n" ";" WORDLIST ${WORDLIST_CONTENTS})
list(REMOVE_ITEM WORDLIST "")
list(LENGTH WORDLIST GEN_WORDLIST_EN_SIZE)

if(NOT GEN_WORDLIST_EN_SIZE EQUAL 2048)
    message(FATAL_ERROR "Wordlist must contain 2048 words, found: ${GEN_WORDLIST_EN_SIZE}")
endif()

string(REGEX REPLACE ";" "\",\n    \"" GEN_WORDLIST_EN "${WORDLIST}")
set(GEN_WORDLIST_EN "\"${GEN_WORDLIST_EN}\"")

configure_file(cmake/bip39_wordlist.h.in ${WORDLIST_OUTPUT_DIR}/bip39_wordlist.h @ONLY)
configure_file(cmake/bip39_wordlist.c.in ${WORDLIST_OUTPUT_DIR}/bip39_wordlist.c @ONLY)

add_library(bip39_wordlist STATIC ${WORDLIST_OUTPUT_DIR}/bip39_wordlist.c)
target_include_directories(bip39_wordlist PUBLIC ${WORDLIST_OUTPUT_DIR})
