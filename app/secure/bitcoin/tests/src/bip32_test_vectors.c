// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "bip32_test_vectors.h"

// Test vectors from:
// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#user-content-Test_Vectors

static const uint8_t vector1_seed[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                       0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
static const uint8_t vector2_seed[] = {
    0xff, 0xfc, 0xf9, 0xf6, 0xf3, 0xf0, 0xed, 0xea, 0xe7, 0xe4, 0xe1, 0xde, 0xdb, 0xd8, 0xd5, 0xd2,
    0xcf, 0xcc, 0xc9, 0xc6, 0xc3, 0xc0, 0xbd, 0xba, 0xb7, 0xb4, 0xb1, 0xae, 0xab, 0xa8, 0xa5, 0xa2,
    0x9f, 0x9c, 0x99, 0x96, 0x93, 0x90, 0x8d, 0x8a, 0x87, 0x84, 0x81, 0x7e, 0x7b, 0x78, 0x75, 0x72,
    0x6f, 0x6c, 0x69, 0x66, 0x63, 0x60, 0x5d, 0x5a, 0x57, 0x54, 0x51, 0x4e, 0x4b, 0x48, 0x45, 0x42};
static const uint8_t vector3_seed[] = {
    0x4b, 0x38, 0x15, 0x41, 0x58, 0x3b, 0xe4, 0x42, 0x33, 0x46, 0xc6, 0x43, 0x85, 0x0d, 0xa4, 0xb3,
    0x20, 0xe4, 0x6a, 0x87, 0xae, 0x3d, 0x2a, 0x4e, 0x6d, 0xa1, 0x1e, 0xba, 0x81, 0x9c, 0xd4, 0xac,
    0xba, 0x45, 0xd2, 0x39, 0x31, 0x9a, 0xc1, 0x4f, 0x86, 0x3b, 0x8d, 0x5a, 0xb5, 0xa0, 0xd0, 0xc6,
    0x4d, 0x2e, 0x8a, 0x1e, 0x7d, 0x14, 0x57, 0xdf, 0x2e, 0x5a, 0x3c, 0x51, 0xc7, 0x32, 0x35, 0xbe};
static const uint8_t vector4_seed[] = {
    0x3d, 0xdd, 0x56, 0x02, 0x28, 0x58, 0x99, 0xa9, 0x46, 0x11, 0x45, 0x06, 0x15, 0x7c, 0x79, 0x97,
    0xe5, 0x44, 0x45, 0x28, 0xf3, 0x00, 0x3f, 0x61, 0x34, 0x71, 0x21, 0x47, 0xdb, 0x19, 0xb6, 0x78};

const bip32_test_vector_t bip32_test_vectors[BIP32_TEST_VECTOR_COUNT] = {
    // Test Vector 1
    {.seed = vector1_seed,
     .seed_size = sizeof(vector1_seed),
     .path = "m",
     .xprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejM"
             "RNNU3TGtRBeJgk33yuGB"
             "xrMPHi",
     .xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqse"
             "fD265TMg7usUDFdp6W1E"
             "GMcet8"},
    {.seed = vector1_seed,
     .seed_size = sizeof(vector1_seed),
     .path = "m/0h",
     .xprv = "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT1"
             "1eZG7XnxHrnYeSvkzY7d"
             "2bhkJ7",
     .xpub = "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1b"
             "gwQ9xv5ski8PX9rL2dZX"
             "vgGDnw"},
    {.seed = vector1_seed,
     .seed_size = sizeof(vector1_seed),
     .path = "m/0h/1",
     .xprv = "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8"
             "MSY3H2EU4pWcQDnRnrVA"
             "1xe8fs",
     .xpub = "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq5"
             "27Hqck2AxYysAA7xmALp"
             "puCkwQ"},
    {.seed = vector1_seed,
     .seed_size = sizeof(vector1_seed),
     .path = "m/0h/1/2h",
     .xprv = "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRi"
             "NMjANTtpgP4mLTj34bhn"
             "ZX7UiM",
     .xpub = "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n"
             "7epu4trkrX7x7DogT5Uv"
             "6fcLW5"},
    {.seed = vector1_seed,
     .seed_size = sizeof(vector1_seed),
     .path = "m/0h/1/2h/2",
     .xprv = "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsu"
             "nu5Mm3wDvUAKRHSC34sJ"
             "7in334",
     .xpub = "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37s"
             "R62cfN7fe5JnJ7dh8zL4"
             "fiyLHV"},
    {.seed = vector1_seed,
     .seed_size = sizeof(vector1_seed),
     .path = "m/0H/1/2H/2/1000000000",
     .xprv = "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFS"
             "ruoUihUZREPSL39UNdE3"
             "BBDu76",
     .xpub = "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8y"
             "GasTvXEYBVPamhGW6cFJ"
             "odrTHy"},
    {.seed = vector2_seed,
     .seed_size = sizeof(vector2_seed),
     .path = "m",
     .xprv = "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqP"
             "qm55Qn3LqFtT2emdEXVY"
             "sCzC2U",
     .xpub = "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6m"
             "r8BDzTJY47LJhkJ8UB7W"
             "EGuduB"},
    {.seed = vector2_seed,
     .seed_size = sizeof(vector2_seed),
     .path = "m/0",
     .xprv = "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex"
             "8G81dwSM1fwqWpWkeS3v"
             "86pgKt",
     .xpub = "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDzne"
             "zpbZb7ap6r1D3tgFxHmw"
             "MkQTPH"},
    {.seed = vector2_seed,
     .seed_size = sizeof(vector2_seed),
     .path = "m/0/2147483647h",
     .xprv = "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRg"
             "VsFawNzmjuHc2YmYRmag"
             "cEPdU9",
     .xpub = "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8R"
             "uJiHjaDMBU4Zn9h8LZNn"
             "BC5y4a"},
    {.seed = vector2_seed,
     .seed_size = sizeof(vector2_seed),
     .path = "m/0/2147483647h/1",
     .xprv = "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXaj"
             "PPdbRCHuWS6T8XA2ECKA"
             "Ddw4Ef",
     .xpub = "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89L"
             "ojfZ537wTfunKau47EL2"
             "dhHKon"},
    {.seed = vector2_seed,
     .seed_size = sizeof(vector2_seed),
     .path = "m/0/2147483647h/1/2147483646h",
     .xprv = "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxF"
             "LJ8HFsTjSyQbLYnMpCqE"
             "2VbFWc",
     .xpub = "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2"
             "grBGRjaDMzQLcgJvLJuZ"
             "ZvRcEL"},
    {.seed = vector2_seed,
     .seed_size = sizeof(vector2_seed),
     .path = "m/0/2147483647h/1/2147483646h/2",
     .xprv = "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTy"
             "efMLEcBYJUuekgW4BYPJ"
             "cr9E7j",
     .xpub = "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2r"
             "nY5agb9rXpVGyy3bdW6E"
             "EgAtqt"},
    {.seed = vector3_seed,
     .seed_size = sizeof(vector3_seed),
     .path = "m",
     .xprv = "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9d"
             "GuVrtHHs7pXeTzjuxBrC"
             "mmhgC6",
     .xpub = "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1c"
             "ZAceL7SfJ1Z3GC8vBgp2"
             "epUt13"},
    {.seed = vector3_seed,
     .seed_size = sizeof(vector3_seed),
     .path = "m/0h",
     .xprv = "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJC"
             "VVFceUvJFjaPdGZ2y9WA"
             "CViL4L",
     .xpub = "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MY"
             "o6oDaPPLPxSb7gwQN3ih"
             "19Zm4Y"},

    {.seed = vector4_seed,
     .seed_size = sizeof(vector4_seed),
     .path = "m",
     .xprv = "xprv9s21ZrQH143K48vGoLGRPxgo2JNkJ3J3fqkirQC2zVdk5Dgd5w14S7fRDyHH4dWNHUgkvsvNDCkvAwcSH"
             "NAQwhwgNMgZhLtQC63zx"
             "whQmRv",
     .xpub = "xpub661MyMwAqRbcGczjuMoRm6dXaLDEhW1u34gKenbeYqAix21mdUKJyuyu5F1rzYGVxyL6tmgBUAEPrEz92"
             "mBXjByMRiJdba9wpnN37"
             "RLLAXa"},
    {.seed = vector4_seed,
     .seed_size = sizeof(vector4_seed),
     .path = "m/0h",
     .xprv = "xprv9vB7xEWwNp9kh1wQRfCCQMnZUEG21LpbR9NPCNN1dwhiZkjjeGRnaALmPXCX7SgjFTiCTT6bXes17boXt"
             "jq3xLpcDjzEuGLQBM5oh"
             "qkao9G",
     .xpub = "xpub69AUMk3qDBi3uW1sXgjCmVjJ2G6WQoYSnNHyzkmdCHEhSZ4tBok37xfFEqHd2AddP56Tqp4o56AePAgCj"
             "YdvpW2PU2jbUPFKsav5u"
             "t6Ch1m"},
    {.seed = vector4_seed,
     .seed_size = sizeof(vector4_seed),
     .path = "m/0h/1h",
     .xprv = "xprv9xJocDuwtYCMNAo3Zw76WENQeAS6WGXQ55RCy7tDJ8oALr4FWkuVoHJeHVAcAqiZLE7Je3vZJHxspZdFH"
             "fnBEjHqU5hG1Jaj32dVo"
             "S6XLT1",
     .xpub = "xpub6BJA1jSqiukeaesWfxe6sNK9CCGaujFFSJLomWHprUL9DePQ4JDkM5d88n49sMGJxrhpjazuXYWdMf17C"
             "9T5XnxkopaeS7jGk1Gyy"
             "VziaMt"},

};

const bip32_invalid_test_vector_t bip32_invalid_test_vectors[BIP32_INVALID_TEST_VECTOR_COUNT] = {
    {.xprv = "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFGTQQD3dC4H2D5GBj7vWvSQaa"
             "Bv5cxi9gafk7NF3pnBju"
             "6dwKvH",
     .xpub = NULL,
     .description = "prvkey version / pubkey mismatch"},
    {.xprv = "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFGpWnsj83BHtEy5Zt8CcDr1Ui"
             "RXuWCmTQLxEK9vbz5gPs"
             "tX92JQ",
     .xpub = NULL,
     .description = "invalid prvkey prefix 04"},
    {.xprv = "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFAzHGBP2UuGCqWLTAPLcMtD9y"
             "5gkZ6Eq3Rjuahrv17fEQ"
             "3Qen6J",
     .xpub = NULL,
     .description = "invalid prvkey prefix 01"},
    {.xprv = "xprv9s2SPatNQ9Vc6GTbVMFPFo7jsaZySyzk7L8n2uqKXJen3KUmvQNTuLh3fhZMBoG3G4ZW1N2kZuHEPY53q"
             "mbZzCHshoQnNf4GvELZf"
             "qTUrcv",
     .xpub = NULL,
     .description = "zero depth with non-zero parent fingerprint"},
    {.xprv = "xprv9s21ZrQH4r4TsiLvyLXqM9P7k1K3EYhA1kkD6xuquB5i39AU8KF42acDyL3qsDbU9NmZn6MsGSUYZEsuo"
             "ePmjzsB3eFKSUEh3Gu1N"
             "3cqVUN",
     .xpub = NULL,
     .description = "zero depth with non-zero index"},
    {.xprv = "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzF93Y5wvzdUayhgkkFoicQZcP3"
             "y52uPPxFnfoLZB21Teqt"
             "1VvEHx",
     .xpub = NULL,
     .description = "private key 0 not in 1..n-1"},
    {.xprv = "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFAzHGBP2UuGCqWLTAPLcMtD5S"
             "DKr24z3aiUvKr9bJpdrc"
             "Lg1y3G",
     .xpub = NULL,
     .description = "private key n not in 1..n-1"},
    {.xprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejM"
             "RNNU3TGtRBeJgk33yuGB"
             "xrMPHL",
     .xpub = NULL,
     .description = "invalid checksum"},
    {.xprv = NULL,
     .xpub = "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6LBpB85b3D2yc8sfvZU521AAw"
             "dZafEz7mnzBBsz4wKY5f"
             "TtTQBm",
     .description = "pubkey version / prvkey mismatch"},
    {.xprv = NULL,
     .xpub = "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6Txnt3siSujt9RCVYsx4qHZGc"
             "62TG4McvMGcAUjeuwZdd"
             "uYEvFn",
     .description = "invalid pubkey prefix 04"},
    {.xprv = NULL,
     .xpub = "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6N8ZMMXctdiCjxTNq964yKkwr"
             "kBJJwpzZS4HS2fxvyYUA"
             "4q2Xe4",
     .description = "invalid pubkey prefix 01"},
    {.xprv = NULL,
     .xpub = "xpub661no6RGEX3uJkY4bNnPcw4URcQTrSibUZ4NqJEw5eBkv7ovTwgiT91XX27VbEXGENhYRCf7hyEbWrR3F"
             "ewATdCEebj6znwMfQkhR"
             "YHRLpJ",
     .description = "zero depth with non-zero parent fingerprint"},
    {.xprv = NULL,
     .xpub = "xpub661MyMwAuDcm6CRQ5N4qiHKrJ39Xe1R1NyfouMKTTWcguwVcfrZJaNvhpebzGerh7gucBvzEQWRugZDuD"
             "XjNDRmXzSZe4c7mnTK97"
             "pTvGS8",
     .description = "zero depth with non-zero index"},
    {.xprv = NULL,
     .xpub = "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6Q5JXayek4PRsn35jii4veMim"
             "ro1xefsM58PgBMrvdYre"
             "8QyULY",
     .description = "invalid pubkey 0200...07"},
};
