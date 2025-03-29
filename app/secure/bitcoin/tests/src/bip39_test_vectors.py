import requests

URL = "https://raw.githubusercontent.com/trezor/python-mnemonic/master/vectors.json"
vectors = requests.get(URL).json()["english"]

struct_def = f"""#pragma once

#include <stdint.h>
#include <stddef.h>

#define BIP39_TEST_VECTOR_COUNT {len(vectors)}

typedef struct {{
    const char *mnemonic;
    uint8_t entropy[32];
    size_t entropy_size;
    uint8_t seed[64];
    size_t seed_size;
}} bip39_test_vector_t;

extern const bip39_test_vector_t bip39_test_vectors[BIP39_TEST_VECTOR_COUNT];

"""

c_source = """#include "bip39_test_vectors.h"

const bip39_test_vector_t bip39_test_vectors[BIP39_TEST_VECTOR_COUNT] = {
"""

vector_entries = [
    f'    {{ \"{mnemonic.replace("\"", "\\\"")}\", {{ {", ".join(f"0x{entropy[i:i+2]}" for i in range(0, len(entropy), 2))} }}, {len(entropy) // 2}, '
    f'{{ {", ".join(f"0x{seed[i:i+2]}" for i in range(0, len(seed), 2))} }}, {len(seed) // 2} }}'
    for vector in vectors if len(vector) >= 3
    for entropy, mnemonic, seed in [vector[:3]]
]

c_source += ",\n".join(vector_entries) + "\n};\n"

for filename, content in {"bip39_test_vectors.h": struct_def, "bip39_test_vectors.c": c_source}.items():
    with open(filename, "w") as f:
        f.write(content)
