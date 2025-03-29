// Copyright (C) 2025 milrt <milrt@proton.me>
// SPDX-License-Identifier: GPL-3.0-or-later

#include "utils.h"
#include <stddef.h>
#include <string.h>

char *get_token(char *str, const char *delim, char **saveptr)
{
    if (!saveptr || !delim) {
        return NULL;
    }

    if (str) {
        *saveptr = str;
    }

    if (!*saveptr || **saveptr == '\0') {
        return NULL;
    }

    // Skip leading delimiters
    char *token = *saveptr + strspn(*saveptr, delim);
    if (*token == '\0') {
        *saveptr = NULL;
        return NULL; // Only delimiters were found
    }

    // Find the end of the token
    char *end = token + strcspn(token, delim);
    if (*end != '\0') {
        *end = '\0';        // Null-terminate token
        *saveptr = end + 1; // Move pointer to next token
    } else {
        *saveptr = NULL; // No more tokens
    }

    return token;
}
