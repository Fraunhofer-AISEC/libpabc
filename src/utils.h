/**
 * Copyright (c) 2021 Fraunhofer AISEC
 *
 * SPDX-License-Identifier: Apache-2.0
 **/



// using the relic library https://github.com/relic-toolkit/

#ifndef UTILS_H
#define UTILS_H

#include "context.h"
#include "credential.h"
#include "pabc/pabc_utils.h"
#include <relic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RELIC_ERR_MSG "A RELIC operation failed."
#define JANSSON_ERR_MSG "A Jansson operation failed."
#define POINT_COMPRESSION 0 // TODO ???
#define NONCE_BITS 256
#define JSON_RADIX 16
#define JANSSON_ENC_FLAGS (JSON_INDENT (2))
#define JANSSON_DEC_FLAGS 0

#define print_and_return(cond)                                                 \
  do {                                                                         \
    fprintf (stderr, "Met condition (%d) at %s:%d...\n", cond, __FILE__,        \
             __LINE__);                                                         \
    return cond;                                                               \
  } while (0)

size_t find_attribute_idx_by_name (
  struct pabc_context const *const ctx,
  struct pabc_public_parameters const *const public_parameters,
  char const *const name);

#endif // UTILS_H
