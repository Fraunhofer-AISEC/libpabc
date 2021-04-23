/**
 * Copyright (c) 2021 Fraunhofer AISEC
 *
 * SPDX-License-Identifier: Apache-2.0
 **/



// using the relic library https://github.com/relic-toolkit/

#ifndef NONCE_H
#define NONCE_H

#include "pabc/pabc_nonce.h"
#include "utils.h"
#include <relic.h>

struct pabc_nonce
{
  bn_t nonce;
};

enum pabc_status pabc_nonce_deep_copy (struct pabc_context const *const ctx,
                                       struct pabc_nonce **dest,
                                       struct pabc_nonce const *const src);

enum pabc_status pabc_nonce_compare (struct pabc_context const *const ctx,
                                     struct pabc_nonce *const first,
                                     struct pabc_nonce *const second);

#endif // NONCE_H
