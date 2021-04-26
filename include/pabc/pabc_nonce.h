/**
 * Copyright (c) 2021 Fraunhofer AISEC
 *
 * SPDX-License-Identifier: Apache-2.0
 **/

#include "pabc_utils.h"

#ifndef PABC_NONCE_H
#define PABC_NONCE_H

/*!
 * A structure holding a nonce.
 */
struct pabc_nonce;

struct pabc_context;

enum pabc_status pabc_new_nonce (struct pabc_context const *const ctx,
                                 struct pabc_nonce **nonce);

enum pabc_status pabc_populate_nonce (struct pabc_context const *const ctx,
                                      struct pabc_nonce *nonce);

void pabc_free_nonce (struct pabc_context const *const ctx,
                      struct pabc_nonce **nonce);

#endif // PABC_NONCE_H
