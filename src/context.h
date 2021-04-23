/**
 * Copyright (c) 2021 Fraunhofer AISEC
 *
 * SPDX-License-Identifier: Apache-2.0
 **/



// using the relic library https://github.com/relic-toolkit/

#ifndef CONTEXT_H
#define CONTEXT_H

#include "hash.h"
#include "pabc/pabc_context.h"
#include "relic.h"
#include "utils.h"

/*!
 * Global context holding publicly available information.
 */
struct pabc_context
{
  // ! The group order. ord(G1) == ord(G2) == ord(GT)
  bn_t group_order;

  // ! Generator of G1
  g1_t g1_gen;

  // ! Generator of G2
  g2_t g2_gen;

  // ! Reusable memory for computing hashes.
  struct hash_container *hash;
};

#endif // CONTEXT_H
