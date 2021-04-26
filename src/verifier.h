/**
 * Copyright (c) 2021 Fraunhofer AISEC
 *
 * SPDX-License-Identifier: Apache-2.0
 **/

// using the relic library https://github.com/relic-toolkit/

#ifndef VERIFIER_H
#define VERIFIER_H

#include "credential.h"
#include "hash.h"
#include "issuer.h"
#include "pabc/pabc_verifier.h"
#include "utils.h"
#include <relic.h>

struct pabc_verifier_mem
{
  gt_t lhs;
  gt_t rhs;
  g1_t t1tilde;
  g1_t HRand_s_r2;
  g1_t ABarNeg;
  g1_t temp;
  g1_t t2tilde;
  g1_t temp2;
  bn_t cp;
  bn_t inner_hash_result;
  bn_t AttrsI;
};

enum pabc_status pabc_verifier_mem_init (struct pabc_verifier_mem **const mem);
void pabc_verifier_mem_free (struct pabc_verifier_mem **const mem);

#endif // VERIFIER_H
