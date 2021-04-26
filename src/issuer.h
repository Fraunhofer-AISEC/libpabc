/**
 * Copyright (c) 2021 Fraunhofer AISEC
 *
 * SPDX-License-Identifier: Apache-2.0
 **/

// using the relic library https://github.com/relic-toolkit/

#ifndef ISSUER_H
#define ISSUER_H

#include "attributes.h"
#include "context.h"
#include "credential.h"
#include "hash.h"
#include "nonce.h"
#include "pabc/pabc_issuer.h"
#include "user.h"
#include "utils.h"
#include <jansson.h>
#include <relic.h>

enum pabc_status new_issuer_public_key (
  struct pabc_context const *const ctx,
  struct pabc_public_parameters const *const public_parameters,
  struct pabc_issuer_public_key **ipk);

void free_issuer_public_key (
  struct pabc_context const *const ctx,
  struct pabc_public_parameters const *const public_parameters,
  struct pabc_issuer_public_key **ipk);

enum pabc_status verify_pok (struct pabc_context *const ctx,
                             struct pabc_credential_request *const cr,
                             struct pabc_issuer_public_key *const ipk);

struct pabc_issuer_mem
{
  bn_t AttrsI;
  bn_t c_bar;
  bn_t mod_inv;
  bn_t r;
  bn_t temp_bn_t;
  g1_t MulAll;
  g1_t t1bar;
  g1_t t2;
  g1_t temp;
  g1_t temp_g1t;
  g2_t t1;
};

enum pabc_status pabc_issuer_mem_init (struct pabc_issuer_mem **const mem);
void pabc_issuer_mem_free (struct pabc_issuer_mem **const mem);

#endif // ISSUER_H
