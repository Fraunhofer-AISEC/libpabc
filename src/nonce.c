/**
 * Copyright (c) 2021 Fraunhofer AISEC
 *
 * SPDX-License-Identifier: Apache-2.0
 **/

#include "nonce.h"

enum pabc_status
pabc_new_nonce (struct pabc_context const *const ctx,
                struct pabc_nonce **nonce)
{
  if (ctx == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (nonce == NULL)
    print_and_return (PABC_UNINITIALIZED);

  struct pabc_nonce *new_nonce = malloc (sizeof(struct pabc_nonce));
  if (new_nonce == NULL)
    print_and_return (PABC_OOM);
  RLC_TRY {
    bn_null (new_nonce->nonce);
    bn_new (new_nonce->nonce);
  }
  RLC_CATCH_ANY {
    bn_free (new_nonce->nonce);
    PABC_FREE_NULL (new_nonce);
    print_and_return (PABC_RELIC_FAIL);
  }
  RLC_FINALLY {}

  *nonce = new_nonce;

  return PABC_OK;
}


enum pabc_status
pabc_populate_nonce (struct pabc_context const *const ctx,
                     struct pabc_nonce *nonce)
{
  if (ctx == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (nonce == NULL)
    print_and_return (PABC_UNINITIALIZED);

  RLC_TRY {
    bn_rand (nonce->nonce, RLC_POS, NONCE_BITS);
    bn_mod (nonce->nonce, nonce->nonce, ctx->group_order);
  }
  RLC_CATCH_ANY { print_and_return (PABC_RELIC_FAIL); }
  RLC_FINALLY {}

  return PABC_OK;
}


void
pabc_free_nonce (struct pabc_context const *const ctx,
                 struct pabc_nonce **nonce)
{
  if (ctx == NULL)
    return;
  if (nonce == NULL)
    return;
  if (*nonce == NULL)
    return;

  RLC_TRY { bn_free (*nonce->nonce); }
  RLC_CATCH_ANY {}
  RLC_FINALLY {}

  PABC_FREE_NULL (*nonce);
}


enum pabc_status
pabc_nonce_compare (struct pabc_context const *const ctx,
                    struct pabc_nonce *const first,
                    struct pabc_nonce *const second)
{
  if (ctx == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (first == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (second == NULL)
    print_and_return (PABC_UNINITIALIZED);

  RLC_TRY {
    if (RLC_EQ != bn_cmp (first->nonce, second->nonce))
      print_and_return (PABC_FAILURE);
  }
  RLC_CATCH_ANY { print_and_return (PABC_RELIC_FAIL); }
  RLC_FINALLY {}

  return PABC_OK;
}


enum pabc_status
pabc_nonce_deep_copy (struct pabc_context const *const ctx,
                      struct pabc_nonce **dest,
                      struct pabc_nonce const *const src)
{
  if (ctx == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (src == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (dest == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (*dest != NULL)
    print_and_return (PABC_UNINITIALIZED);

  enum pabc_status pabc_status;
  struct pabc_nonce *cpy_nonce = NULL;

  pabc_status = pabc_new_nonce (ctx, &cpy_nonce);
  if (PABC_OK != pabc_status)
    print_and_return (pabc_status);

  RLC_TRY { bn_copy (cpy_nonce->nonce, src->nonce); }
  RLC_CATCH_ANY {
    pabc_free_nonce (ctx, &cpy_nonce);
    print_and_return (PABC_RELIC_FAIL);
  }
  RLC_FINALLY {}

  *dest = cpy_nonce;
  return PABC_OK;
}
