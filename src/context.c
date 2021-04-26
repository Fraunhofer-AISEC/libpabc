/**
 * Copyright (c) 2021 Fraunhofer AISEC
 *
 * SPDX-License-Identifier: Apache-2.0
 **/

#include "context.h"

static unsigned int pabc_global_context_cntr = 0;

enum pabc_status
pabc_new_ctx (struct pabc_context **ctx)
{
  if (ctx == NULL)
    print_and_return (PABC_UNINITIALIZED);

  struct pabc_context *new_ctx = malloc (sizeof(struct pabc_context));
  if (new_ctx == NULL)
    print_and_return (PABC_OOM);

  enum pabc_status pabc_status;
  pabc_status = new_hash_container (&new_ctx->hash);
  if (PABC_OK != pabc_status)
  {
    PABC_FREE_NULL (new_ctx);
    print_and_return (pabc_status);
  }

  RLC_TRY {
    int r;
    r = core_init ();
    if (r != RLC_OK)
      print_and_return (PABC_RELIC_FAIL);
    r = pc_param_set_any ();
    if (r != RLC_OK)
      print_and_return (PABC_RELIC_FAIL);

    ++pabc_global_context_cntr; // register a new RELIC ctx reference holder

#ifdef PABC_DEBUG
    conf_print ();
#endif

    // get group order
    bn_null (new_ctx->group_order);
    bn_new (new_ctx->group_order);
    pc_get_ord (new_ctx->group_order);

    // get generators for G1 and G2
    g1_null (new_ctx->g1_gen);
    g2_null (new_ctx->g2_gen);
    g1_new (new_ctx->g1_gen);
    g2_new (new_ctx->g2_gen);
    g1_get_gen (new_ctx->g1_gen);
    g2_get_gen (new_ctx->g2_gen);
  }
  RLC_CATCH_ANY {
    g2_free (new_ctx->g2_gen);
    g1_free (new_ctx->g1_gen);
    bn_free (new_ctx->group_order);
    --pabc_global_context_cntr;
    if (pabc_global_context_cntr == 0)
      core_clean ();
    PABC_FREE_NULL (new_ctx);
    print_and_return (PABC_RELIC_FAIL);
  }
  RLC_FINALLY {}

  *ctx = new_ctx;
  return PABC_OK;
}


void
pabc_free_ctx (struct pabc_context **ctx)
{
  if (ctx == NULL)
    return;
  if (*ctx == NULL)
    return;

  --pabc_global_context_cntr;

  RLC_TRY {
    bn_free (ctx->group_order);
    g1_free (ctx->g1_gen);
    g2_free (ctx->g2_gen);

    // only clean the RELIC context if this was the last reference
    if (pabc_global_context_cntr == 0)
      core_clean ();
  }
  RLC_CATCH_ANY {}
  RLC_FINALLY {}
  free_hash_container (&(*ctx)->hash);
  PABC_FREE_NULL (*ctx);
}
