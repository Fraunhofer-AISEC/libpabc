/**
 * Copyright (c) 2021 Fraunhofer AISEC
 *
 * SPDX-License-Identifier: Apache-2.0
 **/





#include "user.h"

enum pabc_status
pabc_gen_credential_request (
  struct pabc_context *const ctx,
  struct pabc_public_parameters const *const public_parameters,
  struct pabc_user_context *const usr_ctx, struct pabc_nonce *const nonce,
  struct pabc_credential_request *const cr)

{
  if (ctx == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (public_parameters == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (usr_ctx == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (nonce == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (cr == NULL)
    print_and_return (PABC_UNINITIALIZED);

  enum pabc_status status;

  struct pabc_user_mem *mem = NULL;
  status = pabc_user_mem_init (&mem);
  if (status != PABC_OK)
    print_and_return (status);

  /*
   * 3.1 Generate pabc_credential Request
   *
   * User will generate the pabc_credential request with attribute values and
   * nonce as input. This is done as follows:
   *
   *    1. Sample a random element sk from Zp as user's master secret.
   *    2. Compute Nym = HSk^(sk) as a commitment to user's master secret.
   *    3. Generate zero knowledge pabc_proof π = PoK{sk: Nym = HSk^sk} = (C, S)
   * as illustrated in section 1.2 which we reproduce here.
   *        - Sample a random element r from Zp.
   *        - Compute t1 = HSk^r.
   *        - Compute challenge C = H(t1 || HSk || Nym || nonce).
   *        - Compute response S = (r + C * sk) mod p.
   */

  RLC_TRY {

    if (PABC_OK != pabc_nonce_deep_copy (ctx, &cr->nonce, nonce))
    {
      pabc_user_mem_free (&mem);
      print_and_return (PABC_FAILURE);
    }

    // 2. Compute Nym = HSk^(sk) as a commitment to user's master secret.
    g1_mul (cr->Nym, public_parameters->ipk->HSk, usr_ctx->sk);

    // Generate zero knowledge pabc_proof π = PoK{sk: Nym = HSk^sk} = (C, S) as
    // illustrated in section 1.2 which we reproduce here.
    //
    // Sample a random element r from Zp.
    bn_rand_mod (mem->r, ctx->group_order);

    // Compute t1 = HSk^r.
    g1_mul (mem->t1, public_parameters->ipk->HSk, mem->r);

    // Compute challenge C = H(t1 || HSk || Nym || nonce).
    int failed = 0;
    status = reset_hash (ctx);
    if (PABC_OK != status)
      failed = 1;

    status = hash_add_g1 (ctx, mem->t1);
    if (PABC_OK != status)
      failed = 1;

    status = hash_add_g1 (ctx, public_parameters->ipk->HSk);
    if (PABC_OK != status)
      failed = 1;

    status = hash_add_g1 (ctx, cr->Nym);
    if (PABC_OK != status)
      failed = 1;

    status = hash_add_bn (ctx, cr->nonce->nonce);
    if (PABC_OK != status)
      failed = 1;

    status = compute_hash (ctx, cr->C);
    if (PABC_OK != status)
      failed = 1;

    if (failed)
    {
      pabc_user_mem_free (&mem);
      pabc_free_nonce (ctx, &cr->nonce);
      print_and_return (status); // last error
    }

    // Compute response S = (r + C * sk) mod p.
    bn_mul (cr->S, cr->C, usr_ctx->sk);
    bn_mod (cr->S, cr->S, ctx->group_order);
    bn_add (cr->S, mem->r, cr->S);
    bn_mod (cr->S, cr->S, ctx->group_order);

    // store plain text attributes in credential
    for (size_t i = 0; i < public_parameters->nr_of_attributes; ++i)
    {
      if (NULL == usr_ctx->plain_attrs[i])
      {
        cr->plain_attrs->attribute_values[i] = NULL;
      }
      else
      {
        cr->plain_attrs->attribute_values[i] = strdup (usr_ctx->plain_attrs[i]);
        if (cr->plain_attrs->attribute_values[i] == NULL)
        {
          for (size_t j = i; j > 0; j--)
          {
            PABC_FREE_NULL (cr->plain_attrs->attribute_values[j - 1]);
          }
          pabc_user_mem_free (&mem);
          pabc_free_nonce (ctx, &cr->nonce);
          print_and_return (PABC_OOM);
        }
      }
    }

    pabc_user_mem_free (&mem);
  }
  RLC_CATCH_ANY { print_and_return (PABC_RELIC_FAIL); }
  RLC_FINALLY {}

  return PABC_OK;
}


enum pabc_status
pabc_free_credential_request (
  struct pabc_context const *const ctx,
  struct pabc_public_parameters const *const public_parameters,
  struct pabc_credential_request **cr)
{
  if (ctx == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (public_parameters == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (cr == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (*cr == NULL)
    print_and_return (PABC_UNINITIALIZED);

  if ((*cr)->nonce)
    pabc_free_nonce (ctx, &(*cr)->nonce);
  if ((*cr)->plain_attrs != NULL)
    pabc_free_plain_attrs (ctx, &(*cr)->plain_attrs);

  RLC_TRY {
    g1_free (cr->Nym);
    bn_free (cr->C);
    bn_free (cr->S);
  }
  RLC_CATCH_ANY { print_and_return (PABC_RELIC_FAIL); }
  RLC_FINALLY {}
  PABC_FREE_NULL (*cr);

  return PABC_OK;
}


enum pabc_status
pabc_new_credential_request (
  struct pabc_context const *const ctx,
  struct pabc_public_parameters const *const public_parameters,
  struct pabc_credential_request **cr)
{
  if (ctx == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (public_parameters == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (cr == NULL)
    print_and_return (PABC_UNINITIALIZED);

  enum pabc_status status;

  struct pabc_credential_request *new_cr =
    malloc (sizeof(struct pabc_credential_request));
  if (new_cr == NULL)
    print_and_return (PABC_OOM);

  new_cr->nonce = NULL;

  status = pabc_new_plain_attrs (ctx, public_parameters, &new_cr->plain_attrs);
  if (PABC_OK != status)
  {
    PABC_FREE_NULL (new_cr);
    print_and_return (status);
  }

  RLC_TRY {
    bn_null (new_cr->C);
    bn_null (new_cr->S);
    bn_new (new_cr->C);
    bn_new (new_cr->S);
  }
  RLC_CATCH_ANY {
    PABC_FREE_NULL (new_cr);
    print_and_return (PABC_RELIC_FAIL);
  }
  RLC_FINALLY {} *cr = new_cr;

  return PABC_OK;
}


enum pabc_status
pabc_new_proof (struct pabc_context const *const ctx,
                struct pabc_public_parameters const *const public_parameters,
                struct pabc_blinded_proof **proof)
{
  if (ctx == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (public_parameters == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (proof == NULL)
    print_and_return (PABC_UNINITIALIZED);

  enum pabc_status status;

  struct pabc_blinded_proof *new_proof =
    malloc (sizeof(struct pabc_blinded_proof));
  if (new_proof == NULL)
    print_and_return (PABC_OOM);

  status =
    pabc_new_attribute_predicates (ctx, public_parameters, &new_proof->DI);
  if (PABC_OK != status)
  {
    PABC_FREE_NULL (new_proof);
    print_and_return (status);
  }

  status = pabc_new_nonce (ctx, &new_proof->nonce);
  if (PABC_OK != status)
  {

    pabc_free_attribute_predicates (ctx, public_parameters, &new_proof->DI);
    PABC_FREE_NULL (new_proof);
    print_and_return (status);
  }

  RLC_TRY {
    g1_null (new_proof->APrime);
    g1_new (new_proof->APrime);

    g1_null (new_proof->ABar);
    g1_new (new_proof->ABar);

    g1_null (new_proof->BPrime);
    g1_new (new_proof->BPrime);

    bn_null (new_proof->ProofC);
    bn_new (new_proof->ProofC);

    bn_null (new_proof->ProofSSk);
    bn_new (new_proof->ProofSSk);

    bn_null (new_proof->ProofSE);
    bn_new (new_proof->ProofSE);

    bn_null (new_proof->ProofSR2);
    bn_new (new_proof->ProofSR2);

    bn_null (new_proof->ProofSR3);
    bn_new (new_proof->ProofSR3);

    bn_null (new_proof->ProofSSPrime);
    bn_new (new_proof->ProofSSPrime);

    new_proof->ProofSAttrs =
      malloc (sizeof(bn_t) * public_parameters->nr_of_attributes);
    if (new_proof->ProofSAttrs == NULL)
    {
      pabc_free_nonce (ctx, &new_proof->nonce);
      pabc_free_attribute_predicates (ctx, public_parameters, &new_proof->DI);
      PABC_FREE_NULL (new_proof);
      print_and_return (PABC_OOM);
    }
    for (size_t i = 0; i < public_parameters->nr_of_attributes; ++i)
    {
      bn_null (new_proof->ProofSAttrs[i]);
      bn_new (new_proof->ProofSAttrs[i]);
    }

    g1_null (new_proof->Nym);
    g1_new (new_proof->Nym);
  }
  RLC_CATCH_ANY {
    g1_free (new_proof->Nym);
    for (size_t i = 0; i < public_parameters->nr_of_attributes; ++i)
      bn_free (new_proof->ProofSAttrs[i]);
    PABC_FREE_NULL (new_proof->ProofSAttrs);
    bn_free (new_proof->ProofSSPrime);
    bn_free (new_proof->ProofSR3);
    bn_free (new_proof->ProofSR2);
    bn_free (new_proof->ProofSE);
    bn_free (new_proof->ProofSSk);
    bn_free (new_proof->ProofC);
    g1_free (new_proof->BPrime);
    g1_free (new_proof->ABar);
    g1_free (new_proof->APrime);

    pabc_free_nonce (ctx, &new_proof->nonce);
    pabc_free_attribute_predicates (ctx, public_parameters, &new_proof->DI);
    PABC_FREE_NULL (new_proof);
    print_and_return (PABC_OOM);
  }
  RLC_FINALLY {}

  *proof = new_proof;

  return PABC_OK;
}


enum pabc_status
pabc_free_proof (struct pabc_context const *const ctx,
                 struct pabc_public_parameters const *const public_parameters,
                 struct pabc_blinded_proof **proof)
{
  if (ctx == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (public_parameters == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (proof == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (*proof == NULL)
    print_and_return (PABC_UNINITIALIZED);

  pabc_free_attribute_predicates (ctx, public_parameters, &(*proof)->DI);

  RLC_TRY {
    g1_free ((*proof)->APrime);
    g1_null ((*proof)->APrime);

    g1_free ((*proof)->ABar);
    g1_null ((*proof)->ABar);

    g1_free ((*proof)->BPrime);
    g1_null ((*proof)->BPrime);

    bn_free ((*proof)->ProofC);
    bn_null ((*proof)->ProofC);

    bn_free ((*proof)->ProofSSk);
    bn_null ((*proof)->ProofSSk);

    bn_free ((*proof)->ProofSE);
    bn_null ((*proof)->ProofSE);

    bn_free ((*proof)->ProofSR2);
    bn_null ((*proof)->ProofSR2);

    bn_free ((*proof)->ProofSR3);
    bn_null ((*proof)->ProofSR3);

    bn_free ((*proof)->ProofSSPrime);
    bn_null ((*proof)->ProofSSPrime);

    for (size_t i = 0; i < public_parameters->nr_of_attributes; ++i)
    {
      bn_free ((*proof)->ProofSAttrs[i]);
      bn_null ((*proof)->ProofSAttrs[i]);
    }
    PABC_FREE_NULL ((*proof)->ProofSAttrs);

    g1_free ((*proof)->Nym);
    g1_null ((*proof)->Nym);
  }
  RLC_CATCH_ANY { print_and_return (PABC_RELIC_FAIL); }
  RLC_FINALLY {}

  pabc_free_nonce (ctx, &(*proof)->nonce);

  PABC_FREE_NULL (*proof);

  return PABC_OK;
}


enum pabc_status
pabc_gen_proof (
  struct pabc_context *const ctx, struct pabc_user_context *const usr_ctx,
  struct pabc_public_parameters *const public_parameters,
  struct pabc_blinded_proof *const proof, struct pabc_credential *const cred)

{
  if (ctx == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (usr_ctx == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (public_parameters == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (proof == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (cred == NULL)
    print_and_return (PABC_UNINITIALIZED);

  enum pabc_status status;

  struct pabc_user_mem *mem = NULL;
  status = pabc_user_mem_init (&mem);
  if (status != PABC_OK)
    print_and_return (status);

  RLC_TRY {
    // 1. Randomize A: sample a random element r1 from Zp*, and compute A' =
    // A^r1.
    bn_rand_mod (mem->r1, ctx->group_order);
    g1_mul (proof->APrime, cred->A, mem->r1);

    // 2. Compute _A = A'^(−e) · B^r1
    g1_neg (proof->ABar, proof->APrime);
    g1_mul (proof->ABar, proof->ABar, cred->e);
    g1_mul (mem->Br1, cred->B, mem->r1);
    g1_add (proof->ABar, proof->ABar, mem->Br1);
    // r3 = 1/r1.
    bn_mod_inv (mem->r3, mem->r1, ctx->group_order);

    // 3. Sample an element r2 from Zp.
    bn_rand_mod (mem->r2, ctx->group_order);

    // 4. Compute B' = B^r1 · HRand^(-r2)
    g1_mul (proof->BPrime, cred->B, mem->r1);
    g1_neg (mem->HRandr2, public_parameters->ipk->HRand);
    g1_mul (mem->HRandr2, mem->HRandr2, mem->r2);
    g1_add (proof->BPrime, proof->BPrime, mem->HRandr2);
    // s' = s - r2·r3.
    bn_mul (mem->r2r3, mem->r2, mem->r3);
    bn_mod (mem->r2r3, mem->r2r3, ctx->group_order);
    bn_sub (mem->sPrime, cred->s, mem->r2r3);
    bn_mod (mem->sPrime, mem->sPrime, ctx->group_order);

    // 5. Generate zero knowledge pabc_proof π = PoK{(sk, {ai}_hidden, e, r2,
    // r3, s')} such that
    //
    // _A/B' = A'^(-e) · HRand^r2 and
    //
    // g1 · MulAll(hi^ai_reveal) = (B')^r3 · HRand^(-s') · HSk^(-sk) ·
    // MulAll(hi^(-ai_hidden)), and hi is a shorthand for HAttrs[i].

    // r_ai : for i belongs to _D(attributes not disclosed), means
    // D[i]==0
    bn_t *r_ai = malloc (sizeof(bn_t) * public_parameters->nr_of_attributes);
    if (r_ai == NULL)
    {
      pabc_user_mem_free (&mem);
      print_and_return (PABC_OOM);
    }
    for (size_t i = 0; i < public_parameters->nr_of_attributes; ++i)
    {
      bn_null (r_ai[i]);
      if (proof->DI->D[i] == PABC_NOT_DISCLOSED)
      {
        bn_new (r_ai[i]);
        bn_rand_mod (r_ai[i], ctx->group_order);
      }
    }

    //  r_e : random from Zp
    bn_rand_mod (mem->r_e, ctx->group_order);

    //  r_r2 : random from Zp
    bn_rand_mod (mem->r_r2, ctx->group_order);

    //  r_r3 : random from Zp
    bn_rand_mod (mem->r_r3, ctx->group_order);

    //  r_s' : random from Zp
    bn_rand_mod (mem->r_sp, ctx->group_order);

    //  r_sk : random from Zp
    bn_rand_mod (mem->r_sk, ctx->group_order);

    // E : E = HSk^r_sk
    g1_mul (mem->E, public_parameters->ipk->HSk, mem->r_sk);

    // t1 : t1 = A'^r_e · HRand^r_r2
    g1_mul (mem->t1, proof->APrime, mem->r_e);
    g1_mul (mem->HRand_r_r2, public_parameters->ipk->HRand, mem->r_r2);
    g1_add (mem->t1, mem->t1, mem->HRand_r_r2);

    // t2 : t2 = (B')^r_r3 · HRand^r_s' · E^(-1) · MulAll(hi^r_ai)
    g1_mul (mem->t2, proof->BPrime, mem->r_r3);
    g1_mul (mem->HRand_r_sp, public_parameters->ipk->HRand, mem->r_sp);
    g1_add (mem->t2, mem->t2, mem->HRand_r_sp);
    g1_neg (mem->E_neg, mem->E);
    g1_add (mem->t2, mem->t2, mem->E_neg);
    g1_set_infty (mem->mul_all_hi_r_ai);
    for (size_t i = 0; i < public_parameters->nr_of_attributes; ++i)
    {
      if (proof->DI->D[i] == PABC_NOT_DISCLOSED)
      {
        g1_mul (mem->temp, public_parameters->ipk->HAttrs[i], r_ai[i]);
        g1_add (mem->mul_all_hi_r_ai, mem->mul_all_hi_r_ai, mem->temp);
      }
    }
    g1_add (mem->t2, mem->t2, mem->mul_all_hi_r_ai);

    // c' : c' = H(A', _A, B', nym, t1, t2, g1, HRand, h1, ... , hL, w)
    int failed = 0;
    status = reset_hash (ctx);
    if (PABC_OK != status)
      failed = 1;
    status = hash_add_g1 (ctx, proof->APrime);
    if (PABC_OK != status)
      failed = 1;
    status = hash_add_g1 (ctx, proof->ABar);
    if (PABC_OK != status)
      failed = 1;
    status = hash_add_g1 (ctx, proof->BPrime);
    if (PABC_OK != status)
      failed = 1;
    status = hash_add_g1 (ctx, cred->Nym);
    if (PABC_OK != status)
      failed = 1;
    status = hash_add_g1 (ctx, mem->t1);
    if (PABC_OK != status)
      failed = 1;
    status = hash_add_g1 (ctx, mem->t2);
    if (PABC_OK != status)
      failed = 1;
    status = hash_add_g1 (ctx, ctx->g1_gen);
    if (PABC_OK != status)
      failed = 1;
    status = hash_add_g1 (ctx, public_parameters->ipk->HRand);
    if (PABC_OK != status)
      failed = 1;
    for (size_t i = 0; i < public_parameters->nr_of_attributes; ++i)
    {
      status = hash_add_g1 (ctx, public_parameters->ipk->HAttrs[i]);
      if (PABC_OK != status)
        failed = 1;
    }
    status = hash_add_g2 (ctx, public_parameters->ipk->w);
    if (PABC_OK != status)
      failed = 1;
    status = compute_hash (ctx, mem->cp);
    if (PABC_OK != status)
      failed = 1;

    if (failed == 1)
    {
      // clean up
      pabc_user_mem_free (&mem);
      for (size_t i = 0; i < public_parameters->nr_of_attributes; ++i)
        if (proof->DI->D[i] == PABC_NOT_DISCLOSED)
        {
          bn_free (r_ai[i]);
        }
      PABC_FREE_NULL (r_ai);
      print_and_return (status); // last error
    }

    // nonce : nonce, with τ bit length, randomly generated again

    status = pabc_populate_nonce (ctx, proof->nonce);
    if (PABC_OK != status)
    {
      // clean up
      pabc_user_mem_free (&mem);
      for (size_t i = 0; i < public_parameters->nr_of_attributes; ++i)
        if (proof->DI->D[i] == PABC_NOT_DISCLOSED)
        {
          bn_free (r_ai[i]);
        }
      PABC_FREE_NULL (r_ai);
      print_and_return (status);
    }

    // c : c = H(nonce, c', (D, I))
    failed = 0;
    status = reset_hash (ctx);
    if (PABC_OK != status)
      failed = 1;
    status = hash_add_bn (ctx, proof->nonce->nonce);
    if (PABC_OK != status)
      failed = 1;
    status = hash_add_bn (ctx, mem->cp);
    if (PABC_OK != status)
      failed = 1;
    status = hash_add_DI (ctx, public_parameters, proof->DI);
    if (PABC_OK != status)
      failed = 1;
    status = compute_hash (ctx, proof->ProofC);
    if (PABC_OK != status)
      failed = 1;
    if (failed == 1)
    {
      // clean up
      pabc_user_mem_free (&mem);
      for (size_t i = 0; i < public_parameters->nr_of_attributes; ++i)
        if (proof->DI->D[i] == PABC_NOT_DISCLOSED)
        {
          bn_free (r_ai[i]);
        }
      PABC_FREE_NULL (r_ai);
      print_and_return (status); // last error
    }

    // s_sk : s_sk = r_sk + c · sk
    bn_mul (mem->temp_bnt, proof->ProofC, usr_ctx->sk);
    bn_add (proof->ProofSSk, mem->r_sk, mem->temp_bnt);
    bn_mod (proof->ProofSSk, proof->ProofSSk, ctx->group_order);

    // s_ai : s_ai = r_ai - c · ai, for i belongs to _D(attributes not
    // disclosed)
    for (size_t i = 0; i < public_parameters->nr_of_attributes; ++i)
    {
      if (proof->DI->D[i] == PABC_NOT_DISCLOSED)
      {
        failed = 0;
        status = reset_hash (ctx);
        if (PABC_OK != status)
          failed = 1;
        status = hash_add_str (ctx, cred->plain_attrs->attribute_values[i]);
        if (PABC_OK != status)
          failed = 1;
        status = compute_hash (ctx, mem->AttrsI);
        if (PABC_OK != status)
          failed = 1;
        if (failed == 1)
        {
          // clean up
          pabc_user_mem_free (&mem);
          for (size_t j = 0; j < public_parameters->nr_of_attributes; ++j)
            if (proof->DI->D[j] == PABC_NOT_DISCLOSED)
            {
              bn_free (r_ai[j]);
            }
          PABC_FREE_NULL (r_ai);
          print_and_return (status); // last error
        }
        bn_mul (proof->ProofSAttrs[i], proof->ProofC, mem->AttrsI);
        bn_sub (proof->ProofSAttrs[i], r_ai[i], proof->ProofSAttrs[i]);
        bn_mod (proof->ProofSAttrs[i], proof->ProofSAttrs[i], ctx->group_order);
      }
    }

    // s_e : s_e = r_e - c · e
    bn_mul (proof->ProofSE, proof->ProofC, cred->e);
    bn_mod (proof->ProofSE, proof->ProofSE, ctx->group_order);
    bn_sub (proof->ProofSE, mem->r_e, proof->ProofSE);
    bn_mod (proof->ProofSE, proof->ProofSE, ctx->group_order);

    // s_r2 : s_r2 = r_r2 + c · r2
    bn_mul (proof->ProofSR2, proof->ProofC, mem->r2);
    bn_mod (proof->ProofSR2, proof->ProofSR2, ctx->group_order);
    bn_add (proof->ProofSR2, mem->r_r2, proof->ProofSR2);
    bn_mod (proof->ProofSR2, proof->ProofSR2, ctx->group_order);

    // s_r3 : s_r3 = r_r3 + c · r3
    bn_mul (proof->ProofSR3, proof->ProofC, mem->r3);
    bn_mod (proof->ProofSR3, proof->ProofSR3, ctx->group_order);
    bn_add (proof->ProofSR3, mem->r_r3, proof->ProofSR3);
    bn_mod (proof->ProofSR3, proof->ProofSR3, ctx->group_order);

    // s_s' : s_s' = r_s' - c · s'
    bn_mul (proof->ProofSSPrime, proof->ProofC, mem->sPrime);
    bn_mod (proof->ProofSSPrime, proof->ProofSSPrime, ctx->group_order);
    bn_sub (proof->ProofSSPrime, mem->r_sp, proof->ProofSSPrime);
    bn_mod (proof->ProofSSPrime, proof->ProofSSPrime, ctx->group_order);

    // copy nym
    g1_copy (proof->Nym, cred->Nym);

    // clean up
    pabc_user_mem_free (&mem);
    for (size_t i = 0; i < public_parameters->nr_of_attributes; ++i)
    {
      if (proof->DI->D[i] == PABC_NOT_DISCLOSED)
      {
        bn_free (r_ai[i]);
      }
    }
    PABC_FREE_NULL (r_ai);
    bn_free (temp_bnt);
  }
  RLC_CATCH_ANY { print_and_return (PABC_RELIC_FAIL); }
  RLC_FINALLY {}

  return PABC_OK;
}


enum pabc_status
pabc_new_user_context (
  struct pabc_context const *const ctx,
  struct pabc_public_parameters const *const public_parameters,
  struct pabc_user_context **usr_ctx)
{
  if (ctx == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (public_parameters == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (usr_ctx == NULL)
    print_and_return (PABC_UNINITIALIZED);

  struct pabc_user_context *new_usr_ctx =
    malloc (sizeof(struct pabc_user_context));
  if (new_usr_ctx == NULL)
    print_and_return (PABC_OOM);
  new_usr_ctx->plain_attrs =
    malloc (sizeof(char *) * public_parameters->nr_of_attributes);
  if (new_usr_ctx->plain_attrs == NULL)
  {
    PABC_FREE_NULL (new_usr_ctx);
    print_and_return (PABC_OOM);
  }
  for (size_t i = 0; i < public_parameters->nr_of_attributes; ++i)
    new_usr_ctx->plain_attrs[i] = NULL;

  RLC_TRY {
    bn_null (new_usr_ctx->sk);
    bn_new (new_usr_ctx->sk);
  }
  RLC_CATCH_ANY {
    PABC_FREE_NULL (new_usr_ctx->plain_attrs);
    PABC_FREE_NULL (new_usr_ctx);
    print_and_return (PABC_RELIC_FAIL);
  }
  RLC_FINALLY {}

  *usr_ctx = new_usr_ctx;

  return PABC_OK;
}


enum pabc_status
pabc_populate_user_context (struct pabc_context *const ctx,
                            struct pabc_user_context *const usr_ctx)
{
  if (ctx == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (usr_ctx == NULL)
    print_and_return (PABC_UNINITIALIZED);

  RLC_TRY {
    // 1. Sample a random element sk from Zp as user's master secret.
    bn_rand_mod (usr_ctx->sk, ctx->group_order);
  }
  RLC_CATCH_ANY { print_and_return (PABC_RELIC_FAIL); }
  RLC_FINALLY {}

  return PABC_OK;
}


enum pabc_status
pabc_free_user_context (
  struct pabc_context const *const ctx,
  struct pabc_public_parameters const *const public_parameters,
  struct pabc_user_context **usr_ctx)
{
  if (ctx == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (public_parameters == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (usr_ctx == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (*usr_ctx == NULL)
    print_and_return (PABC_UNINITIALIZED);

  RLC_TRY {
    bn_free ((*usr_ctx)->sk);
    for (size_t i = 0; i < public_parameters->nr_of_attributes; ++i)
      PABC_FREE_NULL ((*usr_ctx)->plain_attrs[i]);
    PABC_FREE_NULL ((*usr_ctx)->plain_attrs);
    PABC_FREE_NULL ((*usr_ctx));
  }
  RLC_CATCH_ANY { print_and_return (PABC_RELIC_FAIL); }
  RLC_FINALLY {}

  return PABC_OK;
}


enum pabc_status
pabc_set_attribute_value (
  struct pabc_context const *const ctx,
  struct pabc_public_parameters const *const public_parameters,
  struct pabc_user_context *const usr_ctx, size_t pos,
  char const *const val)
{
  if (ctx == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (public_parameters == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (usr_ctx == NULL)
    print_and_return (PABC_UNINITIALIZED);
  // if (val == NULL)
  //   print_and_return (PABC_UNINITIALIZED);

  if (pos >= public_parameters->nr_of_attributes)
    print_and_return (PABC_FAILURE);

  if (NULL == val)
  {
    usr_ctx->plain_attrs[pos] = NULL;
    return PABC_OK;
  }

  char **str_ptr = &usr_ctx->plain_attrs[pos];
  char *new_mem_location;
  new_mem_location = realloc (*str_ptr, strlen (val) + 1);
  if (new_mem_location == NULL)
    print_and_return (PABC_OOM);
  *str_ptr = new_mem_location;
  strcpy (*str_ptr, val);
  return PABC_OK;
}


enum pabc_status
pabc_new_attribute_predicates (
  struct pabc_context const *const ctx,
  struct pabc_public_parameters const *const public_parameters,
  struct pabc_attribute_predicates_D_I **DI)
{
  if (ctx == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (public_parameters == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (DI == NULL)
    print_and_return (PABC_UNINITIALIZED);

  struct pabc_attribute_predicates_D_I *new_DI =
    malloc (sizeof(struct pabc_attribute_predicates_D_I));
  if (new_DI == NULL)
    print_and_return (PABC_OOM);

  new_DI->D =
    malloc (public_parameters->nr_of_attributes * sizeof(enum pabc_status));
  if (new_DI->D == NULL)
  {
    PABC_FREE_NULL (new_DI);
    print_and_return (PABC_OOM);
  }

  for (size_t i = 0; i < public_parameters->nr_of_attributes; ++i)
    new_DI->D[i] = PABC_NOT_DISCLOSED;

  new_DI->I = malloc (sizeof(char *) * public_parameters->nr_of_attributes);
  if (new_DI->I == NULL)
  {
    PABC_FREE_NULL (new_DI->D);
    PABC_FREE_NULL (new_DI);
    print_and_return (PABC_OOM);
  }
  for (size_t i = 0; i < public_parameters->nr_of_attributes; ++i)
    new_DI->I[i] = NULL;

  *DI = new_DI;

  return PABC_OK;
}


enum pabc_status
pabc_set_attribute_predicate (
  struct pabc_context *const ctx,
  struct pabc_public_parameters const *const public_parameters,
  struct pabc_blinded_proof *const proof, size_t pos,
  enum pabc_status disclosed, struct pabc_credential const *const cred)
{
  if (ctx == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (public_parameters == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (proof == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (cred == NULL)
    print_and_return (PABC_UNINITIALIZED);

  if ((disclosed != PABC_DISCLOSED) && (disclosed != PABC_NOT_DISCLOSED))
    print_and_return (PABC_FAILURE);

  if (pos >= public_parameters->nr_of_attributes)
    print_and_return (PABC_OOB);

  if (proof->DI->D[pos] == disclosed)
    return PABC_OK; // nothing to do

  if (proof->DI->D[pos] == PABC_NOT_DISCLOSED) // => disclosed == PABC_DISCLOSED
  {
    proof->DI->D[pos] = disclosed;
    if (cred->plain_attrs->attribute_values[pos])
    {
      proof->DI->I[pos] =
        realloc (proof->DI->I[pos],
                 strlen (cred->plain_attrs->attribute_values[pos]) + 1);
      if (proof->DI->I[pos] == NULL)
        print_and_return (PABC_OOM);
      strcpy (proof->DI->I[pos], cred->plain_attrs->attribute_values[pos]);
    }
    else
    {
      // disclosed attribute is not set
      proof->DI->I[pos] = NULL;
    }
  }
  else   // previously disclosed attribut should not be disclosed
  {
    proof->DI->D[pos] = PABC_NOT_DISCLOSED;
    // TODO securly overwrite???
    PABC_FREE_NULL (proof->DI->I[pos]);
  }
  return PABC_OK;
}


enum pabc_status
pabc_free_attribute_predicates (
  struct pabc_context const *const ctx,
  struct pabc_public_parameters const *const public_parameters,
  struct pabc_attribute_predicates_D_I **DI)
{
  if (ctx == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (public_parameters == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (DI == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (*DI == NULL)
    print_and_return (PABC_UNINITIALIZED);

  for (size_t i = 0; i < public_parameters->nr_of_attributes; ++i)
    PABC_FREE_NULL ((*DI)->I[i]);
  PABC_FREE_NULL ((*DI)->I);
  PABC_FREE_NULL ((*DI)->D);
  PABC_FREE_NULL (*DI);

  return PABC_OK;
}


enum pabc_status
pabc_set_disclosure_by_attribute_name (
  struct pabc_context *const ctx,
  struct pabc_public_parameters const *const public_parameters,
  struct pabc_blinded_proof *const proof, char const *const name,
  enum pabc_status disclosed, struct pabc_credential const *const cred)
{
  if (ctx == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (public_parameters == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (proof == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (name == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (cred == NULL)
    print_and_return (PABC_UNINITIALIZED);

  size_t pos = find_attribute_idx_by_name (ctx, public_parameters, name);
  if (pos > public_parameters->nr_of_attributes)
    print_and_return (PABC_FAILURE);
  return pabc_set_attribute_predicate (ctx, public_parameters, proof, pos,
                                       disclosed, cred);
}


enum pabc_status
pabc_set_attribute_value_by_name (
  struct pabc_context const *const ctx,
  struct pabc_public_parameters const *const public_parameters,
  struct pabc_user_context *const usr_ctx, char const *const name,
  char const *const value)
{
  if (ctx == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (public_parameters == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (usr_ctx == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (name == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (value == NULL)
    print_and_return (PABC_UNINITIALIZED);

  size_t pos = find_attribute_idx_by_name (ctx, public_parameters, name);
  if (pos > public_parameters->nr_of_attributes)
    print_and_return (PABC_ATTRIBUTE_UNKOWN);
  return pabc_set_attribute_value (ctx, public_parameters, usr_ctx, pos, value);
}


enum pabc_status
pabc_user_mem_init (struct pabc_user_mem **const mem)
{
  if (! mem)
    print_and_return (PABC_UNINITIALIZED);

  // allocate struct
  struct pabc_user_mem *new_mem = malloc (sizeof(struct pabc_user_mem));
  if (! new_mem)
    print_and_return (PABC_OOM);
  *mem = new_mem;

  // RELIC null
  RLC_TRY {
    bn_null ((*mem)->AttrsI);
    bn_null ((*mem)->cp);
    bn_null ((*mem)->r);
    bn_null ((*mem)->r1);
    bn_null ((*mem)->r2);
    bn_null ((*mem)->r2r3);
    bn_null ((*mem)->r3);
    bn_null ((*mem)->r_e);
    bn_null ((*mem)->r_r2);
    bn_null ((*mem)->r_r3);
    bn_null ((*mem)->r_sk);
    bn_null ((*mem)->r_sp);
    bn_null ((*mem)->sPrime);
    bn_null ((*mem)->temp_bnt);
    g1_null ((*mem)->Br1);
    g1_null ((*mem)->E);
    g1_null ((*mem)->E_neg);
    g1_null ((*mem)->HRand_r_r2);
    g1_null ((*mem)->HRand_r_sp);
    g1_null ((*mem)->HRandr2);
    g1_null ((*mem)->mul_all_hi_r_ai);
    g1_null ((*mem)->t1);
    g1_null ((*mem)->t2);
    g1_null ((*mem)->temp);
  }
  RLC_CATCH_ANY {
    PABC_FREE_NULL (*mem);
    print_and_return (PABC_RELIC_FAIL);
  }
  RLC_FINALLY {}

  // RELIC new
  RLC_TRY {
    bn_new ((*mem)->AttrsI);
    bn_new ((*mem)->cp);
    bn_new ((*mem)->r);
    bn_new ((*mem)->r1);
    bn_new ((*mem)->r2);
    bn_new ((*mem)->r2r3);
    bn_new ((*mem)->r3);
    bn_new ((*mem)->r_e);
    bn_new ((*mem)->r_r2);
    bn_new ((*mem)->r_r3);
    bn_new ((*mem)->r_sk);
    bn_new ((*mem)->r_sp);
    bn_new ((*mem)->sPrime);
    bn_new ((*mem)->temp_bnt);
    g1_new ((*mem)->Br1);
    g1_new ((*mem)->E);
    g1_new ((*mem)->E_neg);
    g1_new ((*mem)->HRand_r_r2);
    g1_new ((*mem)->HRand_r_sp);
    g1_new ((*mem)->HRandr2);
    g1_new ((*mem)->mul_all_hi_r_ai);
    g1_new ((*mem)->t1);
    g1_new ((*mem)->t2);
    g1_new ((*mem)->temp);
  }
  RLC_CATCH_ANY {
    pabc_user_mem_free (mem);
    print_and_return (PABC_RELIC_FAIL);
  }
  RLC_FINALLY {}

  return PABC_OK;
}


enum pabc_status
pabc_user_mem_free (struct pabc_user_mem **const mem)
{
  if (! mem)
    print_and_return (PABC_UNINITIALIZED);
  RLC_TRY {
    bn_free ((*mem)->AttrsI);
    bn_free ((*mem)->cp);
    bn_free ((*mem)->r);
    bn_free ((*mem)->r1);
    bn_free ((*mem)->r2);
    bn_free ((*mem)->r2r3);
    bn_free ((*mem)->r3);
    bn_free ((*mem)->r_e);
    bn_free ((*mem)->r_r2);
    bn_free ((*mem)->r_r3);
    bn_free ((*mem)->r_sk);
    bn_free ((*mem)->r_sp);
    bn_free ((*mem)->sPrime);
    bn_free ((*mem)->temp_bnt);
    g1_free ((*mem)->Br1);
    g1_free ((*mem)->E);
    g1_free ((*mem)->E_neg);
    g1_free ((*mem)->HRand_r_r2);
    g1_free ((*mem)->HRand_r_sp);
    g1_free ((*mem)->HRandr2);
    g1_free ((*mem)->mul_all_hi_r_ai);
    g1_free ((*mem)->t1);
    g1_free ((*mem)->t2);
    g1_free ((*mem)->temp);
  }
  RLC_CATCH_ANY { print_and_return (PABC_RELIC_FAIL); }
  RLC_FINALLY {
    PABC_FREE_NULL (*mem);
    return PABC_OK;
  }
}
