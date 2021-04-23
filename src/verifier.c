/**
 * Copyright (c) 2021 Fraunhofer AISEC
 *
 * SPDX-License-Identifier: Apache-2.0
 **/





#include "verifier.h"

enum pabc_status
pabc_verify_blinded_proof (
  struct pabc_context *const ctx,
  struct pabc_public_parameters *const public_parameters,
  struct pabc_nonce *const nonce, struct pabc_blinded_proof *const proof)
{

  return pabc_verify_blinded_proof_no_nonce (
    ctx, public_parameters, proof,
    pabc_nonce_compare (ctx, nonce, proof->nonce));
}


enum pabc_status
pabc_verify_blinded_proof_no_nonce (
  struct pabc_context *const ctx,
  struct pabc_public_parameters *const public_parameters,
  struct pabc_blinded_proof *const proof,
  enum pabc_status nonce_verified_by_caller)
{
  // TODO currently, this code only checks the points. we should also check the
  // plain attributes matching the point or document this as a user
  // responsibility (discouraged)

  if (ctx == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (public_parameters == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (proof == NULL)
    print_and_return (PABC_UNINITIALIZED);

  if (nonce_verified_by_caller != PABC_OK)
    print_and_return (nonce_verified_by_caller);

  enum pabc_status result = PABC_OK;
  int failed = 0;
  enum pabc_status status;

  struct pabc_verifier_mem *mem = NULL;

  status = pabc_verifier_mem_init (&mem);
  if (status != PABC_OK)
    print_and_return (status);

  // check that there are no revealed attributes that are not disclosed accoding
  // to SAttrs
  for (size_t i = 0; i < public_parameters->nr_of_attributes; ++i)
  {
    char const *const attr_val = proof->DI->I[i];
    enum pabc_status const flag = proof->DI->D[i];
    bn_t sattrs = {*proof->ProofSAttrs[i]};

    if (attr_val && (flag != PABC_DISCLOSED))
      print_and_return (PABC_FAILURE);
    if (attr_val && ! bn_is_zero (sattrs))
      print_and_return (PABC_FAILURE);

    if (! bn_is_zero (sattrs) && (flag == PABC_DISCLOSED))
      print_and_return (PABC_FAILURE);
    if (! bn_is_zero (sattrs) && (attr_val != NULL))
      print_and_return (PABC_FAILURE);

    if ((flag == PABC_DISCLOSED) && ! bn_is_zero (sattrs))
      print_and_return (PABC_FAILURE);

    if ((flag == PABC_NOT_DISCLOSED) && attr_val)
      print_and_return (PABC_FAILURE);
    if ((flag == PABC_NOT_DISCLOSED) && bn_is_zero (sattrs))
      print_and_return (PABC_FAILURE);
  }

  RLC_TRY {

    // 1. Check if A' != 1 in G1; if false, return false.
    if (g1_is_infty (proof->APrime) != 0)
    {
      pabc_verifier_mem_free (&mem);
      print_and_return (PABC_FAILURE);
    }

    // 2. check if e(A', w) == e(_A, g2); if false, return false. This is zk-PoK
    // for A.
    pc_map (mem->lhs, proof->APrime, public_parameters->ipk->w);
    pc_map (mem->rhs, proof->ABar, ctx->g2_gen);
    if (gt_cmp (mem->lhs, mem->rhs) != RLC_EQ)
      result = PABC_FAILURE;

    // 3. Parse π : {c, s_sk, {s_ai}, s_e, s_r2, s_r3, s_s', nonce} <- π; if
    // failed, return false.

    // 4.  ~t1 : ~t1 = A'^s_e · HRand^s_r2 · (_A/B')^(-c) . This is zk-PoK for
    // e, r2.
    // A'^s_e
    g1_mul (mem->t1tilde, proof->APrime, proof->ProofSE);
    // HRand^s_r2
    g1_mul (mem->HRand_s_r2, public_parameters->ipk->HRand, proof->ProofSR2);
    g1_add (mem->t1tilde, mem->t1tilde, mem->HRand_s_r2);
    // (_A/B')^(-c)
    g1_neg (mem->ABarNeg, proof->ABar);
    g1_mul (mem->temp, mem->ABarNeg, proof->ProofC);
    g1_add (mem->t1tilde, mem->t1tilde, mem->temp);
    g1_mul (mem->temp, proof->BPrime, proof->ProofC);
    g1_add (mem->t1tilde, mem->t1tilde, mem->temp);

    // ~t2 : (B')^s_r3 · HRand^s_s' · HSk^(-s_sk) · MulAll(hi^(-s_ai)) ·
    // (g1·MulAll(hi^ai))^(-c)
    /*
     * the i above, first MulAll( ) belongs to _D, where D[i]==0(false)
     * the i above, second MulAll( ) belongs to D, where D[i]==1(true)
     * This is ZKPoK for r3, s', gsk, ai of _D.
     */
    // (B')^s_r3
    g1_mul (mem->t2tilde, proof->BPrime, proof->ProofSR3);
    // HRand^s_s'
    g1_mul (mem->temp, public_parameters->ipk->HRand, proof->ProofSSPrime);
    g1_add (mem->t2tilde, mem->t2tilde, mem->temp);
    // HSk^(-s_sk)
    g1_neg (mem->temp, public_parameters->ipk->HSk);
    g1_mul (mem->temp, mem->temp, proof->ProofSSk);
    g1_add (mem->t2tilde, mem->t2tilde, mem->temp);
    // MulAll(hi^(-s_ai))
    g1_set_infty (mem->temp);
    for (size_t i = 0; i < public_parameters->nr_of_attributes; ++i)
    {
      if (proof->DI->D[i] == PABC_NOT_DISCLOSED)
      {
        g1_copy (
          mem->temp2,
          public_parameters->ipk->HAttrs[i]);   // TODO why not g1_neg ?????????
        g1_mul (mem->temp2, mem->temp2, proof->ProofSAttrs[i]);
        g1_add (mem->temp, mem->temp, mem->temp2);
      }
    }
    g1_add (mem->t2tilde, mem->t2tilde, mem->temp);
    // (g1·MulAll(hi^ai))^(-c)
    g1_set_infty (mem->temp);
    for (size_t i = 0; i < public_parameters->nr_of_attributes;
         ++i) // MulAll(hi^ai)
    {
      if (proof->DI->D[i] == PABC_DISCLOSED)
      {
        status = reset_hash (ctx);
        if (PABC_OK != status)
          failed = 1;

        status = hash_add_str (ctx, proof->DI->I[i]);
        if (PABC_OK != status)
          failed = 1;

        status = compute_hash (ctx, mem->AttrsI);
        if (PABC_OK != status)
          failed = 1;

        if (failed == 1)
        {
          pabc_verifier_mem_free (&mem);
          print_and_return (status); // last error
        }

        g1_mul (mem->temp2, public_parameters->ipk->HAttrs[i], mem->AttrsI);
        g1_add (mem->temp, mem->temp, mem->temp2);
      }
    }
    g1_add (mem->temp, ctx->g1_gen, mem->temp);
    g1_neg (mem->temp, mem->temp);
    g1_mul (mem->temp, mem->temp, proof->ProofC);
    g1_add (mem->t2tilde, mem->t2tilde, mem->temp);

    // 6. c' : c' = H(nonce, H(A', _A, B', nym, ~t1, ~t2, g1, HRand, h1, ... ,
    // hL, w), (D, I))
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
    status = hash_add_g1 (ctx, proof->Nym);
    if (PABC_OK != status)
      failed = 1;
    status = hash_add_g1 (ctx, mem->t1tilde);
    if (PABC_OK != status)
      failed = 1;
    status = hash_add_g1 (ctx, mem->t2tilde);
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
    status = compute_hash (ctx, mem->inner_hash_result);
    if (PABC_OK != status)
      failed = 1;

    status = reset_hash (ctx);
    if (PABC_OK != status)
      failed = 1;
    status = hash_add_bn (ctx, proof->nonce->nonce);
    if (PABC_OK != status)
      failed = 1;
    status = hash_add_bn (ctx, mem->inner_hash_result);
    if (PABC_OK != status)
      failed = 1;
    status = hash_add_DI (ctx, public_parameters, proof->DI);
    if (PABC_OK != status)
      failed = 1;
    status = compute_hash (ctx, mem->cp);
    if (PABC_OK != status)
      failed = 1;

    if (failed == 1)
    {
      pabc_verifier_mem_free (&mem);

      print_and_return (status); // last error
    }

    // 7. Check if c == c' : if false: return false. Otherwise return true.
    if (bn_cmp (proof->ProofC, mem->cp) != RLC_EQ)
      result = PABC_FAILURE;

    // clean up
    pabc_verifier_mem_free (&mem);
  }
  RLC_CATCH_ANY { result = PABC_RELIC_FAIL; }
  RLC_FINALLY {}

  // all checks finished
  return result;
}


enum pabc_status
pabc_verifier_mem_init (struct pabc_verifier_mem **const mem)
{
  if (! mem)
    print_and_return (PABC_UNINITIALIZED);

  // allocate struct
  struct pabc_verifier_mem *new_mem = malloc (sizeof(struct pabc_verifier_mem));
  if (! new_mem)
    print_and_return (PABC_OOM);
  *mem = new_mem;

  // RELIC null
  RLC_TRY {
    bn_null ((*mem)->AttrsI);
    bn_null ((*mem)->cp);
    bn_null ((*mem)->inner_hash_result);
    g1_null ((*mem)->ABarNeg);
    g1_null ((*mem)->HRand_s_r2);
    g1_null ((*mem)->t1tilde);
    g1_null ((*mem)->t2tilde);
    g1_null ((*mem)->temp);
    g1_null ((*mem)->temp2);
    gt_null ((*mem)->lhs);
    gt_null ((*mem)->rhs);
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
    bn_new ((*mem)->inner_hash_result);
    g1_new ((*mem)->ABarNeg);
    g1_new ((*mem)->HRand_s_r2);
    g1_new ((*mem)->t1tilde);
    g1_new ((*mem)->t2tilde);
    g1_new ((*mem)->temp);
    g1_new ((*mem)->temp2);
    gt_new ((*mem)->lhs);
    gt_new ((*mem)->rhs);
  }
  RLC_CATCH_ANY {
    pabc_verifier_mem_free (mem);
    print_and_return (PABC_RELIC_FAIL);
  }
  RLC_FINALLY {}

  return PABC_OK;
}


enum pabc_status
pabc_verifier_mem_free (struct pabc_verifier_mem **const mem)
{
  if (! mem)
    print_and_return (PABC_UNINITIALIZED);
  RLC_TRY {
    bn_free ((*mem)->AttrsI);
    bn_free ((*mem)->cp);
    bn_free ((*mem)->inner_hash_result);
    g1_free ((*mem)->ABarNeg);
    g1_free ((*mem)->HRand_s_r2);
    g1_free ((*mem)->t1tilde);
    g1_free ((*mem)->t2tilde);
    g1_free ((*mem)->temp);
    g1_free ((*mem)->temp2);
    gt_free ((*mem)->lhs);
    gt_free ((*mem)->rhs);
  }
  RLC_CATCH_ANY { print_and_return (PABC_RELIC_FAIL); }
  RLC_FINALLY {
    PABC_FREE_NULL (*mem);
    return PABC_OK;
  }
}
