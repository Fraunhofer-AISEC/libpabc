/**
 * Copyright (c) 2021 Fraunhofer AISEC
 *
 * SPDX-License-Identifier: Apache-2.0
 **/





#include "issuer.h"

enum pabc_status
pabc_new_public_parameters (struct pabc_context const *const ctx,
                            struct pabc_attributes const *const attrs,
                            struct pabc_public_parameters **public_parameters)
{
  if (ctx == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (attrs == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (public_parameters == NULL)
    print_and_return (PABC_UNINITIALIZED);

  enum pabc_status pabc_status;

  struct pabc_public_parameters *new_public_parameters =
    malloc (sizeof(struct pabc_public_parameters));
  if (new_public_parameters == NULL)
    print_and_return (PABC_OOM);

  new_public_parameters->nr_of_attributes = attrs->nr_of_attributes;

  struct pabc_issuer_public_key *ipk = NULL;
  pabc_status = new_issuer_public_key (ctx, new_public_parameters, &ipk);
  if (PABC_OK != pabc_status)
  {
    PABC_FREE_NULL (new_public_parameters);
    print_and_return (pabc_status);
  }
  new_public_parameters->ipk = ipk;

  // deep copy the struct
  pabc_status = pabc_new_attributes (ctx, &new_public_parameters->attrs);
  if (PABC_OK != pabc_status)
  {
    free_issuer_public_key (ctx, new_public_parameters, &ipk);
    PABC_FREE_NULL (new_public_parameters);
    print_and_return (pabc_status);
  }

  pabc_status = pabc_attrs_deep_copy (ctx, &new_public_parameters->attrs,
                                      attrs);
  if (PABC_OK != pabc_status)
  {
    pabc_free_attributes (ctx, &new_public_parameters->attrs);
    free_issuer_public_key (ctx, new_public_parameters, &ipk);
    PABC_FREE_NULL (new_public_parameters);
    print_and_return (pabc_status);
  }

  *public_parameters = new_public_parameters;
  return PABC_OK;
}


enum pabc_status
pabc_free_public_parameters (struct pabc_context const *const ctx,
                             struct pabc_public_parameters **public_parameters)
{
  if (ctx == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (public_parameters == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (*public_parameters == NULL)
    print_and_return (PABC_UNINITIALIZED);

  enum pabc_status pabc_status;

  pabc_status = free_issuer_public_key (ctx, *public_parameters,
                                        &(*public_parameters)->ipk);
  if (pabc_status != PABC_OK)
    print_and_return (pabc_status); // TODO or continue?

  pabc_status = pabc_free_attributes (ctx, &(*public_parameters)->attrs);
  if (pabc_status != PABC_OK)
    print_and_return (pabc_status); // TODO or continue?

  PABC_FREE_NULL (*public_parameters);
  return PABC_OK;
}


enum pabc_status
pabc_populate_issuer_secret_key (struct pabc_context *const ctx,
                                 struct pabc_issuer_secret_key *const isk)
{
  if (ctx == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (isk == NULL)
    print_and_return (PABC_UNINITIALIZED);

  RLC_TRY {
    // 1. Sample a random element x from Zp, and compute w = g2^x.
    bn_rand_mod (isk->x, ctx->group_order);
  }
  RLC_CATCH_ANY { print_and_return (PABC_RELIC_FAIL); }
  RLC_FINALLY {}
  return PABC_OK;
}


enum pabc_status
pabc_populate_issuer_public_key (
  struct pabc_context *const ctx,
  struct pabc_public_parameters *const public_parameters,
  struct pabc_issuer_secret_key *const isk)
{
  if (ctx == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (public_parameters == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (isk == NULL)
    print_and_return (PABC_UNINITIALIZED);

  enum pabc_status status;

  struct pabc_issuer_mem *mem = NULL;
  status = pabc_issuer_mem_init (&mem);
  if (status != PABC_OK)
    print_and_return (status);

  struct pabc_issuer_public_key *ipk = public_parameters->ipk;
  if (ipk == NULL)
    print_and_return (PABC_UNINITIALIZED);

  RLC_TRY {
    // 1. Sample a random element x from Zp, and compute w = g2^x.
    g2_mul_gen (ipk->w, isk->x);

    // 2. Sample a random element _g1 from G1. And compute _g2 = _g1^x.
    g1_rand (ipk->_g1);
    g1_mul (ipk->_g2, ipk->_g1, isk->x);

    // 3. Generate non-interactive pabc_proof of knowledge π = PoK{x: w = g2^x
    // && _g2 = _g1^x} = (C, S) according to section 1.2 which we reproduce
    // here.
    //
    // r : sample a random element r from Zp
    bn_rand_mod (mem->r, ctx->group_order);

    // t1 : compute t1 = g2^r.
    g2_mul_gen (mem->t1, mem->r);

    // t2 : compute t2 = _g1^r.
    g1_mul (mem->t2, ipk->_g1, mem->r);

    // C : C = H(t1 || t2 || g2 || _g1 || w || _g2)
    // TODO remove ASSERT
    PABC_ASSERT (reset_hash (ctx));
    PABC_ASSERT (hash_add_g2 (ctx, mem->t1));
    PABC_ASSERT (hash_add_g1 (ctx, mem->t2));
    PABC_ASSERT (hash_add_g2 (ctx, ctx->g2_gen));
    PABC_ASSERT (hash_add_g1 (ctx, ipk->_g1));
    PABC_ASSERT (hash_add_g2 (ctx, ipk->w));
    PABC_ASSERT (hash_add_g1 (ctx, ipk->_g2));
    PABC_ASSERT (compute_hash (ctx, ipk->C));

    // 4. S = (r + C * x) mod p
    bn_mul (ipk->S, ipk->C, isk->x);           // S = C * x
    bn_mod (ipk->S, ipk->S, ctx->group_order); // S = S mod p
    bn_add (ipk->S, mem->r, ipk->S);           // S = r + S
    bn_mod (ipk->S, ipk->S, ctx->group_order); // S = S mod p

    // 4. Sample an array of elements from G1 for AttributeNames. For each
    // attribute in AttributeNames, compute HAttrs[i] = random(G1)
    for (size_t i = 0; i < public_parameters->nr_of_attributes; ++i)
    {
      g1_rand (ipk->HAttrs[i]);
    }

    // 5. Sample two random elements from G1: HRand and HSk.
    g1_rand (ipk->HRand);
    g1_rand (ipk->HSk);

    // clean up
    pabc_issuer_mem_free (&mem);
  }
  RLC_CATCH_ANY { print_and_return (PABC_RELIC_FAIL); }
  RLC_FINALLY {}
  return PABC_OK;
}


enum pabc_status
pabc_new_issuer_secret_key (struct pabc_context const *const ctx,
                            struct pabc_issuer_secret_key **isk)
{
  if (ctx == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (isk == NULL)
    print_and_return (PABC_UNINITIALIZED);

  struct pabc_issuer_secret_key *new_isk =
    malloc (sizeof(struct pabc_issuer_secret_key));
  if (new_isk == NULL)
    print_and_return (PABC_OOM);

  RLC_TRY {
    bn_null (new_isk->x);
    bn_new (new_isk->x);
  }
  RLC_CATCH_ANY {
    bn_free (new_isk->x);
    PABC_FREE_NULL (new_isk);
    print_and_return (PABC_RELIC_FAIL);
  }
  RLC_FINALLY {}

  *isk = new_isk;
  return PABC_OK;
}


enum pabc_status
pabc_free_issuer_secret_key (struct pabc_context const *const ctx,
                             struct pabc_issuer_secret_key **isk)
{
  if (ctx == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (isk == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (*isk == NULL)
    print_and_return (PABC_UNINITIALIZED);

  RLC_TRY { bn_free ((*isk)->x); }
  RLC_CATCH_ANY { print_and_return (PABC_RELIC_FAIL); }
  RLC_FINALLY {}

  PABC_FREE_NULL (*isk);
  return PABC_OK;
}


enum pabc_status
new_issuer_public_key (
  struct pabc_context const *const ctx,
  struct pabc_public_parameters const *const public_parameters,
  struct pabc_issuer_public_key **ipk)
{
  if (ctx == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (public_parameters == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (ipk == NULL)
    print_and_return (PABC_UNINITIALIZED);

  struct pabc_issuer_public_key *new_ipk =
    malloc (sizeof(struct pabc_issuer_public_key));
  if (new_ipk == NULL)
    print_and_return (PABC_OOM);

  RLC_TRY {
    new_ipk->HAttrs =
      malloc (sizeof(g1_t) * public_parameters->nr_of_attributes);
    if (new_ipk->HAttrs == NULL)
    {
      PABC_FREE_NULL (new_ipk);
      print_and_return (PABC_OOM);
    }
    for (size_t i = 0; i < public_parameters->nr_of_attributes; ++i)
    {
      g1_null (new_ipk->HAttrs[i]);
      g1_new (new_ipk->HAttrs[i]);
    }
    g2_null (new_ipk->w);
    g2_new (new_ipk->w);

    g1_null (new_ipk->_g1);
    g1_new (new_ipk->_g1);

    g1_null (new_ipk->_g2);
    g1_new (new_ipk->_g2);

    bn_null (new_ipk->C);
    bn_new (new_ipk->C);

    bn_null (new_ipk->S);
    bn_new (new_ipk->S);

    g1_null (new_ipk->HRand);
    g1_new (new_ipk->HRand);

    g1_null (new_ipk->HSk);
    g1_new (new_ipk->HSk);
  }
  RLC_CATCH_ANY {
    g1_free (new_ipk->HSk);
    g1_free (new_ipk->HRand);
    bn_free (new_ipk->S);
    bn_free (new_ipk->C);
    g1_free (new_ipk->_g2);
    g1_free (new_ipk->_g1);
    g2_free (new_ipk->w);
    for (size_t i = 0; i < public_parameters->nr_of_attributes; ++i)
      g1_free (new_ipk->HAttrs[i]);
    PABC_FREE_NULL (new_ipk->HAttrs);
    PABC_FREE_NULL (new_ipk);
  }
  RLC_FINALLY {}

  *ipk = new_ipk;
  return PABC_OK;
}


enum pabc_status
free_issuer_public_key (
  struct pabc_context const *const ctx,
  struct pabc_public_parameters const *const public_parameters,
  struct pabc_issuer_public_key **ipk)
{
  if (ctx == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (public_parameters == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (ipk == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (*ipk == NULL)
    print_and_return (PABC_UNINITIALIZED);

  RLC_TRY {
    g2_free ((*ipk)->w);
    g1_free ((*ipk)->_g1);
    g1_free ((*ipk)->_g2);
    bn_free ((*ipk)->C);
    bn_free ((*ipk)->S);
    g1_free ((*ipk)->HRand);
    g1_free ((*ipk)->HSk);

    for (size_t i = 0; i < public_parameters->nr_of_attributes; ++i)
      g1_free ((*ipk)->HAttrs[i]);
    PABC_FREE_NULL ((*ipk)->HAttrs);
  }
  RLC_CATCH_ANY { print_and_return (PABC_RELIC_FAIL); }
  RLC_FINALLY {}

  PABC_FREE_NULL (*ipk);

  return PABC_OK;
}


enum pabc_status
pabc_issuer_credential_sign (
  struct pabc_context *const ctx,
  struct pabc_public_parameters const *const public_parameters,
  struct pabc_credential_request *const cr,
  struct pabc_credential *const cred, struct pabc_nonce *const expected_nonce,
  struct pabc_issuer_secret_key *const isk)
{
  if (ctx == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (public_parameters == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (cr == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (cred == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (expected_nonce == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (isk == NULL)
    print_and_return (PABC_UNINITIALIZED);

  enum pabc_status status;
  struct pabc_issuer_mem *mem = NULL;
  status = pabc_issuer_mem_init (&mem);
  if (status != PABC_OK)
    print_and_return (status);

  status = pabc_nonce_compare (ctx, expected_nonce, cr->nonce);
  if (PABC_OK != status)
    print_and_return (status);

  status = verify_pok (ctx, cr, public_parameters->ipk);
  if (PABC_OK != status)
    print_and_return (status);

  /*
     Sample two random elements e, s from Zp.
     Compute B = g1 · HRand^s · Nym · MulAll(HAttrs[i]^(Attrs[i]))
     Compute A = B^(1/(e+x)).
     Return pabc_credential (A, B, e, s, Attrs)
   */
  RLC_TRY {
    // Sample two random elements e, s from Zp.
    bn_rand_mod (cred->e, ctx->group_order);
    bn_rand_mod (cred->s, ctx->group_order);
    // Compute B = g1 · HRand^s · Nym · MulAll(HAttrs[i]^(Attrs[i]))
    g1_get_gen (cred->B);
    g1_mul (mem->temp, public_parameters->ipk->HRand, cred->s);
    g1_add (cred->B, cred->B, mem->temp);
    g1_add (cred->B, cred->B, cr->Nym);
    // compute MulAll(HAttrs[i]^(Attrs[i]))
    g1_set_infty (mem->MulAll);
    for (size_t i = 0; i < public_parameters->nr_of_attributes; ++i)
    {
      PABC_ASSERT (reset_hash (ctx));
      PABC_ASSERT (hash_add_str (ctx, cr->plain_attrs->attribute_values[i]));
      PABC_ASSERT (compute_hash (ctx, mem->AttrsI));
      g1_mul (mem->temp, public_parameters->ipk->HAttrs[i], mem->AttrsI);
      g1_add (mem->MulAll, mem->MulAll, mem->temp);
    }
    g1_add (cred->B, cred->B, mem->MulAll);

    // Compute A = B^(1/(e+x)).
    bn_add (mem->temp_bn_t, cred->e, isk->x);
    bn_mod_inv (mem->mod_inv, mem->temp_bn_t, ctx->group_order);
    g1_mul (cred->A, cred->B, mem->mod_inv);

    // copy plain attributes
    PABC_ASSERT (
      pabc_plain_attrs_deep_copy (ctx, &cred->plain_attrs, cr->plain_attrs));

    g1_copy (cred->Nym, cr->Nym);

    // clean up
    pabc_issuer_mem_free (&mem);
  }
  RLC_CATCH_ANY { print_and_return (PABC_RELIC_FAIL); }
  RLC_FINALLY {}

  return PABC_OK;
}


enum pabc_status
pabc_new_credential (
  struct pabc_context const *const ctx,
  struct pabc_public_parameters const *const public_parameters,
  struct pabc_credential **cred)
{
  if (ctx == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (public_parameters == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (cred == NULL)
    print_and_return (PABC_UNINITIALIZED);

  enum pabc_status status;

  struct pabc_credential *new_cred = malloc (sizeof(struct pabc_credential));
  if (new_cred == NULL)
    print_and_return (PABC_OOM);

  struct pabc_plain_attributes *plain_attrs = NULL;
  status = pabc_new_plain_attrs (ctx, public_parameters, &plain_attrs);
  if (PABC_OK != status)
  {
    PABC_FREE_NULL (new_cred);
    return status;
  }

  new_cred->plain_attrs = plain_attrs;

  RLC_TRY {
    g1_null (new_cred->A);
    g1_new (new_cred->A);

    g1_null (new_cred->B);
    g1_new (new_cred->B);

    bn_null (new_cred->e);
    bn_new (new_cred->e);

    bn_null (new_cred->s);
    bn_new (new_cred->s);
  }
  RLC_CATCH_ANY {
    bn_free (new_cred->s);
    bn_free (new_cred->e);
    g1_free (new_cred->B);
    g1_free (new_cred->A);
    pabc_free_plain_attrs (ctx, &new_cred->plain_attrs);
    PABC_FREE_NULL (new_cred);
  }
  RLC_FINALLY {}

  *cred = new_cred;
  return PABC_OK;
}


enum pabc_status
pabc_free_credential (
  struct pabc_context const *const ctx,
  struct pabc_public_parameters const *const public_parameters,

  struct pabc_credential **cred)
{
  if (ctx == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (public_parameters == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (cred == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (*cred == NULL)
    print_and_return (PABC_UNINITIALIZED);

  if ((*cred)->plain_attrs != NULL)
    pabc_free_plain_attrs (ctx, &(*cred)->plain_attrs);

  RLC_TRY {
    g1_free ((*cred)->A);
    g1_free ((*cred)->B);
    bn_free ((*cred)->e);
    bn_free ((*cred)->s);
    g1_free ((*cred)->Nym);
  }
  RLC_CATCH_ANY { print_and_return (PABC_RELIC_FAIL); }
  RLC_FINALLY {}

  PABC_FREE_NULL (*cred);

  return PABC_OK;
}


enum pabc_status
verify_pok (struct pabc_context *const ctx,
            struct pabc_credential_request *const cr,
            struct pabc_issuer_public_key *const ipk)
{
  if (ctx == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (cr == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (ipk == NULL)
    print_and_return (PABC_UNINITIALIZED);

  enum pabc_status status;
  struct pabc_issuer_mem *mem = NULL;
  status = pabc_issuer_mem_init (&mem);
  if (status != PABC_OK)
    print_and_return (status);

  /*
   * _t1 = Hsk^S * Nym^(-c)
   *
   * _P = _t1||Hsk||Nym||nonce
   *
   * _C = hash_to_int(_P)
   *
   * // use C to compare with _C, which was calculated just now
   * if C == _C {
   *       return true
   * } else {
   *       return false
   * }
   */
  enum pabc_status verify_result = PABC_FAILURE;
  RLC_TRY {
    // _t1 = g2^S * w^(-c)
    g1_mul (mem->t1bar, ipk->HSk, cr->S);
    g1_neg (mem->temp_g1t, cr->Nym);
    g1_mul (mem->temp_g1t, mem->temp_g1t, cr->C);
    g1_add (mem->t1bar, mem->t1bar, mem->temp_g1t);

    // _P = _t1||Hsk||Nym||nonce

    // TODO remove ASSERT
    PABC_ASSERT (reset_hash (ctx));
    PABC_ASSERT (hash_add_g1 (ctx, mem->t1bar));
    PABC_ASSERT (hash_add_g1 (ctx, ipk->HSk));
    PABC_ASSERT (hash_add_g1 (ctx, cr->Nym));
    PABC_ASSERT (hash_add_bn (ctx, cr->nonce->nonce));
    PABC_ASSERT (compute_hash (ctx, mem->c_bar));

    if (bn_cmp (mem->c_bar, cr->C) == RLC_EQ)
      verify_result = PABC_OK;

    // clean up
    pabc_issuer_mem_free (&mem);
  }
  RLC_CATCH_ANY { print_and_return (PABC_RELIC_FAIL); }
  RLC_FINALLY {}

  return verify_result;
}


/*
 * TODO this is how the check should be performed according to
 * https://github.com/ontio/ontology-crypto/wiki/Anonymous-Credential#12-non-interactive-proof-of-knowledge-pok-protocol
 */
int
verify_pok2 (struct pabc_context *const ctx,
             struct pabc_credential_request *const cr,
             struct pabc_issuer_public_key *const ipk)
{
  if (ctx == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (cr == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (ipk == NULL)
    print_and_return (PABC_UNINITIALIZED);

  /*
   * _t1 = g2^S * w^(-c)
   *
   * _t2 = _g1^S * _g2^(-c)
   *
   * _P = _t1 || _t2 || g2 || _g1 || w || _g2
   *
   * _C = hash_to_int(_P)
   *
   * // use C to compare with _C, which was calculated just now
   * if C == _C {
   *       return true
   * } else {
   *       return false
   * }
   */
  int verify_result = 1;
  RLC_TRY {
    // _t1 = g2^S * w^(-c)
    g2_t t1bar;
    g2_null (t1bar);
    g2_new (t1bar);
    g2_t temp_g2t;
    g2_null (temp_g2t);
    g2_new (temp_g2t);
    g2_mul (t1bar, ctx->g2_gen, cr->S);
    g2_neg (temp_g2t, ipk->w);
    g2_mul (temp_g2t, temp_g2t, cr->C);
    g2_add (t1bar, t1bar, temp_g2t);

    // _t2 = _g1^S * _g2^(-c)
    g1_t t2bar;
    g1_null (t2bar);
    g1_new (t2bar);
    g1_t temp_g1t;
    g1_null (temp_g1t);
    g1_new (temp_g1t);
    g1_mul (t2bar, ipk->_g1, cr->S);
    g1_neg (temp_g1t, ipk->_g2);
    g1_mul (temp_g1t, temp_g1t, cr->C);
    g1_add (t2bar, t2bar, temp_g1t);

    // _P = _t1 || _t2 || g2 || _g1 || w || _g2
    bn_t c_bar;
    bn_null (c_bar);
    bn_new (c_bar);
    reset_hash (ctx);
    hash_add_g2 (ctx, t1bar);
    hash_add_g1 (ctx, t2bar);
    hash_add_g2 (ctx, ctx->g2_gen);
    hash_add_g1 (ctx, ipk->_g1);
    hash_add_g2 (ctx, ipk->w);
    hash_add_g1 (ctx, ipk->_g2);
    compute_hash (ctx, c_bar);

    if (bn_cmp (c_bar, cr->C) == RLC_EQ)
      verify_result = 0;

    // clean up
    g2_free (t1bar);
    g2_free (temp_g2t);
    g1_free (t2bar);
    g1_free (temp_g1t);
    bn_free (c_bar);
  }
  RLC_CATCH_ANY { print_and_return (PABC_RELIC_FAIL); }
  RLC_FINALLY {}
  return verify_result;
}


enum pabc_status
pabc_params_get (struct pabc_context const *const ctx,
                 struct pabc_public_parameters const *const pp,
                 size_t *const nr_params, char ***params)
{
  if (NULL == ctx)
    print_and_return (PABC_UNINITIALIZED);
  if (NULL == pp)
    print_and_return (PABC_UNINITIALIZED);
  *nr_params = pp->nr_of_attributes;

  *params = malloc (sizeof(char *) * pp->nr_of_attributes);
  if (NULL == *params)
    print_and_return (PABC_OOM);

  char **matrix = *params;
  for (size_t i = 0; i < pp->nr_of_attributes; ++i)
  {
    matrix[i] = strdup (pp->attrs->attribute_names[i]);
    if (NULL == matrix[i])
    {
      for (size_t j = i; j > 1; --j)
        PABC_FREE_NULL (matrix[j - 1]);
      PABC_FREE_NULL (*params);
    }
  }
  return PABC_OK;
}


enum pabc_status
pabc_issuer_mem_init (struct pabc_issuer_mem **const mem)
{
  if (! mem)
    print_and_return (PABC_UNINITIALIZED);

  // allocate struct
  struct pabc_issuer_mem *new_mem = malloc (sizeof(struct pabc_issuer_mem));
  if (! new_mem)
    print_and_return (PABC_OOM);
  *mem = new_mem;

  // RELIC null
  RLC_TRY {
    bn_null ((*mem)->AttrsI);
    bn_null ((*mem)->c_bar);
    bn_null ((*mem)->mod_inv);
    bn_null ((*mem)->r);
    bn_null ((*mem)->temp_bn_t);
    g1_null ((*mem)->MullAll);
    g1_null ((*mem)->t1bar);
    g1_null ((*mem)->t2);
    g1_null ((*mem)->temp);
    g1_null ((*mem)->temp_g1t);
    g2_null ((*mem)->t1);
  }
  RLC_CATCH_ANY {
    PABC_FREE_NULL (*mem);
    print_and_return (PABC_RELIC_FAIL);
  }
  RLC_FINALLY {}

  // RELIC new
  RLC_TRY {
    bn_new ((*mem)->AttrsI);
    bn_new ((*mem)->c_bar);
    bn_new ((*mem)->mod_inv);
    bn_new ((*mem)->r);
    bn_new ((*mem)->temp_bn_t);
    g1_new ((*mem)->MullAll);
    g1_new ((*mem)->t1bar);
    g1_new ((*mem)->t2);
    g1_new ((*mem)->temp);
    g1_new ((*mem)->temp_g1t);
    g2_new ((*mem)->t1);
  }
  RLC_CATCH_ANY {
    pabc_issuer_mem_free (mem);
    print_and_return (PABC_RELIC_FAIL);
  }
  RLC_FINALLY {}

  return PABC_OK;
}


enum pabc_status
pabc_issuer_mem_free (struct pabc_issuer_mem **const mem)
{
  if (! mem)
    print_and_return (PABC_UNINITIALIZED);
  RLC_TRY {
    bn_free ((*mem)->AttrsI);
    bn_free ((*mem)->c_bar);
    bn_free ((*mem)->mod_inv);
    bn_free ((*mem)->r);
    bn_free ((*mem)->temp_bn_t);
    g1_free ((*mem)->MullAll);
    g1_free ((*mem)->t1bar);
    g1_free ((*mem)->t2);
    g1_free ((*mem)->temp);
    g1_free ((*mem)->temp_g1t);
    g2_free ((*mem)->t1);
  }
  RLC_CATCH_ANY { print_and_return (PABC_RELIC_FAIL); }
  RLC_FINALLY {
    PABC_FREE_NULL (*mem);
    return PABC_OK;
  }
}
