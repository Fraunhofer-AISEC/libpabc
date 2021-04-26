/**
 * Copyright (c) 2021 Fraunhofer AISEC
 *
 * SPDX-License-Identifier: Apache-2.0
 **/

// using the relic library https://github.com/relic-toolkit/

#ifndef USER_H
#define USER_H

#include "credential.h"
#include "hash.h"
#include "issuer.h"
#include "nonce.h"
#include "pabc/pabc_user.h"
#include "utils.h"
#include <relic.h>

/*!
 * Holds private user information
 */
struct pabc_user_context
{
  bn_t sk;            // ! user master secret;
  char **plain_attrs; // ! plain text attributes
};

/*!
 * Sets a attribute predicate.
 *
 * \param [in] ctx The global contest to use
 * \param [in] public_parameters The parameters to use
 * \param [in,out] proof The proof to manipulate
 * \param [in] pos the attribute position (0 based indexing)
 * \param [in] disclosed 1 -> attribute disclosed, 0 -> not disclosed
 * \param [in] cred the pabc_credential to use
 * \return Success status
 */
enum pabc_status pabc_set_attribute_predicate (
  struct pabc_context *const ctx,
  struct pabc_public_parameters const *const public_parameters,
  struct pabc_blinded_proof *const proof, size_t pos,
  enum pabc_status disclosed, struct pabc_credential const *const cred);

enum pabc_status pabc_set_attribute_value (
  struct pabc_context const *const ctx,
  struct pabc_public_parameters const *const public_parameters,
  struct pabc_user_context *const usr_ctx, size_t pos,
  char const *const value);

/*!
 * Allocates new array D and I for the attribute predicates.

 * \param [in] public_parameters The public parameters to use (number of
 * attributes).
 * \return The allocated structure. Must be freed by caller (see
 * ::pabc_free_attribute_predicates).
 */
enum pabc_status pabc_new_attribute_predicates (
  struct pabc_context const *const ctx,
  struct pabc_public_parameters const *const public_parameters,
  struct pabc_attribute_predicates_D_I **DI);

/*!
 * Frees the D and I arrays.
 *
 * \param [in,out] DI The attributes to free (previously allocated by
 * ::pabc_new_attribute_predicates).
 * \param [in] public_parameters The public parameters to use (number of
 * attributes).
 */
void pabc_free_attribute_predicates (
  struct pabc_context const *const ctx,
  struct pabc_public_parameters const *const public_parameters,
  struct pabc_attribute_predicates_D_I **DI);

struct pabc_user_mem
{
  bn_t AttrsI;
  bn_t cp;
  bn_t r1;
  bn_t r2;
  bn_t r2r3;
  bn_t r3;
  bn_t r;
  bn_t r_e;
  bn_t r_r2;
  bn_t r_r3;
  bn_t r_sk;
  bn_t r_sp;
  bn_t sPrime;
  bn_t temp_bnt;
  g1_t Br1;
  g1_t E;
  g1_t E_neg;
  g1_t HRand_r_r2;
  g1_t HRand_r_sp;
  g1_t HRandr2;
  g1_t mul_all_hi_r_ai;
  g1_t t1;
  g1_t t2;
  g1_t temp;
};

enum pabc_status pabc_user_mem_init (struct pabc_user_mem **const mem);
void pabc_user_mem_free (struct pabc_user_mem **const mem);

#endif // USER_H
