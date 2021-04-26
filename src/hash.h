/**
 * Copyright (c) 2021 Fraunhofer AISEC
 *
 * SPDX-License-Identifier: Apache-2.0
 **/

// using the relic library https://github.com/relic-toolkit/

#ifndef HASH_H
#define HASH_H

#include "attributes.h"
#include "context.h"
#include <limits.h>
#include <relic.h>

#define HASH_LEN RLC_MD_LEN_SH256

struct pabc_context;

struct pabc_attribute_predicates_D_I;

struct hash_container
{
  size_t size;                   // ! currently used memory
  size_t available_memory;       // ! total available memory
  uint8_t *ptr;                  // ! memory for data to be hashed
  uint8_t hash_result[HASH_LEN]; // ! result of hash computation is
                                 // (intermediately) stored here
};

/*!
 * Computes the hash and stores the result (modulo the group order).
 *
 * \param[in] ctx The global context to use
 * \param[out] hash_result The result is stored here
 */
enum pabc_status compute_hash (struct pabc_context *const ctx, bn_t
                               hash_result);

/*!
 * Allocates and initializes a new hash container.
 * \param [out] hash The new container. Must be freed by caller.
 */
enum pabc_status new_hash_container (struct hash_container **hash);

void free_hash_container (struct hash_container **h);

enum pabc_status reset_hash (struct pabc_context *const ctx);

enum pabc_status hash_add_g1 (struct pabc_context *const ctx, g1_t g);

enum pabc_status hash_add_g2 (struct pabc_context *const ctx, g2_t g);

enum pabc_status hash_add_bn (struct pabc_context *const ctx, bn_t bn);

enum pabc_status hash_add_str (struct pabc_context *const ctx,
                               char const *const str);

enum pabc_status hash_add_int (struct pabc_context *const ctx,
                               int const *const i);

enum pabc_status
hash_add_pabc_status (struct pabc_context *const ctx,
                      enum pabc_status const *const pabc_status);

enum pabc_status
hash_add_DI (struct pabc_context *const ctx,
             struct pabc_public_parameters *const public_parameters,
             struct pabc_attribute_predicates_D_I *const DI);

#endif // HASH_H
