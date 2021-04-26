/**
 * Copyright (c) 2021 Fraunhofer AISEC
 *
 * SPDX-License-Identifier: Apache-2.0
 **/

#include "hash.h"

enum pabc_status
reset_hash (struct pabc_context *const ctx)
{
  if (ctx == NULL)
    print_and_return (PABC_UNINITIALIZED);

  ctx->hash->size = 0;

  return PABC_OK;
}


enum pabc_status
hash_add_g1 (struct pabc_context *const ctx, g1_t g)
{
  if (ctx == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (g == NULL)
    print_and_return (PABC_UNINITIALIZED);

  struct hash_container *h = ctx->hash;
  RLC_TRY {
    int g1_size = g1_size_bin (g, POINT_COMPRESSION);
    if (g1_size < 0)
      print_and_return (PABC_FAILURE);
    size_t new_size = h->size + (size_t) g1_size;
    if (new_size > h->available_memory)
    {
      uint8_t *new_buffer = realloc (h->ptr, new_size);
      if (new_buffer == NULL)
        print_and_return (PABC_OOM);
      h->ptr = new_buffer;
      h->available_memory = new_size;
    }
    g1_write_bin (h->ptr + h->size, g1_size, g, POINT_COMPRESSION);
    h->size += (size_t) g1_size;
  }
  RLC_CATCH_ANY { print_and_return (PABC_RELIC_FAIL); }
  RLC_FINALLY {}

  return PABC_OK;
}


enum pabc_status
hash_add_g2 (struct pabc_context *const ctx, g2_t g)
{
  if (ctx == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (g == NULL)
    print_and_return (PABC_UNINITIALIZED);

  struct hash_container *h = ctx->hash;
  RLC_TRY {
    int g2_size = g2_size_bin (g, POINT_COMPRESSION);
    if (g2_size < 0)
      print_and_return (PABC_FAILURE);
    size_t new_size = h->size + (size_t) g2_size;
    if (new_size > h->available_memory)
    {
      uint8_t *new_buffer = realloc (h->ptr, new_size);
      if (new_buffer == NULL)
        print_and_return (PABC_OOM);
      h->ptr = new_buffer;
      h->available_memory = new_size;
    }
    g2_write_bin (h->ptr + h->size, g2_size, g, POINT_COMPRESSION);
    h->size += (size_t) g2_size;
  }
  RLC_CATCH_ANY { print_and_return (PABC_RELIC_FAIL); }
  RLC_FINALLY {}

  return PABC_OK;
}


enum pabc_status
hash_add_bn (struct pabc_context *const ctx, bn_t bn)
{
  if (ctx == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (bn == NULL)
    print_and_return (PABC_UNINITIALIZED);

  struct hash_container *h = ctx->hash;
  RLC_TRY {
    int bn_size = bn_size_bin (bn);
    if (bn_size < 0)
      print_and_return (PABC_FAILURE);
    size_t new_size = h->size + (size_t) bn_size;
    if (new_size > h->available_memory)
    {
      uint8_t *new_buffer = realloc (h->ptr, new_size);
      if (new_buffer == NULL)
        print_and_return (PABC_OOM);
      h->ptr = new_buffer;
      h->available_memory = new_size;
    }
    bn_write_bin (h->ptr + h->size, bn_size, bn);
    h->size += (size_t) bn_size;
  }
  RLC_CATCH_ANY { print_and_return (PABC_RELIC_FAIL); }
  RLC_FINALLY {}

  return PABC_OK;
}


enum pabc_status
hash_add_str (struct pabc_context *const ctx,
              char const *const str)
{
  if (ctx == NULL)
    print_and_return (PABC_UNINITIALIZED);

  struct hash_container *h = ctx->hash;
  if (str)
  {
    size_t str_size = strlen (str) + 1; // include the \0 terminator
    size_t new_size = h->size + str_size;
    if (new_size > h->available_memory)
    {
      uint8_t *new_buffer = realloc (h->ptr, new_size);
      if (new_buffer == NULL)
        print_and_return (PABC_OOM);
      h->ptr = new_buffer;
      h->available_memory = new_size;
    }
    memcpy (h->ptr + h->size, str, str_size);
    h->size += str_size;
  }
  else   // handle null string as empty string -> TODO SECURITY
  {
    size_t str_size = 1; // include the \0 terminator
    size_t new_size = h->size + str_size;
    if (new_size > h->available_memory)
    {
      uint8_t *new_buffer = realloc (h->ptr, new_size);
      if (new_buffer == NULL)
        print_and_return (PABC_OOM);
      h->ptr = new_buffer;
      h->available_memory = new_size;
    }
    memset (h->ptr + h->size, '\0', str_size);
    h->size += str_size;
  }

  return PABC_OK;
}


enum pabc_status
hash_add_int (struct pabc_context *const ctx,
              int const *const i)
{
  if (ctx == NULL)
    print_and_return (PABC_UNINITIALIZED);

  struct hash_container *h = ctx->hash;
  size_t int_size = sizeof(int);
  size_t new_size = h->size + int_size;
  if (new_size > h->available_memory)
  {
    uint8_t *new_buffer = realloc (h->ptr, new_size);
    if (new_buffer == NULL)
      print_and_return (PABC_OOM);
    h->ptr = new_buffer;
    h->available_memory = new_size;
  }
  memcpy (h->ptr + h->size, i, int_size);
  h->size += int_size;

  return PABC_OK;
}


enum pabc_status
hash_add_pabc_status (struct pabc_context *const ctx,
                      enum pabc_status const *const pabc_status)
{
  return hash_add_int (ctx, (int const *const) pabc_status);
}


enum pabc_status
hash_add_DI (struct pabc_context *ctx,
             struct pabc_public_parameters *const public_parameters,
             struct pabc_attribute_predicates_D_I *const DI)
{
  if (ctx == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (public_parameters == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (DI == NULL)
    print_and_return (PABC_UNINITIALIZED);

  enum pabc_status pabc_status;
  for (size_t i = 0; i < public_parameters->nr_of_attributes; ++i)
  {
    pabc_status = hash_add_pabc_status (ctx, &DI->D[i]);
    if (pabc_status != PABC_OK)
      print_and_return (pabc_status);

    if (DI->D[i] == PABC_DISCLOSED)
    {
      pabc_status = hash_add_str (ctx, DI->I[i]);
      if (pabc_status != PABC_OK)
        print_and_return (pabc_status);
    }
    else
    {
      pabc_status = hash_add_str (ctx, "");
      if (pabc_status != PABC_OK)
        print_and_return (pabc_status);
    }
  }

  return PABC_OK;
}


enum pabc_status
compute_hash (struct pabc_context *const ctx,
              bn_t hash_result)
{
  if (ctx == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (hash_result == NULL)
    print_and_return (PABC_UNINITIALIZED);

  struct hash_container *h = ctx->hash;
  if (h->size > INT_MAX)
    print_and_return (PABC_FAILURE);
  RLC_TRY {
    md_map_sh256 (h->hash_result, (const uint8_t *const) h->ptr, (int) h->size);
    bn_read_bin (hash_result, h->hash_result, HASH_LEN * sizeof(uint8_t));
    bn_mod (hash_result, hash_result, ctx->group_order);
  }
  RLC_CATCH_ANY { print_and_return (PABC_RELIC_FAIL); }
  RLC_FINALLY {}

  return PABC_OK;
}


enum pabc_status
new_hash_container (struct hash_container **hash_container)
{
  if (hash_container == NULL)
    print_and_return (PABC_UNINITIALIZED);

  struct hash_container *new_hash_container =
    malloc (sizeof(struct hash_container));
  if (new_hash_container == NULL)
    print_and_return (PABC_OOM);
  new_hash_container->ptr = NULL;
  new_hash_container->size = 0;
  new_hash_container->available_memory = 0;

  *hash_container = new_hash_container;
  return PABC_OK;
}


void
free_hash_container (struct hash_container **hash_container)
{
  if (hash_container == NULL)
    return;
  if (*hash_container == NULL)
    return;

  PABC_FREE_NULL ((*hash_container)->ptr);
  PABC_FREE_NULL (*hash_container);
}
