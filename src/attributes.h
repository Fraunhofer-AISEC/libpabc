/**
 * Copyright (c) 2021 Fraunhofer AISEC
 *
 * SPDX-License-Identifier: Apache-2.0
 **/

// using the relic library https://github.com/relic-toolkit/

#ifndef ATTRIBUTES_H
#define ATTRIBUTES_H

#include "pabc/pabc_attributes.h"
#include "utils.h"
#include <relic.h>

struct pabc_attributes
{
  char **attribute_names;
  size_t nr_of_attributes;
};

struct pabc_plain_attributes
{
  char **attribute_values;
  size_t nr_of_attributes;
};

struct pabc_attribute_predicates_D_I
{
  enum pabc_status *D; // disclose attribute i iff D[i] == PABC_DISCLOSED
  char **I; // attributes (if(D[i] == 1) I[i] == attrs else I[i] == null
};

enum pabc_status pabc_new_plain_attrs (
  struct pabc_context const *const ctx,
  struct pabc_public_parameters const *const public_parameters,
  struct pabc_plain_attributes **plain_attrs);

void pabc_free_plain_attrs (struct pabc_context const *const ctx,
                            struct pabc_plain_attributes **plain_attrs);

enum pabc_status pabc_attrs_deep_copy (struct pabc_context const *const ctx,
                                       struct pabc_attributes **dest,
                                       struct pabc_attributes const *const src);

enum pabc_status
pabc_plain_attrs_deep_copy (struct pabc_context const *const ctx,
                            struct pabc_plain_attributes **dest,
                            struct pabc_plain_attributes const *const src);

#endif // ATTRIBUTES_H
