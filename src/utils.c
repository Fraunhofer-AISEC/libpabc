/**
 * Copyright (c) 2021 Fraunhofer AISEC
 *
 * SPDX-License-Identifier: Apache-2.0
 **/





#include "utils.h"

size_t
find_attribute_idx_by_name (
  struct pabc_context const *const ctx,
  struct pabc_public_parameters const *const public_parameters,
  char const *const name)
{
  if (ctx == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (public_parameters == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (name == NULL)
    print_and_return (PABC_UNINITIALIZED);

  for (size_t i = 0; i < public_parameters->nr_of_attributes; ++i)
  {
    if (strcmp (public_parameters->attrs->attribute_names[i], name) == 0)
      return i;
  }
  return public_parameters->nr_of_attributes;
}
