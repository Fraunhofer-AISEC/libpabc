/**
 * Copyright (c) 2021 Fraunhofer AISEC
 *
 * SPDX-License-Identifier: Apache-2.0
 **/





#include "attributes.h"

enum pabc_status
pabc_attributes_add (struct pabc_context const *const ctx,
                     struct pabc_attributes *const attrs,
                     char const *const name)
{
  if (ctx == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (attrs == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (name == NULL)
    print_and_return (PABC_UNINITIALIZED);

  /*
   * TODO implement check
  // check unqiue name
  if (find_attribute_idx_by_name (ctx, pp, name) <
      pp->nr_of_attributes)
    return PABC_FAILURE;
  */

  char **new_an = realloc (attrs->attribute_names,
                           sizeof(char *) * (attrs->nr_of_attributes + 1));
  if (new_an == NULL)
    print_and_return (PABC_OOM);
  attrs->attribute_names = new_an;

  attrs->attribute_names[attrs->nr_of_attributes] = malloc (strlen (name) + 1);
  if (attrs->attribute_names[attrs->nr_of_attributes] == NULL)
  {
    PABC_FREE_NULL (new_an);
    print_and_return (PABC_OOM);
  }

  strcpy (attrs->attribute_names[attrs->nr_of_attributes], name);

  // adjusting here is sufficient (0 based indexing)
  attrs->nr_of_attributes++;

  return PABC_OK;
}


enum pabc_status
pabc_new_attributes (struct pabc_context const *const ctx,
                     struct pabc_attributes **attrs)
{
  if (ctx == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (attrs == NULL)
    print_and_return (PABC_UNINITIALIZED);

  struct pabc_attributes *new_attrs = malloc (sizeof(struct pabc_attributes));
  if (new_attrs == NULL)
    print_and_return (PABC_OOM);
  new_attrs->nr_of_attributes = 0;
  new_attrs->attribute_names = NULL;

  *attrs = new_attrs;
  return PABC_OK;
}


enum pabc_status
pabc_free_attributes (struct pabc_context const *const ctx,
                      struct pabc_attributes **attrs)
{
  if (ctx == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (attrs == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (*attrs == NULL)
    print_and_return (PABC_UNINITIALIZED);

  for (size_t i = 0; i < (*attrs)->nr_of_attributes; ++i)
    PABC_FREE_NULL ((*attrs)->attribute_names[i]);
  PABC_FREE_NULL ((*attrs)->attribute_names);
  PABC_FREE_NULL (*attrs);

  return PABC_OK;
}


enum pabc_status
pabc_attrs_deep_copy (struct pabc_context const *const ctx,
                      struct pabc_attributes **dest,
                      struct pabc_attributes const *const src)
{
  if (ctx == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (dest == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (*dest == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (src == NULL)
    print_and_return (PABC_UNINITIALIZED);

  (*dest)->nr_of_attributes = src->nr_of_attributes;

  (*dest)->attribute_names = malloc (sizeof(char *) * src->nr_of_attributes);
  if ((*dest)->attribute_names == NULL)
    print_and_return (PABC_OOM);

  for (size_t i = 0; i < src->nr_of_attributes; ++i)
  {
    (*dest)->attribute_names[i] = strdup (src->attribute_names[i]);
    if ((*dest)->attribute_names[i] == NULL)
    {
      // undo previous malloc
      for (size_t j = i; j > 0; --j)
        PABC_FREE_NULL ((*dest)->attribute_names[j - 1]);
      PABC_FREE_NULL ((*dest)->attribute_names);
      print_and_return (PABC_OOM);
    }
  }

  return PABC_OK;
}


enum pabc_status
pabc_new_plain_attrs (
  struct pabc_context const *const ctx,
  struct pabc_public_parameters const *const public_parameters,
  struct pabc_plain_attributes **plain_attrs)
{
  if (ctx == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (public_parameters == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (plain_attrs == NULL)
    print_and_return (PABC_UNINITIALIZED);

  struct pabc_plain_attributes *new_plain_attrs =
    malloc (sizeof(struct pabc_plain_attributes));
  if (new_plain_attrs == NULL)
    print_and_return (PABC_OOM);

  new_plain_attrs->nr_of_attributes = public_parameters->nr_of_attributes;
  new_plain_attrs->attribute_values =
    malloc (sizeof(char *) * public_parameters->nr_of_attributes);
  if (new_plain_attrs->attribute_values == NULL)
  {
    PABC_FREE_NULL (new_plain_attrs);
    print_and_return (PABC_OOM);
  }

  for (size_t i = 0; i < public_parameters->nr_of_attributes; ++i)
    new_plain_attrs->attribute_values[i] = NULL;

  *plain_attrs = new_plain_attrs;
  return PABC_OK;
}


enum pabc_status
pabc_free_plain_attrs (struct pabc_context const *const ctx,
                       struct pabc_plain_attributes **plain_attrs)
{
  if (ctx == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (plain_attrs == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (*plain_attrs == NULL)
    print_and_return (PABC_UNINITIALIZED);

  for (size_t i = 0; i < (*plain_attrs)->nr_of_attributes; ++i)
  {
    if (NULL != (*plain_attrs)->attribute_values[i])
    {
      PABC_FREE_NULL ((*plain_attrs)->attribute_values[i]);
    }
  }
  PABC_FREE_NULL ((*plain_attrs)->attribute_values);
  PABC_FREE_NULL (*plain_attrs);

  return PABC_OK;
}


enum pabc_status
pabc_plain_attrs_deep_copy (struct pabc_context const *const ctx,
                            struct pabc_plain_attributes **dest,
                            struct pabc_plain_attributes const *const src)
{
  if (ctx == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (dest == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (*dest == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (src == NULL)
    print_and_return (PABC_UNINITIALIZED);

  (*dest)->nr_of_attributes = src->nr_of_attributes;

  // allocated when calling pabc_new_plain_attrs
  // (*dest)->attribute_values = malloc (sizeof(char *) *
  // src->nr_of_attributes); if ((*dest)->attribute_values == NULL)
  //  print_and_return (PABC_OOM);

  for (size_t i = 0; i < src->nr_of_attributes; ++i)
  {
    if (src->attribute_values[i])
    {
      (*dest)->attribute_values[i] = strdup (src->attribute_values[i]);
      if ((*dest)->attribute_values[i] == NULL)
      {
        // undo previous malloc
        for (size_t j = i; j > 0; --j)
          PABC_FREE_NULL ((*dest)->attribute_values[j - 1]);
        PABC_FREE_NULL ((*dest)->attribute_values);
        print_and_return (PABC_OOM);
      }
    }
    else
    {
      (*dest)->attribute_values[i] = NULL;
    }
  }

  return PABC_OK;
}
