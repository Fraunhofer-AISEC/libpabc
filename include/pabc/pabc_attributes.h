/**
 * Copyright (c) 2021 Fraunhofer AISEC
 *
 * SPDX-License-Identifier: Apache-2.0
 **/

#ifndef PABC_ATTRIBUTES_H
#define PABC_ATTRIBUTES_H

#include "pabc_utils.h"
#include <stddef.h>

struct pabc_attributes;
struct pabc_context;
struct pabc_public_parameters;

/*!
 * Appends an attribute name to the public parameters.
 * Names must be unique.
 *
 * \param [in] ctx The global context to use.
 * \param [in] attrs The attributes to manipulate (must be
 * allocated by ::pabc_new_attributes first).
 * \param [in] name The name of the attribute.
 * \return Success status.
 */
enum pabc_status pabc_attributes_add (struct pabc_context const *const ctx,
                                      struct pabc_attributes *const attrs,
                                      char const *const name);

/*!
 * Allocates a new attributes structure.
 *
 * \param [in] ctx The global context to use.
 * \param [in,out] attrs The attributes structure to allocate. Must be freed by
 * caller (see ::pabc_free_attributes)
 * \return Success status.
 */
enum pabc_status pabc_new_attributes (struct pabc_context const *const ctx,
                                      struct pabc_attributes **attrs);

/*!
 * Frees an attributes structure.
 *
 * \param [in] ctx The global context to use.
 * \param [in,out] attrs The structure to free.
 */
void pabc_free_attributes (struct pabc_context const *const ctx,
                           struct pabc_attributes **attrs);

#endif // PABC_ATTRIBUTES_H
