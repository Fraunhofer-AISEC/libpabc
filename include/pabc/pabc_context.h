/**
 * Copyright (c) 2021 Fraunhofer AISEC
 *
 * SPDX-License-Identifier: Apache-2.0
 **/

#ifndef PABC_CONTEXT_H
#define PABC_CONTEXT_H

#include "pabc_utils.h"

/*!
 * Global context holding publicly available information.
 */
struct pabc_context;

/*!
 * Allocates and populates a new pabc_context. This also initializes the RELIC
 * core and pairing parameters.
 *
 * \param [in,out] ctx The context. Must be freed by caller (see
 * ::pabc_free_ctx).
 * \return Success status.
 */
enum pabc_status pabc_new_ctx (struct pabc_context **ctx);

/*!
 * Frees the context and cleans up the RELIC core.
 *
 * \param [in,out] ctx the context to be freed (allocated by ::pabc_new_ctx).
 */
void pabc_free_ctx (struct pabc_context **ctx);

#endif // PABC_CONTEXT_H
