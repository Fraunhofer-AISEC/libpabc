/**
 * Copyright (c) 2021 Fraunhofer AISEC
 *
 * SPDX-License-Identifier: Apache-2.0
 **/

#ifndef PABC_CREDENTIAL_H
#define PABC_CREDENTIAL_H

#include "pabc_utils.h"

/*!
 * A credential issued by an authority to a user after reviewing a credential
 * request.
 */
struct pabc_credential;

/*!
 * A credential request created by a user and sent to an issuer.
 */
struct pabc_credential_request;

/*!
 * An issuer public key.
 */
struct pabc_issuer_public_key;

/*!
 * An issuer secret key used to create credentials.
 */
struct pabc_issuer_secret_key;

/*!
 * A proof created by a user and sent to a verifier. The user can decide which
 * attributes to disclose.
 */
struct pabc_blinded_proof;

/*!
 * The public information used by all parties.
 */
struct pabc_public_parameters;

struct pabc_context;
enum pabc_status pabc_params_get (struct pabc_context const *const ctx,
                                  struct pabc_public_parameters const *const pp,
                                  size_t *const nr_params, char ***params);

#endif // PABC_CREDENTIAL_H
