/**
 * Copyright (c) 2021 Fraunhofer AISEC
 *
 * SPDX-License-Identifier: Apache-2.0
 **/





#ifndef PABC_ISSUER_H
#define PABC_ISSUER_H

#include "pabc_utils.h"
#include <stddef.h>

struct pabc_issuer_public_key;
struct pabc_attributes;
struct pabc_context;
struct pabc_credential;
struct pabc_credential_request;
struct pabc_issuer_secret_key;
struct pabc_nonce;
struct pabc_public_parameters;

typedef enum pabc_status (*PABC_RequestAttributeVerificationCallback)(
  void *ctx, const char *name, const char *value);

/*!
 * Allocate a public parameters structure.
 *
 * \param [in] ctx The global context to use.
 * \param [in] attrs The attributes to use. It makes a deep copy of the
 * attributes.
 * \param [out] public_parameters The allocated structure. Must be freed by
 * caller (see
 * ::pabc_free_public_parameters).
 * \return Success status.
 */
enum pabc_status
pabc_new_public_parameters (struct pabc_context const *const ctx,
                            struct pabc_attributes const *const attrs,
                            struct pabc_public_parameters **public_parameters);

/*!
 * Frees a public parameters structure.
 *
 * \param [in] ctx The global context to use.
 * \param [in,out] public_parameters The structure to be freed (allocated by
 * ::pabc_new_public_parameters).
 * \return Success status.
 */
enum pabc_status
pabc_free_public_parameters (struct pabc_context const *const ctx,
                             struct pabc_public_parameters **public_parameters);

/*!
 * Populate issuer secret key. Must be kept secret by the issuer.
 *
 * \param [in,out] ctx The global context to use.
 * \param [in,out] isk The issuer secret key to populate (must be allocated by
 * ::pabc_new_issuer_secret_key).
 * \return Success status.
 */
enum pabc_status
pabc_populate_issuer_secret_key (struct pabc_context *const ctx,
                                 struct pabc_issuer_secret_key *const isk);

/*!
 * Populate issuer public key. The secret key must be ready first (see
 * ::pabc_populate_issuer_secret_key).
 *
 * \param [in,out] ctx The global context to use.
 * \param [in,out] public_parameters The public parameters to use (must be
 * allocated by ::pabc_new_public_parameters).
 * \param [in,out] isk The issuer secret key to use.
 * \return Success status.
 */
enum pabc_status pabc_populate_issuer_public_key (
  struct pabc_context *const ctx,
  struct pabc_public_parameters *const public_parameters,
  struct pabc_issuer_secret_key *const isk);

/*!
 * Allocate an issuer secret key structure.
 *
 * \param [in] ctx The global context to use.
 * \param [out] isk The allocated structure. Must be freed by caller (see
 * ::pabc_free_issuer_secret_key).
 * \return Success status.
 */
enum pabc_status
pabc_new_issuer_secret_key (struct pabc_context const *const ctx,
                            struct pabc_issuer_secret_key **isk);

/*!
 * Frees an issuer secret key structure.
 *
 * \param [in] ctx The global context to use.
 * \param [in,out] isk The structure to be freed (allocated by
 * ::pabc_new_issuer_secret_key).
 * \return Success status.
 */
enum pabc_status
pabc_free_issuer_secret_key (struct pabc_context const *const ctx,
                             struct pabc_issuer_secret_key **isk);

/*!
 * Issue a credential. The issuer must first verify the submitted credential
 * request (plain text attributes) and then uses this function to create a
 * credential. The credential can then be send to the user.
 *
 * TODO: provide functions to enumerate credential attributes.
 *
 * \param [in,out] ctx The global context to use.
 * \param [in,out] public_parameters The public parameters to use.
 * \param [in,out] cr The credential request to use.
 * \param [in,out] cred The credential to issue/fill (must be allocated by
 * ::pabc_new_credential first).
 * \param [in,out] expected_nonce The noce to expect. Will return an error, if
 * this does not match the nonce provided in the \p cr
 * \param [in,out] isk The issuer secret key to use.
 * \return PABC_OK on success
 */
enum pabc_status pabc_issuer_credential_sign (
  struct pabc_context *const ctx,
  struct pabc_public_parameters const *const public_parameters,
  struct pabc_credential_request *const cr,
  struct pabc_credential *const cred, struct pabc_nonce *const expected_nonce,
  struct pabc_issuer_secret_key *const isk);

/*!
 * Allocate a credential structure.
 *
 * \param [in] ctx The global context to use.
 * \param [in] public_parameters The public parameters to use.
 * \param [out] cred The allocated structure. Must be freed by caller (see
 * ::pabc_free_credential).
 * \return Success status.
 */
enum pabc_status pabc_new_credential (
  struct pabc_context const *const ctx,
  struct pabc_public_parameters const *const public_parameters,
  struct pabc_credential **cred);

/*!
 * Frees a credential structure.
 *
 * \param [in] ctx The global context to use.
 * \param [in,out] cred The structure to be freed (allocated by
 * ::pabc_new_credential).
 * \param [in] public_parameters The public parameters to use (number of
 * attributes).
 * \return Success status.
 */
enum pabc_status pabc_free_credential (
  struct pabc_context const *const ctx,
  struct pabc_public_parameters const *const public_parameters,
  struct pabc_credential **cred);

#endif // PABC_ISSUER_H
