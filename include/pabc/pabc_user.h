/**
 * Copyright (c) 2021 Fraunhofer AISEC
 *
 * SPDX-License-Identifier: Apache-2.0
 **/

#ifndef PABC_USER_H
#define PABC_USER_H

#include "pabc_utils.h"
#include <stddef.h>

struct pabc_public_parameters;
struct pabc_credential;
struct pabc_context;
struct pabc_blinded_proof;
struct pabc_credential_request;
struct pabc_attribute_predicates_D_I;
struct pabc_nonce;

/*!
 * Holds private user information (including secret key)
 */
struct pabc_user_context;

/*!
 * Set the disclosure flag of an attribute by name.
 *
 * \param [in,out] ctx The global context to use.
 * \param [in] public_parameters The public parameters to use (number of
 * attributes and attribute names).
 * \param [in,out] proof The proof to be manipulated.
 * \param [in] name The name of the attribute.
 * \param [in] disclosed A flag indicating that the attribute is disclosed
 * (::PABC_DISCLOSED or not disclosed (::PABC_NOT_DISCLOSED).
 * \param [in,out] cred The credential to use.
 * \return Success status.
 */
enum pabc_status pabc_set_disclosure_by_attribute_name (
  struct pabc_context *const ctx,
  struct pabc_public_parameters const *const public_parameters,
  struct pabc_blinded_proof *const proof, char const *const name,
  enum pabc_status disclosed, struct pabc_credential const *const cred);

/*!
 * Allocates a new user context.
 *
 * \param [in] ctx The global context to use.
 * \param [in] public_parameters The public parameters to use (number of
 * attributes).
 * \param [out] usr_ctx The allocated structure. Must be freed by caller (see
 * ::pabc_free_user_context).
 * \return Success status.
 */
enum pabc_status pabc_new_user_context (
  struct pabc_context const *const ctx,
  struct pabc_public_parameters const *const public_parameters,
  struct pabc_user_context **usr_ctx);

/*!
 * Populates a user context.
 *
 * \param [in,out] ctx The global context to use.
 * \param [in,out] usr_ctx The user context to populate (previously allocated by
 * ::pabc_new_user_context).
 * \return Success status.
 */
enum pabc_status
pabc_populate_user_context (struct pabc_context *const ctx,
                            struct pabc_user_context *const usr_ctx);

/*!
 * Frees a user context.
 *
 * TODO overwrite secret keys?
 *
 * \param [in] ctx The global context to use.
 * \param [in] public_parameters The public parameters to use (number of
 * attributes).
 * \param [in,out] usr_ctx The context to free (previously allocated by
 * ::pabc_new_user_context).
 */
void pabc_free_user_context (
  struct pabc_context const *const ctx,
  struct pabc_public_parameters const *const public_parameters,
  struct pabc_user_context **usr_ctx);

/*!
 * Populate a credential request. The user attributes must be set (see
 * ::pabc_set_attribute_value_by_name) before calling
 * this function.
 *
 * \param [in,out] ctx The global context to use.
 * \param [in] public_parameters The public parameters to use (number of
 * attributes).
 * \param [in,out] usr_ctx The user context to use (hold attributes and user
 * secret key).
 * \param [in,out] nonce The nonce to use for this credential request. It will
 * be deep-copied into the cred request.
 * \param [in,out] cr The credential request to populate. Must be allocated
 * before calling this function (see ::pabc_new_credential_request).
 * \return Success status.
 */
enum pabc_status pabc_gen_credential_request (
  struct pabc_context *const ctx,
  struct pabc_public_parameters const *const public_parameters,
  struct pabc_user_context *const usr_ctx, struct pabc_nonce *const nonce,
  struct pabc_credential_request *const cr);

/*!
 * Allocates a new credential request.
 *
 * \param [in] ctx The global context to use.
 * \param [in] public_parameters The public parameters to use (number of
 * attributes).
 * \param [out] cr The allocated structure. Must be freed by caller (see
 * ::pabc_free_credential_request).
 * \return Success status.
 */
enum pabc_status pabc_new_credential_request (
  struct pabc_context const *const ctx,
  struct pabc_public_parameters const *const public_parameters,
  struct pabc_credential_request **cr);

/*!
 * Frees a credential request.
 *
 * \param [in] ctx The global context to use.
 * \param [in] public_parameters The public parameters to use (number of
 * attributes).
 * \param [in,out] cr The structure to free (previously allocated by
 * ::pabc_new_credential_request).
 */
void pabc_free_credential_request (
  struct pabc_context const *const ctx,
  struct pabc_public_parameters const *const public_parameters,
  struct pabc_credential_request **cr);

/*!
 * Allocates a new proof.
 *
 * \param [in] ctx The global context to use.
 * \param [in] public_parameters The public parameters to use (number of
 * attributes).
 * \param [out] proof The allocated structure. Must be freed by calles (see
 * ::pabc_free_proof).
 * \return Success status.
 */
enum pabc_status
pabc_new_proof (struct pabc_context const *const ctx,
                struct pabc_public_parameters const *const public_parameters,
                struct pabc_blinded_proof **proof);

/*!
 * Frees a proof.
 *
 * \param [in] ctx The global context to use.
 * \param [in] public_parameters The public parameters to use (number of
 * attributes).
 * \param [in,out] proof The structure to free (previously allocated by
 * ::pabc_new_proof)
 */
void pabc_free_proof (
  struct pabc_context const *const ctx,
  struct pabc_public_parameters const *const public_parameters,
  struct pabc_blinded_proof **proof);

/*!
 * Generates a blinded proof. The user must first decide which attributes to
 * disclose (see ::pabc_set_disclosure_by_attribute_name).
 *
 * \param [in,out] ctx The global context to use.
 * \param [in,out] usr_ctx The user context to use.
 * \param [in] public_parameters The public parameters to use (number of
 * attributes).
 * \param [in,out] proof The proof to generate. Must be allocated before calling
 * this function (see ::pabc_new_proof).
 * \param [in,out] cred The credential to use for generating the proof
 * (previously issued by ::pabc_issuer_credential_sign).
 * \return Success status.
 */
enum pabc_status pabc_gen_proof (
  struct pabc_context *const ctx, struct pabc_user_context *const usr_ctx,
  struct pabc_public_parameters *const public_parameters,
  struct pabc_blinded_proof *const proof, struct pabc_credential *const cred);

/*!
 * Set an attribute value by name.
 *
 * \param [in] ctx The global context to use.
 * \param [in] public_parameters The public parameters to use (number of
 * attributes and attribute names).
 * \param [in,out] usr_ctx The user context to use. Attribute values are stored
 * here. \param [in] name The name of the attribute. \param [in] value The
 * attribute value. \return Success status.
 * \return Success status.
 */
enum pabc_status pabc_set_attribute_value_by_name (
  struct pabc_context const *const ctx,
  struct pabc_public_parameters const *const public_parameters,
  struct pabc_user_context *const usr_ctx, char const *const name,
  char const *const value);

#endif // PABC_USER_H
