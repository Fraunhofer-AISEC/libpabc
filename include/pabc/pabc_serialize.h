/**
 * Copyright (c) 2021 Fraunhofer AISEC
 *
 * SPDX-License-Identifier: Apache-2.0
 **/

#ifndef PABC_SERIALIZE_H
#define PABC_SERIALIZE_H

#include "pabc_utils.h"

struct pabc_blinded_proof;
struct pabc_context;
struct pabc_credential;
struct pabc_credential_request;
struct pabc_issuer_secret_key;
struct pabc_nonce;
struct pabc_public_parameters;
struct pabc_user_context;

// TODO: can use more const here!!!

/*!
 * JSON encode an issuer secret key.
 *
 * \param [in] ctx The global context to use.
 * \param [in] isk The issuer secret key to encode.
 * \param [out] json The JSON string is stored here. Must be freed by caller.
 * \return Success status.
 */
enum pabc_status
pabc_encode_issuer_secret_key (struct pabc_context const *const ctx,
                               struct pabc_issuer_secret_key *const isk,
                               char **json);

/*!
 * JSON decode an issuer secret key.
 *
 * \param [in] ctx The global context to use.
 * \param [in,out] isk The issuer secret key is stored here. Must be allocated
 * before calling this function (see ::pabc_new_issuer_secret_key).
 * \param [in] data The JSON string to use.
 * \return Success status.
 */
enum pabc_status
pabc_decode_issuer_secret_key (struct pabc_context const *const ctx,
                               struct pabc_issuer_secret_key *const isk,
                               char const *const data);

/*!
 * JSON encode public parameters.
 *
 * \param [in] ctx The global context to use.
 * \param [in] public_parameters The public parameters to encode.
 * \param [out] json The JSON string is stored here. Must be freed by caller.
 * \return Success status.
 */
enum pabc_status pabc_encode_public_parameters (
  struct pabc_context const *const ctx,
  struct pabc_public_parameters *const public_parameters, char **json);

/*!
 * JSON decode public parameters.
 *
 * \param [in] ctx The global context to use.
 * \param [in,out] public_parameters The public parameters are stored here. Must
 * be allocated before calling this function (see ::pabc_new_public_parameters).
 * \param [in] data The JSON string
 * to use. \return Success status.
 */
enum pabc_status pabc_decode_and_new_public_parameters (
  struct pabc_context const *const ctx,
  struct pabc_public_parameters **public_parameters, char const *const data);

/*!
 * JSON encode a user context.
 *
 * \param [in] ctx The global context to use.
 * \param [in] usr_ctx The user context to encode.
 * \param [in] public_parameters The public parameters to use (number of
 * attributes).
 * \param [out] json The JSON string is stored here. Must be freed by caller.
 * \return Success status.
 */
enum pabc_status pabc_encode_user_ctx (
  struct pabc_context const *const ctx,
  struct pabc_public_parameters const *const public_parameters,
  struct pabc_user_context *const usr_ctx, char **json);

/*!
 * JSON decode a user context.
 *
 * \param [in] ctx The global context to use.
 * \param [in,out] usr_ctx The user context is stored here. Must be allocated
 * before calling this function (see ::pabc_new_user_context).
 * \param [in] public_parameters The public parameters to use (number of
 * attributes).
 * \param [in] data The JSON string to use.
 * \return Success status.
 */
enum pabc_status pabc_decode_user_ctx (
  struct pabc_context const *const ctx,
  struct pabc_public_parameters const *const public_parameters,
  struct pabc_user_context *const usr_ctx, char const *const data);

/*!
 * JSON encode a credential request.
 *
 * \param [in] ctx The global context to use.
 * \param [in] cr The credential request to encode.
 * \param [in] public_parameters The public parameters to use (number of
 * attributes).
 * \param [out] json The JSON string is stored here. Must be freed by caller.
 * \return Success status.
 */
enum pabc_status pabc_encode_credential_request (
  struct pabc_context const *const ctx,
  struct pabc_public_parameters const *const public_parameters,
  struct pabc_credential_request *const cr, char **json);

/*!
 * JSON decode a credential request.
 *
 * \param [in] ctx The global context to use.
 * \param [in,out] cr The credetnial request is stored here. Must be allocated
 * before calling this function (see ::pabc_new_credential_request).
 * \param [in] public_parameters The public parameters to use (number of
 * attributes).
 * \param [in] data The JSON string to use.
 * \return Success status.
 */
enum pabc_status pabc_decode_credential_request (
  struct pabc_context const *const ctx,
  struct pabc_public_parameters const *const public_parameters,
  struct pabc_credential_request *const cr, char const *const data);

/*!
 * JSON encode a credential.
 *
 * \param [in] ctx The global context to use.
 * \param [in] cred The credential to encode.
 * \param [in] public_parameters The public parameters to use (number of
 * attributes).
 * \param [out] json The JSON string is stored here. Must be freed by caller.
 * \return Success status.
 */
enum pabc_status pabc_encode_credential (
  struct pabc_context const *const ctx,
  struct pabc_public_parameters const *const public_parameters,
  struct pabc_credential *const cred, char **json);

/*!
 * JSON decode a credential.
 *
 * \param [in] ctx The global context to use.
 * \param [in,out] cred The credential is stored here. Must be allocated
 * before calling this function (see ::pabc_new_credential).
 * \param [in] public_parameters The public parameters to use (number of
 * attributes).
 * \param [in] data The JSON string to use.
 * \return Success status.
 */
enum pabc_status pabc_decode_credential (
  struct pabc_context const *const ctx,
  struct pabc_public_parameters const *const public_parameters,
  struct pabc_credential *const cred, char const *const data);

/*!
 * JSON encode a proof.
 *
 * \param [in] ctx The global context to use.
 * \param [in] proof The proof to encode.
 * \param [in] public_parameters The public parameters to use (number of
 * attributes).
 * \param [out] json The JSON string is stored here. Must be freed by caller.
 * \return Success status.
 */
enum pabc_status
pabc_encode_proof (struct pabc_context const *const ctx,
                   struct pabc_public_parameters const *const public_parameters,
                   struct pabc_blinded_proof *const proof, char **json);

/*!
 * JSON decode a proof.
 *
 * \param [in] ctx The global context to use.
 * \param [in,out] proof The proof is stored here. Must be allocated
 * before calling this function (see ::pabc_new_proof).
 * \param [in] public_parameters The public parameters to use (number of
 * attributes).
 * \param [in] data The JSON string to use.
 * \return Success status.
 */
enum pabc_status
pabc_decode_proof (struct pabc_context const *const ctx,
                   struct pabc_public_parameters const *const public_parameters,
                   struct pabc_blinded_proof *const proof,
                   char const *const data);

enum pabc_status pabc_encode_nonce (struct pabc_context const *const ctx,
                                    struct pabc_nonce *const nonce,
                                    char **json);

enum pabc_status pabc_decode_nonce (struct pabc_context const *const ctx,
                                    struct pabc_nonce *const nonce,
                                    char const *const data);

#endif // PABC_SERIALIZE_H
