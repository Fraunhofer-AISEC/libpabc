/**
 * Copyright (c) 2021 Fraunhofer AISEC
 *
 * SPDX-License-Identifier: Apache-2.0
 **/





#ifndef PABC_JSON_CREDS_H
#define PABC_JSON_CREDS_H

#include "pabc_json_constants.h"
#include "pabc_utils.h"

struct pabc_blinded_proof;
struct pabc_context;
struct pabc_credential;
struct pabc_credential_request;
struct pabc_issuer_secret_key;
struct pabc_nonce;
struct pabc_public_parameters;
struct pabc_user_context;

/**
 * Encode a public parameter with additional meta information about the issuer
 * secret key used and the public paramters used.
 *
 * \param ctx [in,out] The context to use.
 * \param public_params [in,out] The public parameters to encode.
 * \param pp_id [in] The id string to store for the public parameters.
 * \param isk_key_id [in] The id string to store for the issuer secret key.
 * \param json_out [out] JSON result will be stored here. Must be freed by
 * caller.
 * \return Success status
 */
enum pabc_status pabc_cred_encode_public_parameters (
  struct pabc_context const *const ctx,
  struct pabc_public_parameters *const public_params, char const *const pp_id,
  char const *const isk_key_id, char **json_out);

/**
 * Parse a public parameters JSON and extract the issuer ID.
 *
 * \warning This function only parses the JSON. No
 * cryptographic checks are performed.
 *
 * \param public_params [in] The public parameters to parse.
 * \param issuer [out] The issuer ID will be stored here. Must be freed by
 * caller.
 * \return Success status.
 */
enum pabc_status pabc_cred_get_issuerid_from_pp (char const *const
                                                 public_params,
                                                 char **issuer);

/**
 * Parse a public parameters JSON and extract the public parameters ID.
 *
 * \warning This function only parses the JSON. No
 * cryptographic checks are performed.
 *
 * \param public_params [in] The public parameters to parse.
 * \param pp [out] The public parameters ID will be stored here. Must be
 * freed by caller.
 * \return Success status.
 */
enum pabc_status pabc_cred_get_ppid_from_pp (char const *const public_params,
                                             char **pp);

/**
 * Encodes a cr and adds additional meta information. The user ID will be added
 * as additional attribute.
 *
 * \param ctx [in,out] The context to use.
 * \param public_params [in] The public parameters to use.
 * \param cr [in] The cr to encode.
 * \param user_id [in] The user id to use.
 * \param pp_id [in] The public parameters id to use.
 * \param json_out [out] The JSON cr will be stored here. Must be freed by
 * caller. \return Success status.
 */
enum pabc_status
pabc_cred_encode_cr (struct pabc_context const *const ctx,
                     struct pabc_public_parameters const *const public_params,
                     struct pabc_credential_request *const cr,
                     char const *const user_id, char const *const pp_id,
                     char **json_out);

/**
 * Parse a credential request JSON and extract the public parameters ID.
 *
 * \warning This function only parses the JSON. No
 * cryptographic checks are performed.
 *
 * \param cr [in] The cr to parse.
 * \param ppid [out] The public parameters ID will be stored here. Must be
 * freed by caller.
 * \return Success status.
 */
enum pabc_status pabc_cred_get_ppid_from_cr (char const *const cr, char **ppid);

/**
 * Parse a credential request JSON and extract the user ID.
 *
 * \warning This function only parses the JSON. No
 * cryptographic checks are performed.
 *
 * \param cr [in] The cr to parse.
 * \param userid [out] The user ID will be stored here. Must be
 * freed by caller.
 * \return Success status.
 */
enum pabc_status pabc_cred_get_userid_from_cr (char const *const cr,
                                               char **userid);

/**
 * Encodes a credential and adds additional meta information. The user ID will
 * be added as additional attribute.
 *
 * \param ctx [in,out] The context to use.
 * \param public_params [in] The public parameters to use.
 * \param cred [in] The credential to encode.
 * \param user_id [in] The user id to use.
 * \param pp_id [in] The public parameters id to use.
 * \param json_out [out] The JSON cr will be stored here. Must be freed by
 * caller.
 * \return Success status.
 */
enum pabc_status
pabc_cred_encode_cred (struct pabc_context const *const ctx,
                       struct pabc_public_parameters const *const public_params,
                       struct pabc_credential *const cred,
                       char const *const user_id, char const *const pp_id,
                       char **json_out);

/**
 * Parse a credential JSON and extract the public parameters ID.
 *
 * \warning This function only parses the JSON. No
 * cryptographic checks are performed.
 *
 * \param cred [in] The credential to parse.
 * \param ppid [out] The public parameters ID will be stored here. Must be
 * freed by caller.
 * \return Success status.
 */
enum pabc_status pabc_cred_get_ppid_from_cred (char const *const cred,
                                               char **ppid);

/**
 * Parse a credential JSON and extract the user ID.
 *
 * \warning This function only parses the JSON. No
 * cryptographic checks are performed.
 *
 * \param cred [in] The cred to parse.
 * \param userid [out] The user ID will be stored here. Must be
 * freed by caller.
 * \return Success status.
 */
enum pabc_status pabc_cred_get_userid_from_cred (char const *const cred,
                                                 char **userid);

/**
 * Encodes a proof and adds additional meta information. The user ID will
 * be added as additional attribute.
 *
 * \param ctx [in,out] The context to use.
 * \param public_params [in] The public parameters to use.
 * \param proof [in] The proof to encode.
 * \param user_id [in] The user id to use.
 * \param pp_id [in] The public parameters id to use.
 * \param json_out [out] The JSON cr will be stored here. Must be freed by
 * caller.
 * \return Success status.
 */
enum pabc_status
pabc_cred_encode_proof (struct pabc_context const *const ctx,
                        struct pabc_public_parameters const *const
                        public_params,
                        struct pabc_blinded_proof *const proof,
                        char const *const user_id, char const *const pp_id,
                        char **json_out);

/**
 * Parse a proof JSON and extract the public parameters ID.
 *
 * \warning This function only parses the JSON. No
 * cryptographic checks are performed.
 *
 * \param proof [in] The proof to parse.
 * \param ppid [out] The public parameters ID will be stored here. Must be
 * freed by caller.
 * \return Success status.
 */
enum pabc_status pabc_cred_get_ppid_from_proof (char const *const proof,
                                                char **ppid);

/**
 * Parse a proof JSON and extract the user ID.
 *
 * \warning This function only parses the JSON. No
 * cryptographic checks are performed.
 *
 * \param proof [in] The proof to parse.
 * \param userid [out] The user ID will be stored here. Must be
 * freed by caller.
 * \return Success status.
 */
enum pabc_status pabc_cred_get_userid_from_proof (char const *const proof,
                                                  char **userid);

/**
 * Inspect a credential request.
 *
 * \warning This function only parses the JSON credential request. No
 * cryptographic checks are performed.
 *
 * \param json_cr [in] The credential request to inspect.
 * \param callback [in] The callback to call. First argument is attribute name,
 * second is attribute value and third is the passed through \p caller_ctx
 * \param caller_ctx [in] Caller context passed through to callback.
 * \return Success status.
 */
enum pabc_status pabc_cred_inspect_cred_request (
  char const *const json_cr,
  void (*callback)(char const *const, char const *const, void *),
  void *caller_ctx);

/**
 * Inspect a credential.
 *
 * \warning This function only parses the JSON credential. No
 * cryptographic checks are performed.
 *
 * \param json_credential [in] The credential to inspect.
 * \param callback [in] The callback to call. First argument is attribute name,
 * second is attribute value and third is the passed through \p caller_ctx
 * \param caller_ctx [in] Caller context passed through to callback.
 * \return Success status.
 */
enum pabc_status pabc_cred_inspect_credential (
  char const *const json_credential,
  void (*callback)(char const *const, char const *const, void *),
  void *caller_ctx);

/**
 * Inspect a proof.
 *
 * \warning This function only parses the JSON proof. No
 * cryptographic checks are performed.
 *
 * \param json_proof [in] The proof to inspect.
 * \param callback [in] The callback to call. First argument is attribute name,
 * second is attribute value and third is the passed through \p caller_ctx
 * \param caller_ctx [in] Caller context passed through to callback.
 * \return Success status.
 */
enum pabc_status pabc_cred_inspect_proof (char const *const json_proof,
                                          void (*callback)(char const *const,
                                                           char const *const,
                                                           void *),
                                          void *caller_ctx);

/**
 * Extract an attribute value from a credential request. No crypto checks are
 * performed.
 *
 * \param [in] cr The cr to parse.
 * \param [in] name The name of the attribute to extract.
 * \param [out] value The attribute value is stored here. Must be freed by
 * caller.
 * \return Success status.
 */
enum pabc_status pabc_cred_get_attr_by_name_from_cr (char const *const cr,
                                                     char const *const name,
                                                     char **value);

/**
 * Extract an attribute value from a credential. No crypto checks are
 * performed.
 *
 * \param [in] cred The credential to parse.
 * \param [in] name The name of the attribute to extract.
 * \param [out] value The attribute value is stored here. Must be freed by
 * caller.
 * \return Success status.
 */
enum pabc_status pabc_cred_get_attr_by_name_from_cred (char const *const cred,
                                                       char const *const name,
                                                       char **value);

/**
 * Extract an attribute value from a proof. No crypto checks are
 * performed.
 *
 * \param [in] proof The proof to parse.
 * \param [in] name The name of the attribute to extract.
 * \param [out] value The attribute value is stored here. Must be freed by
 * caller.
 * \return Success status.
 */
enum pabc_status pabc_cred_get_attr_by_name_from_proof (char const *const proof,
                                                        char const *const name,
                                                        char **value);

#endif // PABC_JSON_CREDS_H
