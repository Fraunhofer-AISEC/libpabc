/**
 * Copyright (c) 2021 Fraunhofer AISEC
 *
 * SPDX-License-Identifier: Apache-2.0
 **/





#include "json_creds.h"

enum pabc_status
pabc_cred_encode_public_parameters (
  struct pabc_context const *const ctx,
  struct pabc_public_parameters *const public_params, char const *const pp_id,
  char const *const isk_key_id, char **json_out)
{
  if (! ctx)
    print_and_return (PABC_UNINITIALIZED);
  if (! public_params)
    print_and_return (PABC_UNINITIALIZED);
  if (! pp_id)
    print_and_return (PABC_UNINITIALIZED);
  if (! json_out)
    print_and_return (PABC_UNINITIALIZED);

  enum pabc_status status;
  char *pabc_pp_json = NULL;
  int r;

  // encode public parameters
  status = pabc_encode_public_parameters (ctx, public_params, &pabc_pp_json);
  if (status != PABC_OK)
    print_and_return (status);

  // add issuer id and pp id
  json_error_t error;
  json_t *json = json_loads (pabc_pp_json, JANSSON_DEC_FLAGS, &error);
  if (! json)
  {
    PABC_FREE_NULL (pabc_pp_json);
    print_and_return (PABC_JANSSON_FAIL);
  }
  r = json_object_set_new (json, PABC_JSON_ISSUER_ID_KEY,
                           json_pack ("s", isk_key_id));
  if (r != 0)
  {
    json_decref (json);
    PABC_FREE_NULL (pabc_pp_json);
    print_and_return (PABC_JANSSON_FAIL);
  }

  r = json_object_set_new (json, PABC_JSON_PP_ID_KEY, json_pack ("s", pp_id));
  if (r != 0)
  {
    json_decref (json);
    PABC_FREE_NULL (pabc_pp_json);
    print_and_return (PABC_JANSSON_FAIL);
  }

  // dump string
  char *s = json_dumps (json, JANSSON_ENC_FLAGS);
  if (! s)
  {
    json_decref (json);
    PABC_FREE_NULL (pabc_pp_json);
    print_and_return (PABC_JANSSON_FAIL);
  }

  *json_out = s;

  json_decref (json);
  PABC_FREE_NULL (pabc_pp_json);
  return PABC_OK;
}


enum pabc_status
pabc_cred_get_issuerid_from_pp (char const *const public_params,
                                char **issuer)
{
  if (! public_params)
    print_and_return (PABC_UNINITIALIZED);
  if (! issuer)
    print_and_return (PABC_UNINITIALIZED);

  json_error_t error;
  json_t *json = json_loads (public_params, JANSSON_DEC_FLAGS, &error);
  if (! json)
  {
    print_and_return (PABC_JANSSON_FAIL);
  }
  json_t *isk_id = json_object_get (json, PABC_JSON_ISSUER_ID_KEY);
  if (! isk_id)
  {
    json_decref (json);
    return PABC_FAILURE;
  }
  char *s = strdup (json_string_value (isk_id));
  if (! s)
  {
    json_decref (json);
    print_and_return (PABC_OOM);
  }
  *issuer = s;

  json_decref (json);

  return PABC_OK;
}


enum pabc_status
pabc_cred_get_ppid_from_pp (char const *const public_params,
                            char **pp)
{

  if (! public_params)
    print_and_return (PABC_UNINITIALIZED);
  if (! pp)
    print_and_return (PABC_UNINITIALIZED);

  json_error_t error;
  json_t *json = json_loads (public_params, JANSSON_DEC_FLAGS, &error);
  if (! json)
  {
    print_and_return (PABC_JANSSON_FAIL);
  }
  json_t *pp_id = json_object_get (json, PABC_JSON_PP_ID_KEY);
  if (! pp_id)
  {
    json_decref (json);
    return PABC_FAILURE;
  }
  char *s = strdup (json_string_value (pp_id));
  if (! s)
  {
    json_decref (json);
    print_and_return (PABC_OOM);
  }
  *pp = s;

  json_decref (json);

  return PABC_OK;
}


enum pabc_status
pabc_cred_encode_cr (struct pabc_context const *const ctx,
                     struct pabc_public_parameters const *const public_params,
                     struct pabc_credential_request *const cr,
                     char const *const user_id, char const *const pp_id,
                     char **json_out)
{
  if (! ctx)
    print_and_return (PABC_UNINITIALIZED);
  if (! public_params)
    print_and_return (PABC_UNINITIALIZED);
  if (! cr)
    print_and_return (PABC_UNINITIALIZED);
  if (! user_id)
    print_and_return (PABC_UNINITIALIZED);
  if (! pp_id)
    print_and_return (PABC_UNINITIALIZED);
  if (! json_out)
    print_and_return (PABC_UNINITIALIZED);

  enum pabc_status status;
  char *pabc_cr_json = NULL;
  int r;

  // encode cr
  status =
    pabc_encode_credential_request (ctx, public_params, cr, &pabc_cr_json);
  if (status != PABC_OK)
    print_and_return (status);

  // add user id and pp id
  json_error_t error;
  json_t *json = json_loads (pabc_cr_json, JANSSON_DEC_FLAGS, &error);
  if (! json)
  {
    PABC_FREE_NULL (pabc_cr_json);
    print_and_return (PABC_JANSSON_FAIL);
  }
  r = json_object_set_new (json, PABC_JSON_USER_ID_KEY, json_pack ("s",
                                                                   user_id));
  if (r != 0)
  {
    json_decref (json);
    PABC_FREE_NULL (pabc_cr_json);
    print_and_return (PABC_JANSSON_FAIL);
  }

  r = json_object_set_new (json, PABC_JSON_PP_ID_KEY, json_pack ("s", pp_id));
  if (r != 0)
  {
    json_decref (json);
    PABC_FREE_NULL (pabc_cr_json);
    print_and_return (PABC_JANSSON_FAIL);
  }

  // dump string
  char *s = json_dumps (json, JANSSON_ENC_FLAGS);
  if (! s)
  {
    json_decref (json);
    PABC_FREE_NULL (pabc_cr_json);
    print_and_return (PABC_JANSSON_FAIL);
  }

  *json_out = s;

  json_decref (json);
  PABC_FREE_NULL (pabc_cr_json);
  return PABC_OK;
}


enum pabc_status
pabc_cred_get_ppid_from_cr (char const *const cr, char **ppid)
{
  if (! cr)
    print_and_return (PABC_UNINITIALIZED);
  if (! ppid)
    print_and_return (PABC_UNINITIALIZED);

  json_error_t error;
  json_t *json = json_loads (cr, JANSSON_DEC_FLAGS, &error);
  if (! json)
  {
    print_and_return (PABC_JANSSON_FAIL);
  }
  json_t *pp_id = json_object_get (json, PABC_JSON_PP_ID_KEY);
  if (! pp_id)
  {
    json_decref (json);
    return PABC_FAILURE;
  }
  char *s = strdup (json_string_value (pp_id));
  if (! s)
  {
    json_decref (json);
    print_and_return (PABC_OOM);
  }
  *ppid = s;

  json_decref (json);

  return PABC_OK;
}


enum pabc_status
pabc_cred_get_userid_from_cr (char const *const cr,
                              char **userid)
{

  if (! cr)
    print_and_return (PABC_UNINITIALIZED);
  if (! userid)
    print_and_return (PABC_UNINITIALIZED);

  json_error_t error;
  json_t *json = json_loads (cr, JANSSON_DEC_FLAGS, &error);
  if (! json)
  {
    print_and_return (PABC_JANSSON_FAIL);
  }
  json_t *usr_id = json_object_get (json, PABC_JSON_USER_ID_KEY);
  if (! usr_id)
  {
    json_decref (json);
    return PABC_FAILURE;
  }
  char *s = strdup (json_string_value (usr_id));
  if (! s)
  {
    json_decref (json);
    print_and_return (PABC_OOM);
  }
  *userid = s;

  json_decref (json);

  return PABC_OK;
}


enum pabc_status
pabc_cred_encode_cred (struct pabc_context const *const ctx,
                       struct pabc_public_parameters const *const public_params,
                       struct pabc_credential *const cred,
                       char const *const user_id, char const *const pp_id,
                       char **json_out)
{
  if (! ctx)
    print_and_return (PABC_UNINITIALIZED);
  if (! public_params)
    print_and_return (PABC_UNINITIALIZED);
  if (! cred)
    print_and_return (PABC_UNINITIALIZED);
  if (! user_id)
    print_and_return (PABC_UNINITIALIZED);
  if (! pp_id)
    print_and_return (PABC_UNINITIALIZED);
  if (! json_out)
    print_and_return (PABC_UNINITIALIZED);

  enum pabc_status status;
  char *pabc_cred_json = NULL;
  int r;

  // encode credential
  status = pabc_encode_credential (ctx, public_params, cred, &pabc_cred_json);
  if (status != PABC_OK)
    print_and_return (status);

  // add user id and pp id
  json_error_t error;
  json_t *json = json_loads (pabc_cred_json, JANSSON_DEC_FLAGS, &error);
  if (! json)
  {
    PABC_FREE_NULL (pabc_cred_json);
    print_and_return (PABC_JANSSON_FAIL);
  }
  r = json_object_set_new (json, PABC_JSON_USER_ID_KEY, json_pack ("s",
                                                                   user_id));
  if (r != 0)
  {
    json_decref (json);
    PABC_FREE_NULL (pabc_cred_json);
    print_and_return (PABC_JANSSON_FAIL);
  }

  r = json_object_set_new (json, PABC_JSON_PP_ID_KEY, json_pack ("s", pp_id));
  if (r != 0)
  {
    json_decref (json);
    PABC_FREE_NULL (pabc_cred_json);
    print_and_return (PABC_JANSSON_FAIL);
  }

  // dump string
  char *s = json_dumps (json, JANSSON_ENC_FLAGS);
  if (! s)
  {
    json_decref (json);
    PABC_FREE_NULL (pabc_cred_json);
    print_and_return (PABC_JANSSON_FAIL);
  }

  *json_out = s;

  json_decref (json);
  PABC_FREE_NULL (pabc_cred_json);
  return PABC_OK;
}


enum pabc_status
pabc_cred_get_ppid_from_cred (char const *const cred,
                              char **ppid)
{
  if (! cred)
    print_and_return (PABC_UNINITIALIZED);
  if (! ppid)
    print_and_return (PABC_UNINITIALIZED);

  json_error_t error;
  json_t *json = json_loads (cred, JANSSON_DEC_FLAGS, &error);
  if (! json)
  {
    print_and_return (PABC_JANSSON_FAIL);
  }
  json_t *pp_id = json_object_get (json, PABC_JSON_PP_ID_KEY);
  if (! pp_id)
  {
    json_decref (json);
    return PABC_FAILURE;
  }
  char *s = strdup (json_string_value (pp_id));
  if (! s)
  {
    json_decref (json);
    print_and_return (PABC_OOM);
  }
  *ppid = s;

  json_decref (json);

  return PABC_OK;
}


enum pabc_status
pabc_cred_get_userid_from_cred (char const *const cred,
                                char **userid)
{

  if (! cred)
    print_and_return (PABC_UNINITIALIZED);
  if (! userid)
    print_and_return (PABC_UNINITIALIZED);

  json_error_t error;
  json_t *json = json_loads (cred, JANSSON_DEC_FLAGS, &error);
  if (! json)
  {
    print_and_return (PABC_JANSSON_FAIL);
  }
  json_t *usr_id = json_object_get (json, PABC_JSON_USER_ID_KEY);
  if (! usr_id)
  {
    json_decref (json);
    return PABC_FAILURE;
  }
  char *s = strdup (json_string_value (usr_id));
  if (! s)
  {
    json_decref (json);
    print_and_return (PABC_OOM);
  }
  *userid = s;

  json_decref (json);

  return PABC_OK;
}


enum pabc_status
pabc_cred_encode_proof (struct pabc_context const *const ctx,
                        struct pabc_public_parameters const *const
                        public_params,
                        struct pabc_blinded_proof *const proof,
                        char const *const user_id, char const *const pp_id,
                        char **json_out)
{
  if (! ctx)
    print_and_return (PABC_UNINITIALIZED);
  if (! public_params)
    print_and_return (PABC_UNINITIALIZED);
  if (! proof)
    print_and_return (PABC_UNINITIALIZED);
  if (! user_id)
    print_and_return (PABC_UNINITIALIZED);
  if (! pp_id)
    print_and_return (PABC_UNINITIALIZED);
  if (! json_out)
    print_and_return (PABC_UNINITIALIZED);

  enum pabc_status status;
  char *pabc_proof_json = NULL;
  int r;

  // encode credential
  status = pabc_encode_proof (ctx, public_params, proof, &pabc_proof_json);
  if (status != PABC_OK)
    print_and_return (status);

  // add user id and pp id
  json_error_t error;
  json_t *json = json_loads (pabc_proof_json, JANSSON_DEC_FLAGS, &error);
  if (! json)
  {
    PABC_FREE_NULL (pabc_proof_json);
    print_and_return (PABC_JANSSON_FAIL);
  }
  r = json_object_set_new (json, PABC_JSON_USER_ID_KEY, json_pack ("s",
                                                                   user_id));
  if (r != 0)
  {
    json_decref (json);
    PABC_FREE_NULL (pabc_proof_json);
    print_and_return (PABC_JANSSON_FAIL);
  }

  r = json_object_set_new (json, PABC_JSON_PP_ID_KEY, json_pack ("s", pp_id));
  if (r != 0)
  {
    json_decref (json);
    PABC_FREE_NULL (pabc_proof_json);
    print_and_return (PABC_JANSSON_FAIL);
  }

  // dump string
  char *s = json_dumps (json, JANSSON_ENC_FLAGS);
  if (! s)
  {
    json_decref (json);
    PABC_FREE_NULL (pabc_proof_json);
    print_and_return (PABC_JANSSON_FAIL);
  }

  *json_out = s;

  json_decref (json);
  PABC_FREE_NULL (pabc_proof_json);
  return PABC_OK;
}


enum pabc_status
pabc_cred_get_ppid_from_proof (char const *const proof,
                               char **ppid)
{
  if (! proof)
    print_and_return (PABC_UNINITIALIZED);
  if (! ppid)
    print_and_return (PABC_UNINITIALIZED);

  json_error_t error;
  json_t *json = json_loads (proof, JANSSON_DEC_FLAGS, &error);
  if (! json)
  {
    print_and_return (PABC_JANSSON_FAIL);
  }
  json_t *pp_id = json_object_get (json, PABC_JSON_PP_ID_KEY);
  if (! pp_id)
  {
    json_decref (json);
    return PABC_FAILURE;
  }
  char *s = strdup (json_string_value (pp_id));
  if (! s)
  {
    json_decref (json);
    print_and_return (PABC_OOM);
  }
  *ppid = s;

  json_decref (json);

  return PABC_OK;
}


enum pabc_status
pabc_cred_get_userid_from_proof (char const *const proof,
                                 char **userid)
{

  if (! proof)
    print_and_return (PABC_UNINITIALIZED);
  if (! userid)
    print_and_return (PABC_UNINITIALIZED);

  json_error_t error;
  json_t *json = json_loads (proof, JANSSON_DEC_FLAGS, &error);
  if (! json)
  {
    print_and_return (PABC_JANSSON_FAIL);
  }
  json_t *usr_id = json_object_get (json, PABC_JSON_USER_ID_KEY);
  if (! usr_id)
  {
    json_decref (json);
    return PABC_FAILURE;
  }
  char *s = strdup (json_string_value (usr_id));
  if (! s)
  {
    json_decref (json);
    print_and_return (PABC_OOM);
  }
  *userid = s;

  json_decref (json);

  return PABC_OK;
}


enum pabc_status
pabc_cred_inspect_cred_request (
  char const *const json_cr,
  void (*callback)(char const *const, char const *const, void *),
  void *caller_ctx)
{
  if (! json_cr)
    print_and_return (PABC_UNINITIALIZED);
  if (! callback)
    print_and_return (PABC_UNINITIALIZED);

  json_error_t error;
  json_t *json = json_loads (json_cr, JANSSON_DEC_FLAGS, &error);
  if (! json)
    print_and_return (PABC_FAILURE);

  char const *attr_name;
  json_t *attr_val;
  json_object_foreach (json_object_get (json, PABC_JSON_PLAIN_ATTRS_KEY),
                       attr_name, attr_val) {
    (*callback)(attr_name, json_string_value (attr_val), caller_ctx);
  }
  json_decref (json);

  return PABC_OK;
}


enum pabc_status
pabc_cred_inspect_credential (
  char const *const json_credential,
  void (*callback)(char const *const, char const *const, void *),
  void *caller_ctx)
{
  if (! json_credential)
    print_and_return (PABC_UNINITIALIZED);
  if (! callback)
    print_and_return (PABC_UNINITIALIZED);

  json_error_t error;
  json_t *json = json_loads (json_credential, JANSSON_DEC_FLAGS, &error);
  if (! json)
    print_and_return (PABC_FAILURE);

  char const *attr_name;
  json_t *attr_val;
  json_object_foreach (json_object_get (json, PABC_JSON_PLAIN_ATTRS_KEY),
                       attr_name, attr_val) {
    (*callback)(attr_name, json_string_value (attr_val), caller_ctx);
  }
  json_decref (json);

  return PABC_OK;
}


enum pabc_status
pabc_cred_inspect_proof (char const *const json_proof,
                         void (*callback)(char const *const,
                                          char const *const,
                                          void *),
                         void *caller_ctx)
{
  if (! json_proof)
    print_and_return (PABC_UNINITIALIZED);
  if (! callback)
    print_and_return (PABC_UNINITIALIZED);

  json_error_t error;
  json_t *json = json_loads (json_proof, JANSSON_DEC_FLAGS, &error);
  if (! json)
    print_and_return (PABC_JANSSON_FAIL);

  char const *attr_name;
  json_t *attr_val;
  json_object_foreach (json_object_get (json, "DI"), attr_name, attr_val) {
    (*callback)(attr_name, json_string_value (attr_val), caller_ctx);
  }
  json_decref (json);

  return PABC_OK;
}


/**
 * An internal helper for extracting an attribute value from a cr/cred/proof.
 * \p value must be freed by caller.
 */
enum pabc_status
pabc_cred_helper_extract_val_from_json (char const *const json_in,
                                        char const *const name, char **value)
{
  if (! json_in)
    print_and_return (PABC_UNINITIALIZED);
  if (! name)
    print_and_return (PABC_UNINITIALIZED);
  if (! value)
    print_and_return (PABC_UNINITIALIZED);

  json_error_t error;
  json_t *json = json_loads (json_in, JANSSON_DEC_FLAGS, &error);
  if (! json)
    print_and_return (PABC_JANSSON_FAIL);
  json_t *attrs = json_object_get (json, PABC_JSON_PLAIN_ATTRS_KEY);
  if (! attrs)
  {
    json_decref (json);
    print_and_return (PABC_FAILURE);
  }
  json_t *attr_val = json_object_get (attrs, name);
  if (! attr_val)
  {
    json_decref (json);
    print_and_return (PABC_FAILURE);
  }
  char const *attr_val_string = json_string_value (attr_val);
  if (! attr_val_string)
  {
    json_decref (json);
    print_and_return (PABC_FAILURE);
  }
  char *ret_string = strdup (attr_val_string);
  if (! ret_string)
  {
    json_decref (json);
    print_and_return (PABC_OOM);
  }

  *value = ret_string;

  return PABC_OK;
}


enum pabc_status
pabc_cred_get_attr_by_name_from_cr (char const *const cr,
                                    char const *const name,
                                    char **value)
{
  if (! cr)
    print_and_return (PABC_UNINITIALIZED);
  if (! name)
    print_and_return (PABC_UNINITIALIZED);
  if (! value)
    print_and_return (PABC_UNINITIALIZED);

  return pabc_cred_helper_extract_val_from_json (cr, name, value);
}


enum pabc_status
pabc_cred_get_attr_by_name_from_cred (char const *const cred,
                                      char const *const name,
                                      char **value)
{
  if (! cred)
    print_and_return (PABC_UNINITIALIZED);
  if (! name)
    print_and_return (PABC_UNINITIALIZED);
  if (! value)
    print_and_return (PABC_UNINITIALIZED);

  return pabc_cred_helper_extract_val_from_json (cred, name, value);
}


enum pabc_status
pabc_cred_get_attr_by_name_from_proof (char const *const proof,
                                       char const *const name,
                                       char **value)
{
  if (! proof)
    print_and_return (PABC_UNINITIALIZED);
  if (! name)
    print_and_return (PABC_UNINITIALIZED);
  if (! value)
    print_and_return (PABC_UNINITIALIZED);

  return pabc_cred_helper_extract_val_from_json (proof, name, value);
}
