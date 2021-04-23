/**
 * Copyright (c) 2021 Fraunhofer AISEC
 *
 * SPDX-License-Identifier: Apache-2.0
 **/





#include "serialize.h"

// TODO duplicated code b64 encode/decode, adding to json obj / json array ...

enum pabc_status
json_add_obj_bn_t (json_t *const json, bn_t *const payload,
                   char const *const name)
{
  if (json == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (payload == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (name == NULL)
    print_and_return (PABC_UNINITIALIZED);

  RLC_TRY {
    int str_size = bn_size_str (*payload, JSON_RADIX);
    if (str_size < 0)
      print_and_return (PABC_FAILURE);

    char *str = malloc (sizeof(char) * (size_t) str_size);
    if (str == NULL)
      print_and_return (PABC_OOM);

    bn_write_str (str, str_size, *payload, JSON_RADIX);
    int r = json_object_set_new (json, name, json_pack ("s", str));
    PABC_FREE_NULL (str);
    if (r != 0)
      print_and_return (PABC_JANSSON_FAIL);
  }
  RLC_CATCH_ANY { print_and_return (PABC_RELIC_FAIL); }
  RLC_FINALLY {}

  return PABC_OK;
}


enum pabc_status
json_add_obj_g1_t (json_t *const json, g1_t *const payload,
                   char const *const name)
{
  if (json == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (payload == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (name == NULL)
    print_and_return (PABC_UNINITIALIZED);

  RLC_TRY {
    int bytes_size = g1_size_bin (*payload, POINT_COMPRESSION);
    if (bytes_size < 0)
      print_and_return (PABC_FAILURE);

    uint8_t *bytes = malloc (sizeof(uint8_t) * (size_t) bytes_size);
    if (bytes == NULL)
      print_and_return (PABC_OOM);

    g1_write_bin (bytes, bytes_size, *payload, POINT_COMPRESSION);
    // encode base 64
    base64_encodestate _state;
    base64_init_encodestate (&_state);

    char *str = calloc ((size_t) bytes_size * 2, sizeof(char));
    if (str == NULL)
    {
      PABC_FREE_NULL (bytes);
      print_and_return (PABC_OOM);
    }

    int b64_length =
      base64_encode_block ((char *) bytes, bytes_size, str, &_state);
    int b64_length_end = base64_encode_blockend (str + b64_length, &_state);
    // overwrite trailing \n
    str[b64_length + b64_length_end - 1] =
      '\0';   // ok, because base64 needs for chars for 3 bytes and we allocated
              // twice the input length

    // dump json
    int r = json_object_set_new (json, name, json_pack ("s", str));
    PABC_FREE_NULL (str);
    PABC_FREE_NULL (bytes);
    if (r != 0)
      print_and_return (PABC_JANSSON_FAIL);
  }
  RLC_CATCH_ANY { print_and_return (PABC_RELIC_FAIL); }
  RLC_FINALLY {}

  return PABC_OK;
}


enum pabc_status
json_add_obj_g2_t (json_t *const json, g2_t *const payload,
                   char const *const name)
{
  if (json == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (payload == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (name == NULL)
    print_and_return (PABC_UNINITIALIZED);

  RLC_TRY {
    int bytes_size = g2_size_bin (*payload, POINT_COMPRESSION);
    if (bytes_size < 0)
      print_and_return (PABC_FAILURE);

    uint8_t *bytes = malloc (sizeof(uint8_t) * (size_t) bytes_size);
    if (bytes == NULL)
      print_and_return (PABC_OOM);

    g2_write_bin (bytes, bytes_size, *payload, POINT_COMPRESSION);
    // encode base 64
    base64_encodestate _state;
    base64_init_encodestate (&_state);

    char *str = calloc ((size_t) bytes_size * 2, sizeof(char));
    if (str == NULL)
    {
      PABC_FREE_NULL (bytes);
      print_and_return (PABC_OOM);
    }

    int b64_length =
      base64_encode_block ((char *) bytes, bytes_size, str, &_state);
    int b64_length_end = base64_encode_blockend (str + b64_length, &_state);
    // overwrite trailing \n
    str[b64_length + b64_length_end - 1] =
      '\0';   // ok, because base64 needs for chars for 3 bytes and we allocated
              // twice the input length

    // dump json
    int r = json_object_set_new (json, name, json_pack ("s", str));
    PABC_FREE_NULL (str);
    PABC_FREE_NULL (bytes);
    if (r != 0)
      print_and_return (PABC_JANSSON_FAIL);
  }
  RLC_CATCH_ANY { print_and_return (PABC_RELIC_FAIL); }
  RLC_FINALLY {}

  return PABC_OK;
}


enum pabc_status
json_append_array_g1_t (json_t *const json,
                        g1_t *const payload)
{
  if (json == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (payload == NULL)
    print_and_return (PABC_UNINITIALIZED);

  RLC_TRY {
    int bytes_size = g1_size_bin (*payload, POINT_COMPRESSION);
    if (bytes_size < 0)
      print_and_return (PABC_FAILURE);

    uint8_t *bytes = malloc (sizeof(uint8_t) * (size_t) bytes_size);
    if (bytes == NULL)
      print_and_return (PABC_OOM);

    g1_write_bin (bytes, bytes_size, *payload, POINT_COMPRESSION);
    // encode base 64
    base64_encodestate _state;
    base64_init_encodestate (&_state);

    char *str = calloc ((size_t) bytes_size * 2, sizeof(char));
    if (str == NULL)
    {
      PABC_FREE_NULL (bytes);
      print_and_return (PABC_OOM);
    }

    int b64_length =
      base64_encode_block ((char *) bytes, bytes_size, str, &_state);
    int b64_length_end = base64_encode_blockend (str + b64_length, &_state);
    // overwrite trailing \n
    str[b64_length + b64_length_end - 1] =
      '\0';   // ok, because base64 needs for chars for 3 bytes and we allocated
              // twice the input length

    // dump json
    int r = json_array_append_new (json, json_pack ("s", str));
    PABC_FREE_NULL (str);
    PABC_FREE_NULL (bytes);
    if (r != 0)
      print_and_return (PABC_JANSSON_FAIL);
  }
  RLC_CATCH_ANY { print_and_return (PABC_RELIC_FAIL); }
  RLC_FINALLY {}

  return PABC_OK;
}


enum pabc_status
json_append_array_bn_t (json_t *const json,
                        bn_t *const payload)
{
  if (json == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (payload == NULL)
    print_and_return (PABC_UNINITIALIZED);

  RLC_TRY {
    int bytes_size = bn_size_str (*payload, JSON_RADIX);
    if (bytes_size < 0)
      print_and_return (PABC_FAILURE);

    uint8_t *bytes = malloc (sizeof(uint8_t) * (size_t) bytes_size);
    if (bytes == NULL)
      print_and_return (PABC_OOM);

    bn_write_str ((char *) bytes, bytes_size, *payload, JSON_RADIX);
    // dump json
    int r = json_array_append_new (json, json_pack ("s", bytes));
    PABC_FREE_NULL (bytes);
    if (r != 0)
      print_and_return (PABC_JANSSON_FAIL);
  }
  RLC_CATCH_ANY { print_and_return (PABC_RELIC_FAIL); }
  RLC_FINALLY {}

  return PABC_OK;
}


enum pabc_status
json_append_array_str (json_t *const json,
                       char const *const payload)
{
  if (json == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (payload == NULL)
    print_and_return (PABC_UNINITIALIZED);

  int r = json_array_append_new (json, json_pack ("s", payload));
  if (r != 0)
    print_and_return (PABC_JANSSON_FAIL);

  return PABC_OK;
}


/*!
 * Encodes an issuer secret key to JSON.
 *
 * \param [in] isk the key to encode
 * \param [out] json c string (must be freed by caller)
 * \return success status
 */
enum pabc_status
pabc_encode_issuer_secret_key (struct pabc_context const *const ctx,
                               struct pabc_issuer_secret_key *const isk,
                               char **json)
{
  if (ctx == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (isk == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (json == NULL)
    print_and_return (PABC_UNINITIALIZED);

  json_t *json_root = json_object ();
  if (json == NULL)
    print_and_return (PABC_OOM);

  enum pabc_status pabc_status;

  pabc_status = json_add_obj_bn_t (json_root, &isk->x, PABC_JSON_X_KEY);
  if (pabc_status != PABC_OK)
  {
    json_decref (json_root);
    print_and_return (pabc_status);
  }

  char *s = json_dumps (json_root, JANSSON_ENC_FLAGS);
  if (s == NULL)
    print_and_return (PABC_JANSSON_FAIL);

  *json = s;
  json_decref (json_root);

  return PABC_OK;
}


enum pabc_status
pabc_decode_issuer_secret_key (struct pabc_context const *const ctx,
                               struct pabc_issuer_secret_key *const isk,
                               char const *const data)
{
  if (ctx == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (isk == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (data == NULL)
    print_and_return (PABC_UNINITIALIZED);

  json_error_t error;
  json_t *json = json_loads (data, JANSSON_DEC_FLAGS, &error);
  if (json == NULL)
  {
    // printf ("%s\n", error.text);
    print_and_return (PABC_JANSSON_FAIL);
  }
  json_t *json_isk = json_object_get (json, PABC_JSON_X_KEY);
  if (json_isk == NULL)
  {
    json_decref (json);
    print_and_return (PABC_JANSSON_FAIL);
  }
  const char *str = json_string_value (json_isk);
  if (str == NULL)
  {
    json_decref (json);
    print_and_return (PABC_JANSSON_FAIL);
  }

  if (strlen (str) > INT_MAX)
  {
    json_decref (json);
    print_and_return (PABC_FAILURE);
  }
  RLC_TRY { bn_read_str (isk->x, str, (int) strlen (str), JSON_RADIX); }
  RLC_CATCH_ANY { print_and_return (PABC_RELIC_FAIL); }
  RLC_FINALLY {}

  json_decref (json);

  return PABC_OK;
}


enum pabc_status
pabc_encode_public_parameters (
  struct pabc_context const *const ctx,
  struct pabc_public_parameters *const public_parameters, char **json)
{
  if (ctx == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (public_parameters == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (json == NULL)
    print_and_return (PABC_UNINITIALIZED);

  enum pabc_status pabc_status;
  int r;

  json_t *json_root = json_object ();
  if (json_root == NULL)
    print_and_return (PABC_JANSSON_FAIL);

  // nr_of_attributes
  r = json_object_set_new (json_root, PABC_JSON_NR_ATTRS_KEY,
                           json_pack ("i",
                                      public_parameters->nr_of_attributes));
  if (r != 0)
  {
    json_decref (json_root);
    print_and_return (PABC_JANSSON_FAIL);
  }

  // ipk
  json_t *json_ipk = NULL;
  pabc_status = encode_issuer_public_key (ctx, public_parameters, &json_ipk);
  if (PABC_OK != pabc_status)
  {
    json_decref (json_root);
    print_and_return (pabc_status);
  }
  r = json_object_set_new (json_root, PABC_JSON_IPK_KEY, json_ipk);
  if (r != 0)
  {
    json_decref (json_root);
    print_and_return (PABC_JANSSON_FAIL);
  }

  // attribute names array
  json_t *an = json_array ();
  if (an == NULL)
  {
    json_decref (json_root);
    print_and_return (PABC_JANSSON_FAIL);
  }
  for (size_t i = 0; i < public_parameters->nr_of_attributes; ++i)
  {
    r = json_array_append_new (
      an, json_pack ("s", public_parameters->attrs->attribute_names[i]));
    if (r != 0)
    {
      json_decref (json_root);
      print_and_return (PABC_JANSSON_FAIL);
    }
  }
  r = json_object_set_new (json_root, PABC_JSON_ATTRS_KEY, an);
  if (r != 0)
  {
    json_decref (json_root);
    print_and_return (PABC_JANSSON_FAIL);
  }

  // return string
  char *s = json_dumps (json_root, JANSSON_ENC_FLAGS);
  if (s == NULL)
  {
    json_decref (json_root);
    print_and_return (PABC_JANSSON_FAIL);
  }
  *json = s;
  json_decref (json_root);

  return PABC_OK;
}


enum pabc_status
pabc_decode_and_new_public_parameters (
  struct pabc_context const *const ctx,
  struct pabc_public_parameters **public_parameters, char const *const data)
{
  if (ctx == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (public_parameters == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (data == NULL)
    print_and_return (PABC_UNINITIALIZED);

  enum pabc_status pabc_status;

  json_error_t error;
  json_t *json = json_loads (data, JANSSON_DEC_FLAGS, &error);
  if (json == NULL)
  {
    // printf ("%s\n", error.text);
    print_and_return (PABC_JANSSON_FAIL);
  }

  struct pabc_attributes *attrs = NULL;
  pabc_status = pabc_new_attributes (ctx, &attrs);
  if (PABC_OK != pabc_status)
  {
    json_decref (json);
    print_and_return (pabc_status);
  }

  // attribute_names
  json_t *json_an = json_object_get (json, PABC_JSON_ATTRS_KEY);
  if (json_an == NULL)
  {
    pabc_free_attributes (ctx, &attrs);
    json_decref (json);
    print_and_return (PABC_JANSSON_FAIL);
  }
  size_t index;
  json_t *value;
  json_array_foreach (json_an, index, value) {
    const char *str = json_string_value (value);
    if (str == NULL)
    {
      pabc_free_attributes (ctx, &attrs);
      json_decref (json);
      print_and_return (PABC_JANSSON_FAIL);
    }
    pabc_status = pabc_attributes_add (ctx, attrs, str);
    if (pabc_status != PABC_OK)
    {
      pabc_free_attributes (ctx, &attrs);
      json_decref (json);
      print_and_return (PABC_JANSSON_FAIL);
    }
  }

  pabc_status = pabc_new_public_parameters (ctx, attrs, public_parameters);
  if (PABC_OK != pabc_status)
  {
    json_decref (json);
    pabc_free_attributes (ctx, &attrs);
    print_and_return (pabc_status);
  }
  pabc_free_attributes (ctx, &attrs); // not needed any more

  // nr_of_attributes
  json_t *json_nr_attributes = json_object_get (json, PABC_JSON_NR_ATTRS_KEY);
  if (json_nr_attributes == NULL)
  {
    pabc_free_public_parameters (ctx, public_parameters);
    json_decref (json);
    print_and_return (PABC_JANSSON_FAIL);
  }
  json_int_t nr = json_integer_value (json_nr_attributes);
  if (nr < 0)
  {
    pabc_free_public_parameters (ctx, public_parameters);
    json_decref (json);
    print_and_return (PABC_FAILURE);
  }
  (*public_parameters)->nr_of_attributes = (size_t) nr;

  // issuer_public_key
  json_t *json_ipk = json_object_get (json, PABC_JSON_IPK_KEY);
  if (json_ipk == NULL)
  {
    pabc_free_public_parameters (ctx, public_parameters);
    json_decref (json);
    print_and_return (PABC_JANSSON_FAIL);
  }
  pabc_status = decode_issuer_public_key (ctx, *public_parameters, json_ipk);
  if (pabc_status != PABC_OK)
  {
    pabc_free_public_parameters (ctx, public_parameters);
    json_decref (json);
    print_and_return (pabc_status);
  }

  // clean up
  json_decref (json);

  return PABC_OK;
}


enum pabc_status
encode_issuer_public_key (struct pabc_context const *const ctx,
                          struct pabc_public_parameters *const
                          public_parameters,
                          json_t **json)
{
  if (ctx == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (public_parameters == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (json == NULL)
    print_and_return (PABC_UNINITIALIZED);

  enum pabc_status pabc_status;

  struct pabc_issuer_public_key *const ipk = public_parameters->ipk;
  if (public_parameters->ipk == NULL)
    print_and_return (PABC_UNINITIALIZED);

  json_t *json_root = json_object ();
  if (json_root == NULL)
    print_and_return (PABC_JANSSON_FAIL);

  int r;
  // g1_t HAttrs*
  json_t *HAttrs = json_array ();
  if (HAttrs == NULL)
  {
    json_decref (json_root);
    print_and_return (PABC_JANSSON_FAIL);
  }

  for (size_t i = 0; i < public_parameters->nr_of_attributes; ++i)
  {
    pabc_status = json_append_array_g1_t (HAttrs, &ipk->HAttrs[i]);
    if (PABC_OK != pabc_status)
    {
      json_decref (HAttrs);
      json_decref (json_root);
      print_and_return (pabc_status);
    }
  }
  r = json_object_set_new (json_root, PABC_JSON_HATTRS_KEY, HAttrs);
  if (r != 0)
  {
    json_decref (HAttrs);
    json_decref (json_root);
    print_and_return (PABC_JANSSON_FAIL);
  }

  // g1_t HRand
  pabc_status = json_add_obj_g1_t (json_root, &ipk->HRand, PABC_JSON_HRAND_KEY);
  if (PABC_OK != pabc_status)
  {
    json_decref (json_root);
    print_and_return (pabc_status);
  }

  // g1_t HSk
  pabc_status = json_add_obj_g1_t (json_root, &ipk->HSk, PABC_JSON_HSK_KEY);
  if (pabc_status != PABC_OK)
  {
    json_decref (json_root);
    print_and_return (pabc_status);
  }

  // g2_t w
  pabc_status = json_add_obj_g2_t (json_root, &ipk->w, PABC_JSON_W_KEY);
  if (pabc_status != PABC_OK)
  {
    json_decref (json_root);
    print_and_return (pabc_status);
  }

  // g1_t _g1
  pabc_status = json_add_obj_g1_t (json_root, &ipk->_g1, PABC_JSON_G1_KEY);
  if (pabc_status != PABC_OK)
  {
    json_decref (json_root);
    print_and_return (pabc_status);
  }

  // g1_t _g2
  pabc_status = json_add_obj_g1_t (json_root, &ipk->_g2, PABC_JSON_G2_KEY);
  if (pabc_status != PABC_OK)
  {
    json_decref (json_root);
    print_and_return (pabc_status);
  }

  // bn_t C
  pabc_status = json_add_obj_bn_t (json_root, &ipk->C, PABC_JSON_C_KEY);
  if (pabc_status != PABC_OK)
  {
    json_decref (json_root);
    print_and_return (pabc_status);
  }

  // bn_t S
  pabc_status = json_add_obj_bn_t (json_root, &ipk->S, PABC_JSON_S_KEY);
  if (pabc_status != PABC_OK)
  {
    json_decref (json_root);
    print_and_return (pabc_status);
  }

  *json = json_root;
  return PABC_OK;
}


enum pabc_status
decode_issuer_public_key (struct pabc_context const *const ctx,
                          struct pabc_public_parameters *const
                          public_parameters,
                          json_t *const json)
{
  if (ctx == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (public_parameters == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (json == NULL)
    print_and_return (PABC_UNINITIALIZED);

  enum pabc_status pabc_status;
  struct pabc_issuer_public_key *ipk = public_parameters->ipk;
  if (ipk == NULL)
    print_and_return (PABC_UNINITIALIZED);

  // g1_t * HAttrs
  size_t index;
  json_t *value;
  json_t *HAttrs = json_object_get (json, PABC_JSON_HATTRS_KEY);
  if (HAttrs == NULL)
    print_and_return (PABC_JANSSON_FAIL);

  json_array_foreach (HAttrs, index, value) {
    if (index > public_parameters->nr_of_attributes)
      print_and_return (PABC_OOB);
    pabc_status = json_decode_g1_t (value, &ipk->HAttrs[index]);
    if (pabc_status != PABC_OK)
      print_and_return (pabc_status);
  }

  // g1_t HRand
  pabc_status =
    json_decode_g1_t (json_object_get (json, PABC_JSON_HRAND_KEY), &ipk->HRand);
  if (pabc_status != PABC_OK)
    print_and_return (pabc_status);

  // g1_t HSk
  pabc_status =
    json_decode_g1_t (json_object_get (json, PABC_JSON_HSK_KEY), &ipk->HSk);
  if (pabc_status != PABC_OK)
    print_and_return (pabc_status);

  // g2_t w
  pabc_status =
    json_decode_g2_t (json_object_get (json, PABC_JSON_W_KEY), &ipk->w);
  if (pabc_status != PABC_OK)
    print_and_return (pabc_status);

  // g1_t _g1
  pabc_status =
    json_decode_g1_t (json_object_get (json, PABC_JSON_G1_KEY), &ipk->_g1);
  if (pabc_status != PABC_OK)
    print_and_return (pabc_status);

  // g1_t _g2
  pabc_status =
    json_decode_g1_t (json_object_get (json, PABC_JSON_G2_KEY), &ipk->_g2);
  if (pabc_status != PABC_OK)
    print_and_return (pabc_status);

  // bn_t C
  pabc_status =
    json_decode_bn_t (json_object_get (json, PABC_JSON_C_KEY), &ipk->C);
  if (pabc_status != PABC_OK)
    print_and_return (pabc_status);

  // bn_t S
  pabc_status =
    json_decode_bn_t (json_object_get (json, PABC_JSON_S_KEY), &ipk->S);
  if (pabc_status != PABC_OK)
    print_and_return (pabc_status);

  return PABC_OK;
}


enum pabc_status
json_decode_bn_t (json_t *const json, bn_t *target)
{
  if (json == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (target == NULL)
    print_and_return (PABC_UNINITIALIZED);

  char const *str = json_string_value (json);
  if (str == NULL)
    print_and_return (PABC_JANSSON_FAIL);
  if (strlen (str) > INT_MAX)
    print_and_return (PABC_FAILURE);
  RLC_TRY { bn_read_str (*target, str, (int) strlen (str), JSON_RADIX); }
  RLC_CATCH_ANY { print_and_return (PABC_RELIC_FAIL); }
  RLC_FINALLY {}
  return PABC_OK;
}


enum pabc_status
json_decode_g1_t (json_t *const json, g1_t *target)
{
  if (json == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (target == NULL)
    print_and_return (PABC_UNINITIALIZED);

  char const *str = json_string_value (json);
  if (str == NULL)
    print_and_return (PABC_JANSSON_FAIL);
  size_t str_len = strlen (str);
  if (str_len > INT_MAX)
    print_and_return (PABC_FAILURE);

  // base64 decode
  base64_decodestate _state;
  base64_init_decodestate (&_state);
  char *decoded = calloc (str_len, sizeof(char));
  if (decoded == NULL)
    print_and_return (PABC_OOM);
  int decoded_length = base64_decode_block (str, (int) str_len, decoded,
                                            &_state);
  if (decoded_length < 0)
  {
    PABC_FREE_NULL (decoded);
    print_and_return (PABC_FAILURE);
  }
  if ((decoded_length == 0) || ((size_t) decoded_length > str_len))
  {
    PABC_FREE_NULL (decoded);
    print_and_return (PABC_FAILURE);
  }
  RLC_TRY { g1_read_bin (*target, (uint8_t *) decoded, decoded_length); }
  RLC_CATCH_ANY { print_and_return (PABC_RELIC_FAIL); }
  RLC_FINALLY {}
  PABC_FREE_NULL (decoded);

  return PABC_OK;
}


enum pabc_status
json_decode_g2_t (json_t *const json, g2_t *target)
{
  if (json == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (target == NULL)
    print_and_return (PABC_UNINITIALIZED);

  char const *str = json_string_value (json);
  if (str == NULL)
    print_and_return (PABC_JANSSON_FAIL);

  size_t str_len = strlen (str);
  if (str_len > INT_MAX)
    print_and_return (PABC_FAILURE);

  // base64 decode
  base64_decodestate _state;
  base64_init_decodestate (&_state);
  char *decoded = calloc (str_len, sizeof(char));
  if (decoded == NULL)
    print_and_return (PABC_OOM);

  int decoded_length = base64_decode_block (str, (int) str_len, decoded,
                                            &_state);
  if (decoded_length < 0)
  {
    PABC_FREE_NULL (decoded);
    print_and_return (PABC_FAILURE);
  }
  if ((decoded_length == 0) || ((size_t) decoded_length > str_len))
  {
    PABC_FREE_NULL (decoded);
    print_and_return (PABC_FAILURE);
  }
  RLC_TRY { g2_read_bin (*target, (uint8_t *) decoded, decoded_length); }
  RLC_CATCH_ANY { print_and_return (PABC_RELIC_FAIL); }
  RLC_FINALLY {}
  PABC_FREE_NULL (decoded);

  return PABC_OK;
}


enum pabc_status
json_decode_str (json_t *const json, char **target)
{
  if (json == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (target == NULL)
    print_and_return (PABC_UNINITIALIZED);

  char const *str = json_string_value (json);
  if (str == NULL)
    print_and_return (PABC_JANSSON_FAIL);

  char *new_target = realloc (*target, strlen (str) + 1);
  if (new_target == NULL)
    print_and_return (PABC_OOM); // no need to free target -> caller's job

  *target = new_target;
  strcpy (*target, str);
  return PABC_OK;
}


enum pabc_status
pabc_encode_user_ctx (
  struct pabc_context const *const ctx,
  struct pabc_public_parameters const *const public_parameters,
  struct pabc_user_context *const usr_ctx, char **json)
{
  if (ctx == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (public_parameters == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (usr_ctx == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (json == NULL)
    print_and_return (PABC_UNINITIALIZED);

  enum pabc_status pabc_status;

  json_t *json_root = json_object ();
  if (json == NULL)
    print_and_return (PABC_JANSSON_FAIL);

  // bn_t sk
  pabc_status = json_add_obj_bn_t (json_root, &usr_ctx->sk, PABC_JSON_SK_KEY);
  if (pabc_status != PABC_OK)
  {
    json_decref (json_root);
    print_and_return (pabc_status);
  }

  // char **plain_attrs
  json_t *array = json_array ();
  if (array == NULL)
  {
    json_decref (json_root);
    print_and_return (pabc_status);
  }

  int r;
  for (size_t i = 0; i < public_parameters->nr_of_attributes; ++i)
  {
    if (usr_ctx->plain_attrs[i])
    {
      r = json_array_append_new (array, json_pack ("s",
                                                   usr_ctx->plain_attrs[i]));
    }
    else
    {
      r = json_array_append_new (array, json_null ());
    }
    if (r != 0)
    {
      json_decref (array);
      json_decref (json_root);
      print_and_return (PABC_JANSSON_FAIL);
    }
  }
  r = json_object_set_new (json_root, PABC_JSON_PLAIN_ATTRS_KEY, array);
  if (r != 0)
  {
    json_decref (json_root);
    print_and_return (PABC_JANSSON_FAIL);
  }

  // dump
  char *s = json_dumps (json_root, JANSSON_ENC_FLAGS);
  if (s == NULL)
  {
    json_decref (json_root);
    print_and_return (PABC_JANSSON_FAIL);
  }
  *json = s;
  json_decref (json_root);

  return PABC_OK;
}


enum pabc_status
pabc_decode_user_ctx (
  struct pabc_context const *const ctx,
  struct pabc_public_parameters const *const public_parameters,
  struct pabc_user_context *const usr_ctx, char const *const data)
{

  if (ctx == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (public_parameters == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (usr_ctx == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (data == NULL)
    print_and_return (PABC_UNINITIALIZED);

  enum pabc_status pabc_status;

  json_error_t error;
  json_t *json = json_loads (data, JANSSON_DEC_FLAGS, &error);
  if (json == NULL)
  {
    // printf ("%s\n", error.text);
    print_and_return (PABC_JANSSON_FAIL);
  }

  // bn_t sk
  json_t *json_sk = json_object_get (json, PABC_JSON_SK_KEY);
  if (json_sk == NULL)
  {
    json_decref (json);
    print_and_return (PABC_JANSSON_FAIL);
  }
  const char *str = json_string_value (json_sk);
  if (str == NULL)
  {
    json_decref (json);
    print_and_return (PABC_JANSSON_FAIL);
  }
  if (strlen (str) > INT_MAX)
  {
    json_decref (json);
    print_and_return (PABC_FAILURE);
  }
  RLC_TRY { bn_read_str (usr_ctx->sk, str, (int) strlen (str), JSON_RADIX); }
  RLC_CATCH_ANY {
    json_decref (json);
    print_and_return (PABC_RELIC_FAIL);
  }
  RLC_FINALLY {}

  // char **plain_attrs
  json_t *plain_attrs = json_object_get (json, PABC_JSON_PLAIN_ATTRS_KEY);
  if (plain_attrs == NULL)
    print_and_return (PABC_JANSSON_FAIL);

  size_t index;
  json_t *value;
  json_array_foreach (plain_attrs, index, value) {
    if (index > public_parameters->nr_of_attributes) // OOB
    {
      json_decref (json);
      print_and_return (PABC_OOB);
    }
    str = json_string_value (value); // str or NULL if not a valid json string
    pabc_status =
      pabc_set_attribute_value (ctx, public_parameters, usr_ctx, index, str);
    if (PABC_OK != pabc_status)
    {
      json_decref (json);
      print_and_return (pabc_status);
    }
  }
  json_decref (json);

  return PABC_OK;
}


enum pabc_status
pabc_encode_credential_request (
  struct pabc_context const *const ctx,
  struct pabc_public_parameters const *const public_parameters,
  struct pabc_credential_request *const cr, char **json)
{
  if (ctx == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (public_parameters == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (cr == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (json == NULL)
    print_and_return (PABC_UNINITIALIZED);

  enum pabc_status status;

  json_t *json_root = json_object ();
  if (json == NULL)
    print_and_return (PABC_JANSSON_FAIL);

  // g1_t Nym
  status = json_add_obj_g1_t (json_root, &cr->Nym, PABC_JSON_NYM_KEY);
  if (status != PABC_OK)
  {
    json_decref (json_root);
    print_and_return (status);
  }

  // bn_t nonce
  // TODO could adapt to use pabc_{encode,decode}_nonce here
  status = json_add_obj_bn_t (json_root, &cr->nonce->nonce,
                              PABC_JSON_NONCE_KEY);
  if (status != PABC_OK)
  {
    json_decref (json_root);
    print_and_return (status);
  }

  // bn_t C
  status = json_add_obj_bn_t (json_root, &cr->C, PABC_JSON_C_KEY);
  if (status != PABC_OK)
  {
    json_decref (json_root);
    print_and_return (status);
  }

  // bn_t S
  status = json_add_obj_bn_t (json_root, &cr->S, PABC_JSON_S_KEY);
  if (status != PABC_OK)
  {
    json_decref (json_root);
    print_and_return (status);
  }

  // plain attributes
  json_t *array_plain_attrs = NULL;
  status = json_encode_plain_attributes (ctx, public_parameters,
                                         &array_plain_attrs, cr->plain_attrs);
  if (status != PABC_OK)
  {
    json_decref (json_root);
    print_and_return (status);
  }

  int r = json_object_set_new (json_root, PABC_JSON_PLAIN_ATTRS_KEY,
                               array_plain_attrs);
  if (r != 0)
  {
    json_decref (array_plain_attrs);
    json_decref (json_root);
    print_and_return (PABC_JANSSON_FAIL);
  }

  // dump
  char *s = json_dumps (json_root, JANSSON_ENC_FLAGS);
  if (s == NULL)
  {
    json_decref (json_root);
    print_and_return (PABC_JANSSON_FAIL);
  }
  *json = s;
  json_decref (json_root);

  return PABC_OK;
}


enum pabc_status
pabc_decode_credential_request (
  struct pabc_context const *const ctx,
  struct pabc_public_parameters const *const public_parameters,
  struct pabc_credential_request *const cr, char const *const data)
{
  if (ctx == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (public_parameters == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (cr == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (data == NULL)
    print_and_return (PABC_UNINITIALIZED);

  enum pabc_status status;
  json_error_t error;
  json_t *json = json_loads (data, JANSSON_DEC_FLAGS, &error);
  if (json == NULL)
  {
    // printf ("%s\n", error.text);
    print_and_return (PABC_JANSSON_FAIL);
  }

  // g1_t Nym
  status = json_decode_g1_t (json_object_get (json, PABC_JSON_NYM_KEY),
                             &cr->Nym);
  if (status != PABC_OK)
  {
    json_decref (json);
    print_and_return (status);
  }

  // bn_t nonce
  // TODO could adapt to use pabc_{encode,decode}_nonce here
  status = pabc_new_nonce (ctx, &cr->nonce); // nonce is NULL here
  if (PABC_OK != status)
  {
    json_decref (json);
    print_and_return (status);
  }
  status = json_decode_bn_t (json_object_get (json, PABC_JSON_NONCE_KEY),
                             &cr->nonce->nonce);
  if (status != PABC_OK)
  {
    pabc_free_nonce (ctx, &cr->nonce);
    json_decref (json);
    print_and_return (status);
  }

  // bn_t C
  status = json_decode_bn_t (json_object_get (json, PABC_JSON_C_KEY), &cr->C);
  if (status != PABC_OK)
  {
    pabc_free_nonce (ctx, &cr->nonce);
    json_decref (json);
    print_and_return (status);
  }

  // bn_t S
  status = json_decode_bn_t (json_object_get (json, PABC_JSON_S_KEY), &cr->S);
  if (status != PABC_OK)
  {
    pabc_free_nonce (ctx, &cr->nonce);
    json_decref (json);
    print_and_return (status);
  }

  // plain attributes
  json_t *plain_attrs = json_object_get (json, PABC_JSON_PLAIN_ATTRS_KEY);
  if (plain_attrs == NULL)
  {
    pabc_free_nonce (ctx, &cr->nonce);
    json_decref (json);
    print_and_return (PABC_JANSSON_FAIL);
  }
  status = json_decode_plain_attributes (ctx, public_parameters, plain_attrs,
                                         cr->plain_attrs);
  if (status != PABC_OK)
  {
    pabc_free_nonce (ctx, &cr->nonce);
    json_decref (json);
    print_and_return (status);
  }

  json_decref (json);

  return PABC_OK;
}


enum pabc_status
pabc_encode_credential (
  struct pabc_context const *const ctx,
  struct pabc_public_parameters const *const public_parameters,
  struct pabc_credential *const cred, char **json)
{
  if (ctx == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (public_parameters == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (cred == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (json == NULL)
    print_and_return (PABC_UNINITIALIZED);

  enum pabc_status status;

  json_t *json_root = json_object ();
  if (json == NULL)
    print_and_return (PABC_JANSSON_FAIL);

  // g1_t A
  status = json_add_obj_g1_t (json_root, &cred->A, PABC_JSON_A_KEY);
  if (status != PABC_OK)
  {
    json_decref (json_root);
    print_and_return (status);
  }

  // g1_t B
  status = json_add_obj_g1_t (json_root, &cred->B, PABC_JSON_B_KEY);
  if (status != PABC_OK)
  {
    json_decref (json_root);
    print_and_return (status);
  }

  // bn_t e
  status = json_add_obj_bn_t (json_root, &cred->e, PABC_JSON_E_KEY);
  if (status != PABC_OK)
  {
    json_decref (json_root);
    print_and_return (status);
  }

  // bn_t s
  status = json_add_obj_bn_t (json_root, &cred->s, PABC_JSON_CREDS_KEY);
  if (status != PABC_OK)
  {
    json_decref (json_root);
    print_and_return (status);
  }

  // g1_t Nym
  status = json_add_obj_g1_t (json_root, &cred->Nym, PABC_JSON_NYM_KEY);
  if (status != PABC_OK)
  {
    json_decref (json_root);
    print_and_return (status);
  }

  // plain attributes
  json_t *array_plain_attrs = NULL;
  status = json_encode_plain_attributes (ctx, public_parameters,
                                         &array_plain_attrs, cred->plain_attrs);
  if (status != PABC_OK)
  {
    json_decref (json_root);
    print_and_return (status);
  }
  int r = json_object_set_new (json_root, PABC_JSON_PLAIN_ATTRS_KEY,
                               array_plain_attrs);
  if (r != 0)
  {
    json_decref (array_plain_attrs);
    json_decref (json_root);
    print_and_return (PABC_JANSSON_FAIL);
  }

  // dump
  char *s = json_dumps (json_root, JANSSON_ENC_FLAGS);
  if (s == NULL)
  {
    json_decref (json_root);
    print_and_return (PABC_JANSSON_FAIL);
  }
  *json = s;
  json_decref (json_root);

  return PABC_OK;
}


enum pabc_status
pabc_decode_credential (
  struct pabc_context const *const ctx,
  struct pabc_public_parameters const *const public_parameters,
  struct pabc_credential *const cred, char const *const data)
{
  if (ctx == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (public_parameters == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (cred == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (data == NULL)
    print_and_return (PABC_UNINITIALIZED);

  json_error_t error;
  json_t *json = json_loads (data, JANSSON_DEC_FLAGS, &error);
  if (json == NULL)
  {
    // printf ("%s\n", error.text);
    print_and_return (PABC_JANSSON_FAIL);
  }

  // g1_t A
  enum pabc_status status;
  status = json_decode_g1_t (json_object_get (json, PABC_JSON_A_KEY), &cred->A);
  if (status != PABC_OK)
  {
    json_decref (json);
    print_and_return (status);
  }

  // g1_t B
  status = json_decode_g1_t (json_object_get (json, PABC_JSON_B_KEY), &cred->B);
  if (status != PABC_OK)
  {
    json_decref (json);
    print_and_return (status);
  }

  // bn_t e
  status = json_decode_bn_t (json_object_get (json, PABC_JSON_E_KEY), &cred->e);
  if (status != PABC_OK)
  {
    json_decref (json);
    print_and_return (status);
  }

  // bn_t s
  status =
    json_decode_bn_t (json_object_get (json, PABC_JSON_CREDS_KEY), &cred->s);
  if (status != PABC_OK)
  {
    json_decref (json);
    print_and_return (status);
  }

  // g1_t Nym
  status =
    json_decode_g1_t (json_object_get (json, PABC_JSON_NYM_KEY), &cred->Nym);
  if (status != PABC_OK)
  {
    json_decref (json);
    print_and_return (status);
  }
  // plain attributes
  json_t *plain_attrs = json_object_get (json, PABC_JSON_PLAIN_ATTRS_KEY);
  status = json_decode_plain_attributes (ctx, public_parameters, plain_attrs,
                                         cred->plain_attrs);
  if (status != PABC_OK)
  {
    json_decref (json);
    print_and_return (status);
  }

  json_decref (json);

  return PABC_OK;
}


enum pabc_status
pabc_encode_proof (struct pabc_context const *const ctx,
                   struct pabc_public_parameters const *const public_parameters,
                   struct pabc_blinded_proof *const proof, char **json)
{
  if (ctx == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (public_parameters == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (proof == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (json == NULL)
    print_and_return (PABC_UNINITIALIZED);

  enum pabc_status pabc_status;

  json_t *json_root = json_object ();
  if (json == NULL)
    print_and_return (PABC_JANSSON_FAIL);

  // g1_t APrime
  pabc_status =
    json_add_obj_g1_t (json_root, &proof->APrime, PABC_JSON_APRIME_KEY);
  if (pabc_status != PABC_OK)
  {
    json_decref (json_root);
    print_and_return (pabc_status);
  }

  // g1_t ABar
  pabc_status = json_add_obj_g1_t (json_root, &proof->ABar, PABC_JSON_ABAR_KEY);
  if (pabc_status != PABC_OK)
  {
    json_decref (json_root);
    print_and_return (pabc_status);
  }

  // g1_t BPrime
  pabc_status =
    json_add_obj_g1_t (json_root, &proof->BPrime, PABC_JSON_BPRIME_KEY);
  if (pabc_status != PABC_OK)
  {
    json_decref (json_root);
    print_and_return (pabc_status);
  }

  // bn_t ProofC
  pabc_status =
    json_add_obj_bn_t (json_root, &proof->ProofC, PABC_JSON_PROOFC_KEY);
  if (pabc_status != PABC_OK)
  {
    json_decref (json_root);
    print_and_return (pabc_status);
  }

  // bn_t ProofSSk
  pabc_status =
    json_add_obj_bn_t (json_root, &proof->ProofSSk, PABC_JSON_SSK_KEY);
  if (pabc_status != PABC_OK)
  {
    json_decref (json_root);
    print_and_return (pabc_status);
  }

  // bn_t ProofSE
  pabc_status = json_add_obj_bn_t (json_root, &proof->ProofSE,
                                   PABC_JSON_SE_KEY);
  if (pabc_status != PABC_OK)
  {
    json_decref (json_root);
    print_and_return (pabc_status);
  }

  // bn_t ProofSR2
  pabc_status =
    json_add_obj_bn_t (json_root, &proof->ProofSR2, PABC_JSON_SR2_KEY);
  if (pabc_status != PABC_OK)
  {
    json_decref (json_root);
    print_and_return (pabc_status);
  }

  // bn_t ProofSR3
  pabc_status =
    json_add_obj_bn_t (json_root, &proof->ProofSR3, PABC_JSON_SR3_KEY);
  if (pabc_status != PABC_OK)
  {
    json_decref (json_root);
    print_and_return (pabc_status);
  }

  // bn_t ProofSSPrime
  pabc_status =
    json_add_obj_bn_t (json_root, &proof->ProofSSPrime, PABC_JSON_SSPRIME_KEY);
  if (pabc_status != PABC_OK)
  {
    json_decref (json_root);
    print_and_return (pabc_status);
  }

  // bn_t *ProofSAttrs
  json_t *sattrs = json_object ();
  enum pabc_status status;
  int r;
  if (! sattrs)
  {
    json_decref (json_root);
    print_and_return (PABC_JANSSON_FAIL);
  }
  for (size_t i = 0; i < public_parameters->nr_of_attributes; ++i)
  {
    if (proof->DI->D[i] == PABC_DISCLOSED)
      continue;
    status = json_add_obj_bn_t (sattrs, &proof->ProofSAttrs[i],
                                public_parameters->attrs->attribute_names[i]);
    if (status != PABC_OK)
    {
      json_decref (json_root);
      print_and_return (status);
    }
  }
  r = json_object_set_new (json_root, PABC_JSON_SATTRS_KEY, sattrs);
  if (r != 0)
  {
    json_decref (json_root);
    print_and_return (PABC_JANSSON_FAIL);
  }
  /*
  json_t *array = json_array ();
  if (array == NULL)
  {
    json_decref (json_root);
    print_and_return (PABC_JANSSON_FAIL);
  }
  for (size_t i = 0; i < public_parameters->nr_of_attributes; ++i)
  {
    pabc_status = json_append_array_bn_t (array, &proof->ProofSAttrs[i]);
    if (pabc_status != PABC_OK)
    {
      json_decref (array);
      json_decref (json_root);
      print_and_return (pabc_status);
    }
  }
  int r = json_object_set_new (json_root, PABC_JSON_SATTRS_KEY, array);
  if (r != 0)
  {
    json_decref (array);
    json_decref (json_root);
    print_and_return (pabc_status);
  }
  */

  // bn_t nonce
  // TODO could adapt to use pabc_{encode,decode}_nonce here
  pabc_status =
    json_add_obj_bn_t (json_root, &proof->nonce->nonce, PABC_JSON_NONCE_KEY);
  if (pabc_status != PABC_OK)
  {
    json_decref (json_root);
    print_and_return (pabc_status);
  }

  // g1_t Nym
  pabc_status = json_add_obj_g1_t (json_root, &proof->Nym, PABC_JSON_NYM_KEY);
  if (pabc_status != PABC_OK)
  {
    json_decref (json_root);
    print_and_return (pabc_status);
  }

  // DI
  json_t *json_DI = NULL;
  pabc_status = encode_attribute_prediactes_DI (ctx, public_parameters,
                                                proof->DI, &json_DI);
  if (pabc_status != PABC_OK)
  {
    json_decref (json_DI);
    json_decref (json_root);
    print_and_return (pabc_status);
  }

  r = json_object_set_new (json_root, PABC_JSON_DI_KEY, json_DI);
  if (r != 0)
  {
    json_decref (json_DI);
    json_decref (json_root);
    print_and_return (PABC_JANSSON_FAIL);
  }

  // dump
  char *s = json_dumps (json_root, JANSSON_ENC_FLAGS);
  if (s == NULL)
  {
    json_decref (json_root);
    print_and_return (PABC_JANSSON_FAIL);
  }
  *json = s;
  json_decref (json_root);

  return PABC_OK;
}


enum pabc_status
pabc_decode_proof (struct pabc_context const *const ctx,
                   struct pabc_public_parameters const *const public_parameters,
                   struct pabc_blinded_proof *const proof,
                   char const *const data)

{
  if (ctx == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (public_parameters == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (proof == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (data == NULL)
    print_and_return (PABC_UNINITIALIZED);

  json_error_t error;
  json_t *json = json_loads (data, JANSSON_DEC_FLAGS, &error);
  if (json == NULL)
  {
    // printf ("%s\n", error.text);
    print_and_return (PABC_JANSSON_FAIL);
  }

  // g1_t APrime
  enum pabc_status pabc_status = json_decode_g1_t (
    json_object_get (json, PABC_JSON_APRIME_KEY), &proof->APrime);
  if (pabc_status != PABC_OK)
  {
    json_decref (json);
    print_and_return (pabc_status);
  }

  // g1_t ABar
  pabc_status =
    json_decode_g1_t (json_object_get (json, PABC_JSON_ABAR_KEY), &proof->ABar);
  if (pabc_status != PABC_OK)
  {
    json_decref (json);
    print_and_return (pabc_status);
  }

  // g1_t BPrime
  pabc_status = json_decode_g1_t (json_object_get (json, PABC_JSON_BPRIME_KEY),
                                  &proof->BPrime);
  if (pabc_status != PABC_OK)
  {
    json_decref (json);
    print_and_return (pabc_status);
  }

  // bn_t ProofC
  pabc_status = json_decode_bn_t (json_object_get (json, PABC_JSON_PROOFC_KEY),
                                  &proof->ProofC);
  if (pabc_status != PABC_OK)
  {
    json_decref (json);
    print_and_return (pabc_status);
  }

  // bn_t ProofSSk
  pabc_status = json_decode_bn_t (json_object_get (json, PABC_JSON_SSK_KEY),
                                  &proof->ProofSSk);
  if (pabc_status != PABC_OK)
  {
    json_decref (json);
    print_and_return (pabc_status);
  }

  // bn_t ProofSE
  pabc_status = json_decode_bn_t (json_object_get (json, PABC_JSON_SE_KEY),
                                  &proof->ProofSE);
  if (pabc_status != PABC_OK)
  {
    json_decref (json);
    print_and_return (pabc_status);
  }

  // bn_t ProofSR2
  pabc_status = json_decode_bn_t (json_object_get (json, PABC_JSON_SR2_KEY),
                                  &proof->ProofSR2);
  if (pabc_status != PABC_OK)
  {
    json_decref (json);
    print_and_return (pabc_status);
  }

  // bn_t ProofSR3
  pabc_status = json_decode_bn_t (json_object_get (json, PABC_JSON_SR3_KEY),
                                  &proof->ProofSR3);
  if (pabc_status != PABC_OK)
  {
    json_decref (json);
    print_and_return (pabc_status);
  }

  // bn_t ProofSSPrime
  pabc_status = json_decode_bn_t (json_object_get (json, PABC_JSON_SSPRIME_KEY),
                                  &proof->ProofSSPrime);
  if (pabc_status != PABC_OK)
  {
    json_decref (json);
    print_and_return (pabc_status);
  }

  // bn_t *ProofSAttrs
  json_t *Attrs = json_object_get (json, PABC_JSON_SATTRS_KEY);
  if (Attrs == NULL)
  {
    json_decref (json);
    print_and_return (PABC_JANSSON_FAIL);
  }
  size_t index;
  char const *attr_name;
  json_t *value;
  json_object_foreach (Attrs, attr_name, value) {
    index = find_attribute_idx_by_name (ctx, public_parameters, attr_name);
    if (index > public_parameters->nr_of_attributes) // OOB
    {
      json_decref (json);
      print_and_return (PABC_OOB);
    }
    pabc_status = json_decode_bn_t (value, &proof->ProofSAttrs[index]);
    if (pabc_status != PABC_OK)
    {
      json_decref (json);
      print_and_return (pabc_status);
    }
  }

  // bn_t nonce
  // TODO could adapt to use pabc_{encode,decode}_nonce here
  pabc_status = json_decode_bn_t (json_object_get (json, PABC_JSON_NONCE_KEY),
                                  &proof->nonce->nonce);
  if (pabc_status != PABC_OK)
  {
    json_decref (json);
    print_and_return (pabc_status);
  }

  // g1_t Nym
  pabc_status =
    json_decode_g1_t (json_object_get (json, PABC_JSON_NYM_KEY), &proof->Nym);
  if (pabc_status != PABC_OK)
  {
    json_decref (json);
    print_and_return (pabc_status);
  }

  // DI
  pabc_status = decode_attribute_predicates_D_I (
    ctx, public_parameters, proof->DI,
    json_object_get (json, PABC_JSON_DI_KEY),
    json_object_get (json, PABC_JSON_SATTRS_KEY));
  if (pabc_status != PABC_OK)
  {
    json_decref (json);
    print_and_return (pabc_status);
  }

  json_decref (json);

  return PABC_OK;
}


enum pabc_status
encode_attribute_prediactes_DI (
  struct pabc_context const *const ctx,
  struct pabc_public_parameters const *const public_parameters,
  struct pabc_attribute_predicates_D_I *const DI, json_t **json_out)
{
  if (! ctx)
    print_and_return (PABC_UNINITIALIZED);
  if (! public_parameters)
    print_and_return (PABC_UNINITIALIZED);
  if (! DI)
    print_and_return (PABC_UNINITIALIZED);
  if (! json_out)
    print_and_return (PABC_UNINITIALIZED);

  int r;
  char *attr_name;
  char *attr_val;

  json_t *json_DI = json_object ();
  if (! json_DI)
    print_and_return (PABC_JANSSON_FAIL);

  for (size_t i = 0; i < public_parameters->nr_of_attributes; ++i)
  {
    // only include disclosed attributes
    if (DI->D[i] != PABC_DISCLOSED)
      continue;

    attr_name = public_parameters->attrs->attribute_names[i];
    if (! attr_name)
    {
      json_decref (json_DI);
      print_and_return (PABC_JANSSON_FAIL);
    }

    attr_val = DI->I[i];
    if (attr_val)
    {
      r = json_object_set_new (json_DI, attr_name, json_pack ("s", attr_val));
      if (r != 0)
      {
        json_decref (json_DI);
        print_and_return (PABC_FAILURE);
      }
    }
  }

  *json_out = json_DI;
  return PABC_OK;
}


enum pabc_status
decode_attribute_predicates_D_I (
  struct pabc_context const *const ctx,
  struct pabc_public_parameters const *const public_parameters,
  struct pabc_attribute_predicates_D_I *const DI, json_t *const json,
  json_t const *const json_sattrs)
{

  if (! ctx)
    print_and_return (PABC_UNINITIALIZED);
  if (! public_parameters)
    print_and_return (PABC_UNINITIALIZED);
  if (! DI)
    print_and_return (PABC_UNINITIALIZED);
  if (! json)
    print_and_return (PABC_UNINITIALIZED);
  if (! json_sattrs)
    print_and_return (PABC_UNINITIALIZED);

  enum pabc_status status;

  char const *attr_name;
  json_t *attr_val;

  for (size_t index = 0; index < public_parameters->nr_of_attributes; ++index)
  {
    attr_name = public_parameters->attrs->attribute_names[index];
    index = find_attribute_idx_by_name (ctx, public_parameters, attr_name);

    if (NULL != json_object_get (json_sattrs, attr_name))
      DI->D[index] = PABC_NOT_DISCLOSED;
    else
      DI->D[index] = PABC_DISCLOSED;

    attr_val = json_object_get (json, attr_name);
    if (! attr_val || json_is_null (attr_val))
      DI->I[index] = NULL;
    else
    {
      status = json_decode_str (attr_val, &DI->I[index]);
      if (status != PABC_OK)
      {
        for (size_t i = 0; i < public_parameters->nr_of_attributes; ++i)
          PABC_FREE_NULL (
            DI->I[i]);   // ok to do, as this sets to NULL -> no double free
        print_and_return (status);
      }
    }
  }
  return PABC_OK;
}


enum pabc_status
pabc_encode_nonce (struct pabc_context const *const ctx,
                   struct pabc_nonce *const nonce,
                   char **json)
{
  if (ctx == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (nonce == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (json == NULL)
    print_and_return (PABC_UNINITIALIZED);

  enum pabc_status pabc_status;

  json_t *json_root = json_object ();
  if (json == NULL)
    print_and_return (PABC_JANSSON_FAIL);

  // bn_t nonce
  pabc_status =
    json_add_obj_bn_t (json_root, &nonce->nonce, PABC_JSON_NONCE_KEY);
  if (pabc_status != PABC_OK)
  {
    json_decref (json_root);
    print_and_return (pabc_status);
  }

  // dump
  char *s = json_dumps (json_root, JANSSON_ENC_FLAGS);
  if (s == NULL)
  {
    json_decref (json_root);
    print_and_return (PABC_JANSSON_FAIL);
  }
  *json = s;
  json_decref (json_root);

  return PABC_OK;
}


enum pabc_status
pabc_decode_nonce (struct pabc_context const *const ctx,
                   struct pabc_nonce *const nonce,
                   const char *const data)
{
  if (ctx == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (nonce == NULL)
    print_and_return (PABC_UNINITIALIZED);
  if (data == NULL)
    print_and_return (PABC_UNINITIALIZED);

  enum pabc_status pabc_status;

  json_error_t error;
  json_t *json = json_loads (data, JANSSON_DEC_FLAGS, &error);
  if (json == NULL)
  {
    // printf ("%s\n", error.text);
    print_and_return (PABC_JANSSON_FAIL);
  }

  // bn_t ProofC
  pabc_status = json_decode_bn_t (json_object_get (json, PABC_JSON_NONCE_KEY),
                                  &nonce->nonce);
  if (pabc_status != PABC_OK)
  {
    json_decref (json);
    print_and_return (pabc_status);
  }

  json_decref (json);

  return PABC_OK;
}


enum pabc_status
json_encode_plain_attributes (
  struct pabc_context const *const ctx,
  struct pabc_public_parameters const *const pp, json_t **json_out,
  struct pabc_plain_attributes const *const attributes)
{
  if (! ctx)
    print_and_return (PABC_UNINITIALIZED);
  if (! pp)
    print_and_return (PABC_UNINITIALIZED);
  if (! json_out)
    print_and_return (PABC_UNINITIALIZED);
  if (! attributes)
    print_and_return (PABC_UNINITIALIZED);

  int r;
  char *attr_name = NULL;
  char *attr_val = NULL;
  json_t *json = json_object ();
  if (! json)
    print_and_return (PABC_JANSSON_FAIL);

  for (size_t i = 0; i < pp->nr_of_attributes; ++i)
  {
    attr_name = pp->attrs->attribute_names[i];
    if (! attr_name)
    {
      json_decref (json);
      print_and_return (PABC_FAILURE);
    }
    attr_val = attributes->attribute_values[i];
    if (! attr_val)
    {
      r = json_object_set_new (json, attr_name, json_null ());
    }
    else
    {
      r = json_object_set_new (json, attr_name, json_pack ("s", attr_val));
    }
    if (r != 0)
    {
      json_decref (json);
      print_and_return (PABC_JANSSON_FAIL);
    }
  }
  *json_out = json;
  return PABC_OK;
}


enum pabc_status
json_decode_plain_attributes (struct pabc_context const *const ctx,
                              struct pabc_public_parameters const *const pp,
                              json_t *const json,
                              struct pabc_plain_attributes *const target)
{
  // TODO: check attribute name matches expected attribute name at given
  // position in pp
  if (! ctx)
    print_and_return (PABC_UNINITIALIZED);
  if (! pp)
    print_and_return (PABC_UNINITIALIZED);
  if (! json)
    print_and_return (PABC_UNINITIALIZED);
  if (! target)
    print_and_return (PABC_UNINITIALIZED);

  size_t index;
  char const *attr_name;
  json_t *value;
  json_object_foreach (json, attr_name, value) {
    index = find_attribute_idx_by_name (ctx, pp, attr_name);
    if (index >= pp->nr_of_attributes) // OOB
    {
      for (size_t i = 0; i < pp->nr_of_attributes; ++i)
        PABC_FREE_NULL (target->attribute_values[i]);
      print_and_return (PABC_OOB);
    }

    if (json_is_null (value))
      target->attribute_values[index] = NULL;
    else
    {
      const char *str = json_string_value (value);
      if (str == NULL)
      {
        for (size_t i = 0; i < pp->nr_of_attributes; ++i)
          PABC_FREE_NULL (target->attribute_values[i]);
        print_and_return (PABC_OOM);
      }

      target->attribute_values[index] = strdup (str);
      if (! target->attribute_values[index])
      {
        for (size_t i = 0; i < pp->nr_of_attributes; ++i)
          PABC_FREE_NULL (target->attribute_values[i]);
        print_and_return (PABC_OOM);
      }
    }
  }

  return PABC_OK;
}
