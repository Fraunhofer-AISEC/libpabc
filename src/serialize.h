/**
 * Copyright (c) 2021 Fraunhofer AISEC
 *
 * SPDX-License-Identifier: Apache-2.0
 **/

// using the relic library https://github.com/relic-toolkit/

#ifndef SERIALIZE_H
#define SERIALIZE_H

#include "attributes.h"
#include "credential.h"
#include "pabc/pabc_json_constants.h"
#include "pabc/pabc_serialize.h"
#include "user.h"
#include "utils.h"
#include <b64/cdecode.h>
#include <b64/cencode.h>
#include <jansson.h>
#include <limits.h>
#include <relic.h>

enum pabc_status json_add_obj_bn_t (json_t *const json, bn_t *const payload,
                                    char const *const name);

enum pabc_status json_add_obj_g1_t (json_t *const json, g1_t *const payload,
                                    char const *const name);

enum pabc_status json_add_obj_g2_t (json_t *const json, g2_t *const payload,
                                    char const *const name);

enum pabc_status json_append_array_g1_t (json_t *const json,
                                         g1_t *const payload);

enum pabc_status json_append_array_bn_t (json_t *const json,
                                         bn_t *const payload);

enum pabc_status json_append_array_str (json_t *const json,
                                        char const *const payload);

enum pabc_status
encode_issuer_public_key (struct pabc_context const *const ctx,
                          struct pabc_public_parameters *const
                          public_parameters,
                          json_t **json);

enum pabc_status
decode_issuer_public_key (struct pabc_context const *const ctx,
                          struct pabc_public_parameters *const
                          public_parameters,
                          json_t *const json);

enum pabc_status encode_attribute_prediactes_DI (
  struct pabc_context const *const ctx,
  struct pabc_public_parameters const *const public_parameters,
  struct pabc_attribute_predicates_D_I *const DI, json_t **json_out);

enum pabc_status decode_attribute_predicates_D_I (
  struct pabc_context const *const ctx,
  struct pabc_public_parameters const *const public_parameters,
  struct pabc_attribute_predicates_D_I *const DI, json_t *const json,
  json_t const *const json_sattrs);

enum pabc_status json_decode_bn_t (json_t *const json, bn_t *target);

enum pabc_status json_decode_g1_t (json_t *const json, g1_t *target);

enum pabc_status json_decode_g2_t (json_t *const json, g2_t *target);

enum pabc_status json_decode_str (json_t *const json, char **target);

enum pabc_status json_encode_plain_attributes (
  struct pabc_context const *const ctx,
  struct pabc_public_parameters const *const pp, json_t **json,
  struct pabc_plain_attributes const *const attributes);

enum pabc_status
json_decode_plain_attributes (struct pabc_context const *const ctx,
                              struct pabc_public_parameters const *const pp,
                              json_t *const json,
                              struct pabc_plain_attributes *const target);

#endif // SERIALIZE_H
