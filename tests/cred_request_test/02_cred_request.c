/**
 * Copyright (c) 2021 Fraunhofer AISEC
 *
 * SPDX-License-Identifier: Apache-2.0
 **/





#include "../../src/cli_helper.h"
#include <pabc/pabc.h>
#include <stdio.h>
#include <stdlib.h>

int
main ()
{
  printf ("Generating credential request...\n");

  struct pabc_context *ctx = NULL;
  struct pabc_public_parameters *public_parameters = NULL;
  struct pabc_credential_request *cr = NULL;
  struct pabc_user_context *usr_ctx = NULL;

  int r;

  // general setup
  PABC_ASSERT (pabc_new_ctx (&ctx));

  // load public parametrs
  char *buffer;
  r = read_file ("./public_parameters.json", &buffer);
  if (r != 0)
  {
    printf ("Failed to read public parameters file.\n");
    exit (1);
  }
  PABC_ASSERT (
    pabc_decode_and_new_public_parameters (ctx, &public_parameters, buffer));
  PABC_FREE_NULL (buffer);

  // populate a user context
  PABC_ASSERT (pabc_new_user_context (ctx, public_parameters, &usr_ctx));
  PABC_ASSERT (pabc_populate_user_context (ctx, usr_ctx));
  PABC_ASSERT (pabc_set_attribute_value_by_name (ctx, public_parameters,
                                                 usr_ctx,
                                                 "TEST1 name", "TEST1 value"));
  PABC_ASSERT (pabc_set_attribute_value_by_name (ctx, public_parameters,
                                                 usr_ctx,
                                                 "TEST2 name", "TEST2 value"));
  PABC_ASSERT (pabc_set_attribute_value_by_name (ctx, public_parameters,
                                                 usr_ctx,
                                                 "TEST3 name", "TEST3 value"));

  // JSON user_context
  char *json;
  PABC_ASSERT (pabc_encode_user_ctx (ctx, public_parameters, usr_ctx, &json));
  printf ("User context:\n%s\n", json);
  r = write_file ("./user_context.json", json);
  if (r != 0)
    printf ("Failed to write user context file.\n");
  PABC_FREE_NULL (json);

  // read issuer nonce
  struct pabc_nonce *nonce = NULL;
  PABC_ASSERT (pabc_new_nonce (ctx, &nonce));
  r = read_file ("./issuer_nonce.json", &buffer);
  if (r != 0)
  {
    printf ("Failed to read issuer nonce file.\n");
    exit (1);
  }
  PABC_ASSERT (pabc_decode_nonce (ctx, nonce, buffer));
  PABC_FREE_NULL (buffer);

  // populate a credential request
  PABC_ASSERT (pabc_new_credential_request (ctx, public_parameters, &cr));
  PABC_ASSERT (
    pabc_gen_credential_request (ctx, public_parameters, usr_ctx, nonce, cr));

  // JSON credential request
  PABC_ASSERT (
    pabc_encode_credential_request (ctx, public_parameters, cr, &json));
  printf ("Credential request:\n%s\n", json);
  r = write_file ("./credential_request.json", json);
  if (r != 0)
    printf ("Failed to write credential request file.\n");
  PABC_FREE_NULL (json);

  // clean up
  pabc_free_nonce (ctx, &nonce);
  pabc_free_credential_request (ctx, public_parameters, &cr);
  pabc_free_user_context (ctx, public_parameters, &usr_ctx);
  pabc_free_public_parameters (ctx, &public_parameters);
  pabc_free_ctx (&ctx);

  return 0;
}
