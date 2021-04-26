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
  printf ("Granting credential request...\n");

  struct pabc_context *ctx = NULL;
  struct pabc_public_parameters *public_parameters = NULL;
  struct pabc_credential_request *cr = NULL;
  struct pabc_issuer_secret_key *isk = NULL;
  struct pabc_credential *cred = NULL;

  int r;

  // general setup
  PABC_ASSERT (pabc_new_ctx (&ctx));

  // load public parametrs
  char *buffer;
  r = read_file ("./public_parameters.json", &buffer);
  if (r != 0)
  {
    printf ("Failed to read public_parameters file.\n");
    exit (1);
  }
  PABC_ASSERT (
    pabc_decode_and_new_public_parameters (ctx, &public_parameters, buffer));
  PABC_FREE_NULL (buffer);

  // load credential request
  r = read_file ("./credential_request.json", &buffer);
  if (r != 0)
  {
    printf ("Failed to read credential request file.\n");
    exit (1);
  }
  PABC_ASSERT (pabc_new_credential_request (ctx, public_parameters, &cr));
  PABC_ASSERT (
    pabc_decode_credential_request (ctx, public_parameters, cr, buffer));
  PABC_FREE_NULL (buffer);

  // load issuer secret key
  r = read_file ("./issuer_secret_key.json", &buffer);
  if (r != 0)
  {
    printf ("Failed to read isk file.\n");
    exit (1);
  }
  PABC_ASSERT (pabc_new_issuer_secret_key (ctx, &isk));
  PABC_ASSERT (pabc_decode_issuer_secret_key (ctx, isk, buffer));
  PABC_FREE_NULL (buffer);

  // read issuer nonce
  struct pabc_nonce *nonce = NULL;
  pabc_new_nonce (ctx, &nonce);
  r = read_file ("./issuer_nonce.json", &buffer);
  if (r != 0)
  {
    printf ("Failed to read nonce file.\n");
    exit (1);
  }
  PABC_ASSERT (pabc_decode_nonce (ctx, nonce, buffer));
  PABC_FREE_NULL (buffer);

  // issue credential
  PABC_ASSERT (pabc_new_credential (ctx, public_parameters, &cred));
  PABC_ASSERT (pabc_issuer_credential_sign (ctx, public_parameters, cr, cred,
                                            nonce, isk));

  // JSON credential
  char *json;
  PABC_ASSERT (pabc_encode_credential (ctx, public_parameters, cred, &json));
  printf ("Credential:\n%s\n", json);
  r = write_file ("./credential.json", json);
  if (r != 0)
    printf ("Failed to write credential file.\n");
  PABC_FREE_NULL (json);

  // clean up
  pabc_free_nonce (ctx, &nonce);
  pabc_free_credential_request (ctx, public_parameters, &cr);
  pabc_free_credential (ctx, public_parameters, &cred);
  pabc_free_public_parameters (ctx, &public_parameters);
  pabc_free_issuer_secret_key (ctx, &isk);
  pabc_free_ctx (&ctx);

  return 0;
}
