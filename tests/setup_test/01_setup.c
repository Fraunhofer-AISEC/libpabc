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
  printf ("Setting up issuer key pair...\n");

  struct pabc_context *ctx = NULL;
  struct pabc_issuer_secret_key *isk = NULL;
  struct pabc_public_parameters *public_parameters = NULL;

  enum pabc_status pabc_status;
  char *json;
  int r;

  // general setup
  PABC_ASSERT (pabc_new_ctx (&ctx));

  // issuer secret key
  PABC_ASSERT (pabc_new_issuer_secret_key (ctx, &isk));
  pabc_status = pabc_populate_issuer_secret_key (ctx, isk);
  if (pabc_status != PABC_OK)
    printf ("Failed to generate issuer secret key.\n");
  // store in json file
  pabc_status = pabc_encode_issuer_secret_key (ctx, isk, &json);
  if (pabc_status != PABC_OK)
    printf ("Failed to encode issuer secret key.\n");
  printf ("Issuer Secret Key:\n%s\n", json);
  r = write_file ("./issuer_secret_key.json", json);
  if (r != 0)
    printf ("Failed to write file\n");
  PABC_FREE_NULL (json);

  // issuer public key / public parameters
  struct pabc_attributes *attrs = NULL;
  pabc_new_attributes (ctx, &attrs);

  pabc_status = pabc_attributes_add (ctx, attrs, "TEST1 name");
  if (pabc_status != PABC_OK)
    printf ("Failed to append attribute.");
  pabc_status = pabc_attributes_add (ctx, attrs, "TEST2 name");
  if (pabc_status != PABC_OK)
    printf ("Failed to append attribute.");
  pabc_status = pabc_attributes_add (ctx, attrs, "TEST3 name");
  if (pabc_status != PABC_OK)
    printf ("Failed to append attribute.");

  PABC_ASSERT (pabc_new_public_parameters (ctx, attrs, &public_parameters));
  if (public_parameters == NULL)
    printf ("%s", "Failed to allocate public parameters.");

  pabc_status = pabc_populate_issuer_public_key (ctx, public_parameters, isk);
  if (pabc_status != PABC_OK)
    printf ("Failed to generate issuer public key.\n");
  // store in json file
  pabc_status = pabc_encode_public_parameters (ctx, public_parameters, &json);
  if (pabc_status != PABC_OK)
    printf ("Failed to encode public parameters.\n");
  printf ("public parameters:\n%s\n", json);
  r = write_file ("./public_parameters.json", json);
  if (r != 0)
    printf ("Failed to write file\n");
  PABC_FREE_NULL (json);

  // prepare a nonce
  struct pabc_nonce *nonce = NULL;
  pabc_new_nonce (ctx, &nonce);
  pabc_populate_nonce (ctx, nonce);
  // store in json file
  pabc_status = pabc_encode_nonce (ctx, nonce, &json);
  if (pabc_status != PABC_OK)
    printf ("Failed to encode nonce.\n");
  printf ("nonce:\n%s\n", json);
  r = write_file ("./issuer_nonce.json", json);
  if (r != 0)
    printf ("Failed to write file\n");
  PABC_FREE_NULL (json);

  // clean up
  pabc_free_nonce (ctx, &nonce);
  pabc_free_attributes (ctx, &attrs);
  pabc_free_issuer_secret_key (ctx, &isk);
  pabc_free_public_parameters (ctx, &public_parameters);
  pabc_free_ctx (&ctx);

  return 0;
}
