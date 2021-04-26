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
  struct pabc_user_context *usr_ctx = NULL;
  struct pabc_public_parameters *public_parameters = NULL;
  struct pabc_credential *cred = NULL;
  struct pabc_blinded_proof *proof = NULL;

  int r;

  // general setup
  PABC_ASSERT (pabc_new_ctx (&ctx));

  // load public parametrs
  char *buffer;
  r = read_file ("./public_parameters.json", &buffer);
  if (r != 0)
  {
    printf ("Failed to read file.\n");
    exit (1);
  }
  PABC_ASSERT (
    pabc_decode_and_new_public_parameters (ctx, &public_parameters, buffer));
  PABC_FREE_NULL (buffer);

  // load credential
  r = read_file ("./credential.json", &buffer);
  if (r != 0)
  {
    printf ("Failed to read file.\n");
    exit (1);
  }
  PABC_ASSERT (pabc_new_credential (ctx, public_parameters, &cred));
  PABC_ASSERT (pabc_decode_credential (ctx, public_parameters, cred, buffer));
  PABC_FREE_NULL (buffer);

  // load user context
  r = read_file ("./user_context.json", &buffer);
  if (r != 0)
  {
    printf ("Failed to read file.\n");
    exit (1);
  }
  PABC_ASSERT (pabc_new_user_context (ctx, public_parameters, &usr_ctx));
  PABC_ASSERT (pabc_decode_user_ctx (ctx, public_parameters, usr_ctx, buffer));
  PABC_FREE_NULL (buffer);

  // generate proof
  PABC_ASSERT (pabc_new_proof (ctx, public_parameters, &proof));
  PABC_ASSERT (pabc_set_disclosure_by_attribute_name (
                 ctx, public_parameters, proof, "TEST1 name", PABC_DISCLOSED,
                 cred));
  PABC_ASSERT (pabc_set_disclosure_by_attribute_name (
                 ctx, public_parameters, proof, "TEST2 name", PABC_DISCLOSED,
                 cred));
  PABC_ASSERT (pabc_set_disclosure_by_attribute_name (
                 ctx, public_parameters, proof, "TEST3 name", PABC_DISCLOSED,
                 cred));
  PABC_ASSERT (pabc_set_disclosure_by_attribute_name (
                 ctx, public_parameters, proof, "TEST2 name",
                 PABC_NOT_DISCLOSED, cred));

  PABC_ASSERT (pabc_gen_proof (ctx, usr_ctx, public_parameters, proof, cred));

  // JSON proof
  char *json;
  PABC_ASSERT (pabc_encode_proof (ctx, public_parameters, proof, &json));
  printf ("Proof:\n%s\n", json);
  r = write_file ("./proof.json", json);
  if (r != 0)
    printf ("Failed to write file.\n");
  PABC_FREE_NULL (json);

  // clean up
  pabc_free_user_context (ctx, public_parameters, &usr_ctx);
  pabc_free_proof (ctx, public_parameters, &proof);
  pabc_free_credential (ctx, public_parameters, &cred);
  pabc_free_public_parameters (ctx, &public_parameters);
  pabc_free_ctx (&ctx);

  return 0;
}
