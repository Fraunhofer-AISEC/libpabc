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
  printf ("Verifying representation...\n");

  struct pabc_context *ctx = NULL;
  struct pabc_public_parameters *public_parameters = NULL;
  struct pabc_blinded_proof *proof = NULL;

  int r;

  // general setup
  PABC_ASSERT (pabc_new_ctx (&ctx));

  // load public parameters
  // obtain file size:
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

  // load proof
  r = read_file ("./proof.json", &buffer);
  if (r != 0)
  {
    printf ("Failed to read file.\n");
    exit (1);
  }
  PABC_ASSERT (pabc_new_proof (ctx, public_parameters, &proof));
  PABC_ASSERT (pabc_decode_proof (ctx, public_parameters, proof, buffer));
  PABC_FREE_NULL (buffer);

  enum pabc_status nonce_checked_by_caller =
    PABC_OK;   // The caller must verify the nonce (reply attacks).
  PABC_ASSERT (pabc_verify_blinded_proof_no_nonce (ctx, public_parameters,
                                                   proof,
                                                   nonce_checked_by_caller));

  // clean up
  pabc_free_proof (ctx, public_parameters, &proof);
  pabc_free_public_parameters (ctx, &public_parameters);
  pabc_free_ctx (&ctx);

  return 0;
}
