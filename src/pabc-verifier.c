/**
 * Copyright (c) 2021 Fraunhofer AISEC
 *
 * SPDX-License-Identifier: Apache-2.0
 **/

#include "cli_helper.h"
#include <getopt.h>
#include <pabc/pabc.h>
#include <stdio.h>
#include <stdlib.h>

/**
 * List parameters flag
 */
static int list_params_flag = 0;

/**
 * Import public parameters.
 */
static char *import_pp_str = NULL;

/**
 * Issuer select flag
 */
static char *issuer = NULL;

/**
 * Attribute key/value pair
 */
static char *check_string = NULL;

/**
 * The parameter set to use
 */
static char *pp_name = NULL;

/**
 * Verbose flag
 */
static int verbose = 0;

/**
 * Return code
 */
static int ret;

/**
 * Gloabl context
 */
static struct pabc_context *ctx = NULL;

_Noreturn static void
shutdown ()
{
  if (NULL != ctx)
    pabc_free_ctx (&ctx);
  if (NULL != issuer)
    PABC_FREE_NULL (issuer);
  if (NULL != check_string)
    PABC_FREE_NULL (check_string);
  if (NULL != pp_name)
    PABC_FREE_NULL (pp_name);
  if (NULL != import_pp_str)
    PABC_FREE_NULL (import_pp_str);
  exit (ret);
}


static void
print_help ()
{
  printf ("pabc-verifier -- (C) 2020 Fraunhofer AISEC\n\n");
  printf ("-h, --help                                   Print this help.\n");
  printf ("-v, --verbose                                Verbose mode.\n");
  printf ("-L, --list-parameters                        List available "
          "parameter sets. Use with `-i`\n");
  printf ("-p, --params                                 The parameters set to "
          "use.\n");
  printf ("-c, --check CREDENTIAL                       Verifiy the provided "
          "credential. The credential's key/value pairs will be printed to "
          "stdout. Use with `-i`, `-p`.\n");
  printf ("-I, --import-params JSON_PP                  Import public "
          "parameters. Use with `-p`.\n");
}


static void
inspect_proof (char const *const attr_name,
               char const *const attr_val, void *inspect_ctx)
{
  (void) inspect_ctx;
  fprintf (stderr, "Proof inspect: \"%s\" -> \"%s\"\n", attr_name, attr_val);
}


static void
check_str ()
{
  struct pabc_public_parameters *pp = NULL;
  struct pabc_blinded_proof *proof = NULL;

  enum pabc_status status;

  status = pabc_cred_inspect_proof (check_string, &inspect_proof, NULL);
  if (status != PABC_OK)
  {
    fprintf (stderr, "Failed to inspect proof.\n");
    ret = 1;
    shutdown ();
  }

  { // print meta inforomation
    char *pp_id = NULL;
    char *user_id = NULL;
    status = pabc_cred_get_ppid_from_proof (check_string, &pp_id);
    if (status != PABC_OK)
    {
      fprintf (stderr, "Failed to parse proof.\n");
      ret = 1;
      shutdown ();
    }
    status = pabc_cred_get_userid_from_proof (check_string, &user_id);
    if (status != PABC_OK)
    {
      fprintf (stderr, "Failed to parse proof.\n");
      ret = 1;
      PABC_FREE_NULL (pp_id);
      shutdown ();
    }
    fprintf (stderr,
             "Parsing proof with public params id: \"%s\" and user id \"%s\".\n",
             pp_id, user_id);
    PABC_FREE_NULL (pp_id);
    PABC_FREE_NULL (user_id);
  }

  // load stuff
  status = load_public_parameters (ctx, pp_name, &pp);
  if (status != PABC_OK)
  {
    fprintf (stderr, "Failed to read public parameters.\n");
    ret = 1;
    shutdown ();
  }

  // proof
  status = pabc_new_proof (ctx, pp, &proof);
  if (PABC_OK != status)
  {
    fprintf (stderr, "Failed to allocate proof.\n");
    pabc_free_public_parameters (ctx, &pp);
    ret = 1;
    shutdown ();
  }
  status = pabc_decode_proof (ctx, pp, proof, check_string);
  if (PABC_OK != status)
  {
    fprintf (stderr, "Failed to decode proof.\n");
    pabc_free_proof (ctx, pp, &proof);
    pabc_free_public_parameters (ctx, &pp);
    ret = 1;
    shutdown ();
  }

  // verify proof
  // TODO FIXME check nonce
  if (PABC_OK != pabc_verify_blinded_proof_no_nonce (ctx, pp, proof, PABC_OK))
  {
    fprintf (stderr, "Failed to verify blinded proof.\n");
    ret = 1;
    pabc_free_proof (ctx, pp, &proof);
    pabc_free_public_parameters (ctx, &pp);
    shutdown ();
  }

  // print proof
  printf ("Proof verified.\n");

  // clean up
  pabc_free_proof (ctx, pp, &proof);
  pabc_free_public_parameters (ctx, &pp);
}


static void
import_public_params ()
{
  enum pabc_status status;
  status = import_pp (pp_name, import_pp_str);
  if (status != PABC_OK)
  {
    fprintf (stderr, "Failed to import public parameters.\n");
    ret = 1;
    shutdown ();
  }
}


int
main (int argc, char **argv)
{
  int c;

  PABC_ASSERT (pabc_new_ctx (&ctx));

  while (1)
  {
    static struct option long_options[] = {
      {"help", no_argument, 0, 'h'},
      {"verbose", no_argument, 0, 'v'},
      {"list-parameters", no_argument, 0, 'L'},
      {"params", required_argument, 0, 'p'},
      {"check", required_argument, 0, 'c'},
      {"import-params", required_argument, 0, 'I'},
      {0, 0, 0, 0}
    };
    /* getopt_long stores the option index here. */
    int option_index = 0;

    c = getopt_long (argc, argv, "hvLp:c:I:", long_options, &option_index);

    /* Detect the end of the options. */
    if (c == -1)
      break;

    switch (c)
    {
    case 0:
      /* If this option set a flag, do nothing else now. */
      if (long_options[option_index].flag != 0)
        break;
      printf ("option %s", long_options[option_index].name);
      if (optarg)
        printf (" with arg %s", optarg);
      printf ("\n");
      break;
    case 'h':
      print_help ();
      shutdown ();
    case 'v':
      verbose = 1;
      break;
    case 'L':
      list_params_flag = 1;
      break;
    case 'p':
      if (optarg)
        pp_name = strdup (optarg);
      else
        abort ();
      break;
    case 'c':
      if (optarg)
        check_string = strdup (optarg);
      else
        abort ();
      break;
    case 'I':
      if (optarg)
        import_pp_str = strdup (optarg);
      else
        abort ();
      break;

    case '?':
      /* getopt_long already printed an error message. */
      print_help ();
      ret = 1;
      shutdown ();

    default:
      abort ();
    }
  }

  if (list_params_flag)
  {
    list_parameters ();
    shutdown ();
  }

  if (NULL != check_string)
  {
    if (NULL == pp_name)
    {
      fprintf (stderr, "No parameters name given\n");
      ret = 1;
      shutdown ();
    }

    check_str ();
    shutdown ();
  }

  if (import_pp_str)
  {
    if (! pp_name)
    {
      fprintf (stderr, "No parameters set given\n");
      ret = 1;
      shutdown ();
    }

    import_public_params ();
    shutdown ();
  }

  shutdown ();
}
