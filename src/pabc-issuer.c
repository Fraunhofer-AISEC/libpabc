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
 * List issuers flag
 */
static int list_issuers_flag = 0;

/**
 * List public parameters flag
 */
static int list_parameters_flag = 0;

/**
 * Create issuer flag
 */
static char *create_issuer = NULL;

/**
 * Create parameter flag
 */
static char *create_parameter = NULL;

/**
 * Attributes flag
 */
static char *attributes = NULL;

/**
 * Issuer select flag
 */
static char *issuer = NULL;

/**
 * Parameters set to use
 */
static char *pp_name = NULL;

/**
 * The nonce in JSON form
 */
static char *nonce_str = NULL;

/**
 * Issue request parameter
 */
static char *request = NULL;

/**
 * Create a nonce flag.
 */
static int create_nonce = 0;

/**
 * Create an export flag.
 */
static int export_pp_flag = 0;

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
  if (NULL != attributes)
    PABC_FREE_NULL (attributes);
  if (NULL != create_issuer)
    PABC_FREE_NULL (create_issuer);
  if (NULL != create_parameter)
    PABC_FREE_NULL (create_parameter);
  if (NULL != request)
    PABC_FREE_NULL (request);
  if (NULL != pp_name)
    PABC_FREE_NULL (pp_name);
  if (NULL != nonce_str)
    PABC_FREE_NULL (nonce_str);
  exit (ret);
}


static void
inspect_cr (char const *const attr_name, char const *const attr_val,
            void *inspect_ctx)
{
  (void) inspect_ctx;
  fprintf (stderr, "CR inspect: \"%s\" -> \"%s\"\n", attr_name, attr_val);
}


static void
print_help ()
{
  printf ("pabc-issuer -- (C) 2020 Fraunhofer AISEC\n\n");
  printf ("-h, --help                                   Print this help.\n");
  printf ("-v, --verbose                                Verbose mode.\n");
  printf ("-c, --create-issuer NAME                     Create a new "
          "issuer.\n");
  printf ("-C, --create-parameter PARAM                 Create a new parameter "
          "set.\n");
  printf ("-l, --list-issuer                            List available "
          "issuers.\n");
  printf ("-L, --list-parameters                        List available "
          "parameter sets.\n");
  printf ("-i, --issuer NAME                            Use issuer NAME.\n");
  printf ("-p, --params                                 Use parameters NAME."
          "\n");
  printf ("-a, --attributes A,B,C,...                   Speficies attributes "
          "for credential template. Use with `-C`\n");
  printf ("-s, --sign REQUEST                           Sign a credential "
          "request with issuer specified with `-i`\n");
  printf ("-n, --expected-nonce JSON                    The expected nonce.\n");
  printf ("-y, --get-nonce                              Get a random nocne.\n");
  printf ("-e, --export                                 Export public "
          "parameters. USe with `p`.\n");
}


static void
sign_credential ()
{
  struct pabc_issuer_secret_key *isk = NULL;
  struct pabc_public_parameters *pp = NULL;
  struct pabc_credential_request *cr = NULL;
  struct pabc_credential *cred = NULL;
  struct pabc_nonce *nonce = NULL;

  enum pabc_status status;

  status = pabc_cred_inspect_cred_request (request, &inspect_cr, NULL);
  if (status != PABC_OK)
  {
    fprintf (stderr, "Failed to inspect cr.\n");
    ret = 1;
    shutdown ();
  }

  status = load_public_parameters (ctx, pp_name, &pp);
  if (status != PABC_OK)
  {
    fprintf (stderr, "Failed to read public parameters.\n");
    ret = 1;
    shutdown ();
  }

  // load stuff: isk
  if (PABC_OK != read_issuer_secret_key (issuer, &isk))
  {
    fprintf (stderr, "Unable to read secret key of `%s'\n", issuer);
    pabc_free_public_parameters (ctx, &pp);
    ret = 1;
    shutdown ();
  }

  // load stuff: cr
  status = pabc_new_credential_request (ctx, pp, &cr);
  if (PABC_OK != status)
  {
    fprintf (stderr, "Failed to allocate cr.\n");
    pabc_free_issuer_secret_key (ctx, &isk);
    pabc_free_public_parameters (ctx, &pp);
    ret = 1;
    shutdown ();
  }

  char *user_id = NULL;
  char *pp_id = NULL;
  status = pabc_cred_get_userid_from_cr (request, &user_id);
  if (status != PABC_OK)
  {
    fprintf (stderr, "Failed to read cr.\n");
    pabc_free_issuer_secret_key (ctx, &isk);
    pabc_free_public_parameters (ctx, &pp);
    ret = 1;
    shutdown ();
  }

  status = pabc_cred_get_ppid_from_cr (request, &pp_id);
  if (status != PABC_OK)
  {
    fprintf (stderr, "Failed to read cr.\n");
    PABC_FREE_NULL (user_id);
    pabc_free_issuer_secret_key (ctx, &isk);
    pabc_free_public_parameters (ctx, &pp);
    ret = 1;
    shutdown ();
  }

  fprintf (stderr,
           "Parsing cr request with public parameters id: \"%s\" und user id: "
           "\"%s\".\n",
           pp_id, user_id);

  status = pabc_decode_credential_request (ctx, pp, cr, request);
  if (status != PABC_OK)
  {
    fprintf (stderr, "Failed to decode cr.\n");
    PABC_FREE_NULL (user_id);
    PABC_FREE_NULL (pp_id);
    pabc_free_credential_request (ctx, pp, &cr);
    pabc_free_issuer_secret_key (ctx, &isk);
    pabc_free_public_parameters (ctx, &pp);
    ret = 1;
    shutdown ();
  }

  // load stuff: nonce
  status = pabc_new_nonce (ctx, &nonce);
  if (status != PABC_OK)
  {
    fprintf (stderr, "Failed to allocate nonce.\n");
    PABC_FREE_NULL (user_id);
    PABC_FREE_NULL (pp_id);
    pabc_free_credential_request (ctx, pp, &cr);
    pabc_free_issuer_secret_key (ctx, &isk);
    pabc_free_public_parameters (ctx, &pp);
    ret = 1;
    shutdown ();
  }
  status = pabc_decode_nonce (ctx, nonce, nonce_str);
  if (status != PABC_OK)
  {
    fprintf (stderr, "Failed to decode nonce.\n");
    PABC_FREE_NULL (user_id);
    PABC_FREE_NULL (pp_id);
    pabc_free_nonce (ctx, &nonce);
    pabc_free_credential_request (ctx, pp, &cr);
    pabc_free_issuer_secret_key (ctx, &isk);
    pabc_free_public_parameters (ctx, &pp);
    ret = 1;
    shutdown ();
  }

  // sign credential
  status = pabc_new_credential (ctx, pp, &cred);
  if (status != PABC_OK)
  {
    fprintf (stderr, "Failed to allocate credential.\n");
    PABC_FREE_NULL (user_id);
    PABC_FREE_NULL (pp_id);
    pabc_free_nonce (ctx, &nonce);
    pabc_free_credential_request (ctx, pp, &cr);
    pabc_free_issuer_secret_key (ctx, &isk);
    pabc_free_public_parameters (ctx, &pp);
    ret = 1;
    shutdown ();
  }

  // status = pabc_compare_nonce(); TODO
  status = pabc_issuer_credential_sign (ctx, pp, cr, cred, nonce, isk);
  if (status != PABC_OK)
  {
    fprintf (stderr, "Failed to sign credential.\n");
    PABC_FREE_NULL (user_id);
    PABC_FREE_NULL (pp_id);
    pabc_free_nonce (ctx, &nonce);
    pabc_free_credential_request (ctx, pp, &cr);
    pabc_free_issuer_secret_key (ctx, &isk);
    pabc_free_public_parameters (ctx, &pp);
    ret = 1;
    shutdown ();
  }

  // print credential
  char *json = NULL;
  status = pabc_cred_encode_cred (ctx, pp, cred, user_id, pp_id, &json);
  if (status != PABC_OK)
  {
    fprintf (stderr, "Failed to encode credential.\n");
    PABC_FREE_NULL (user_id);
    PABC_FREE_NULL (pp_id);
    pabc_free_nonce (ctx, &nonce);
    pabc_free_credential_request (ctx, pp, &cr);
    pabc_free_issuer_secret_key (ctx, &isk);
    pabc_free_public_parameters (ctx, &pp);
    ret = 1;
    shutdown ();
  }
  PABC_FREE_NULL (user_id);
  PABC_FREE_NULL (pp_id);
  printf ("%s\n", json);

  PABC_FREE_NULL (json);

  // clean up
  pabc_free_nonce (ctx, &nonce);
  pabc_free_credential (ctx, pp, &cred);
  pabc_free_credential_request (ctx, pp, &cr);
  pabc_free_issuer_secret_key (ctx, &isk);
  pabc_free_public_parameters (ctx, &pp);
}


static void
add_issuer ()
{
  if (verbose)
    printf ("Setting up issuer key pair...\n");

  struct pabc_issuer_secret_key *isk = NULL;

  enum pabc_status pabc_status;

  // issuer secret key
  PABC_ASSERT (pabc_new_issuer_secret_key (ctx, &isk));
  pabc_status = pabc_populate_issuer_secret_key (ctx, isk);
  if (pabc_status != PABC_OK)
  {
    fprintf (stderr, "Failed to generate issuer secret key.\n");
    pabc_free_issuer_secret_key (ctx, &isk);
    return;
  }
  PABC_ASSERT (write_issuer_key (create_issuer, isk));
  pabc_free_issuer_secret_key (ctx, &isk);
}


static void
add_pp ()
{
  struct pabc_issuer_secret_key *isk = NULL;
  struct pabc_public_parameters *public_parameters = NULL;
  struct pabc_attributes *pabc_attrs = NULL;
  enum pabc_status pabc_status;
  char *tmp;
  char *attrs;

  // general setup
  PABC_ASSERT (pabc_new_attributes (ctx, &pabc_attrs));

  if (PABC_OK != read_issuer_secret_key (issuer, &isk))
  {
    fprintf (stderr, "Unable to read secret key of `%s'\n", issuer);
    ret = 1;
    shutdown ();
  }

  // issuer public key / public parameters
  // FIXME this API is not ideal. Should be hidde from caller.
  attrs = strdup (attributes);
  tmp = strtok (attrs, ",");
  while (NULL != tmp)
  {
    pabc_attributes_add (ctx, pabc_attrs, tmp);
    tmp = strtok (NULL, ",");
  }
  PABC_FREE_NULL (attrs);
  PABC_ASSERT (pabc_new_public_parameters (ctx, pabc_attrs,
                                           &public_parameters));
  pabc_status = pabc_populate_issuer_public_key (ctx, public_parameters, isk);
  if (pabc_status != PABC_OK)
  {
    fprintf (stderr, "Failed to generate credential.\n");
    pabc_free_issuer_secret_key (ctx, &isk);
    pabc_free_public_parameters (ctx, &public_parameters);
    ret = 1;
    shutdown ();
  }
  write_public_parameters (create_parameter, public_parameters, issuer);

  // clean up
  pabc_free_attributes (ctx, &pabc_attrs);
  pabc_free_issuer_secret_key (ctx, &isk);
  pabc_free_public_parameters (ctx, &public_parameters);
}


static void
get_nonce ()
{
  struct pabc_nonce *nonce = NULL;
  enum pabc_status status;

  status = pabc_new_nonce (ctx, &nonce);
  if (status != PABC_OK)
  {
    fprintf (stderr, "Failed to allocate nonce.\n");
    ret = 1;
    shutdown ();
  }
  pabc_populate_nonce (ctx, nonce);
  if (status != PABC_OK)
  {
    fprintf (stderr, "Failed to generate nonce.\n");
    pabc_free_nonce (ctx, &nonce);
    ret = 1;
    shutdown ();
  }
  char *json = NULL;
  status = pabc_encode_nonce (ctx, nonce, &json);
  if (status != PABC_OK)
  {
    fprintf (stderr, "Failed to encode nonce.\n");
    pabc_free_nonce (ctx, &nonce);
    ret = 1;
    shutdown ();
  }
  printf ("%s\n", json);
  PABC_FREE_NULL (json);
  pabc_free_nonce (ctx, &nonce);
}


static void
export_public_params ()
{
  enum pabc_status status;
  char *json = NULL;
  status = export_pp (pp_name, &json);
  if (status != PABC_OK)
  {
    fprintf (stderr, "Failed to read json.\n");
    ret = 1;
    shutdown ();
  }
  printf ("%s\n", json);
  PABC_FREE_NULL (json);
}


int
main (int argc, char **argv)
{
  int c;

  while (1)
  {
    static struct option long_options[] = {
      {"help", no_argument, 0, 'h'},
      {"verbose", no_argument, 0, 'v'},
      {"list-issuers", no_argument, 0, 'l'},
      {"list-parameters", no_argument, 0, 'L'},
      /* These options don’t set a flag.
         We distinguish them by their indices. */
      {"create-issuer", required_argument, 0, 'c'},
      {"create-parameters", required_argument, 0, 'C'},
      {"attributes", required_argument, 0, 'a'},
      {"issuer", required_argument, 0, 'i'},
      {"params", required_argument, 0, 'p'},
      {"sign", required_argument, 0, 's'},
      {"expected-nonce", required_argument, 0, 'n'},
      {"get-nonce", no_argument, 0, 'y'},
      {"export", no_argument, 0, 'e'},
      {0, 0, 0, 0}
    };
    /* getopt_long stores the option index here. */
    int option_index = 0;

    c = getopt_long (argc, argv, "i:p:c:C:s:a:lLhvn:ye", long_options,
                     &option_index);

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
    case 'l':
      list_issuers_flag = 1;
      break;
    case 'L':
      list_parameters_flag = 1;
      break;
    case 'c':
      create_issuer = strdup (optarg);
      break;
    case 'i':
      issuer = strdup (optarg);
      break;
    case 'p':
      if (optarg)
        pp_name = strdup (optarg);
      else
        abort ();
      break;

    case 'C':
      create_parameter = strdup (optarg);
      break;
    case 'a':
      attributes = strdup (optarg);
      break;

    case 's':
      request = strdup (optarg);
      break;

    case 'h':
      print_help ();
      shutdown ();
    case 'v':
      verbose = 1;
      break;
    case 'n':
      if (optarg)
        nonce_str = strdup (optarg);
      else
        abort ();
      break;
    case 'y':
      create_nonce = 1;
      break;
    case 'e':
      export_pp_flag = 1;
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

  PABC_ASSERT (pabc_new_ctx (&ctx));

  if (NULL != create_issuer)
  {
    add_issuer ();
    shutdown ();
  }

  if (list_issuers_flag)
  {
    list_issuer ();
    shutdown ();
  }
  if (list_parameters_flag)
  {
    list_parameters ();
    shutdown ();
  }

  if (NULL != create_parameter)
  {
    if (NULL == issuer)
    {
      fprintf (stderr, "No issuer given\n");
      ret = 1;
      shutdown ();
    }
    if (NULL == attributes)
    {
      fprintf (stderr, "No attributes given\n");
      ret = 1;
      shutdown ();
    }
    add_pp ();
    shutdown ();
  }

  if (NULL != request)
  {
    if (NULL == issuer)
    {
      fprintf (stderr, "No issuer given\n");
      ret = 1;
      shutdown ();
    }
    if (NULL == pp_name)
    {
      fprintf (stderr, "No parameters set given\n");
      ret = 1;
      shutdown ();
    }
    if (NULL == nonce_str)
    {
      fprintf (stderr, "No nonce given\n");
      ret = 1;
      shutdown ();
    }

    sign_credential ();
    shutdown ();
  }

  if (create_nonce == 1)
  {
    get_nonce ();
    shutdown ();
  }

  if (export_pp_flag == 1)
  {
    if (! pp_name)
    {
      fprintf (stderr, "No public parameters given\n");
      ret = 1;
      shutdown ();
    }
    export_public_params ();
    shutdown ();
  }

  shutdown ();
}
