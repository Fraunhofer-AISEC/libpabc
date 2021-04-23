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
 * List credentials flag
 */
static int list_users_flag = 0;

/**
 * Create issuer flag
 */
static char *create_issuer = NULL;

/**
 * Selected parameter set
 */
static char *pp_name = NULL;

/**
 * Create credential request
 */
static char *create_cr = NULL;

/**
 * Create credential request
 */
static char *create_usr = NULL;

/**
 * A signed credential
 */
static char *signed_cred = NULL;

/**
 * User name to use
 */
static char *usr_name = NULL;

/**
 * Attributes flag
 */
static char *attributes = NULL;

/**
 * Issue request parameter
 */
static char *request = NULL;

/**
 * Attribute key/value pair
 */
static char *set_attr = NULL;

/**
 * Attributes to be disclosed
 */
static char *attrs_discl = NULL;

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
  if (NULL != attributes)
    PABC_FREE_NULL (attributes);
  if (NULL != create_issuer)
    PABC_FREE_NULL (create_issuer);
  if (NULL != request)
    PABC_FREE_NULL (request);
  if (NULL != create_usr)
    PABC_FREE_NULL (create_usr);
  if (NULL != set_attr)
    PABC_FREE_NULL (set_attr);
  if (NULL != usr_name)
    PABC_FREE_NULL (usr_name);
  if (NULL != create_cr)
    PABC_FREE_NULL (create_cr);
  if (NULL != attrs_discl)
    PABC_FREE_NULL (attrs_discl);
  if (NULL != pp_name)
    PABC_FREE_NULL (pp_name);
  if (NULL != signed_cred)
    PABC_FREE_NULL (signed_cred);
  if (NULL != import_pp_str)
    PABC_FREE_NULL (import_pp_str);
  exit (ret);
}


static void
print_help ()
{
  // TODO update text
  printf ("pabc-user -- (C) 2020 Fraunhofer AISEC\n\n");
  printf ("-h, --help                                   Print this help.\n");
  printf ("-v, --verbose                                Verbose mode.\n");
  printf ("-u, --user NAME                              Use user NAME.\n");
  printf ("-i, --issuer NAME                            Use issuer NAME.\n");
  printf ("-p, --params NAME                            Use parameters NAME."
          "\n");
  printf ("-L, --list-parameters                        List available "
          "parameter sets.\n");
  printf ("-q, --list-user                              List available "
          "users.\n");
  printf ("-r, --create-cr JSON_NONCE                   Create a CR. "
          "Use with `-p` and `-u`.\n");
  printf ("-c, --create-user NAME                       Create a new user. Use "
          "with `p`.\n");
  printf ("-d, --disclose ATTRS                         Create a blinded proof "
          "with attributes ATTRS (comma separated) disclosed. Use with `-p` and "
          "`u` "
          "and `x`.\n");
  printf ("-s, --set-attr K=V                           Sets attribute K to "
          "value V. Use with `-p` and `-u`.\n");
  printf ("-d, --reveal-attrs \"Attr1,Attr2,...\"       Reveal/disclose these "
          "attributes. Use with `-p`, `-u` and `-x`.\n");
  printf ("-x, --signed-cred JSON_CRED                  A signed credential "
          "use with `-d`.\n");
  printf ("-I, --import-params JSON_PP                  Import public "
          "parameters. Use with `-p`.\n");
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
    pabc_free_ctx (&ctx);
    return;
  }
  PABC_ASSERT (write_issuer_key (create_issuer, isk));
  pabc_free_issuer_secret_key (ctx, &isk);
}


static void
add_user ()
{
  struct pabc_public_parameters *pp = NULL;
  struct pabc_user_context *usr_ctx = NULL;
  enum pabc_status status;

  status = load_public_parameters (ctx, pp_name, &pp);
  if (status != PABC_OK)
  {
    fprintf (stderr, "Failed to read public parameters.\n");
    ret = 1;
    shutdown ();
  }

  if (PABC_OK != pabc_new_user_context (ctx, pp, &usr_ctx))
  {
    pabc_free_public_parameters (ctx, &pp);
    ret = 1;
    shutdown ();
  }

  if (PABC_OK != pabc_populate_user_context (ctx, usr_ctx))
  {
    pabc_free_user_context (ctx, pp, &usr_ctx);
    pabc_free_public_parameters (ctx, &pp);
    ret = 1;
    shutdown ();
  }

  // store usr_ctx to file
  status = write_usr_ctx (create_usr, pp_name, ctx, pp, usr_ctx);
  if (PABC_OK != status)
  {
    ret = 1;
  }

  // clean up
  pabc_free_user_context (ctx, pp, &usr_ctx);
  pabc_free_public_parameters (ctx, &pp);
}


static void
set_attribute ()
{
  struct pabc_public_parameters *pp = NULL;
  struct pabc_user_context *usr_ctx = NULL;
  enum pabc_status status;

  // load stuff
  status = load_public_parameters (ctx, pp_name, &pp);
  if (status != PABC_OK)
  {
    fprintf (stderr, "Failed to read public parameters.\n");
    ret = 1;
    shutdown ();
  }

  status = read_usr_ctx (usr_name, pp_name, ctx, pp, &usr_ctx);
  if (PABC_OK != status)
  {
    fprintf (stderr, "Failed to read user context.\n");
    pabc_free_public_parameters (ctx, &pp);
    ret = 1;
    shutdown ();
  }

  // split set_attr into key=value
  char *key = NULL;
  char *value = NULL;
  key = strtok (set_attr, ATTR_DELIM);
  value = strtok (NULL, ATTR_DELIM);
  if ((NULL != strtok (NULL, ATTR_DELIM)) || // there is a second ATTR_DELIM
      (key == NULL) || (value == NULL))
  {
    fprintf (stderr, "Failed to parse attribtue.\n");
    pabc_free_user_context (ctx, pp, &usr_ctx);
    pabc_free_public_parameters (ctx, &pp);
    ret = 1;
    shutdown ();
  }

  // set attribute
  status = pabc_set_attribute_value_by_name (ctx, pp, usr_ctx, key, value);
  if (PABC_OK != status)
  {
    fprintf (stderr, "Failed to set attribute.\n");
    pabc_free_user_context (ctx, pp, &usr_ctx);
    pabc_free_public_parameters (ctx, &pp);
    ret = 1;
    shutdown ();
  }

  // write to file
  status = write_usr_ctx (usr_name, pp_name, ctx, pp, usr_ctx);
  if (PABC_OK != status)
  {
    fprintf (stderr, "Failed to write user context file.\n");
    ret = 1;
  }

  // clean up
  pabc_free_user_context (ctx, pp, &usr_ctx);
  pabc_free_public_parameters (ctx, &pp);
}


static void
create_cred_req ()
{
  struct pabc_public_parameters *pp = NULL;
  struct pabc_user_context *usr_ctx = NULL;
  struct pabc_credential_request *cr = NULL;
  struct pabc_nonce *nonce = NULL;

  enum pabc_status status;

  // load stuff
  status = load_public_parameters (ctx, pp_name, &pp);
  if (status != PABC_OK)
  {
    fprintf (stderr, "Failed to read public parameters.\n");
    ret = 1;
    shutdown ();
  }

  status = read_usr_ctx (usr_name, pp_name, ctx, pp, &usr_ctx);
  if (PABC_OK != status)
  {
    fprintf (stderr, "Failed to read user context.\n");
    pabc_free_public_parameters (ctx, &pp);
    ret = 1;
    shutdown ();
  }

  // nonce
  status = pabc_new_nonce (ctx, &nonce);
  if (status != PABC_OK)
  {
    fprintf (stderr, "Failed to allocate nonce.\n");
    pabc_free_user_context (ctx, pp, &usr_ctx);
    pabc_free_public_parameters (ctx, &pp);
    ret = 1;
    shutdown ();
  }
  status = pabc_decode_nonce (ctx, nonce, create_cr);
  if (status != PABC_OK)
  {
    fprintf (stderr, "Failed to decode nonce.\n");
    pabc_free_nonce (ctx, &nonce);
    pabc_free_user_context (ctx, pp, &usr_ctx);
    pabc_free_public_parameters (ctx, &pp);
    ret = 1;
    shutdown ();
  }

  // cr
  status = pabc_new_credential_request (ctx, pp, &cr);
  if (PABC_OK != status)
  {
    fprintf (stderr, "Failed to allocate cr.\n");
    pabc_free_nonce (ctx, &nonce);
    pabc_free_user_context (ctx, pp, &usr_ctx);
    pabc_free_public_parameters (ctx, &pp);
    ret = 1;
    shutdown ();
  }

  status = pabc_gen_credential_request (ctx, pp, usr_ctx, nonce, cr);
  if (PABC_OK != status)
  {
    fprintf (stderr, "Failed to generate cr.\n");
    pabc_free_nonce (ctx, &nonce);
    pabc_free_credential_request (ctx, pp, &cr);
    pabc_free_user_context (ctx, pp, &usr_ctx);
    pabc_free_public_parameters (ctx, &pp);
    ret = 1;
    shutdown ();
  }
  char *json = NULL;
  status = pabc_cred_encode_cr (ctx, pp, cr, usr_name, pp_name, &json);
  if (PABC_OK != status)
  {
    fprintf (stderr, "Failed to serialize cr.\n");
    pabc_free_nonce (ctx, &nonce);
    pabc_free_credential_request (ctx, pp, &cr);
    pabc_free_user_context (ctx, pp, &usr_ctx);
    pabc_free_public_parameters (ctx, &pp);
    ret = 1;
    shutdown ();
  }
  printf ("%s", json);

  // clean up
  PABC_FREE_NULL (json);
  pabc_free_nonce (ctx, &nonce);
  pabc_free_credential_request (ctx, pp, &cr);
  pabc_free_user_context (ctx, pp, &usr_ctx);
  pabc_free_public_parameters (ctx, &pp);
}


static void
inspect_credential (char const *const attr_name,
                    char const *const attr_val, void *inspect_ctx)
{
  (void) inspect_ctx;
  fprintf (stderr, "Credential inspect: \"%s\" -> \"%s\"\n", attr_name,
           attr_val);
}


static void
reveal_attributes ()
{
  struct pabc_public_parameters *pp = NULL;
  struct pabc_user_context *usr_ctx = NULL;
  struct pabc_credential *cred = NULL;
  struct pabc_blinded_proof *proof = NULL;

  enum pabc_status status;

  status = pabc_cred_inspect_credential (signed_cred, &inspect_credential,
                                         NULL);
  if (status != PABC_OK)
  {
    fprintf (stderr, "Failed to inspect credential.\n");
    ret = 1;
    shutdown ();
  }

  // load stuff
  status = load_public_parameters (ctx, pp_name, &pp);
  if (status != PABC_OK)
  {
    fprintf (stderr, "Failed to read public parameters.\n");
    ret = 1;
    shutdown ();
  }

  status = read_usr_ctx (usr_name, pp_name, ctx, pp, &usr_ctx);
  if (PABC_OK != status)
  {
    fprintf (stderr, "Failed to read user context.\n");
    pabc_free_public_parameters (ctx, &pp);
    ret = 1;
    shutdown ();
  }

  status = pabc_new_credential (ctx, pp, &cred);
  if (status != PABC_OK)
  {
    fprintf (stderr, "Failed to allocate credential.\n");
    pabc_free_user_context (ctx, pp, &usr_ctx);
    pabc_free_public_parameters (ctx, &pp);
    ret = 1;
    shutdown ();
  }

  { // print cred meta info
    char *user_id = NULL;
    char *pp_id = NULL;

    status = pabc_cred_get_ppid_from_cred (signed_cred, &pp_id);
    if (status != PABC_OK)
    {
      fprintf (stderr, "Failed to parse credential.\n");
      pabc_free_user_context (ctx, pp, &usr_ctx);
      pabc_free_public_parameters (ctx, &pp);
      ret = 1;
      shutdown ();
    }
    status = pabc_cred_get_userid_from_cred (signed_cred, &user_id);
    if (status != PABC_OK)
    {
      fprintf (stderr, "Failed to parse credential.\n");
      PABC_FREE_NULL (pp_id);
      pabc_free_user_context (ctx, pp, &usr_ctx);
      pabc_free_public_parameters (ctx, &pp);
      ret = 1;
      shutdown ();
    }

    fprintf (stderr,
             "Parsing credential with public params id: \"%s\" and user id: "
             "\"%s\".\n",
             pp_id, user_id);
    PABC_FREE_NULL (user_id);
    PABC_FREE_NULL (pp_id);
  }
  status = pabc_decode_credential (ctx, pp, cred, signed_cred);
  if (status != PABC_OK)
  {
    fprintf (stderr, "Failed to decode credential.\n");
    pabc_free_credential (ctx, pp, &cred);
    pabc_free_user_context (ctx, pp, &usr_ctx);
    pabc_free_public_parameters (ctx, &pp);
    ret = 1;
    shutdown ();
  }

  status = pabc_new_proof (ctx, pp, &proof);
  if (status != PABC_OK)
  {
    fprintf (stderr, "Failed to allocate proof.\n");
    pabc_free_credential (ctx, pp, &cred);
    pabc_free_user_context (ctx, pp, &usr_ctx);
    pabc_free_public_parameters (ctx, &pp);
    ret = 1;
    shutdown ();
  }

  // now we can parse the attributes to disclose and configure the proof
  char *attrs = strdup (attrs_discl);
  if (attrs == NULL)
  {
    fprintf (stderr, "Failed to allocate memory.\n");
    pabc_free_credential (ctx, pp, &cred);
    pabc_free_user_context (ctx, pp, &usr_ctx);
    pabc_free_public_parameters (ctx, &pp);
    ret = 1;
    shutdown ();
  }
  char *token = strtok (attrs, ",");
  while (NULL != token)
  {
    status = pabc_set_disclosure_by_attribute_name (ctx, pp, proof, token,
                                                    PABC_DISCLOSED, cred);
    if (status != PABC_OK)
    {
      fprintf (stderr, "Failed to configure proof.\n");
      PABC_FREE_NULL (attrs);
      pabc_free_credential (ctx, pp, &cred);
      pabc_free_user_context (ctx, pp, &usr_ctx);
      pabc_free_public_parameters (ctx, &pp);
      ret = 1;
      shutdown ();
    }
    token = strtok (NULL, ",");
  }
  PABC_FREE_NULL (attrs);

  // and finally -> sign the proof
  status = pabc_gen_proof (ctx, usr_ctx, pp, proof, cred);
  if (status != PABC_OK)
  {
    fprintf (stderr, "Failed to sign proof.\n");
    pabc_free_proof (ctx, pp, &proof);
    pabc_free_credential (ctx, pp, &cred);
    pabc_free_user_context (ctx, pp, &usr_ctx);
    pabc_free_public_parameters (ctx, &pp);
    ret = 1;
    shutdown ();
  }
  // print the result
  char *json = NULL;
  pabc_cred_encode_proof (ctx, pp, proof, usr_name, pp_name, &json);
  if (PABC_OK != status)
  {
    fprintf (stderr, "Failed to serialize proof.\n");
    pabc_free_proof (ctx, pp, &proof);
    pabc_free_credential (ctx, pp, &cred);
    pabc_free_user_context (ctx, pp, &usr_ctx);
    pabc_free_public_parameters (ctx, &pp);
    ret = 1;
    shutdown ();
  }
  printf ("%s", json);
  // clean up
  PABC_FREE_NULL (json);
  pabc_free_proof (ctx, pp, &proof);
  pabc_free_credential (ctx, pp, &cred);
  pabc_free_user_context (ctx, pp, &usr_ctx);
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
      {"user", required_argument, 0, 'u'},
      {"params", required_argument, 0, 'p'},
      {"list-parameters", no_argument, 0, 'L'},
      {"list-users", no_argument, 0, 'l'},
      {"create-cr", required_argument, 0, 'r'},
      {"create-user", required_argument, 0, 'c'},
      {"set-attr", required_argument, 0, 's'},
      {"reveal-attrs", required_argument, 0, 'd'},
      {"signed-cred", required_argument, 0, 'x'},
      {"import-params", required_argument, 0, 'I'},
      {0, 0, 0, 0}
    };
    /* getopt_long stores the option index here. */
    int option_index = 0;

    c = getopt_long (argc, argv, "hvu:p:Llr:c:s:d:x:I:", long_options,
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
    case 'h':
      print_help ();
      shutdown ();
    case 'v':
      verbose = 1;
      break;
    case 'u':
      if (optarg)
        usr_name = strdup (optarg);
      else
        abort ();
      break;
    case 'p':
      if (optarg)
        pp_name = strdup (optarg);
      else
        abort ();
      break;
    case 'L':
      list_params_flag = 1;
      break;
    case 'l':
      list_users_flag = 1;
      break;
    case 'r':
      if (optarg)
        create_cr = strdup (optarg);
      else
        abort ();
      break;
    case 'c':
      if (optarg)
        create_usr = strdup (optarg);
      else
        abort ();
      break;
    case 's':
      if (optarg)
        set_attr = strdup (optarg);
      else
        abort ();
      break;
    case 'd':
      if (optarg)
        attrs_discl = strdup (optarg);
      else
        abort ();
      break;
    case 'x':
      if (optarg)
        signed_cred = strdup (optarg);
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

  if (list_users_flag)
  {
    list_user ();
    shutdown ();
  }

  if (list_params_flag)
  {
    list_parameters ();
    shutdown ();
  }

  if (NULL != create_issuer)
  {
    add_issuer ();
    shutdown ();
  }
  if (create_cr)
  {
    if (NULL == pp_name)
    {
      fprintf (stderr, "No parameter set given\n");
      ret = 1;
      shutdown ();
    }
    if (NULL == usr_name)
    {
      fprintf (stderr, "No user given\n");
      ret = 1;
      shutdown ();
    }
    create_cred_req ();
    shutdown ();
  }

  if (NULL != create_usr)
  {
    if (NULL == pp_name)
    {
      fprintf (stderr, "No parameter set given\n");
      ret = 1;
      shutdown ();
    }
    if (NULL == pp_name)
    {
      fprintf (stderr, "No parameter set given\n");
      ret = 1;
      shutdown ();
    }
    add_user ();
    shutdown ();
  }

  if (NULL != set_attr)
  {
    if (NULL == pp_name)
    {
      fprintf (stderr, "No parameter set given\n");
      ret = 1;
      shutdown ();
    }
    if (NULL == usr_name)
    {
      fprintf (stderr, "No user given\n");
      ret = 1;
      shutdown ();
    }
    set_attribute ();
    shutdown ();
  }

  if (NULL != attrs_discl)
  {
    if (NULL == pp_name)
    {
      fprintf (stderr, "No parameters set given\n");
      ret = 1;
      shutdown ();
    }
    if (NULL == usr_name)
    {
      fprintf (stderr, "No user given\n");
      ret = 1;
      shutdown ();
    }
    if (NULL == signed_cred)
    {
      fprintf (stderr, "No signed credential given\n");
      ret = 1;
      shutdown ();
    }

    reveal_attributes ();

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
