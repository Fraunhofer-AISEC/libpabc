/**
 * Copyright (c) 2021 Fraunhofer AISEC
 *
 * SPDX-License-Identifier: Apache-2.0
 **/





#include "cli_helper.h"

static char pabc_dir[PATH_MAX + 1];

static const char *
get_homedir ()
{
  const char *homedir;
  if ((homedir = getenv ("HOME")) == NULL)
  {
    homedir = getpwuid (getuid ())->pw_dir;
  }
  return homedir;
}


static int
init_pabc_dir ()
{
  struct stat dirstat;
  int ret;
  char *filename;

  size_t filename_size = strlen (get_homedir ()) + 1 + strlen (".local") + 1;
  filename = malloc (filename_size);
  if (! filename)
    return PABC_FAILURE;
  snprintf (filename, filename_size, "%s/%s", get_homedir (), ".local");

  ret = stat (filename, &dirstat);
  if (0 != ret)
  {
    PABC_FREE_NULL (filename);
    return PABC_FAILURE;
  }
  if (! S_ISDIR (dirstat.st_mode))
  {
    fprintf (stderr, "%s exists but is not a directory!\n", filename);
    PABC_FREE_NULL (filename);
    return PABC_FAILURE;
  }
  ret = access (filename, R_OK | X_OK);
  if (0 > ret)
  {
    fprintf (stderr, "%s not readable!\n", filename);
    PABC_FREE_NULL (filename);
    return PABC_FAILURE;
  }
  snprintf (pabc_dir, PATH_MAX + 1, "%s/%s", filename, "pabc");
  PABC_FREE_NULL (filename);
  ret = mkdir (pabc_dir, S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IXGRP
               | S_IROTH | S_IXOTH);            /* 755 */
  if ((ret != 0) && (errno != EEXIST))
  {
    fprintf (stderr, "Unable to create %s!\n", pabc_dir);
    return PABC_FAILURE;
  }
  return PABC_OK;
}


static const char *
get_pabcdir ()
{
  PABC_ASSERT (init_pabc_dir ());
  return pabc_dir;
}


int
read_file (char const *const filename, char **buffer)
{
  FILE *fh = fopen (filename, "r");
  if (fh == NULL)
    return 1;
  fseek (fh, 0, SEEK_END);
  long lSize = ftell (fh);
  if (lSize < 0)
    goto fail;
  rewind (fh);
  *buffer = calloc ((size_t) lSize + 1, sizeof(char));
  if (*buffer == NULL)
    goto fail;

  // copy the file into the buffer:
  size_t r = fread (*buffer, 1, (size_t) lSize, fh);
  if (r != (size_t) lSize)
    goto fail;

  fclose (fh);
  return 0;

fail:
  fclose (fh);
  return 1;
}


static struct pabc_issuer_secret_key *
read_issuer_keyfile (const char *keyfile)
{
  struct pabc_context *ctx = NULL;
  PABC_ASSERT (pabc_new_ctx (&ctx));
  struct pabc_issuer_secret_key *isk = NULL;
  char *buffer;
  int r;
  r = read_file (keyfile, &buffer);
  if (0 != r)
  {
    fprintf (stderr, "Error reading keyfile\n");
    return NULL;
  }
  PABC_ASSERT (pabc_new_issuer_secret_key (ctx, &isk));
  PABC_ASSERT (pabc_decode_issuer_secret_key (ctx, isk, buffer));
  PABC_FREE_NULL (buffer);
  pabc_free_ctx (&ctx);
  return isk;
}


struct pabc_public_parameters *
read_issuer_ppfile (const char *f, struct pabc_context *const ctx)
{
  enum pabc_status status;
  if (NULL == ctx)
  {
    fprintf (stderr, "No global context provided\n");
    return NULL;
  }
  struct pabc_public_parameters *pp;
  char *buffer;
  int r;
  r = read_file (f, &buffer);
  if (0 != r)
  {
    fprintf (stderr, "Error reading file\n");
    return NULL;
  }

  char *pp_id = NULL;
  char *issuer_id = NULL;
  status = pabc_cred_get_ppid_from_pp (buffer, &pp_id);
  if (status != PABC_OK)
  {
    PABC_FREE_NULL (buffer);
    fprintf (stderr, "Error parsing public parameters.\n");
    return NULL;
  }
  status = pabc_cred_get_issuerid_from_pp (buffer, &issuer_id);
  if (status != PABC_OK)
  {
    PABC_FREE_NULL (buffer);
    fprintf (stderr, "Error parsing public parameters.\n");
    return NULL;
  }
  fprintf (stderr,
           "Parsing public parameters with issuer key id: \"%s\" and pp id: "
           "\"%s\"\n",
           issuer_id, pp_id);
  PABC_FREE_NULL (pp_id);
  PABC_FREE_NULL (issuer_id);

  if (PABC_OK != pabc_decode_and_new_public_parameters (ctx, &pp, buffer))
  {
    PABC_FREE_NULL (buffer);
    return NULL;
  }
  PABC_FREE_NULL (buffer);
  return pp;
}


enum pabc_status
read_issuer_secret_key (const char *issuer,
                        struct pabc_issuer_secret_key **isk)
{
  const char *pdir = get_pabcdir ();
  char fname[PATH_MAX];
  memset (fname, 0, PATH_MAX);

  snprintf (fname, PATH_MAX, "%s/%s%s", pdir, issuer, ISK_EXT);
  *isk = read_issuer_keyfile (fname);
  if (NULL == *isk)
    return PABC_FAILURE;
  return PABC_OK;
}


enum pabc_status
load_public_parameters (struct pabc_context *const ctx,
                        char const *const pp_name,
                        struct pabc_public_parameters **pp)
{
  struct stat dstat;
  char fname[PATH_MAX];
  DIR *dinfo;
  struct dirent *finfo;
  const char *pdir = get_pabcdir ();

  if (ctx == NULL)
    return PABC_UNINITIALIZED;
  if (pp_name == NULL)
    return PABC_UNINITIALIZED;
  if (pp == NULL)
    return PABC_UNINITIALIZED;

  if (0 != stat (pdir, &dstat))
  {
    fprintf (stderr, "Error reading %s\n", pdir);
    return PABC_FAILURE;
  }
  if (! S_ISDIR (dstat.st_mode))
  {
    fprintf (stderr, "Error %s is not a directory\n", pdir);
    return PABC_FAILURE;
  }
  errno = 0;
  dinfo = opendir (pdir);
  if ((EACCES == errno) || (NULL == dinfo))
  {
    fprintf (stderr, "Error reading %s\n", pdir);
    return PABC_FAILURE;
  }
  while (NULL != (finfo = readdir (dinfo)))
  {
    if ((0 == strcmp (finfo->d_name, ".")) || (0 == strcmp (finfo->d_name,
                                                            "..")))
      continue;
    snprintf (fname, PATH_MAX, "%s/%s", pdir, finfo->d_name);
    if ((strlen (PP_EXT) >= strlen (finfo->d_name)) ||
        (0 != strcmp (finfo->d_name + strlen (finfo->d_name) - strlen (PP_EXT),
                      PP_EXT)) ||
        (strlen (pp_name) + strlen (PP_EXT) != strlen (finfo->d_name)) ||
        (0 != strncmp (finfo->d_name, pp_name, strlen (pp_name))))
      continue;
    else
      *pp = read_issuer_ppfile (fname, ctx);
  }
  closedir (dinfo);
  if (*pp)
    return PABC_OK;
  else
    return PABC_FAILURE;
}


int
write_issuer_key (const char *issuer,
                  struct pabc_issuer_secret_key *const isk)
{
  char *buf;
  char *filename;

  size_t filename_size =
    strlen (get_pabcdir ()) + 1 + strlen (issuer) + strlen (ISK_EXT) + 1;
  filename = malloc (filename_size);
  if (! filename)
    return PABC_FAILURE;
  snprintf (filename, filename_size, "%s/%s%s", get_pabcdir (), issuer,
            ISK_EXT);

  struct pabc_context *ctx = NULL;
  PABC_ASSERT (pabc_new_ctx (&ctx));

  PABC_ASSERT (pabc_encode_issuer_secret_key (ctx, isk, &buf));

  if (0 != write_file (filename, buf))
  {
    PABC_FREE_NULL (filename);
    PABC_FREE_NULL (buf);
    pabc_free_ctx (&ctx);
    return PABC_FAILURE;
  }
  PABC_FREE_NULL (filename);
  PABC_FREE_NULL (buf);
  pabc_free_ctx (&ctx);
  return PABC_OK;
}


int
write_public_parameters (char const *const pp_name,
                         struct pabc_public_parameters *const pp,
                         char const *const isk_name)
{
  char *json;
  char *filename;
  enum pabc_status status;
  struct pabc_context *ctx = NULL;
  PABC_ASSERT (pabc_new_ctx (&ctx));
  // store in json file
  // status = pabc_encode_public_parameters (ctx, pp, &json);
  status =
    pabc_cred_encode_public_parameters (ctx, pp, pp_name, isk_name, &json);
  if (status != PABC_OK)
  {
    fprintf (stderr, "Failed to encode public parameters.\n");
    pabc_free_ctx (&ctx);
    return PABC_FAILURE;
  }

  size_t filename_size =
    strlen (get_pabcdir ()) + 1 + strlen (pp_name) + strlen (PP_EXT) + 1;
  filename = malloc (filename_size);
  if (! filename)
  {
    PABC_FREE_NULL (json);
    pabc_free_ctx (&ctx);
    return PABC_FAILURE;
  }
  snprintf (filename, filename_size, "%s/%s%s", get_pabcdir (), pp_name,
            PP_EXT);

  if (0 != write_file (filename, json))
  {
    PABC_FREE_NULL (filename);
    PABC_FREE_NULL (json);
    pabc_free_ctx (&ctx);
    return PABC_FAILURE;
  }
  PABC_FREE_NULL (filename);
  PABC_FREE_NULL (json);
  pabc_free_ctx (&ctx);
  return PABC_OK;
}


int
write_file (char const *const filename, const char *buffer)
{

  FILE *fh = fopen (filename, "w");
  if (fh == NULL)
    return 1;
  if (fputs (buffer, fh) == EOF)
    goto fail;
  fclose (fh);
  return 0;

fail:
  fclose (fh);
  return 1;
}


enum pabc_status
write_usr_ctx (char const *const usr_name,
               char const *const pp_name,
               struct pabc_context const *const ctx,
               struct pabc_public_parameters const *const pp,
               struct pabc_user_context *const usr_ctx)
{

  if (NULL == usr_name)
  {
    fprintf (stderr, "No issuer given.\n");
    return PABC_UNINITIALIZED;
  }
  if (NULL == pp_name)
  {
    fprintf (stderr, "No user given.\n");
    return PABC_UNINITIALIZED;
  }
  if (NULL == ctx)
  {
    fprintf (stderr, "No context given.\n");
    return PABC_UNINITIALIZED;
  }
  if (NULL == pp)
  {
    fprintf (stderr, "No public parameters given.\n");
    return PABC_UNINITIALIZED;
  }
  if (NULL == usr_ctx)
  {
    fprintf (stderr, "No user context given.\n");
    return PABC_UNINITIALIZED;
  }

  char *json = NULL;
  enum pabc_status status;
  status = pabc_encode_user_ctx (ctx, pp, usr_ctx, &json);
  if (PABC_OK != status)
  {
    fprintf (stderr, "Failed to encode user context.\n");
    return status;
  }

  char *fname = NULL;
  size_t fname_size = strlen (get_pabcdir ()) + 1 + strlen (usr_name) + 1
                      + strlen (pp_name) + strlen (USR_EXT) + 1;
  fname = malloc (fname_size);
  if (! fname)
  {
    PABC_FREE_NULL (json);
    return PABC_FAILURE;
  }

  snprintf (fname, fname_size, "%s/%s_%s%s", get_pabcdir (), usr_name, pp_name,
            USR_EXT);

  if (0 == write_file (fname, json))
  {
    PABC_FREE_NULL (fname);
    PABC_FREE_NULL (json);
    return PABC_OK;
  }
  else
  {
    PABC_FREE_NULL (fname);
    PABC_FREE_NULL (json);
    return PABC_FAILURE;
  }
}


enum pabc_status
read_usr_ctx (char const *const usr_name,
              char const *const pp_name,
              struct pabc_context const *const ctx,
              struct pabc_public_parameters const *const pp,
              struct pabc_user_context **usr_ctx)
{
  if (NULL == usr_name)
  {
    fprintf (stderr, "No issuer given.\n");
    return PABC_UNINITIALIZED;
  }
  if (NULL == pp_name)
  {
    fprintf (stderr, "No user given.\n");
    return PABC_UNINITIALIZED;
  }
  if (NULL == ctx)
  {
    fprintf (stderr, "No context given.\n");
    return PABC_UNINITIALIZED;
  }
  if (NULL == pp)
  {
    fprintf (stderr, "No public parameters given.\n");
    return PABC_UNINITIALIZED;
  }
  if (NULL == usr_ctx)
  {
    fprintf (stderr, "No user context given.\n");
    return PABC_UNINITIALIZED;
  }

  char *json = NULL;
  enum pabc_status status;

  char *fname = NULL;
  size_t fname_size = strlen (get_pabcdir ()) + 1 + strlen (usr_name) + 1
                      + strlen (pp_name) + strlen (USR_EXT) + 1;
  fname = malloc (fname_size);
  if (! fname)
    return PABC_FAILURE;
  snprintf (fname, fname_size, "%s/%s_%s%s", get_pabcdir (), usr_name, pp_name,
            USR_EXT);

  if (0 != read_file (fname, &json))
  {
    PABC_FREE_NULL (fname);
    return PABC_FAILURE;
  }
  PABC_FREE_NULL (fname);

  status = pabc_new_user_context (ctx, pp, usr_ctx);
  if (PABC_OK != status)
  {
    PABC_FREE_NULL (json);
    return status;
  }
  status = pabc_decode_user_ctx (ctx, pp, *usr_ctx, json);
  PABC_FREE_NULL (json);
  if (PABC_OK != status)
  {
    pabc_free_user_context (ctx, pp, usr_ctx);
    fprintf (stderr, "Failed to encode user context.\n");
    return status;
  }

  return PABC_OK;
}


void
list_parameters (void)
{
  printf ("PUBLIC PARAMETERS:\n"
          "##################\n");
  print_filenames_by_extension (PP_EXT);
}


void
list_issuer (void)
{
  printf ("ISSUERS:\n"
          "########\n");
  print_filenames_by_extension (ISK_EXT);
}


void
list_user (void)
{
  printf ("USERS:\n"
          "######\n");
  print_filenames_by_extension (USR_EXT);
}


enum pabc_status
import_pp (char const *const pp_name,
           char const *const pp_json)
{
  if (! pp_name)
    return PABC_UNINITIALIZED;
  if (! pp_json)
    return PABC_UNINITIALIZED;

  size_t filename_size =
    strlen (get_pabcdir ()) + 1 + strlen (pp_name) + strlen (PP_EXT) + 1;
  char *filename = malloc (filename_size);
  if (! filename)
    return PABC_FAILURE;
  snprintf (filename, filename_size, "%s/%s%s", get_pabcdir (), pp_name,
            PP_EXT);

  if (0 != write_file (filename, pp_json))
  {
    PABC_FREE_NULL (filename);
    return PABC_FAILURE;
  }

  PABC_FREE_NULL (filename);

  return PABC_OK;
}


enum pabc_status
export_pp (char const *const pp_name, char **const pp_json)
{
  if (! pp_name)
    return PABC_UNINITIALIZED;
  if (! pp_json)
    return PABC_UNINITIALIZED;

  size_t filename_size =
    strlen (get_pabcdir ()) + 1 + strlen (pp_name) + strlen (PP_EXT) + 1;
  char *filename = malloc (filename_size);
  if (! filename)
    return PABC_FAILURE;
  snprintf (filename, filename_size, "%s/%s%s", get_pabcdir (), pp_name,
            PP_EXT);

  char *buffer = NULL;
  if (0 != read_file (filename, &buffer))
  {
    PABC_FREE_NULL (filename);
    return PABC_FAILURE;
  }

  PABC_FREE_NULL (filename);

  *pp_json = buffer;
  return PABC_OK;
}


enum pabc_status
print_filenames_by_extension (char const *const extension)
{
  struct stat dstat;
  char fname[PATH_MAX];
  DIR *dinfo;
  struct dirent *finfo;
  const char *pdir = get_pabcdir ();

  if (extension == NULL)
    return PABC_UNINITIALIZED;

  if (0 != stat (pdir, &dstat))
  {
    fprintf (stderr, "Error reading %s\n", pdir);
    return PABC_FAILURE;
  }
  if (! S_ISDIR (dstat.st_mode))
  {
    fprintf (stderr, "Error %s is not a directory\n", pdir);
    return PABC_FAILURE;
  }
  errno = 0;
  dinfo = opendir (pdir);
  if ((EACCES == errno) || (NULL == dinfo))
  {
    fprintf (stderr, "Error reading %s\n", pdir);
    return PABC_FAILURE;
  }
  while (NULL != (finfo = readdir (dinfo)))
  {
    if ((0 == strcmp (finfo->d_name, ".")) || (0 == strcmp (finfo->d_name,
                                                            "..")))
      continue;
    snprintf (fname, PATH_MAX, "%s/%s", pdir, finfo->d_name);
    if ((strlen (extension) >= strlen (finfo->d_name)) ||
        (0 != strcmp (finfo->d_name + strlen (finfo->d_name) - strlen (
                        extension),
                      extension)))
      continue;
    else
      printf ("%s\n", finfo->d_name);
  }
  closedir (dinfo);
  return PABC_OK;
}
