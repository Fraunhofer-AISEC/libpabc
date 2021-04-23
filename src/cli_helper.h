/**
 * Copyright (c) 2021 Fraunhofer AISEC
 *
 * SPDX-License-Identifier: Apache-2.0
 **/





#include <dirent.h>
#include <errno.h>
#include <pabc/pabc.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define ISK_EXT ".isk"

#define PP_EXT ".pp"

#define USR_EXT ".usr"

#define ATTR_DELIM "="

int read_file (char const *const filename, char **buffer);

int write_file (char const *const filename, const char *buffer);

int write_issuer_key (const char *issuer,
                      struct pabc_issuer_secret_key *const isk);

int write_public_parameters (char const *const pp_name,
                             struct pabc_public_parameters *const pp,
                             char const *const isk_name);

enum pabc_status read_issuer_secret_key (const char *issuer,
                                         struct pabc_issuer_secret_key **isk);

/**
 * Load public parameters from file.
 *
 * \param ctx [in,out] The pabc context to use.
 * \param pp_name [in] Name of the parameter set.
 * \param pp [out] Allocates and loads public parameters here.
 * \return Success status.
 */
enum pabc_status load_public_parameters (struct pabc_context *const ctx,
                                         char const *const pp_name,
                                         struct pabc_public_parameters **pp);

struct pabc_public_parameters *
read_issuer_ppfile (const char *f, struct pabc_context *const ctx);

enum pabc_status write_usr_ctx (char const *const user_name,
                                char const *const pp_name,
                                struct pabc_context const *const ctx,
                                struct pabc_public_parameters const *const pp,
                                struct pabc_user_context *const usr_ctx);

enum pabc_status read_usr_ctx (char const *const user_name,
                               char const *const pp_name,
                               struct pabc_context const *const ctx,
                               struct pabc_public_parameters const *const pp,
                               struct pabc_user_context **usr_ctx);

void list_issuer (void);

void list_user (void);

void list_parameters (void);

enum pabc_status import_pp (char const *const pp_name,
                            char const *const pp_json);

enum pabc_status export_pp (char const *const pp_name, char **const pp_json);

enum pabc_status print_filenames_by_extension (char const *const extension);
