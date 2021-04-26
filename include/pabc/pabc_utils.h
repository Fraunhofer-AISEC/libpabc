/**
 * Copyright (c) 2021 Fraunhofer AISEC
 *
 * SPDX-License-Identifier: Apache-2.0
 **/

#ifndef PABC_UTILS_H
#define PABC_UTILS_H

/*!
 * Several status flags used throughout the library.
 */
enum pabc_status
{
  PABC_OK = 1 << 0,      // !< Indicates that the operation succeeded.
  PABC_FAILURE = 1 << 1, // !< Indicates that the operation failed.
  PABC_OOB = 1 << 2,     // !< Indicates that the operation failed because of an
                         // out-of-bounds access.
  PABC_OOM = 1 << 3,     // !< Indicates that a memory allocation failed.
  PABC_RELIC_FAIL = 1 << 4,   // !< Indicates that RELIC encountered an error.
  PABC_JANSSON_FAIL = 1 << 5, // !< Indicates that Jansson encountered an error.
  PABC_UNINITIALIZED = 1 << 6, // !< Indicates that an uninitialized value was
                               // encountered.
  PABC_DISCLOSED =
    1 << 7,   // !< Indicates that an attribute should be disclosed.
  PABC_NOT_DISCLOSED =
    1 << 8,   // !< Indicates that an attribute should not be disclosed.
  PABC_ATTRIBUTE_UNKOWN =
    1 << 9   // !< Indicates that the requested attribute cannot be found with
             // the given public parameters.
};

/**
 * @ingroup logging
 * Assertions
 */
#define PABC_ASSERT(cond)                                                      \
  do {                                                                         \
    if (! (PABC_OK == cond)) {                                                  \
      fprintf (stderr, "Assertion failed at %s:%d..\n", __FILE__, __LINE__);    \
      exit (1);                                                                 \
    }                                                                          \
  } while (0)

#define PABC_FREE_NULL(p)                                                      \
  do {                                                                         \
    free (p);                                                                   \
    (p) = NULL;                                                                \
  } while (0)

#endif // PABC_UTILS_H
