/* vim: set ts=4 sw=4 et: */
/*
 *  This file is part of transient_token.
 *
 *  transient_token is free software: you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License as
 *  published by the Free Software Foundation, either version 3 of the
 *  License, or (at your option) any later version.
 *
 *  transient_token is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with transient_token.  If not, see
 *  <http://www.gnu.org/licenses/>.
 */

/*
 * pam_transient_token.c: PAM module for auth for transient_token
 */

#include <stddef.h>
#include <stdio.h>

#define PAM_SM_AUTH
#include <security/pam_modules.h>

#include "transient_token.h"

#define CHALLENGE_SIZE_BASE64_BYTES       (CHALLENGE_SIZE_QUADS * 4)

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh,
                                   int flags,
                                   int argc,
                                   const char **argv)
{
   int rc;
   const char *token;

   rc = pam_get_item(pamh, PAM_AUTHTOK, (const void **)&token);
   if (rc != PAM_SUCCESS)
     return PAM_AUTHINFO_UNAVAIL;

   /*
    * Parse the token.  It should look like:
    *    TRANSTOK:<uid>:<pid>:<udspath>:<challenge>:<response>:"
    */
   char token_challenge[CHALLENGE_SIZE_BASE64_BYTES];
   char token_response[CHALLENGE_SIZE_BASE64_BYTES];
   char token_udspath[MAX_UDS_PATH];
   int token_pid;
   int token_uid;
   if (sscanf(token, "TRANSTOK:%d:%d:%.*s:%.*s:%.*s:",
              &token_uid,
              &token_pid,
              token_udspath,
              token_challenge,
              token_response) != 5)
     return PAM_AUTH_ERR;

   /* Find out which user is trying to log in. */
   const char *user;
   rc = pam_get_user(pamh, &user, NULL);
   if (rc != PAM_SUCCESS)
     return PAM_AUTHINFO_UNAVAIL;

   /* Verify that the user matches the uid from the token. */
   struct passwd *p = getpwnam(user);
   if (p == NULL)
     return PAM_AUTHINFO_UNAVAIL;
   if (p->pw_uid != uid)
     return PAM_AUTH_ERR;

   /* Open the unix domain socket given.  Check that it matches the given uid
    * and pid. */

   /* Send the challenge and check that the response is correct. */

   return PAM_SUCCESS;
}


PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh,
                              int flags,
                              int argc,
                              const char **argv)
{
  return PAM_SUCCESS;
}


#ifdef PAM_STATIC             /* for the case that this module is static */

struct pam_module _pam_transient_token_modstruct = {   /* static module data */
     "pam_transient_token",
     pam_sm_authenticate,
     pam_sm_setcred,
     NULL,
     NULL,
     NULL,
     pam_sm_chauthtok,
};

#endif                                                 /* end PAM_STATIC */
