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
   const char *password;

   rc = pam_get_item(pamh, PAM_AUTHTOK, (const void **)&password);
   if (rc != PAM_SUCCESS)
     return PAM_AUTHINFO_UNAVAIL;

   if (strcmp(password, "LETMEIN") != 0)
     return PAM_AUTH_ERR;

   return PAM_SUCCESS;

   //

   char stuff[128];
   char challenge[CHALLENGE_SIZE_BASE64_BYTES];
   char response[CHALLENGE_SIZE_BASE64_BYTES];
   int pid;
   int uid;
   char udspath[MAX_UDS_PATH];
   if (sscanf(password, "TRANSTOK:%d:%d:%s:%s:%s:", ) != 5)
     return PAM_AUTH_ERR;

   const char *user;
   rc = pam_get_user(pamh, &user, NULL);
   if (rc != PAM_SUCCESS)
     return PAM_AUTHINFO_UNAVAIL;

   // Token should look like:
   // TRANSTOK:<uid>:<expire-time>:<stuff>

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
