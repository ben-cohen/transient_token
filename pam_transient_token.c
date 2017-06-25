/*
 * Compile using:
 *     gcc -fPIC -c pam_transient_token.c
 *     gcc -shared -o pam_transient_token.so pam_transient_token.o -lpam
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
