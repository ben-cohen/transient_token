/*
 * Compile using:
 *     gcc -fPIC -c pam_transient_token.c
 *     gcc -shared -o pam_transient_token.so pam_transient_token.o -lpam
 */

#define PAM_SM_AUTH
#include <security/pam_modules.h>

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh,
                                   int flags,
                                   int argc,
                                   const char **argv)
{
   void *password;
   int rc = pam_get_item(pamh, PAM_AUTHTOK, (const void **)&password);
   if (rc != PAM_SUCCESS)
     return PAM_AUTHINFO_UNAVAIL;

   if (strcmp(password, "LETMEIN") != 0)
     return PAM_AUTH_ERR;

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
