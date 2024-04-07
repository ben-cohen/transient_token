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

//#define DEBUG 1

#include <stddef.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <pwd.h>
#include <unistd.h>
#ifdef DEBUG
#include <syslog.h>
#endif

#define PAM_SM_AUTH
#include <security/pam_modules.h>
#if defined(_OPENPAM)
#define HAVE_GET_AUTHTOK
#include <security/pam_appl.h>
#elif defined(__LINUX_PAM__)
#define HAVE_GET_AUTHTOK
#include <security/pam_ext.h>
#endif

#include "transient_token.h"

#define CHALLENGE_SIZE_BASE64_BYTES       (CHALLENGE_SIZE_QUADS * 4)
#include <stdlib.h>
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh,
                                   int flags,
                                   int argc,
                                   const char **argv)
{
    int rc;
    const char *token;

#ifdef HAVE_GET_AUTHTOK
    rc = pam_get_authtok(pamh, PAM_AUTHTOK, (const char **)&token, NULL);
#else
    rc = pam_get_item(pamh, PAM_AUTHTOK, (const void **)&token);
#endif
    if (rc != PAM_SUCCESS)
        return PAM_AUTHINFO_UNAVAIL;
#ifndef HAVE_GET_AUTHTOK
    if (token == NULL)
    {
        // TODO: implement conversation
    }
#endif
    if (token == NULL)
        return PAM_AUTHINFO_UNAVAIL;

    /*
     * Parse the token.  It should look like:
     *    TTK<uid>:<pid>:<challenge>"
     */
    char token_challenge[CHALLENGE_SIZE_BASE64_BYTES + 1];
    int token_pid;
    int token_uid;
    char token_format[100];

    rc = snprintf(token_format,
                  sizeof(token_format),
                  "TTK%%d:%%d:%%%d[A-Za-z0-9+/]",
                  CHALLENGE_SIZE_BASE64_BYTES);
    if (rc <= 0 || rc >= sizeof(token_format))
        return PAM_AUTHINFO_UNAVAIL;

#ifdef DEBUG
    openlog("pam_transient_token.so", 0, LOG_AUTHPRIV);
    syslog(LOG_DEBUG,
           "Token is '%s' and token_format is '%s'\n",
           token,
           token_format);
    closelog();
#endif

    rc = sscanf(token,
                token_format,
                &token_uid,
                &token_pid,
                token_challenge);
    if (rc != 3)
        return PAM_AUTH_ERR;

    char udspath[MAX_UDS_PATH + 1];
    rc = snprintf(udspath,
                  sizeof(udspath),
                  UDS_PATH,
                  token_uid,
                  token_pid);
    if (rc <= 0 || rc >= sizeof(udspath))
        return PAM_AUTHINFO_UNAVAIL;

    /* Find out which user is trying to log in. */
    const char *user;
    rc = pam_get_user(pamh, &user, NULL);
    if (rc != PAM_SUCCESS
        || user == NULL
        || user[0] == '\0')
        return PAM_AUTHINFO_UNAVAIL;

    /* Verify that the user matches the uid from the token. */
    struct passwd *p = getpwnam(user);
    if (p == NULL)
        return PAM_AUTHINFO_UNAVAIL;
    if (p->pw_uid != token_uid)
        return PAM_AUTH_ERR;

    /* Open the unix domain socket given.  Check that it matches the given uid
     * and pid. */
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd == -1)
        return PAM_AUTHINFO_UNAVAIL;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, udspath, sizeof(addr.sun_path) - 1);
    rc = connect(fd, (struct sockaddr*)&addr, sizeof(addr));
    if (rc != 0)
        return PAM_AUTH_ERR;

    /* Send the token and check for success. */
    rc = write(fd, token, strlen(token));
    if (rc != strlen(token))
        return PAM_AUTH_ERR;

    char inresponse[sizeof(SUCCESS_STRING)];
    rc = read(fd, inresponse, sizeof(inresponse));
    if (rc != sizeof(SUCCESS_STRING))
        return PAM_AUTH_ERR;
    if (memcmp(SUCCESS_STRING, inresponse, sizeof(SUCCESS_STRING)) != 0)
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
