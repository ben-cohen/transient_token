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
 * transient_token.h: transient_token header file
 */

#ifndef _TRANSIENT_TOKEN_H
#define _TRANSIENT_TOKEN_H

#define CHALLENGE_SIZE_QUADS 4
#define TIMEOUT_SECS 60
#define MAX_UDS_PATH 64
#define UDS_PATH "/tmp/transient-token-%d-%d"

#ifdef PAM_STATIC             /* for the case that this module is static */
extern struct pam_module _pam_transient_token_modstruct;
#endif
#endif
