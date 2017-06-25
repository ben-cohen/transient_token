# vim: noet

#
#  This file is part of transient_token.
#
#  transient_token is free software: you can redistribute it and/or
#  modify it under the terms of the GNU General Public License as
#  published by the Free Software Foundation, either version 3 of the
#  License, or (at your option) any later version.
#
#  transient_token is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#  General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with transient_token.  If not, see
#  <http://www.gnu.org/licenses/>.
#

CFLAGS += -ggdb
CP = cp

all: get_transient_token pam_transient_token.so

get_transient_token: get_transient_token.c transient_token.h
	$(CC) -o get_transient_token get_transient_token.c -lssl -lcrypto $(CFLAGS)

pam_transient_token.so: pam_transient_token.o
	$(CC) -shared -o pam_transient_token.so pam_transient_token.o -lpam $(CFLAGS)

pam_transient_token.o: pam_transient_token.c transient_token.h
	$(CC) -fPIC -c pam_transient_token.c $(CFLAGS)

.PHONY: all


clean:
	$(RM) get_transient_token pam_transient_token.so pam_transient_token.o

install:
	$(CP) get_transient_token /usr/local/bin/get_transient_token
	$(CP) pam_transient_token.so /lib/x86_64-linux-gnu/security/pam_transient_token.so
	$(CP) unix-or-token-auth /etc/pam.d/unix-or-token-auth
