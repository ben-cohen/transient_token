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
 * get_transient_token.c: generate token and verify it for PAM auth
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

#include "transient_token.h"

#define CHALLENGE_SIZE_RAW_BYTES          (CHALLENGE_SIZE_QUADS * 3)
#define CHALLENGE_SIZE_BASE64_BYTES       (CHALLENGE_SIZE_QUADS * 4)

int getrandbase64(char *data_base64)
{
    int rc;
    unsigned char data_raw[CHALLENGE_SIZE_RAW_BYTES];
    BIO *mem = BIO_new(BIO_s_mem());
    if (mem == NULL)
        return -1;

    BIO *base64 = BIO_new(BIO_f_base64());
    if (base64 == NULL)
        return -1;

    mem = BIO_push(base64, mem);
    if (mem == NULL)
        return -1;

    rc = RAND_bytes(data_raw, sizeof(data_raw));
    if (rc != 1)
        return -1;

    rc = BIO_write(base64, data_raw, sizeof(data_raw));
    if (rc != sizeof(data_raw))
        return -1;

    BIO_flush(mem);

    char *bio_data_base64;
    int len = BIO_get_mem_data(mem, &bio_data_base64);
    if (len != CHALLENGE_SIZE_BASE64_BYTES + 1)
        return -1;
    memcpy(data_base64, bio_data_base64, CHALLENGE_SIZE_BASE64_BYTES);

    BIO_free_all(mem);

    return 0;
}


int main()
{
    int rc;
    int len;

    /* Create unix domain socket */
    char udspath[MAX_UDS_PATH + 1];
    len = snprintf(udspath,
                   sizeof(udspath),
                   UDS_PATH,
                   getuid(),
                   getpid());
    if (len <= 0 || len >= sizeof(udspath))
    {
        fprintf(stderr, "snprintf(udspath) failed\n");
        exit(1);
    }
    unlink(udspath);

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd == -1)
    {
        fprintf(stderr, "socket creation failed\n");
        exit(1);
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, udspath, sizeof(addr.sun_path) - 1);
    rc = bind(fd, (struct sockaddr*)&addr, sizeof(addr));
    if (rc != 0)
    {
        fprintf(stderr, "bind failed\n");
        close(fd);
        unlink(udspath);
        exit(1);
    }

    rc = chmod(udspath, 0600);
    if (rc != 0)
    {
        fprintf(stderr, "chmod failed\n");
        close(fd);
        unlink(udspath);
        exit(1);
    }

    rc = listen(fd, 1);
    if (rc != 0)
    {
        fprintf(stderr, "listen failed\n");
        close(fd);
        unlink(udspath);
        exit(1);
    }

    /* Generate a random challenge and response */
    char challenge[CHALLENGE_SIZE_BASE64_BYTES];
    char response[CHALLENGE_SIZE_BASE64_BYTES];
    rc = getrandbase64(challenge);
    if (rc != 0)
    {
        fprintf(stderr, "failed to generate challenge\n");
        close(fd);
        unlink(udspath);
        exit(1);
    }
    rc = getrandbase64(response);
    if (rc != 0)
    {
        fprintf(stderr, "failed to generate response\n");
        close(fd);
        unlink(udspath);
        exit(1);
    }

    /* Generate and print the token */
    char buffer[255];
    len = snprintf(buffer, sizeof(buffer),
                   "TTK%d:%d:%.*s%.*s",
                   getuid(),
                   getpid(),
                   CHALLENGE_SIZE_BASE64_BYTES,
                   challenge,
                   CHALLENGE_SIZE_BASE64_BYTES,
                   response);
    if (len <= 0 || len >= sizeof(buffer))
    {
        fprintf(stderr, "Buffer too small\n");
        close(fd);
        unlink(udspath);
        exit(1);
    }

    /* Print the token */
    printf("%s\n", buffer);
    memset(buffer, 0, sizeof(buffer));

    /* Daemonize */
    fflush(stdout);
    daemon(0, 0);

    /* Listen for up to the timeout */
    // TODO: The timeout could be a command-line option
    struct timeval timeout;
    timeout.tv_sec = TIMEOUT_SECS;
    timeout.tv_usec = 0;
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(fd, &readfds);
    select(FD_SETSIZE, &readfds, NULL, NULL, &timeout);

    /* If something connected then get it... */
    if (FD_ISSET(fd, &readfds))
    {
        // TODO: This bit should also timeout
        socklen_t addrsize = sizeof(addr);
        int fdc = accept(fd, (struct sockaddr*)&addr, &addrsize);

        char inchallenge[CHALLENGE_SIZE_BASE64_BYTES];  
        read(fdc, inchallenge, CHALLENGE_SIZE_BASE64_BYTES);
        if (memcmp(challenge, inchallenge, CHALLENGE_SIZE_BASE64_BYTES) == 0)
        {
            write(fdc, response, sizeof(response));
            write(fdc, "\n", 1);
        }
        else
        {
            write(fdc, "FAIL\n", 5);
        }
        close(fdc);
    }

    /* Tidy up */
    close(fd);
    unlink(udspath);
    return 0;
}
