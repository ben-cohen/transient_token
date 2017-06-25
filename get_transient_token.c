/*
 * Compile using:
 *     gcc -o get_transient_token get_transient_token.c -lssl -lcrypto
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/select.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

#include "transient_token.h"

#define CHALLENGE_SIZE_RAW_BYTES          (CHALLENGE_SIZE_QUADS * 3)
#define CHALLENGE_SIZE_BASE64_BYTES       (CHALLENGE_SIZE_QUADS * 4)

int getrandbase64(char *data_base64)
{
  int rc;
  char data_raw[CHALLENGE_SIZE_RAW_BYTES];
  BIO *base64 = BIO_new(BIO_f_base64());
  if (base64 == NULL)
    return -1;

  BIO *mem = BIO_new_mem_buf(data_base64, CHALLENGE_SIZE_BASE64_BYTES);
  BIO_push(base64, mem);

  rc = RAND_bytes(data_raw, sizeof(data_raw));
  if (rc != 1)
    return -1;

  rc = BIO_write(base64, data_raw, sizeof(data_raw));
  if (rc != sizeof(data_raw))
    return -1;

  BIO_flush(mem);
  BIO_free_all(mem);

  return 0;
}


int main()
{
  int rc;

  /* Create unix domain socket */
  char udspath[MAX_UDS_PATH] = "/tmp/uds";
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
  int len;
  len = snprintf(buffer, sizeof(buffer),
                 "TRANSTOK:%d:%d:%s:%s:%s:",
                 getuid(),
                 getpid(),
                 udspath,
                 challenge,
                 response);
  if (len == sizeof(buffer))
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
    int addrsize = sizeof(addr);
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
