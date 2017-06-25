/*
 * Compile using:
 *     gcc -o get_transient_token get_transient_token.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/select.h>

#define CHALLENGE_SIZE 32
#define TIMEOUT_SECS   10

int main()
{
  int rc;

  /* Create unix domain socket */
  char udspath[32] = "/tmp/uds";
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
  char challenge[CHALLENGE_SIZE];
  char response[CHALLENGE_SIZE];
  // XXX TODO!!

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
  daemon(0, 0);

  /* Listen for up to the timeout */
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

    char inchallenge[CHALLENGE_SIZE];  
    read(fdc, inchallenge, CHALLENGE_SIZE);
    if (memcmp(challenge, inchallenge, CHALLENGE_SIZE) == 0)
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
