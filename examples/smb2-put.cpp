#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "smb2.h"
#include "util.h"

uint8_t buf[256 * 1024];
uint32_t pos;

int usage(void)
{
  fprintf(stderr, "Usage:\n"
          "smb2-put-sync <file> <smb2-url>\n\n"
          "URL format: "
          "smb://[<domain;][<username>@]<host>/<share>/<path>\n");
  exit(1);
}

int main(int argc, char *argv[])
{
  std::string err;
  Smb2ContextPtr smb2;
  struct smb2_url *url;
  smb2fh *fh;
  int count;
  int fd;

  if (argc < 2)
  {
    usage();
  }

  fd = open(argv[1], O_RDONLY);
  if (fd == -1)
  {
    printf("Failed to open local file %s (%s)\n", argv[1], strerror(errno));
    exit(10);
  }

  smb2 = Smb2Context::create();
  if (smb2 == NULL)
  {
    fprintf(stderr, "Failed to init context\n");
    exit(0);
  }

  url = smb2_parse_url(smb2, argv[2], err);
  if (url == NULL)
  {
    fprintf(stderr, "Failed to parse url: %s\n", err.c_str());
    exit(0);
  }

  smb2->smb2SetSecurityMode(SMB2_NEGOTIATE_SIGNING_ENABLED);

  if (smb2->smb2_connect_share(url->server, url->share, url->user, err) != 0)
  {
    printf("smb2_connect_share failed. %s\n", err.c_str());
    exit(10);
  }

  fh = smb2->smb2_open(url->path, O_WRONLY|O_CREAT, err);
  if (fh == NULL)
  {
    printf("smb2_open failed. %s\n", err.c_str());
    exit(10);
  }

  while ((count = read(fd, buf, 1024)) > 0)
  {
    smb2->smb2_write(fh, buf, count, err);
  };

  close(fd);
  smb2->smb2_close(fh, err);
  smb2->smb2_disconnect_share();
  smb2_destroy_url(url);

  return 0;
}
