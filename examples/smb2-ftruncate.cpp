#include <fcntl.h>
#include <inttypes.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

#include "smb2.h"
#include "util.h"

int usage(void)
{
  fprintf(stderr, "Usage:\n"
          "smb2-ftruncate-sync <smb2-url> <length>\n\n"
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

  if (argc < 3)
  {
    usage();
  }

  smb2 = Smb2Context::create();
  if (smb2 == NULL)
  {
    fprintf(stderr, "Failed to init context\n");
    exit(0);
  }

  url = smb2_parse_url(smb2, argv[1], err);
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

  fh = smb2->smb2_open(url->path, O_RDWR, err);
  if (fh == NULL)
  {
    printf("smb2_open failed. %s\n", err.c_str());
    exit(10);
  }

  if (smb2->smb2_ftruncate(fh, strtoll(argv[2], NULL, 10), err) < 0)
  {
    printf("smb2_ftruncate failed. %s\n", err.c_str());
    smb2->smb2_close(fh, err);
    exit(10);
  }

  smb2->smb2_close(fh, err);
  smb2->smb2_disconnect_share();
  smb2_destroy_url(url);

  return 0;
}
