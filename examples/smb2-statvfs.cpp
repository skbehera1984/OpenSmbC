#include <fcntl.h>
#include <inttypes.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

#include "smb2.h"

int usage(void)
{
  fprintf(stderr, "Usage:\n"
          "smb2-statvfs-sync <smb2-url>\n\n"
          "URL format: "
          "smb://[<domain;][<username>@]<host>/<share>/<path>\n");
  exit(1);
}

int main(int argc, char *argv[])
{
  std::string err;
  Smb2ContextPtr smb2;
  struct smb2_url *url;
  struct smb2_statvfs vfs;

  if (argc < 2)
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
  if (smb2_connect_share(smb2, url->server, url->share, url->user, err) != 0)
  {
    printf("smb2_connect_share failed. %s\n", err.c_str());
    exit(10);
  }

  if (smb2_statvfs(smb2, url->path, &vfs, err) < 0)
  {
    printf("smb2_statvfs failed. %s\n", err.c_str());
    exit(10);
  }
  printf("Blocksize:%d\n", vfs.f_bsize);
  printf("Blocks:%"PRIu64"\n", vfs.f_blocks);
  printf("Free:%"PRIu64"\n", vfs.f_bfree);
  printf("Avail:%"PRIu64"\n", vfs.f_bavail);

  smb2_disconnect_share(smb2);
  smb2_destroy_url(url);

  return 0;
}
