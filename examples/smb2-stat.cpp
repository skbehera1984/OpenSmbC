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
#include "util.h"

int usage(void)
{
  fprintf(stderr, "Usage:\n"
          "smb2-stat-sync <smb2-url>\n\n"
          "URL format: "
          "smb://[<domain;][<username>@]<host>/<share>/<path>\n");
  exit(1);
}

int main(int argc, char *argv[])
{
  std::string err;
  Smb2ContextPtr smb2;
  struct smb2_url *url;
  struct smb2_stat_64 st;
  time_t t;

  if (argc < 2) {
    usage();
  }

  smb2 = Smb2Context::create();
  if (smb2 == NULL) {
    fprintf(stderr, "Failed to init context\n");
    exit(0);
  }

  url = smb2_parse_url(smb2, argv[1]);
  if (url == NULL) {
    fprintf(stderr, "Failed to parse url: %s\n", smb2->smb2_get_error());
    exit(0);
  }

  smb2->smb2SetSecurityMode(SMB2_NEGOTIATE_SIGNING_ENABLED);

  if (smb2->smb2_connect_share(url->server, url->share, url->user, err) != 0)
  {
    printf("smb2_connect_share failed. %s\n", err.c_str());
    exit(10);
  }

  if (smb2->smb2_stat(url->path, &st, err) < 0)
  {
    printf("smb2_stat failed. %s\n", err.c_str());
    exit(10);
  }

  switch (st.smb2_type)
  {
    case SMB2_TYPE_FILE:
      printf("Type:FILE\n");
    break;
    case SMB2_TYPE_DIRECTORY:
      printf("Type:DIRECTORY\n");
    break;
    default:
      printf("Type:unknown\n");
    break;
  }
  printf("Size:%"PRIu64"\n", st.smb2_size);
  printf("Inode:0x%"PRIx64"\n", st.smb2_ino);
  printf("Links:%"PRIu32"\n", st.smb2_nlink);
  t = SMBTimeToUTime(st.smb2_atime);
  printf("Atime:%s", asctime(localtime(&t)));
  t = SMBTimeToUTime(st.smb2_mtime);
  printf("Mtime:%s", asctime(localtime(&t)));
  t = SMBTimeToUTime(st.smb2_ctime);
  printf("Ctime:%s", asctime(localtime(&t)));

  smb2->smb2_disconnect_share();
  smb2_destroy_url(url);

  return 0;
}
