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
                "smb2-cat-sync <smb2-url>\n\n"
                "URL format: "
                "smb://[<domain;][<username>@]<host>/<share>/<path>\n");
        exit(1);
}

int main(int argc, char *argv[])
{
  std::string err;
  Smb2ContextPtr smb2;

  if (argc < 2) {
    usage();
  }

  smb2 = Smb2Context::create();
  if (smb2 == NULL)
  {
    fprintf(stderr, "Failed to init context\n");
    exit(0);
  }

  smb2_url *url = smb2_parse_url(smb2, argv[1]);
  if (url == NULL) {
    fprintf(stderr, "Failed to parse url: %s\n", smb2->smb2_get_error());
    exit(0);
  }

  smb2->smb2SetSecurityMode(SMB2_NEGOTIATE_SIGNING_ENABLED);
  smb2->smb2SetPassword("Welcome@123");
  smb2->smb2SetAuthMode(SMB2_SEC_NTLMSSP);

  if (smb2->smb2_connect_share(url->server, url->share, url->user, err) != 0) {
    printf("smb2_connect_share failed. %s\n", err.c_str());
    exit(10);
  }

  smb2fh *fh = smb2->smb2_open(url->path, O_RDONLY, err);
  if (fh == NULL) {
    printf("smb2_open failed. %s\n", err.c_str());
    exit(10);
  }

  uint32_t status = 0;
  while ((status = smb2->smb2_pread(fh, buf, 1024, pos, err)) != SMB2_STATUS_END_OF_FILE ) {
    write(0, buf, fh->byte_count);
    pos += fh->byte_count;
  }
  // EOF might have returned some data
  if (fh->byte_count) {
    write(0, buf, fh->byte_count);
    pos += fh->byte_count;
  }

  smb2->smb2_close(fh, err);
  smb2->smb2_disconnect_share();
  smb2_destroy_url(url);

  return 0;
}
