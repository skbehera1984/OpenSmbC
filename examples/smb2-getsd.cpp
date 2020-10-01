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

#include <string>

int usage(void)
{
  fprintf(stderr, "Usage:\n"
          "smb2-raw-getsd-async <smb2-url>\n\n"
          "URL format: "
          "smb://[<domain;][<username>@]<host>/<share>/<path>\n");
  exit(1);
}

int main(int argc, char *argv[])
{
  std::string err;
  Smb2ContextPtr smb2;
  struct smb2_url *url;

  if (argc < 2)
    usage();

  smb2 = Smb2Context::create();
  if (smb2 == NULL) {
    fprintf(stderr, "Failed to init context\n");
    exit(0);
  }

  url = smb2_parse_url(smb2, argv[1], err);
  if (url == NULL) {
    fprintf(stderr, "Failed to parse url: %s\n", err.c_str());
    exit(0);
  }

  smb2->smb2SetSecurityMode(SMB2_NEGOTIATE_SIGNING_ENABLED);
  smb2->smb2SetPassword("");
  smb2->smb2SetAuthMode(SMB2_SEC_NTLMSSP);

  if (smb2->smb2_connect_share(url->server, url->share, url->user, err) != 0)
  {
    printf("smb2_connect_share failed. %s\n", err.c_str());
    exit(10);
  }

  uint8_t *securityBuf = NULL;
  uint32_t secLen = 0;
  if (smb2->smb2_get_security(url->path, &securityBuf, &secLen, err) != 0)
  {
    printf("Failed to get security descriptor - %s\n", err.c_str());
    exit(10);
  }

  struct smb2_security_descriptor *sd = nullptr;
  smb2DecodeSecurityDescriptor(&sd, securityBuf, secLen, err);

  printSecurityDescriptor(sd);
  smb2FreeSecurityDescriptor(sd);
  free(securityBuf);

  smb2->smb2_disconnect_share();
  smb2_destroy_url(url);

  return 0;
}
