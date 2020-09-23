#include <inttypes.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "smb2.h"
#include "util.h"

int usage(void)
{
        fprintf(stderr, "Usage:\n"
                "smb2-ls-sync <smb2-url>\n\n"
                "URL format: "
                "smb://[<domain;][<username>@]<host>/\n");
        exit(1);
}

int main(int argc, char *argv[])
{
        std::string err;
        Smb2ContextPtr smb2;
        struct smb2_url *url = NULL;
        smb2_shares shares;

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
        smb2->smb2SetAuthMode(SMB2_SEC_NTLMSSP);
        smb2->smb2SetPassword("Welcome@123");

        if (smb2->smb2_list_shares(url->server,
                             url->user,
                             2, /*query share info type*/
                             shares, err) < 0) {
                printf("failed to get share list Error : %s\n", err.c_str());
                return -1;
        }

        if (shares.share_info_type == 1) {
                printf("%-30s %-11s\n", "ShareName", "ShareType");
                printf("%-30s %-11s\n", "=========", "=========");
        } else if (shares.share_info_type == 2) {
                printf("%-30s %-11s %-100s\n", "ShareName", "ShareType", "SharePath");
                printf("%-30s %-11s %-100s\n", "=========", "=========", "=========");
        }
        for(smb2_shareinfo entry : shares.sharelist)
        {
          if (shares.share_info_type == 1)
          {
            printf("%-30s %-11x\n", entry.name.c_str(), entry.share_type);
          }
          else if (shares.share_info_type == 2)
          {
            printf("%-30s %-11x %-100s\n", entry.name.c_str(), entry.share_type, entry.path.c_str());
          }
        }

       return 0;
}
