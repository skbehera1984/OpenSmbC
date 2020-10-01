#include <inttypes.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "smb2.h"
#include "util.h"

int usage(void)
{
        fprintf(stderr, "Usage:\n"
                "smb2-ls-sync <smb2-url>\n\n"
                "URL format: "
                "smb://<domain;username>@<host>/\n");
        exit(1);
}

int main(int argc, char *argv[])
{
        std::string err;
        Smb2ContextPtr smb2 = nullptr;
        smb2_url *url;

        if (argc < 2) {
                usage();
        }

        smb2 = Smb2Context::create();
        if (smb2 == nullptr) {
                fprintf(stderr, "Failed to init context\n");
                exit(0);
        }

        url = smb2_parse_url(smb2, argv[1], err);
        if (url == NULL) {
                fprintf(stderr, "Failed to parse url: %s\n", err.c_str());
                exit(0);
        }

        smb2->smb2SetSecurityMode(SMB2_NEGOTIATE_SIGNING_ENABLED);
        smb2->smb2SetAuthMode(SMB2_SEC_NTLMSSP);
        smb2->smb2SetDomain(url->domain);
        smb2->smb2SetPassword(""); // Set the password for the user

		uint8_t *sid = NULL;
        if (smb2->smb2_lookUpSid(url->user, url->domain, url->server, &sid, err) < 0)
        {
			printf("Failed to get sid - %s\n", err.c_str());
			exit(0);
        }
		printf("get sid successful\n");

        struct smb2_sid *m_sid = (struct smb2_sid *)sid;
        printf("Revision = %d, SubAuthCount = %d\n", m_sid->revision, m_sid->sub_auth_count);
        printf("ID_AUTH = %d,%d,%d,%d,%d,%d\n", m_sid->id_auth[0],m_sid->id_auth[1],m_sid->id_auth[2],m_sid->id_auth[3],m_sid->id_auth[4],m_sid->id_auth[5]);
        int i = 0;
        printf("SubAuth= ");
        for (; i < m_sid->sub_auth_count; i++) {
                printf("0x%x, ", m_sid->sub_auth[i]);
        }
        printf("\n");

        smb2_destroy_url(url);

	return 0;
}
