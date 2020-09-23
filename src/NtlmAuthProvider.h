#ifndef _NTLM_AUTH_PROVIDER_H_
#define _NTLM_AUTH_PROVIDER_H_

#include "smb2.h"
#include "Smb2AuthProvider.h"
#include "PrivateData.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <ctype.h>
#include <stdio.h>
#include <time.h>
#include <string>

using namespace std;

class ntlm_auth_data
{
public:
  ntlm_auth_data();

  unsigned char *buf;
  uint64_t len;
  uint64_t allocated;

  int neg_result;
  unsigned char *ntlm_buf;
  int ntlm_len;

  string user;
  string password;
  string domain;
  string workstation;
  const char *client_challenge;

  uint8_t exported_session_key[SMB2_KEY_SIZE];
};

class NtlmAuthProvider : public Smb2AuthProvider
{
public:
  NtlmAuthProvider() {}
  virtual ~NtlmAuthProvider();

  int negotiateReply(Smb2ContextPtr smb2, std::string& err);
  int sessionRequest(Smb2ContextPtr smb2,
                     unsigned char  *inBuf,
                     int            inBufLen,
                     unsigned char  **OutBuf,
                     uint16_t       *OutBufLen,
                     std::string&   err);
  int getSessionKey(Smb2ContextPtr  smb2,
                    uint8_t         **key,
                    uint8_t         *key_size,
                    std::string&    err);

private:
  int ntlm_negotiate_message();

  int ntlmssp_init_context(string& user,
                           string& password,
                           string& domain,
                           string& workstation,
                           const char *client_challenge);

  int ntlmssp_generate_blob(Smb2ContextPtr smb2,
                            unsigned char  *input_buf,
                            int            input_len,
                            unsigned char  **output_buf,
                            uint16_t       *output_len);

  void ntlmssp_destroy_context();

  int ntlmssp_get_session_key(uint8_t **key,
                              uint8_t *key_size);


public:
  ntlm_auth_data *ntlmAuthData;
};

#endif // _NTLM_AUTH_PROVIDER_H_
