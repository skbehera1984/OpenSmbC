#ifndef _KRB5_AUTH_PROVIDER_H_
#define _KRB5_AUTH_PROVIDER_H_

#include "Smb2AuthProvider.h"

#include <gssapi/gssapi.h>
#include <string>

using namespace std;

struct private_auth_data
{
  gss_ctx_id_t context;
  gss_cred_id_t cred;
  gss_name_t user_name;
  gss_name_t target_name;
  gss_const_OID mech_type;
  uint32_t req_flags;
  gss_buffer_desc output_token;
  char *g_server;
};

class Krb5AuthProvider : public Smb2AuthProvider
{
public:
  Krb5AuthProvider() {}
  virtual ~Krb5AuthProvider();

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
  void           krb5_free_auth_data();
  unsigned char* krb5_get_output_token_buffer();
  int            krb5_get_output_token_length();

  int krb5_negotiate_reply(string&  server,
                           string&  domain,
                           string&  user_name,
                           string&  password,
                           bool     use_cached_creds,
                           string&  err);

  int krb5_session_get_session_key(uint8_t       **session_key,
                                   uint8_t       *session_key_size,
                                   std::string&  err);

  int krb5_session_request(unsigned char         *buf,
                           int                   len,
                           string&               err);

  std::string krb5_get_gss_error(std::string function, uint32_t maj, uint32_t min);

public:
  struct private_auth_data *krb5AuthData;
};

#endif // _KRB5_AUTH_PROVIDER_H_
