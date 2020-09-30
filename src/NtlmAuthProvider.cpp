#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "NtlmAuthProvider.h"
#include "Endian.h"
#include "smb2.h"
#include "util.h"

#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/md4.h>

using namespace std;

#define NEGOTIATE_MESSAGE      0x00000001
#define CHALLENGE_MESSAGE      0x00000002
#define AUTHENTICATION_MESSAGE 0x00000003

#define NTLMSSP_NEGOTIATE_56                               0x80000000
#define NTLMSSP_NEGOTIATE_128                              0x20000000
#define NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY         0x00080000
#define NTLMSSP_TARGET_TYPE_SERVER                         0x00020000
#define NTLMSSP_NEGOTIATE_ALWAYS_SIGN                      0x00008000
#define NTLMSSP_NEGOTIATE_NTLM                             0x00000200
#define NTLMSSP_NEGOTIATE_SIGN                             0x00000010
#define NTLMSSP_REQUEST_TARGET                             0x00000004
#define NTLMSSP_NEGOTIATE_OEM                              0x00000002
#define NTLMSSP_NEGOTIATE_UNICODE                          0x00000001
#define NTLMSSP_NEGOTIATE_KEY_EXCH                         0x40000000

static int
NTOWFv1(const char *password, unsigned char password_hash[16])
{
  struct ucs2 *ucs2_password = NULL;

  ucs2_password = utf8_to_ucs2(password);
  if (ucs2_password == NULL)
    return -1;

  MD4((unsigned char *)ucs2_password->val, ucs2_password->len * 2, password_hash);
  free(ucs2_password);

  return 0;
}

static int
NTOWFv2(const char *user, const char *password, const char *domain, unsigned char ntlmv2_hash[16])
{
  int i, len;
  char *userdomain;
  struct ucs2 *ucs2_userdomain = NULL;
  unsigned char ntlm_hash[16];

  if (NTOWFv1(password, ntlm_hash) < 0)
    return -1;

  len = strlen(user) + 1;
  if (domain)
    len += strlen(domain);

  userdomain = (char*)malloc(len);
  if (userdomain == NULL)
    return -1;

  strcpy(userdomain, user);
  for (i = strlen(userdomain) - 1; i >=0; i--)
  {
    if (islower(userdomain[i]))
    {
      userdomain[i] = toupper(userdomain[i]);
    }
  }
  if (domain)
  {
    strcat(userdomain, domain);
  }

  ucs2_userdomain = utf8_to_ucs2(userdomain);
  if (ucs2_userdomain == NULL)
    return -1;

  unsigned int mdlen = 0;
  HMAC(EVP_md5(), ntlm_hash, 16, (unsigned char *)ucs2_userdomain->val, ucs2_userdomain->len * 2, ntlmv2_hash, &mdlen);
  free(userdomain);
  free(ucs2_userdomain);

  return 0;
}

ntlm_auth_data::ntlm_auth_data()
{
  buf = NULL;
  len = 0;
  allocated = 0;
  neg_result = 0;
  ntlm_buf = NULL;
  ntlm_len = 0;
  user.clear(); password.clear(); domain.clear(); workstation.clear();
  client_challenge = NULL;
  memset(exported_session_key, 0, SMB2_KEY_SIZE);
}

NtlmAuthProvider::~NtlmAuthProvider()
{
  ntlmssp_destroy_context();
}

void
NtlmAuthProvider::ntlmssp_destroy_context()
{
  if (ntlmAuthData == NULL)
    return;

  if (ntlmAuthData->ntlm_buf)
  {
    free(ntlmAuthData->ntlm_buf); ntlmAuthData->ntlm_buf = NULL;
  }
  if (ntlmAuthData->buf)
  {
    free(ntlmAuthData->buf); ntlmAuthData->buf = NULL;
  }

  memset(ntlmAuthData->exported_session_key, 0, SMB2_KEY_SIZE);
  free(ntlmAuthData);
}

int
NtlmAuthProvider::ntlmssp_init_context(string& user,
                                       string& password,
                                       string& domain,
                                       string& workstation,
                                       const char *client_challenge)
{
  ntlmAuthData = new ntlm_auth_data();
  if (ntlmAuthData == NULL)
    return -1;

  ntlmAuthData->user        = user;
  ntlmAuthData->password    = password;
  ntlmAuthData->domain      = domain;
  ntlmAuthData->workstation = workstation;
  ntlmAuthData->client_challenge = client_challenge;

  memset(ntlmAuthData->exported_session_key, 0, SMB2_KEY_SIZE);

  return 0;
}

static int
encoder(const void *buffer, size_t size, void *ptr)
{
  ntlm_auth_data *auth_data = (ntlm_auth_data *)ptr;

  if (size + auth_data->len > auth_data->allocated)
  {
    unsigned char *tmp = auth_data->buf;

    auth_data->allocated = 2 * ((size + auth_data->allocated + 256) & ~0xff);
    auth_data->buf = (unsigned char*)malloc(auth_data->allocated);
    if (auth_data->buf == NULL)
    {
      free(tmp);
      return -1;
    }
    memcpy(auth_data->buf, tmp, auth_data->len);
    free(tmp);
  }

  memcpy(auth_data->buf + auth_data->len, buffer, size);
  auth_data->len += size;

  return 0;
}

int
NtlmAuthProvider::ntlm_negotiate_message()
{
  unsigned char ntlm[32];
  uint32_t u32;

  memset(ntlm, 0, 32);
  memcpy(ntlm, "NTLMSSP", 8);

  u32 = htole32(NEGOTIATE_MESSAGE);
  memcpy(&ntlm[8], &u32, 4);

  u32 = htole32(NTLMSSP_NEGOTIATE_56|NTLMSSP_NEGOTIATE_128|
                NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY|
                //NTLMSSP_NEGOTIATE_ALWAYS_SIGN|
                NTLMSSP_NEGOTIATE_NTLM|
                //NTLMSSP_NEGOTIATE_SIGN|
                NTLMSSP_REQUEST_TARGET|NTLMSSP_NEGOTIATE_OEM|
                NTLMSSP_NEGOTIATE_UNICODE);
  memcpy(&ntlm[12], &u32, 4);

  if (encoder(&ntlm[0], 32, ntlmAuthData) < 0)
    return -1;

  return 0;
}

static int
ntlm_challenge_message(ntlm_auth_data *auth_data, unsigned char *buf, int len)
{
  if (auth_data->ntlm_buf) {
    free(auth_data->ntlm_buf); auth_data->ntlm_buf = NULL;
  }
  auth_data->ntlm_len = len;
  auth_data->ntlm_buf = (unsigned char*)malloc(auth_data->ntlm_len);
  if (auth_data->ntlm_buf == NULL) {
    return -1;
  }
  memcpy(auth_data->ntlm_buf, buf, auth_data->ntlm_len);

  return 0;
}

/* This is not the same temp as in MS-NLMP. This temp has an additional
 * 16 bytes at the start of the buffer.
 * Use &auth_data->val[16] if you want the temp from MS-NLMP
 */
static int
encode_temp(ntlm_auth_data *auth_data, uint64_t t, char *client_challenge,
            char *server_challenge, char *server_name, int server_name_len)
{
  unsigned char sign[8] = {0x01, 0x01, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00};
  unsigned char zero[8] = {0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00};

  if (encoder(&zero, 8, auth_data) < 0) {
    return -1;
  }
  if (encoder(server_challenge, 8, auth_data) < 0) {
    return -1;
  }
  if (encoder(sign, 8, auth_data) < 0) {
    return -1;
  }
  if (encoder(&t, 8, auth_data) < 0) {
    return -1;
  }
  if (encoder(client_challenge, 8, auth_data) < 0) {
    return -1;
  }
  if (encoder(&zero, 4, auth_data) < 0) {
    return -1;
  }
  if (encoder(server_name, server_name_len, auth_data) < 0) {
    return -1;
  }
  if (encoder(&zero, 4, auth_data) < 0) {
    return -1;
  }

  return 0;
}

static int
encode_ntlm_auth(Smb2ContextPtr smb2, ntlm_auth_data *auth_data, char *server_challenge)
{
  int ret = -1;
  unsigned char lm_buf[16];
  unsigned char *NTChallengeResponse_buf = NULL;
  unsigned char ResponseKeyNT[16];
  struct ucs2 *ucs2_domain = NULL;
  struct ucs2 *ucs2_user = NULL;
  struct ucs2 *ucs2_workstation = NULL;
  int NTChallengeResponse_len;
  unsigned char NTProofStr[16];
  unsigned char LMStr[16];
  uint64_t t;
  struct smb2_timeval tv;
  char *server_name_buf;
  int server_name_len;
  uint32_t u32;
  uint32_t server_neg_flags;
  unsigned char key_exch[SMB2_KEY_SIZE];
  unsigned int mdlen = 0;

  tv.tv_sec = time(NULL);
  tv.tv_usec = 0;
  t = timevalToWinEpoch(&tv);

  /* Generate Concatenation of(NTProofStr, temp) */
  if (NTOWFv2(auth_data->user.c_str(),
              auth_data->password.c_str(),
              auth_data->domain.c_str(),
              ResponseKeyNT) < 0)
  {
    goto finished;
  }

  /* get the server neg flags */
  memcpy(&server_neg_flags, &auth_data->ntlm_buf[20], 4);
  server_neg_flags = le32toh(server_neg_flags);

  memcpy(&u32, &auth_data->ntlm_buf[40], 4);
  u32 = le32toh(u32);
  server_name_len = u32 >> 16;

  memcpy(&u32, &auth_data->ntlm_buf[44], 4);
  u32 = le32toh(u32);
  server_name_buf = (char *)&auth_data->ntlm_buf[u32];

  if (encode_temp(auth_data, t, (char *)auth_data->client_challenge,
                  server_challenge, server_name_buf,
                  server_name_len) < 0)
  {
    return -1;
  }

  HMAC(EVP_md5(), ResponseKeyNT, 16, &auth_data->buf[8], auth_data->len-8, NTProofStr, &mdlen);
  memcpy(auth_data->buf, NTProofStr, 16);

  NTChallengeResponse_buf = auth_data->buf;
  NTChallengeResponse_len = auth_data->len;
  auth_data->buf = NULL;
  auth_data->len = 0;
  auth_data->allocated = 0;

  /* get the NTLMv2 Key-Exchange Key
     For NTLMv2 - Key Exchange Key is the Session Base Key
   */
  HMAC(EVP_md5(), ResponseKeyNT, 16, NTProofStr, 16, key_exch, &mdlen);
  memcpy(auth_data->exported_session_key, key_exch, 16);

  /* Generate AUTHENTICATE_MESSAGE */
  encoder("NTLMSSP", 8, auth_data);

  /* message type */
  u32 = htole32(AUTHENTICATION_MESSAGE);
  encoder(&u32, 4, auth_data);

  /* lm challenge response fields */
  memcpy(&lm_buf[0], server_challenge, 8);
  memcpy(&lm_buf[8], auth_data->client_challenge, 8);
  HMAC(EVP_md5(), ResponseKeyNT, 16, &lm_buf[0], 16, LMStr, &mdlen);
  u32 = htole32(0x00180018);
  encoder(&u32, 4, auth_data);
  u32 = 0;
  encoder(&u32, 4, auth_data);

  /* nt challenge response fields */
  u32 = htole32((NTChallengeResponse_len<<16)|
  NTChallengeResponse_len);
  encoder(&u32, 4, auth_data);
  u32 = 0;
  encoder(&u32, 4, auth_data);

  /* domain name fields */
  if (!auth_data->domain.empty())
  {
    ucs2_domain = utf8_to_ucs2(auth_data->domain.c_str());
    if (ucs2_domain == NULL)
    {
      goto finished;
    }
    u32 = ucs2_domain->len * 2;
    u32 = htole32((u32 << 16) | u32);
    encoder(&u32, 4, auth_data);
    u32 = 0;
    encoder(&u32, 4, auth_data);
  }
  else
  {
    u32 = 0;
    encoder(&u32, 4, auth_data);
    encoder(&u32, 4, auth_data);
  }

  /* user name fields */
  ucs2_user = utf8_to_ucs2(auth_data->user.c_str());
  if (ucs2_user == NULL)
  {
    goto finished;
  }
  u32 = ucs2_user->len * 2;
  u32 = htole32((u32 << 16) | u32);
  encoder(&u32, 4, auth_data);
  u32 = 0;
  encoder(&u32, 4, auth_data);

  /* workstation name fields */
  if (!auth_data->workstation.empty())
  {
    ucs2_workstation = utf8_to_ucs2(auth_data->workstation.c_str());
    if (ucs2_workstation == NULL)
    {
      goto finished;
    }
    u32 = ucs2_workstation->len * 2;
    u32 = htole32((u32 << 16) | u32);
    encoder(&u32, 4, auth_data);
    u32 = 0;
    encoder(&u32, 4, auth_data);
  }
  else
  {
    u32 = 0;
    encoder(&u32, 4, auth_data);
    encoder(&u32, 4, auth_data);
  }

  /* encrypted random session key */
  u32 = 0;
  encoder(&u32, 4, auth_data);
  encoder(&u32, 4, auth_data);

  /* negotiate flags */
  u32 = htole32(NTLMSSP_NEGOTIATE_56|NTLMSSP_NEGOTIATE_128|
                NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY|
                //NTLMSSP_NEGOTIATE_ALWAYS_SIGN|
                NTLMSSP_NEGOTIATE_NTLM|
                //NTLMSSP_NEGOTIATE_SIGN|
                NTLMSSP_REQUEST_TARGET|NTLMSSP_NEGOTIATE_OEM|
                NTLMSSP_NEGOTIATE_UNICODE);
  encoder(&u32, 4, auth_data);

  /* append domain */
  u32 = htole32(auth_data->len);
  memcpy(&auth_data->buf[32], &u32, 4);
  if (ucs2_domain)
  {
    encoder(ucs2_domain->val, ucs2_domain->len * 2, auth_data);
  }

  /* append user */
  u32 = htole32(auth_data->len);
  memcpy(&auth_data->buf[40], &u32, 4);
  encoder(ucs2_user->val, ucs2_user->len * 2, auth_data);

  /* append workstation */
  u32 = htole32(auth_data->len);
  memcpy(&auth_data->buf[48], &u32, 4);
  if (ucs2_workstation)
  {
    encoder(ucs2_workstation->val, ucs2_workstation->len * 2, auth_data);
  }

  /* append LMChallengeResponse */
  u32 = htole32(auth_data->len);
  memcpy(&auth_data->buf[16], &u32, 4);
  encoder(LMStr, 16, auth_data);
  encoder(auth_data->client_challenge, 8, auth_data);

  /* append NTChallengeResponse */
  u32 = htole32(auth_data->len);
  memcpy(&auth_data->buf[24], &u32, 4);
  encoder(NTChallengeResponse_buf, NTChallengeResponse_len, auth_data);

  ret = 0;
finished:
  free(ucs2_domain);
  free(ucs2_user);
  free(ucs2_workstation);
  free(NTChallengeResponse_buf);

  return ret;
}

int
NtlmAuthProvider::ntlmssp_generate_blob(Smb2ContextPtr smb2,
                                        unsigned char  *input_buf,
                                        int            input_len,
                                        unsigned char  **output_buf,
                                        uint16_t       *output_len)
{
  if (ntlmAuthData->buf)
  {
    free(ntlmAuthData->buf); ntlmAuthData->buf = NULL;
  }
  ntlmAuthData->len = 0;
  ntlmAuthData->allocated = 0;

  if (input_buf == NULL)
  {
    ntlm_negotiate_message();
  }
  else
  {
    if (ntlm_challenge_message(ntlmAuthData, input_buf, input_len) < 0)
    {
      return -1;
    }
    if (encode_ntlm_auth(smb2, ntlmAuthData, (char *)&ntlmAuthData->ntlm_buf[24]) < 0)
    {
      return -1;
    }
  }

  *output_buf = ntlmAuthData->buf;
  *output_len = ntlmAuthData->len;

  return 0;
}

int
NtlmAuthProvider::ntlmssp_get_session_key(uint8_t **key, uint8_t *key_size)
{
  uint8_t *mkey = NULL;

  if (ntlmAuthData == NULL || key == NULL || key_size == NULL) {
    return -1;
  }

  mkey = (uint8_t *) malloc(SMB2_KEY_SIZE);
  if (mkey == NULL) {
    return -1;
  }
  memcpy(mkey, ntlmAuthData->exported_session_key, SMB2_KEY_SIZE);

  *key = mkey;
  *key_size = SMB2_KEY_SIZE;

  return 0;
}

int
NtlmAuthProvider::negotiateReply(Smb2ContextPtr smb2, std::string& err)
{
  if (smb2->password.empty())
  {
    err = "No password set, can not use NTLM";
    return -1;
  }
  return ntlmssp_init_context(smb2->user,
                              smb2->password,
                              smb2->domain,
                              smb2->workstation,
                              smb2->client_challenge);
}

int
NtlmAuthProvider::sessionRequest(Smb2ContextPtr smb2,
                                 unsigned char  *inBuf,
                                 int            inBufLen,
                                 unsigned char  **OutBuf,
                                 uint16_t       *OutBufLen,
                                 std::string&   err)
{
  return ntlmssp_generate_blob(smb2, inBuf, inBufLen, OutBuf, OutBufLen);
}

int
NtlmAuthProvider::getSessionKey(Smb2ContextPtr  smb2,
                                uint8_t         **key,
                                uint8_t         *key_size,
                                std::string&    err)
{
  return ntlmssp_get_session_key(key, key_size);
}
