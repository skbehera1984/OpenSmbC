#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <string.h>
#include "Smb2SessionSetup.h"
#include "Smb2TreeConnect.h"
#include "Krb5AuthProvider.h"
#include "NtlmAuthProvider.h"

/* strings used to derive SMB signing and encryption keys */
static const char SMB2AESCMAC[] = "SMB2AESCMAC";
static const char SmbSign[] = "SmbSign";
static const char SMBSigningKey[] = "SMBSigningKey";
/* The following strings will be used for deriving other keys
static const char SMB2APP[] = "SMB2APP";
static const char SmbRpc[] = "SmbRpc";
static const char SMB2AESCCM[] = "SMB2AESCCM";
static const char ServerOut[] = "ServerOut";
static const char ServerIn[] = "ServerIn ";
static const char SMBAppKey[] = "SMBAppKey";
static const char SMBS2CCipherKey[] = "SMBS2CCipherKey";
static const char SMBC2SCipherKey[] = "SMBC2SCipherKey";
*/

Smb2SessionSetup::Smb2SessionSetup(Smb2ContextPtr smb2,
                                   AppData *sessionData)
 : Smb2Pdu(smb2, SMB2_SESSION_SETUP, sessionData)
{
}

Smb2SessionSetup::~Smb2SessionSetup()
{
}

int
Smb2SessionSetup::encodeRequest(Smb2ContextPtr smb2, void *Req)
{
  int len;
  uint8_t *buf;
  struct smb2_session_setup_request *req = (struct smb2_session_setup_request *)Req;

  len = SMB2_SESSION_SETUP_REQUEST_SIZE & 0xfffffffe;
  buf = (uint8_t*)malloc(len);
  if (buf == NULL) {
    smb2->smb2_set_error("Failed to allocate session setup buffer");
    return -1;
  }
  memset(buf, 0, len);

  smb2_iovec iov(buf, len, free);
  out.smb2_add_iovector(iov);

  iov.smb2_set_uint16(0, SMB2_SESSION_SETUP_REQUEST_SIZE);
  iov.smb2_set_uint8(2, req->flags);
  iov.smb2_set_uint8(3, req->security_mode);
  iov.smb2_set_uint32(4, req->capabilities);
  iov.smb2_set_uint32(8, req->channel);
  iov.smb2_set_uint16(12, SMB2_HEADER_SIZE + 24);
  iov.smb2_set_uint16(14, req->security_buffer_length);
  iov.smb2_set_uint64(16, req->previous_session_id);

  /* Security buffer */
  buf = (uint8_t*)malloc(req->security_buffer_length);
  if (buf == NULL) {
    smb2->smb2_set_error("Failed to allocate secbuf");
    return -1;
  }
  memcpy(buf, req->security_buffer, req->security_buffer_length);

  iov.buf = buf; iov.len = req->security_buffer_length; iov.free = free;
  out.smb2_add_iovector(iov);

  return 0;
}

Smb2Pdu *
Smb2SessionSetup::createPdu(Smb2ContextPtr                    smb2,
                            struct smb2_session_setup_request *req,
                            AppData                           *sessionData)
{
  Smb2Pdu *pdu;

  pdu = new Smb2SessionSetup(smb2, sessionData);
  if (pdu == NULL) {
    return NULL;
  }

  if (pdu->encodeRequest(smb2, req))
  {
    delete pdu;
    return NULL;
  }

  pdu->out.smb2_pad_to_64bit();

  return pdu;
}

#define IOV_OFFSET (rep->security_buffer_offset - SMB2_HEADER_SIZE - \
                    (SMB2_SESSION_SETUP_REPLY_SIZE & 0xfffe))

int
Smb2SessionSetup::smb2ReplyProcessFixed(Smb2ContextPtr smb2)
{
  if (smb2_is_error_response()) {
    return smb2_process_error_fixed(smb2);
  }

  struct smb2_session_setup_reply *rep;
  smb2_iovec &iov = in.iovs.back();
  uint16_t struct_size;

  rep = (struct smb2_session_setup_reply *)malloc(sizeof(*rep));
  if (rep == NULL) {
    smb2->smb2_set_error("Failed to allocate session setup reply");
    return -1;
  }
  this->payload = rep;

  iov.smb2_get_uint16(0, &struct_size);
  if (struct_size != SMB2_SESSION_SETUP_REPLY_SIZE || (struct_size & 0xfffe) != iov.len)
  {
    smb2->smb2_set_error("Unexpected size of Session Setup reply. Expected %d, got %d", SMB2_SESSION_SETUP_REPLY_SIZE, (int)iov.len);
    return -1;
  }

  iov.smb2_get_uint16(2, &rep->session_flags);
  iov.smb2_get_uint16(4, &rep->security_buffer_offset);
  iov.smb2_get_uint16(6, &rep->security_buffer_length);

  /* Update session ID to use for future PDUs */
  smb2->session_id = this->header_resp.session_id;

  if (rep->security_buffer_length == 0) {
    return 0;
  }
  if (rep->security_buffer_offset < SMB2_HEADER_SIZE + (SMB2_SESSION_SETUP_REPLY_SIZE & 0xfffe))
  {
    smb2->smb2_set_error("Securty buffer overlaps with Session Setup reply header");
    return -1;
  }

  /* Return the amount of data that the security buffer will take up.
   * Including any padding before the security buffer itself.
   */
  return IOV_OFFSET + rep->security_buffer_length;
}

int
Smb2SessionSetup::smb2ReplyProcessVariable(Smb2ContextPtr smb2)
{
  if (smb2_is_error_response()) {
    return smb2_process_error_variable(smb2);
  }

  struct smb2_session_setup_reply *rep = (struct smb2_session_setup_reply *)this->payload;
  smb2_iovec &iov = in.iovs.back();

  rep->security_buffer = &iov.buf[IOV_OFFSET];

  return 0;
}

int
Smb2SessionSetup::smb2ProcessReplyAndAppData(Smb2ContextPtr smb2)
{
  uint32_t status = header_resp.status;
  std::string err;
  struct smb2_session_setup_reply *rep = (struct smb2_session_setup_reply *)payload;

  appData->setNtStatus(status);
  if (status != SMB2_STATUS_SUCCESS && status != SMB2_STATUS_MORE_PROCESSING_REQUIRED)
  {
    smb2->close();
    err = stringf("Session setup failed with (0x%08x) %s", status, nterror_to_str(status));
    appData->setStatusMsg(status, err);
    smb2->endSendReceive();
    return 0;
  }

  // update PreauthIntegrityHash
  if (smb2->dialect >= SMB2_VERSION_0311)
  {
#if !defined(HAVE_OPENSSL_LIBS)
    err = "Dialect negotiated is SMB 3.11. OpenSSL library is required"
          " to generate pre-auth integrity hash";
    appData->setStatusMsg(SMB2_STATUS_NOT_SUPPORTED, err);
    smb2->endSendReceive();
    return 0;
#else
    // hash the request
    if (smb2UpdatePreauthIntegrityHash(smb2, &out, err) < 0)
    {
      err = stringf("SSETUP 1 - smb2UpdatePreauthIntegrityHash failed - %s", err.c_str());
      appData->setStatusMsg(SMB2_STATUS_INSUFFICIENT_RESOURCES, err);
      smb2->endSendReceive();
      return 0;
    }
    if (status != SMB2_STATUS_SUCCESS)
    {
      // hash the response
      /* The last successful SessionSetup response is not used in PreauthIntegrityHash calculation */
      if (smb2UpdatePreauthIntegrityHash (smb2, &in, err) < 0)
      {
        err = stringf("SSETUP 2 - smb2UpdatePreauthIntegrityHash failed - %s", err.c_str());
        appData->setStatusMsg(SMB2_STATUS_INSUFFICIENT_RESOURCES, err);
        smb2->endSendReceive();
        return 0;
      }
    }
#endif
  }

  if (status == SMB2_STATUS_MORE_PROCESSING_REQUIRED)
  {
    Smb2Pdu *pdu;
    struct smb2_session_setup_request req;

    /* Session setup request. */
    memset(&req, 0, sizeof(struct smb2_session_setup_request));
    req.security_mode = smb2->security_mode;

    int ret = smb2->authenticator->sessionRequest(smb2,
                                                  rep->security_buffer,
                                                  rep->security_buffer_length,
                                                  &req.security_buffer,
                                                  &req.security_buffer_length,
                                                  err);
    if (ret < 0)
    {
      smb2->close();
      appData->setStatusMsg(SMB2_STATUS_INTERNAL_ERROR, err);
      smb2->endSendReceive();
      return 0;
    }

    pdu = Smb2SessionSetup::createPdu(smb2, &req, appData);
    if (pdu == NULL)
    {
      err = "Failed to create Smb2SessionSetup PDU";
      smb2->close();
      appData->setStatusMsg(SMB2_STATUS_NO_MEMORY, err);
      smb2->endSendReceive();
      return 0;
    }
    smb2->smb2_queue_pdu(pdu, err);
    return 0;
  }
  else if (smb2->sec == SMB2_SEC_KRB5)
  {
    /* For NTLM the status will be
     * SMB2_STATUS_MORE_PROCESSING_REQUIRED and a second call to
     * gss_init_sec_context will complete the gss session.
     * But for krb5 a second call to gss_init_sec_context is
     * required if GSS_C_MUTUAL_FLAG is set
     */
    if (smb2->authenticator->sessionRequest(smb2,
                                            rep->security_buffer,
                                            rep->security_buffer_length,
                                            NULL,
                                            NULL,
                                            err) < 0)
    {
      appData->setStatusMsg(SMB2_STATUS_INTERNAL_ERROR, err);
      smb2->endSendReceive();
      return 0;
    }
  }

  if (smb2->signing_required)
  {
    uint8_t zero_key[SMB2_KEY_SIZE] = {0};
    int have_valid_session_key = 1;

    if (smb2->authenticator->getSessionKey(smb2, &smb2->session_key,&smb2->session_key_size, err) < 0)
    {
      have_valid_session_key = 0;
    }

    /* check if the session key is proper */
    if (smb2->session_key == NULL || memcmp(smb2->session_key, zero_key, SMB2_KEY_SIZE) == 0)
    {
      have_valid_session_key = 0;
    }
    if (have_valid_session_key == 0)
    {
      smb2->close();
      err = "Signing required by server. Session Key is not available";
      appData->setStatusMsg(SMB2_STATUS_NO_USER_SESSION_KEY, err);
      smb2->endSendReceive();
      return 0;
    }

    /* Derive the signing key from session key
     * This is based on negotiated protocol
     */
    if (smb2->dialect == SMB2_VERSION_0202 || smb2->dialect == SMB2_VERSION_0210)
    {
      /* For SMB2 session key is the signing key */
      memcpy(smb2->signing_key, smb2->session_key, MIN(smb2->session_key_size, SMB2_KEY_SIZE));
    }
    else if (smb2->dialect <= SMB2_VERSION_0302)
    {
#ifdef HAVE_OPENSSL_LIBS
      smb2_derive_key(smb2->session_key,
                      smb2->session_key_size,
                      SMB2AESCMAC,
                      sizeof(SMB2AESCMAC),
                      SmbSign,
                      sizeof(SmbSign),
                      smb2->signing_key);
#else
      smb2->close();
      err = "Signing Requires OpenSSL support";
      appData->setStatusMsg(SMB2_STATUS_NOT_SUPPORTED, err);
      smb2->endSendReceive();
      return 0;
#endif
    }
    else if (smb2->dialect > SMB2_VERSION_0302)
    {
#ifdef HAVE_OPENSSL_LIBS
      smb2_derive_key(smb2->session_key,
                      smb2->session_key_size,
                      SMBSigningKey,
                      sizeof(SMBSigningKey),
                      (char *)smb2->PreauthIntegrityHash,
                      smb2->preauthIntegrityHashLength,
                      smb2->signing_key);
#else
      smb2->close();
      err = "Signing Requires OpenSSL support";
      appData->setStatusMsg(SMB2_STATUS_NOT_SUPPORTED, err);
      smb2->endSendReceive();
      return 0;
#endif
    }
  }

  // Now that we are sending tree connect, authenticator is not required anymore
  delete smb2->authenticator;
  smb2->authenticator = nullptr;

  //Build tree connect request
  std::string uncPath = std::string("\\\\") + smb2->server + std::string("\\") + smb2->share;
  /* UNC for the share in ucs2 format */
  struct ucs2 *ucs2_unc = utf8_to_ucs2(uncPath.c_str());
  if (ucs2_unc == NULL)
  {
    err = stringf("Count not convert UNC:[%s] into UCS2", uncPath.c_str());
    smb2->close();
    appData->setStatusMsg(SMB2_STATUS_NO_MEMORY, err);
    smb2->endSendReceive();
    return -1;
  }

  struct smb2_tree_connect_request req;
  memset(&req, 0, sizeof(struct smb2_tree_connect_request));
  req.flags       = 0;
  req.path_length = 2 * ucs2_unc->len;
  req.path        = ucs2_unc->val;

  Smb2Pdu *pdu = NULL;
  pdu = Smb2TreeConnect::createPdu(smb2, &req, appData);
  if (pdu == NULL)
  {
    smb2->close();
    err = "Failed to create Smb2TreeConnect PDU";
    appData->setStatusMsg(SMB2_STATUS_NO_MEMORY, err);
    smb2->endSendReceive();
    return -1;
  }

  free(ucs2_unc);
  smb2->smb2_queue_pdu(pdu, err);

  return 0;
}

#ifdef HAVE_OPENSSL_LIBS
void
Smb2SessionSetup::smb2_derive_key(uint8_t     *derivation_key,
                                  uint32_t    derivation_key_len,
                                  const char  *label,
                                  uint32_t    label_len,
                                  const char  *context,
                                  uint32_t    context_len,
                                  uint8_t     derived_key[SMB2_KEY_SIZE])
{
  const uint32_t counter = htobe32(1);
  const uint32_t keylen = htobe32(SMB2_KEY_SIZE * 8);
  static uint8_t nul = 0;
  uint8_t final_hash[256/8] = {0};
  uint8_t input_key[SMB2_KEY_SIZE] = {0};
  unsigned int finalHashSize = sizeof(final_hash);

#if (OPENSSL_VERSION_NUMBER <= OPENSSL_VER_102)
  HMAC_CTX hmac = {0};

  memcpy(input_key, derivation_key, MIN(sizeof(input_key), derivation_key_len));
  HMAC_CTX_init(&hmac);
  HMAC_Init_ex(&hmac, input_key, sizeof(input_key), EVP_sha256(), NULL);

  /* i */
  HMAC_Update(&hmac, (unsigned char*) &counter, sizeof(counter));
  /* label */
  HMAC_Update(&hmac, (unsigned char*) label, label_len);
  /* 0x00 */
  HMAC_Update(&hmac, &nul, sizeof(nul));
  /* context */
  HMAC_Update(&hmac, (unsigned char*) context, context_len);
  /* L */
  HMAC_Update(&hmac, (unsigned char*) &keylen, sizeof(keylen));

  HMAC_Final(&hmac, final_hash, &finalHashSize);
  HMAC_CTX_cleanup(&hmac);
#else
  HMAC_CTX *hmac = HMAC_CTX_new();

  HMAC_CTX_reset(hmac);
  memcpy(input_key, derivation_key, MIN(sizeof(input_key), derivation_key_len));
  HMAC_Init_ex(hmac, input_key, sizeof(input_key), EVP_sha256(), NULL);

  /* i */
  HMAC_Update(hmac, (unsigned char*) &counter, sizeof(counter));
  /* label */
  HMAC_Update(hmac, (unsigned char*) label, label_len);
  /* 0x00 */
  HMAC_Update(hmac, &nul, sizeof(nul));
  /* context */
  HMAC_Update(hmac, (unsigned char*) context, context_len);
  /* L */
  HMAC_Update(hmac, (unsigned char*) &keylen, sizeof(keylen));

  HMAC_Final(hmac, final_hash, &finalHashSize);
  HMAC_CTX_free(hmac); hmac= NULL;
#endif
  memcpy(derived_key, final_hash, MIN(finalHashSize, SMB2_KEY_SIZE));
}
#endif
