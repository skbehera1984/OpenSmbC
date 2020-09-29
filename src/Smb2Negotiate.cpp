#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <string.h>

#include "Smb2Negotiate.h"
#include "Smb2SessionSetup.h"
#include "Krb5AuthProvider.h"
#include "NtlmAuthProvider.h"

Smb2Negotiate::Smb2Negotiate(Smb2ContextPtr smb2,
                             AppData *negotiateData)
  : Smb2Pdu(smb2, SMB2_NEGOTIATE, negotiateData)
{
}

Smb2Negotiate::~Smb2Negotiate()
{
}

int
Smb2Negotiate::encodeNegotiateContexts(Smb2ContextPtr smb2,
                                       struct smb2_negotiate_request *req,
                                       uint16_t *num_ctx)
{
  uint16_t ctx_count = 0;

  if (req->neg_ctx_flags & SMB2_NEG_PREAUTH)
  {
    uint8_t *buf;
    int len = 0;

    len = sizeof (smb2_preauth_integ_context);
    if ((len & 0x07) != 0)
    {
      int padlen = 8 - (len & 0x07);
      len += padlen;
    }

    buf = (uint8_t*)malloc(len);
    if (buf == NULL)
    {
      smb2->smb2_set_error("Failed to allocate preauth-integ context buffer");
      return -1;
    }
    memset(buf, 0, len);

    smb2_iovec iov(buf, len, free);
    out.smb2_add_iovector(iov);

    iov.smb2_set_uint16(0, req->preauth_ctx.hdr.ContextType);
    iov.smb2_set_uint16(2, req->preauth_ctx.hdr.DataLength);
    iov.smb2_set_uint32(4, req->preauth_ctx.hdr.Reserved);
    iov.smb2_set_uint16(8, req->preauth_ctx.HashAlgorithmCount);
    iov.smb2_set_uint16(10, req->preauth_ctx.SaltLength);
    iov.smb2_set_uint16(12, req->preauth_ctx.HashAlgorithms);

    memcpy(iov.buf + 14, req->preauth_ctx.Salt, SMB2_PREAUTH_INTEGRITY_SALT_SIZE);
    ctx_count++;
  }

  if (req->neg_ctx_flags & SMB2_NEG_ENC_CAP)
  {
    uint8_t *buf;
    int len = 0;

    len = sizeof(smb2_enc_cap_context);
    if ((len & 0x07) != 0)
    {
      int padlen = 8 - (len & 0x07);
      len += padlen;
    }

    buf = (uint8_t*)malloc(len);
    if (buf == NULL)
    {
      smb2->smb2_set_error("Failed to allocate encryption context buffer");
      return -1;
    }
    memset(buf, 0, len);

    smb2_iovec iov(buf, len, free);
    out.smb2_add_iovector(iov);

    iov.smb2_set_uint16(0, req->enc_ctx.hdr.ContextType);
    iov.smb2_set_uint16(2, req->enc_ctx.hdr.DataLength);
    iov.smb2_set_uint32(4, req->enc_ctx.hdr.Reserved);
    iov.smb2_set_uint16(8, req->enc_ctx.CipherCount);
    iov.smb2_set_uint16(10, req->enc_ctx.Ciphers[0]);
    iov.smb2_set_uint16(12, req->enc_ctx.Ciphers[1]);

    ctx_count++;
  }

  *num_ctx = ctx_count;

  return 0;
}

int
Smb2Negotiate::encodeRequest(Smb2ContextPtr smb2, void *Req)
{
  uint8_t *buf;
  int i, len;
  struct smb2_negotiate_request *req = (struct smb2_negotiate_request *)Req;

  uint16_t ctx_count = 0;

  len = SMB2_NEGOTIATE_REQUEST_SIZE + req->dialect_count * sizeof(uint16_t);

  if ((len & 0x07) != 0)
  {
    int padlen = 8 - (len & 0x07);
    len += padlen;
  }

  buf = (uint8_t*)malloc(len);
  if (buf == NULL)
  {
    smb2->smb2_set_error("Failed to allocate negotiate buffer");
    return -1;
  }
  memset(buf, 0, len);

  smb2_iovec iov(buf, len, free);
  out.smb2_add_iovector(iov);

  iov.smb2_set_uint16(0, SMB2_NEGOTIATE_REQUEST_SIZE);
  iov.smb2_set_uint16(2, req->dialect_count);
  iov.smb2_set_uint16(4, req->security_mode);
  iov.smb2_set_uint32(8, req->capabilities);
  memcpy(iov.buf + 12, req->client_guid, SMB2_GUID_SIZE);

  for (i = 0; i < req->dialect_count; i++)
    iov.smb2_set_uint16(36 + i * sizeof(uint16_t), req->dialects[i]);

  encodeNegotiateContexts(smb2, req, &ctx_count);

  if (req->max_dialect < SMB2_VERSION_0311)
  {
    iov.smb2_set_uint64(28, req->client_start_time);
  }
  else
  {
    req->neg_context_count = ctx_count;
    req->reserved = 0;
    req->neg_context_offset = SMB2_HEADER_SIZE + len;
    iov.smb2_set_uint32(28, req->neg_context_offset);
    iov.smb2_set_uint16(32, req->neg_context_count);
    iov.smb2_set_uint16(34, req->reserved);
  }

  return 0;
}

Smb2Pdu *
Smb2Negotiate::createPdu(Smb2ContextPtr                smb2,
                         struct smb2_negotiate_request *req,
                         AppData                       *negotiateData)
{
  Smb2Pdu *pdu = nullptr;

  pdu = new Smb2Negotiate(smb2, negotiateData);
  if (pdu == nullptr)
    return nullptr;

  if (pdu->encodeRequest(smb2, req))
  {
    delete pdu;
    return NULL;
  }

  pdu->out.smb2_pad_to_64bit();

  return pdu;
}

#define IOV_OFFSET (rep->security_buffer_offset - SMB2_HEADER_SIZE - \
                    (SMB2_NEGOTIATE_REPLY_SIZE & 0xfffe))

int
Smb2Negotiate::smb2ReplyProcessFixed(Smb2ContextPtr smb2)
{
  if (smb2_is_error_response()) {
    return smb2_process_error_fixed(smb2);
  }

  struct smb2_negotiate_reply *rep;
  smb2_iovec &iov = in.iovs.back();
  uint16_t struct_size;

  rep = (struct smb2_negotiate_reply *)malloc(sizeof(*rep));
  if (rep == NULL) {
    smb2->smb2_set_error("Failed to allocate negotiate reply");
    return -1;
  }
  memset(rep, 0, sizeof(struct smb2_negotiate_reply));
  this->payload = rep;

  iov.smb2_get_uint16(0, &struct_size);
  if (struct_size != SMB2_NEGOTIATE_REPLY_SIZE || (struct_size & 0xfffe) != iov.len)
  {
    smb2->smb2_set_error("Unexpected size of Negotiate reply. Expected %d, got %d", SMB2_NEGOTIATE_REPLY_SIZE, (int)iov.len);
    return -1;
  }

  iov.smb2_get_uint16(2, &rep->security_mode);
  iov.smb2_get_uint16(4, &rep->dialect_revision);
  iov.smb2_get_uint16(6, &rep->neg_context_count);
  memcpy(rep->server_guid, iov.buf + 8, SMB2_GUID_SIZE);
  iov.smb2_get_uint32(24, &rep->capabilities);
  iov.smb2_get_uint32(28, &rep->max_transact_size);
  iov.smb2_get_uint32(32, &rep->max_read_size);
  iov.smb2_get_uint32(36, &rep->max_write_size);
  iov.smb2_get_uint64(40, &rep->system_time);
  iov.smb2_get_uint64(48, &rep->server_start_time);
  iov.smb2_get_uint16(56, &rep->security_buffer_offset);
  iov.smb2_get_uint16(58, &rep->security_buffer_length);
  iov.smb2_get_uint32(60, &rep->neg_context_offset);

  if (rep->security_buffer_length == 0 && rep->neg_context_count == 0) {
    return 0;
  }

  /* I assume the security buffer is packed before negotiate contextx */
  if (rep->security_buffer_length) {
    if (rep->security_buffer_offset < SMB2_HEADER_SIZE + (SMB2_NEGOTIATE_REPLY_SIZE & 0xfffe)) {
      smb2->smb2_set_error("Securty buffer overlaps with negotiate reply header");
      return -1;
    }
  }

  /* return the size of data left to read -
   * pad after fixed part + Securty buffer + padding + negotiate contexts + padding if any
   * padding before/after/in-between the buffers
   */
  return (this->respNBLength - this->in.total_size);
}

int
Smb2Negotiate::decodePreauthIntegContext(Smb2ContextPtr smb2,
                                         smb2_iovec   *iov,
                                         struct smb2_negotiate_reply *rep)
{
  uint16_t ContextType;
  uint16_t DataLength;
  uint16_t HashAlgorithmCount;
  uint16_t serverSaltSize;
  int i = 0, offset = 0;
  uint16_t *allHashAlgorithms = NULL;

  iov->smb2_get_uint16(0, &ContextType);
  iov->smb2_get_uint16(2, &DataLength);
  iov->smb2_get_uint16(8, &HashAlgorithmCount);
  iov->smb2_get_uint16(10, &serverSaltSize);

  allHashAlgorithms = (uint16_t*) malloc(HashAlgorithmCount * sizeof(uint16_t));
  if (allHashAlgorithms == NULL)
  {
    smb2->smb2_set_error("Failed to allocate buffer for allHashAlgorithms");
    return -1;
  }

  offset = 12;
  for (; i < HashAlgorithmCount; i++)
  {
    iov->smb2_get_uint16(offset, &allHashAlgorithms[i]);
    offset += sizeof(uint16_t);
  }

  /* use the first hash algorithm */
  smb2->hashAlgorithm = allHashAlgorithms[0];

  //memcpy(smb2->serverSalt, iov->buf + offset, serverSaltSize);
  offset += serverSaltSize;

  return offset;
}

int
Smb2Negotiate::decodeEncryptionContext(Smb2ContextPtr smb2,
                                       smb2_iovec   *iov,
                                       struct smb2_negotiate_reply *rep)
{
  uint16_t ContextType;
  uint16_t DataLength;
  uint16_t CipherCount;
  int i = 0, offset = 0;
  uint16_t *Ciphers = NULL;

  iov->smb2_get_uint16(0, &ContextType);
  iov->smb2_get_uint16(2, &DataLength);
  iov->smb2_get_uint16(8, &CipherCount);

  Ciphers = (uint16_t*) malloc(CipherCount * sizeof(uint16_t));
  if (Ciphers == NULL)
  {
    smb2->smb2_set_error("Failed to allocate buffer for Ciphers");
    return -1;
  }

  offset = 10;
  for (; i < CipherCount; i++)
  {
    iov->smb2_get_uint16(offset, &Ciphers[i]);
    offset += sizeof(uint16_t);
  }

  /* use the first cipher */
  smb2->CipherId = Ciphers[0];

  return offset;
}

int
Smb2Negotiate::decodeNegotiateContexts(Smb2ContextPtr smb2,
                                       smb2_iovec   *iov,
                                       struct smb2_negotiate_reply *rep)
{
  int i = 0;
  uint32_t len = 0;
  uint16_t ctx_type = 0;

  for (; i< rep->neg_context_count; i++)
  {
    smb2_iovec tmpiov;
    tmpiov.buf = &iov->buf[len];
    tmpiov.len = iov->len - len;

    /* get the context type first */
    tmpiov.smb2_get_uint16(0, &ctx_type);
    if (ctx_type == SMB2_PREAUTH_INTEGRITY_CAPABILITIES)
    {
      len = decodePreauthIntegContext(smb2, &tmpiov, rep);
      if (len < 0)
      {
        smb2->smb2_set_error("Failed to decode preauth_integ_context - %s", smb2->smb2_get_error());
        return -1;
      }
    }
    else if (ctx_type == SMB2_ENCRYPTION_CAPABILITIES)
    {
      len = decodeEncryptionContext(smb2, &tmpiov, rep);
      if (len < 0)
      {
        smb2->smb2_set_error("Failed to decode encryption context - %s", smb2->smb2_get_error());
        return -1;
      }
    }

    /* check for any padding */
    if ((len & 0x07) != 0)
    {
      int padlen = 8 - (len & 0x07);
      len += padlen;
    }
  }
  return 0;
}

int Smb2Negotiate::smb2ReplyProcessVariable(Smb2ContextPtr smb2)
{
  if (smb2_is_error_response()) {
    return smb2_process_error_variable(smb2);
  }

  struct smb2_negotiate_reply *rep = (struct smb2_negotiate_reply *)this->payload;
  smb2_iovec &iov = in.iovs.back();
  smb2_iovec tmpiov;
  uint32_t len = 0;

  /* get the security buffer */
  rep->security_buffer = &iov.buf[IOV_OFFSET];

  /* get the contexts */
  len = IOV_OFFSET + rep->security_buffer_length;
  if ((len & 0x07) != 0)
  {
    int padlen = 8 - (len & 0x07);
    len += padlen;
  }

  tmpiov.buf = &iov.buf[len];
  tmpiov.len = iov.len - len;
  if (decodeNegotiateContexts(smb2, &tmpiov, rep) < 0)
  {
    smb2->smb2_set_error("Failed to decode smb2 negotiate contexts - %s", smb2->smb2_get_error());
    return -1;
  }

  return 0;
}

int
Smb2Negotiate::smb2ProcessReplyAndAppData(Smb2ContextPtr smb2)
{
  uint32_t status = header_resp.status;
  std::string err;
  struct smb2_negotiate_reply *rep = (struct smb2_negotiate_reply *)payload;
  int ret;

  appData->setNtStatus(status);

  if (status != SMB2_STATUS_SUCCESS)
  {
    smb2->close();
    err = stringf("Negotiate failed with (0x%08x) %s", status, nterror_to_str(status));
    appData->setErrorMsg(err);
    smb2->endSendReceive();
    return 0;
  }

  if (rep->dialect_revision >= SMB2_VERSION_0311 && rep->neg_context_count == 0)
  {
    err = string("Server negotiated SMB 3.11 without negotiate context");
    appData->setStatusMsg(SMB2_STATUS_INVALID_PARAMETER, err);
    smb2->endSendReceive();
    return 0;
  }

  if (rep->dialect_revision >= SMB2_VERSION_0311 &&
      smb2->CipherId != 0 &&
      rep->capabilities & SMB2_GLOBAL_CAP_ENCRYPTION)
  {
    /* server can return encryption context but not support encryption */
    smb2->serverSupportEncryption = 1;
  }

  /* update the context with the server capabilities */
  if (rep->dialect_revision > SMB2_VERSION_0202)
  {
    if (rep->capabilities & SMB2_GLOBAL_CAP_LARGE_MTU)
    {
      smb2->supports_multi_credit = true;
    }
  }

  smb2->max_transact_size = rep->max_transact_size;
  smb2->max_read_size     = rep->max_read_size;
  smb2->max_write_size    = rep->max_write_size;
  smb2->dialect           = rep->dialect_revision;

  if (rep->security_mode & SMB2_NEGOTIATE_SIGNING_REQUIRED || rep->dialect_revision >= SMB2_VERSION_0311)
  {
#if !defined(HAVE_OPENSSL_LIBS)
    err = string("Server requires msg signing. OpenSSL library is needed");
    appData->setStatusMsg(SMB2_STATUS_NOT_SUPPORTED, err);
    smb2->endSendReceive();
    return 0;
#endif
    /* the SMB 3.11 server doesn't specify signing required, but expects the msg to be signed */
    smb2->signing_required = 1;
  }

  if (rep->dialect_revision >= SMB2_VERSION_0311)
  {
#if !defined(HAVE_OPENSSL_LIBS)
    err = "Server negotiated SMB 3.11. OpenSSL library is required to generate pre-auth integrity hash";
    appData->setStatusMsg(SMB2_STATUS_NOT_SUPPORTED, err);
    smb2->endSendReceive();
    return 0;
#else
    if (smb2->PreauthIntegrityHash)
      free(smb2->PreauthIntegrityHash);

    smb2->PreauthIntegrityHash = (uint8_t*)calloc(1, EVP_MD_size(EVP_sha512()));
    if (smb2->PreauthIntegrityHash == NULL)
    {
      err = "Failed to allocate buffer for PreauthIntegrityHash";
      appData->setStatusMsg(SMB2_STATUS_NOT_SUPPORTED, err);
      smb2->endSendReceive();
      return 0;
    }
    smb2->preauthIntegrityHashLength = EVP_MD_size(EVP_sha512());

    // hash the request
    if (smb2UpdatePreauthIntegrityHash(smb2, &out, err) < 0)
    {
      err = stringf("NEG_REQ - smb2UpdatePreauthIntegrityHash failed - %s", err.c_str());
      appData->setStatusMsg(SMB2_STATUS_INSUFFICIENT_RESOURCES, err);
      smb2->endSendReceive();
      return 0;
    }
    // hash the response
    if (smb2UpdatePreauthIntegrityHash(smb2, &in, err) < 0)
    {
      err = stringf("NEG_RESP - smb2UpdatePreauthIntegrityHash failed - %s", err.c_str());
      appData->setStatusMsg(SMB2_STATUS_INSUFFICIENT_RESOURCES, err);
      smb2->endSendReceive();
      return 0;
    }
#endif
  }

  // Create the authenticator
  if (smb2->authenticator)
  {
    delete smb2->authenticator;
    smb2->authenticator = nullptr;
  }

  if (smb2->sec == SMB2_SEC_KRB5)
    smb2->authenticator = new Krb5AuthProvider();
  else
    smb2->authenticator = new NtlmAuthProvider();

  if (smb2->authenticator == nullptr)
  {
    err = "Failed to create Authenticator object";
    smb2->close();
    appData->setStatusMsg(SMB2_STATUS_NO_MEMORY, err);
    smb2->endSendReceive();
    return 0;
  }

  if (smb2->authenticator->negotiateReply(smb2, err) < 0)
  {
    smb2->close();
    appData->setStatusMsg(SMB2_STATUS_LOGON_FAILURE, err);
    smb2->endSendReceive();
    return 0;
  }

  /* Now send the session setup request */
  Smb2Pdu *pdu;
  struct smb2_session_setup_request req;

  memset(&req, 0, sizeof(struct smb2_session_setup_request));
  req.security_mode = smb2->security_mode;

  ret = smb2->authenticator->sessionRequest(smb2, NULL, 0,
                                            &req.security_buffer,
                                            &req.security_buffer_length,
                                            err);
  if (ret < 0)
  {
    err = "Auth sessionRequest Failed :" + err;
    appData->setStatusMsg(SMB2_STATUS_INTERNAL_ERROR, err);
    smb2->close();
    smb2->endSendReceive();
    return 0;
  }

  pdu = Smb2SessionSetup::createPdu(smb2, &req, appData);
  if (pdu == NULL)
  {
    err = "Failed to create SessionSetup PDU";
    appData->setStatusMsg(SMB2_STATUS_NO_MEMORY, err);
    smb2->endSendReceive();
    smb2->close();
    return 0;
  }

  if (!smb2->smb2_queue_pdu(pdu, err))
  {
    err = "Failed to send PDU:" + err;
    appData->setStatusMsg(SMB2_STATUS_INTERNAL_ERROR, err);
    smb2->endSendReceive();
    smb2->close();
    return 0;
  }

  return 0;
}
