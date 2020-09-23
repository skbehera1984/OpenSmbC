#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "Smb2Pdu.h"
#include "Smb2Signing.h"

Smb2Pdu::Smb2Pdu(Smb2ContextPtr    smb2,
                 enum smb2_command command,
                 AppData           *appData)
{
  // first initialize to defaults
  memset(&header, 0 , sizeof(struct smb2_header));
  memset(hdr, 0, SMB2_HEADER_SIZE);
  out.clear();
  next_compound = nullptr;
  respNBLength = 0;
  memset(&header_resp, 0 , sizeof(struct smb2_header));
  payload = nullptr;
  in.clear();
  this->appData = nullptr;
  this->bIsLastInCompound = true;

  char magic[4] = {0xFE, 'S', 'M', 'B'};
  memcpy(header.protocol_id, magic, 4);

  /* ZERO out the signature. Signature calculation happens by zeroing out */
  memset(header.signature, 0, 16);

  header.struct_size = SMB2_HEADER_SIZE;
  header.command = command;
  header.flags = 0;
  header.sync.process_id = 0xFEFF;

  if (smb2->dialect == SMB2_VERSION_0202)
  {
    header.credit_charge = 0;
  }
  else if (header.command == SMB2_NEGOTIATE)
  {
    /* We don't have any credits yet during negprot */
    header.credit_charge = 0;
  }
  else
  {
    /* Defaults to 1
     * Multi-Credit requests like READ/WRITE/IOCTL/QUERYDIR
     * will adjusted this after it has marshalled the fixed part of the PDU.
     */
    header.credit_charge = 1;
  }
  header.credit_request_response = MAX_CREDITS - smb2->credits;

  switch (command)
  {
    case SMB2_NEGOTIATE:
    case SMB2_SESSION_SETUP:
    case SMB2_LOGOFF:
    case SMB2_ECHO:
    /* case SMB2_CANCEL: */
    break;
    default:
      header.sync.tree_id = smb2->tree_id;
  }

  switch (command)
  {
    case SMB2_NEGOTIATE:
    break;
    default:
      header.session_id = smb2->session_id;
  }

  this->appData = appData;

  out.smb2_add_iovector(hdr, SMB2_HEADER_SIZE, NULL);
}

Smb2Pdu::~Smb2Pdu()
{
  if (next_compound)
  {
    delete next_compound;
    next_compound = NULL;
  }

  out.smb2_free_iovector();
  in.smb2_free_iovector();
  if (payload)
  {
    free(payload);
    payload = NULL;
  }
  if (appData)
  {
    if (appData->isDelete())
    {
      delete appData;
      appData = nullptr;
    }
  }
}

uint32_t Smb2Pdu::getReqNBLength()
{
  uint32_t netBiosLen = this->out.total_size;

  Smb2Pdu *tmp = this->next_compound;
  while (tmp)
  {
    netBiosLen += tmp->out.total_size;
    tmp = tmp->next_compound;
  }
  return netBiosLen;
}

uint32_t Smb2Pdu::getReqCreditCharge()
{
  uint32_t creditCharge = this->header.credit_charge;

  Smb2Pdu *tmp = this->next_compound;
  while (tmp)
  {
    creditCharge += tmp->header.credit_charge;
    tmp = tmp->next_compound;
  }
  return creditCharge;
}

smb2_io_vectors Smb2Pdu::getAllComOutVecs()
{
  smb2_io_vectors allVecs;

  allVecs.smb2_append_iovectors(this->out);

  Smb2Pdu *tmp = this->next_compound;
  while (tmp)
  {
    allVecs.smb2_append_iovectors(tmp->out);
    tmp = tmp->next_compound;
  }
  return allVecs;
}

void Smb2Pdu::setResponseHeader(struct smb2_header *rhdr)
{
  memcpy(header_resp.protocol_id, rhdr->protocol_id, 4);
  header_resp.struct_size = rhdr->struct_size;
  header_resp.credit_charge = rhdr->credit_charge;
  header_resp.status = rhdr->status;
  header_resp.command = rhdr->command;
  header_resp.credit_request_response = rhdr->credit_request_response;
  header_resp.flags = rhdr->flags;
  header_resp.next_command = rhdr->next_command;
  header_resp.message_id = rhdr->message_id;
  if (rhdr->flags & SMB2_FLAGS_ASYNC_COMMAND)
  {
    header_resp.async.async_id = rhdr->async.async_id;
  }
  else
  {
    header_resp.sync.process_id = rhdr->sync.process_id;
    header_resp.sync.tree_id = rhdr->sync.tree_id;
  }
  header_resp.session_id = rhdr->session_id;
  memcpy(header_resp.signature, rhdr->signature, 16);
}

void
Smb2Pdu::smb2_add_compound_pdu(Smb2Pdu *next_pdu)
{
  Smb2Pdu *pdu = this;

  /* find the last pdu in the chain */
  while (pdu->next_compound)
    pdu = pdu->next_compound;

  /* Fixup the next command offset in the header */
  pdu->header.next_command = pdu->out.total_size;

  /* Fixup flags */
  next_pdu->header.flags |= SMB2_FLAGS_RELATED_OPERATIONS;

  /* set nest pdu */
  pdu->next_compound = next_pdu;
}

void Smb2Pdu::encodeHeader(Smb2ContextPtr smb2)
{
  smb2_iovec *iov = &out.iovs[0];
  struct smb2_header *hdr = &header;

  hdr->message_id = smb2->message_id++;
  if (hdr->credit_charge > 1)
  {
    smb2->message_id += (hdr->credit_charge - 1);
  }

  memcpy(iov->buf, hdr->protocol_id, 4);
  iov->smb2_set_uint16(4, hdr->struct_size);
  iov->smb2_set_uint16(6, hdr->credit_charge);
  iov->smb2_set_uint32(8, hdr->status);
  iov->smb2_set_uint16(12, hdr->command);
  iov->smb2_set_uint16(14, hdr->credit_request_response);
  iov->smb2_set_uint32(16, hdr->flags);
  iov->smb2_set_uint32(20, hdr->next_command);
  iov->smb2_set_uint64(24, hdr->message_id);

  if (hdr->flags & SMB2_FLAGS_ASYNC_COMMAND)
  {
    iov->smb2_set_uint64(32, hdr->async.async_id);
  }
  else
  {
    iov->smb2_set_uint32(32, hdr->sync.process_id);
    iov->smb2_set_uint32(36, hdr->sync.tree_id);
  }

  iov->smb2_set_uint64(40, hdr->session_id);
  memcpy(iov->buf + 48, hdr->signature, 16);
}

int
Smb2Pdu::decodeHeader(smb2_iovec *iov, struct smb2_header *hdr, string& err)
{
  if (iov->len != SMB2_HEADER_SIZE) {
    err = string("io vector for header is wrong size");
    return -1;
  }

  memcpy(&hdr->protocol_id, iov->buf, 4);
  iov->smb2_get_uint16(4, &hdr->struct_size);
  iov->smb2_get_uint16(6, &hdr->credit_charge);
  iov->smb2_get_uint32(8, &hdr->status);
  iov->smb2_get_uint16(12, &hdr->command);
  iov->smb2_get_uint16(14, &hdr->credit_request_response);
  iov->smb2_get_uint32(16, &hdr->flags);
  iov->smb2_get_uint32(20, &hdr->next_command);
  iov->smb2_get_uint64(24, &hdr->message_id);

  if (hdr->flags & SMB2_FLAGS_ASYNC_COMMAND)
  {
    iov->smb2_get_uint64(32, &hdr->async.async_id);
  }
  else
  {
    iov->smb2_get_uint32(32, &hdr->sync.process_id);
    iov->smb2_get_uint32(36, &hdr->sync.tree_id);
  }

  iov->smb2_get_uint64(40, &hdr->session_id);
  memcpy(&hdr->signature, iov->buf + 48, 16);

  return 0;
}

int Smb2Pdu::smb2ReplyGetFixedSize()
{
  if (smb2_is_error_response())
    return (SMB2_ERROR_REPLY_SIZE & 0xfffe);

  switch (header.command)
  {
    case SMB2_NEGOTIATE:
      return (SMB2_NEGOTIATE_REPLY_SIZE & 0xfffe);
    case SMB2_SESSION_SETUP:
      return (SMB2_SESSION_SETUP_REPLY_SIZE & 0xfffe);
    case SMB2_LOGOFF:
      return (SMB2_LOGOFF_REPLY_SIZE & 0xfffe);
    case SMB2_TREE_CONNECT:
      return (SMB2_TREE_CONNECT_REPLY_SIZE & 0xfffe);
    case SMB2_TREE_DISCONNECT:
      return (SMB2_TREE_DISCONNECT_REPLY_SIZE & 0xfffe);
    case SMB2_CREATE:
      return (SMB2_CREATE_REPLY_SIZE & 0xfffe);
    case SMB2_CLOSE:
      return (SMB2_CLOSE_REPLY_SIZE & 0xfffe);
    case SMB2_FLUSH:
      return (SMB2_FLUSH_REPLY_SIZE & 0xfffe);
    case SMB2_READ:
      return (SMB2_READ_REPLY_SIZE & 0xfffe);
    case SMB2_WRITE:
      return (SMB2_WRITE_REPLY_SIZE & 0xfffe);
    case SMB2_IOCTL:
      return (SMB2_IOCTL_REPLY_SIZE & 0xfffe);
    case SMB2_ECHO:
      return (SMB2_ECHO_REPLY_SIZE & 0xfffe);
    case SMB2_QUERY_DIRECTORY:
      return (SMB2_QUERY_DIRECTORY_REPLY_SIZE & 0xfffe);
    case SMB2_QUERY_INFO:
      return (SMB2_QUERY_INFO_REPLY_SIZE & 0xfffe);
    case SMB2_SET_INFO:
      return (SMB2_SET_INFO_REPLY_SIZE & 0xfffe);
  }
  return -1;
}

/* Preauth_Integrity Hash Calculation -
 * Initialize the PreauthIntegrityHash buffer to zero
 * hash of zero initialized PreauthIntegrityHash +
 * hash of negotiate request + hash of negotiate response +
 * hash of session setup request + hash of session setup response if not success
 * repeat the above step with session setup till it is successful
 */
int
Smb2Pdu::smb2_update_preauth_integrity_hash(Smb2ContextPtr  smb2,
                                            smb2_io_vectors *iovs)
{
  EVP_MD_CTX *mdctx = NULL;
  uint32_t digestLen = 0;

  if ((mdctx = EVP_MD_CTX_create()) == NULL)
  {
    smb2->smb2_set_error("smb2_update_preauth_integrity_hash:Failed to allocate EVP_MD_CTX");
    return -1;
  }

  EVP_DigestInit_ex(mdctx, EVP_sha512(), NULL);
  EVP_DigestUpdate(mdctx, smb2->PreauthIntegrityHash, smb2->preauthIntegrityHashLength);

  for (smb2_iovec &v : iovs->iovs)
  {
    EVP_DigestUpdate(mdctx, v.buf, v.len);
  }
  EVP_DigestFinal_ex(mdctx, smb2->PreauthIntegrityHash, &digestLen);
  EVP_MD_CTX_destroy(mdctx);

  return 0;
}

bool Smb2Pdu::smb2_is_error_response()
{
  if ((header_resp.status & SMB2_STATUS_SEVERITY_MASK) == SMB2_STATUS_SEVERITY_ERROR)
  {
    switch (header_resp.status)
    {
      case SMB2_STATUS_MORE_PROCESSING_REQUIRED:
        return 0;
      default:
        return 1;
    }
  }
  return 0;
}

int Smb2Pdu::smb2_process_error_fixed(Smb2ContextPtr smb2)
{
  struct smb2_error_reply *rep;
  smb2_iovec &iov = in.iovs.back();
  uint16_t struct_size;

  rep = (struct smb2_error_reply*)malloc(sizeof(*rep));
  if (rep == NULL)
  {
    smb2->smb2_set_error("Failed to allocate error reply");
    return -1;
  }
  this->payload = rep;

  iov.smb2_get_uint16(0, &struct_size);
  if (struct_size != SMB2_ERROR_REPLY_SIZE || (struct_size & 0xfffe) != iov.len)
  {
    smb2->smb2_set_error("Unexpected size of Error reply. Expected %d, got %d", SMB2_ERROR_REPLY_SIZE, (int)iov.len);
    return -1;
  }

  iov.smb2_get_uint8(2, &rep->error_context_count);
  iov.smb2_get_uint32(4, &rep->byte_count);

  return rep->byte_count;
}

int Smb2Pdu::smb2_process_error_variable(Smb2ContextPtr smb2)
{
  struct smb2_error_reply *rep = (struct smb2_error_reply*)this->payload;
  smb2_iovec &iov = in.iovs.back();

  rep->error_data = &iov.buf[0];

  return 0;
}
