#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <string.h>

#include "Smb2Close.h"

Smb2Close::Smb2Close(Smb2ContextPtr smb2,
                     AppData         *closeData)
  : Smb2Pdu(smb2, SMB2_CLOSE, closeData)
{
}

Smb2Close::~Smb2Close()
{
}

int
Smb2Close::encodeRequest(Smb2ContextPtr smb2, void *Req)
{
  int len;
  uint8_t *buf;
  struct smb2_close_request *req = (struct smb2_close_request *)Req;

  len = SMB2_CLOSE_REQUEST_SIZE & 0xfffffffe;
  buf = (uint8_t*)malloc(len);
  if (buf == NULL)
  {
    appData->setErrorMsg("Smb2Close::encodeRequest:Failed to allocate close buffer");
    return -1;
  }
  memset(buf, 0, len);

  smb2_iovec iov(buf, len, free);
  out.smb2_add_iovector(iov);

  iov.smb2_set_uint16(0, SMB2_CLOSE_REQUEST_SIZE);
  iov.smb2_set_uint16(2, req->flags);
  iov.smb2_set_uint64(8, req->file_id.persistent_id);
  iov.smb2_set_uint64(16, req->file_id.volatile_id);

  return 0;
}

Smb2Pdu *
Smb2Close::createPdu(Smb2ContextPtr            smb2,
                     struct smb2_close_request *req,
                     AppData                   *closeData)
{
  Smb2Pdu *pdu = NULL;

  pdu = new Smb2Close(smb2, closeData);
  if (pdu == NULL)
  {
    closeData->setErrorMsg("Failed to allocate Smb2Close PDU");
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

int
Smb2Close::smb2ReplyProcessFixed(Smb2ContextPtr smb2)
{
  if (smb2ReplyIsError()) {
    return smb2ProcessErrorReplyFixed(smb2);
  }

  struct smb2_close_reply *rep = NULL;
  smb2_iovec &iov = in.iovs.back();
  uint16_t struct_size;

  rep = (struct smb2_close_reply*)malloc(sizeof(*rep));
  if (rep == NULL)
  {
    appData->setErrorMsg("Failed to allocate close reply");
    return -1;
  }
  this->payload = rep;

  iov.smb2_get_uint16(0, &struct_size);
  if (struct_size != SMB2_CLOSE_REPLY_SIZE || (struct_size & 0xfffe) != iov.len)
  {
    string err = stringf("Unexpected size of Close reply. Expected %d, got %d",
                         SMB2_CLOSE_REPLY_SIZE, (int)iov.len);
    appData->setErrorMsg(err);
    return -1;
  }

  iov.smb2_get_uint16(2, &rep->flags);
  iov.smb2_get_uint64(8, &rep->creation_time);
  iov.smb2_get_uint64(16, &rep->last_access_time);
  iov.smb2_get_uint64(24, &rep->last_write_time);
  iov.smb2_get_uint64(32, &rep->change_time);
  iov.smb2_get_uint64(40, &rep->allocation_size);
  iov.smb2_get_uint64(48, &rep->end_of_file);
  iov.smb2_get_uint32(56, &rep->file_attributes);

  return 0;
}

int
Smb2Close::smb2ReplyProcessVariable(Smb2ContextPtr smb2)
{
  if (smb2ReplyIsError()) {
    return smb2ProcessErrorReplyVariable(smb2);
  }

  return 0;
}

int
Smb2Close::smb2ProcessReplyAndAppData(Smb2ContextPtr smb2)
{
  uint32_t status = header_resp.status;

  smb2fh *fh = appData->getFH();

  if (status != SMB2_STATUS_SUCCESS && status != SMB2_STATUS_FILE_CLOSED)
  {
    string err = stringf("Close failed with (0x%08x) %s", status, nterror_to_str(status));
    appData->setErrorMsg(err);
    appData->setNtStatus(status);
    smb2->endSendReceive();
    if (fh != NULL)
      delete fh;
    return 0;
  }

  appData->setNtStatus(SMB2_STATUS_SUCCESS);
  smb2->endSendReceive();
  if (fh != NULL)
    delete fh;

  return 0;
}
