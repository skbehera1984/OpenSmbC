#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <string.h>
#include "Smb2Flush.h"

Smb2Flush::Smb2Flush(Smb2ContextPtr smb2,
                     AppData         *flushData)
  : Smb2Pdu(smb2, SMB2_FLUSH, flushData)
{
}

Smb2Flush::~Smb2Flush()
{
}

int
Smb2Flush::encodeRequest(Smb2ContextPtr smb2, void *Req)
{
  int len;
  uint8_t *buf;
  struct smb2_flush_request *req = (struct smb2_flush_request *)Req;

  len = SMB2_FLUSH_REQUEST_SIZE & 0xfffffffe;
  buf = (uint8_t*)malloc(len);
  if (buf == NULL)
  {
    appData->setErrorMsg("Smb2Flush::encodeRequest:Failed to allocate flush buffer");
    return -1;
  }
  memset(buf, 0, len);

  smb2_iovec iov(buf, len, free);
  out.smb2_add_iovector(iov);

  iov.smb2_set_uint16(0, SMB2_FLUSH_REQUEST_SIZE);
  iov.smb2_set_uint64(8, req->file_id.persistent_id);
  iov.smb2_set_uint64(16, req->file_id.volatile_id);

  return 0;
}

Smb2Pdu *
Smb2Flush::createPdu(Smb2ContextPtr            smb2,
                     struct smb2_flush_request *req,
                     AppData                   *flushData)
{
  Smb2Pdu *pdu;

  pdu = new Smb2Flush(smb2, flushData);
  if (pdu == NULL)
  {
    flushData->setErrorMsg("Failed to allocate Smb2Flush PDU");
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
Smb2Flush::smb2ReplyProcessFixed(Smb2ContextPtr smb2)
{
  if (smb2ReplyIsError()) {
    return smb2ProcessErrorReplyFixed(smb2);
  }

  return 0;
}

int Smb2Flush::smb2ReplyProcessVariable(Smb2ContextPtr smb2)
{
  if (smb2ReplyIsError()) {
    return smb2ProcessErrorReplyVariable(smb2);
  }
  return 0;
}

int
Smb2Flush::smb2ProcessReplyAndAppData(Smb2ContextPtr smb2)
{
  uint32_t status = header_resp.status;
  appData->setNtStatus(status);
  if (status != SMB2_STATUS_SUCCESS)
  {
    string err = stringf("Flush failed with (0x%08x) %s", status, nterror_to_str(status));
    appData->setErrorMsg(err);
    smb2->endSendReceive();
    return 0;
  }

  smb2->endSendReceive();
  return 0;
}
