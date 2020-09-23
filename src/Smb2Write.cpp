#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <string.h>
#include "Smb2Write.h"

Smb2Write::Smb2Write(Smb2ContextPtr  smb2,
                     AppData         *writeData)
  : Smb2Pdu(smb2, SMB2_WRITE, writeData)
{
}

Smb2Write::~Smb2Write()
{
}

int
Smb2Write::encodeRequest(Smb2ContextPtr smb2, void *Req)
{
  int len;
  uint8_t *buf;
  struct smb2_write_request *req = (struct smb2_write_request *)Req;

  len = SMB2_WRITE_REQUEST_SIZE & 0xfffffffe;
  buf = (uint8_t*)malloc(len);
  if (buf == NULL) {
    smb2->smb2_set_error("Failed to allocate write buffer");
    return -1;
  }
  memset(buf, 0, len);

  smb2_iovec iov(buf, len, free);
  out.smb2_add_iovector(iov);

  if (!smb2->supports_multi_credit && req->length > 60 * 1024) {
    req->length = 60 * 1024;
  }
  iov.smb2_set_uint16(0, SMB2_WRITE_REQUEST_SIZE);
  iov.smb2_set_uint16(2, SMB2_HEADER_SIZE + 48);
  iov.smb2_set_uint32(4, req->length);
  iov.smb2_set_uint64(8, req->offset);
  iov.smb2_set_uint64(16, req->file_id.persistent_id);
  iov.smb2_set_uint64(24, req->file_id.volatile_id);
  iov.smb2_set_uint32(32, req->channel);
  iov.smb2_set_uint32(36, req->remaining_bytes);
  iov.smb2_set_uint16(42, req->write_channel_info_length);
  iov.smb2_set_uint32(44, req->flags);

  if (req->write_channel_info_length > 0 || req->write_channel_info != NULL)
  {
    smb2->smb2_set_error("ChannelInfo not yet implemented");
    return -1;
  }

  return 0;
}

Smb2Pdu *
Smb2Write::createPdu(Smb2ContextPtr            smb2,
                     struct smb2_write_request *req,
                     AppData                   *writeData)
{
  Smb2Pdu *pdu;

  pdu = new Smb2Write(smb2, writeData);
  if (pdu == NULL)
    return NULL;

  if (pdu->encodeRequest(smb2, req)) {
    delete pdu;
    return NULL;
  }

  pdu->out.smb2_add_iovector(req->buf, req->length, NULL);
  pdu->out.smb2_pad_to_64bit();

  /* Adjust credit charge for large payloads */
  if (smb2->supports_multi_credit) {
    pdu->header.credit_charge = (req->length - 1) / 65536 + 1; // 3.1.5.2 of [MS-SMB2]
  }

  return pdu;
}

int
Smb2Write::smb2ReplyProcessFixed(Smb2ContextPtr smb2)
{
  if (smb2_is_error_response()) {
    return smb2_process_error_fixed(smb2);
  }

  struct smb2_write_reply *rep;
  smb2_iovec &iov = in.iovs.back();
  uint16_t struct_size;

  rep = (struct smb2_write_reply *)malloc(sizeof(*rep));
  if (rep == NULL) {
    smb2->smb2_set_error("Failed to allocate write reply");
    return -1;
  }
  this->payload = rep;

  iov.smb2_get_uint16(0, &struct_size);
  if (struct_size != SMB2_WRITE_REPLY_SIZE || (struct_size & 0xfffe) != iov.len)
  {
    smb2->smb2_set_error("Unexpected size of Write reply. Expected %d, got %d", SMB2_WRITE_REPLY_SIZE, (int)iov.len);
    return -1;
  }

  iov.smb2_get_uint32(4, &rep->count);
  iov.smb2_get_uint32(8, &rep->remaining);

  return 0;
}

int
Smb2Write::smb2ReplyProcessVariable(Smb2ContextPtr smb2)
{
  if (smb2_is_error_response()) {
    return smb2_process_error_variable(smb2);
  }
  return 0;
}

int
Smb2Write::smb2ProcessReplyAndAppData(Smb2ContextPtr smb2)
{
  uint32_t status = header_resp.status;
  smb2fh *fh = appData->getFH();
  struct smb2_write_reply *rep = (struct smb2_write_reply *)payload;

  appData->setNtStatus(status);
  if (status && status != SMB2_STATUS_END_OF_FILE)
  {
    string err = stringf("Read/Write failed with (0x%08x) %s", status, nterror_to_str(status));
    appData->setErrorMsg(err);
    smb2->endSendReceive();
    return 0;
  }

  fh->offset += rep->count;
  fh->byte_count = rep->count;
  fh->bytes_remaining = rep->remaining;

  smb2->endSendReceive();
  return 0;
}
