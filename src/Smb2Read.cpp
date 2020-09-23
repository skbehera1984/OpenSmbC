#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <string.h>

#include "Smb2Read.h"

Smb2Read::Smb2Read(Smb2ContextPtr  smb2,
                   AppData         *readData)
  : Smb2Pdu(smb2, SMB2_READ, readData)
{
}

Smb2Read::~Smb2Read()
{
}

int
Smb2Read::encodeRequest(Smb2ContextPtr smb2, void *Req)
{
  int len;
  uint8_t *buf;
  struct smb2_read_request *req = (struct smb2_read_request *)Req;

  len = SMB2_READ_REQUEST_SIZE & 0xfffffffe;
  buf = (uint8_t*)malloc(len);
  if (buf == NULL) {
    smb2->smb2_set_error("Failed to allocate read buffer");
    return -1;
  }
  memset(buf, 0, len);

  smb2_iovec iov(buf, len, free);
  out.smb2_add_iovector(iov);

  if (!smb2->supports_multi_credit && req->length > 60 * 1024) {
    req->length = 60 * 1024;
    req->minimum_count = 0;
  }
  iov.smb2_set_uint16(0, SMB2_READ_REQUEST_SIZE);
  iov.smb2_set_uint8(3, req->flags);
  iov.smb2_set_uint32(4, req->length);
  iov.smb2_set_uint64(8, req->offset);
  iov.smb2_set_uint64(16, req->file_id.persistent_id);
  iov.smb2_set_uint64(24, req->file_id.volatile_id);
  iov.smb2_set_uint32(32, req->minimum_count);
  iov.smb2_set_uint32(36, req->channel);
  iov.smb2_set_uint32(40, req->remaining_bytes);
  iov.smb2_set_uint16(46, req->read_channel_info_length);

  if (req->read_channel_info_length > 0 || req->read_channel_info != NULL)
  {
    smb2->smb2_set_error("ChannelInfo not yet implemented");
    return -1;
  }

  /* The buffer must contain at least one byte, even if we do not
   * have any read channel info.
   */
  if (req->read_channel_info == NULL) {
    static uint8_t zero;

    iov.buf = &zero; iov.len = 1; iov.free = NULL;
    out.smb2_add_iovector(iov);
  }

  return 0;
}

Smb2Pdu *
Smb2Read::createPdu(Smb2ContextPtr           smb2,
                    struct smb2_read_request *req,
                    AppData                  *readData)
{
  Smb2Pdu *pdu;

  pdu = new Smb2Read(smb2, readData);
  if (pdu == NULL) {
    return NULL;
  }

  if (pdu->encodeRequest(smb2, req)) {
    delete pdu;
    return NULL;
  }

  pdu->out.smb2_pad_to_64bit();

  /* Adjust credit charge for large payloads */
  if (smb2->supports_multi_credit) {
    pdu->header.credit_charge = (req->length - 1) / 65536 + 1; // 3.1.5.2 of [MS-SMB2]
  }

  return pdu;
}

int
Smb2Read::smb2ReplyProcessFixed(Smb2ContextPtr smb2)
{
  if (smb2_is_error_response()) {
    return smb2_process_error_fixed(smb2);
  }

  struct smb2_read_reply *rep;
  smb2_iovec &iov = in.iovs.back();
  uint16_t struct_size;

  rep = (struct smb2_read_reply *)malloc(sizeof(*rep));
  if (rep == NULL) {
    smb2->smb2_set_error("Failed to allocate read reply");
    return -1;
  }
  rep->readData = NULL;
  this->payload = rep;

  iov.smb2_get_uint16(0, &struct_size);
  if (struct_size > SMB2_READ_REPLY_SIZE) {
    smb2->smb2_set_error("Unexpected size of Read reply. Expected %d, got %d", SMB2_READ_REPLY_SIZE, (int)iov.len);
    return -1;
  }

  iov.smb2_get_uint8(2, &rep->data_offset);
  iov.smb2_get_uint32(4, &rep->data_length);
  iov.smb2_get_uint32(8, &rep->data_remaining);

  if (rep->data_length == 0) {
    return 0;
  }

  if (rep->data_offset != SMB2_HEADER_SIZE + 16) {
    smb2->smb2_set_error("Unexpected data offset in Read reply. Expected %d, got %d", 16, rep->data_offset);
    return -1;
  }

  return rep->data_length;
}

int
Smb2Read::smb2ReplyProcessVariable(Smb2ContextPtr smb2)
{
  if (smb2_is_error_response()) {
    return smb2_process_error_variable(smb2);
  }

  struct smb2_read_reply *rep = (struct smb2_read_reply*)this->payload;
  smb2_iovec &iov = in.iovs.back();
  rep->readData = iov.buf;
  return 0;
}

int
Smb2Read::smb2ProcessReplyAndAppData(Smb2ContextPtr smb2)
{
  uint32_t status = header_resp.status;
  smb2fh *fh = appData->getFH();
  uint8_t *readBuf = appData->getReadBuf();

  appData->setNtStatus(status);
  struct smb2_read_reply *rep = (struct smb2_read_reply *)payload;

  if (status && status != SMB2_STATUS_END_OF_FILE)
  {
    string err = stringf("Read/Write failed with (0x%08x) %s", status, nterror_to_str(status));
    appData->setErrorMsg(err);
    smb2->endSendReceive();
    return 0;
  }

  fh->offset += rep->data_length;
  fh->byte_count = rep->data_length;
  fh->bytes_remaining = rep->data_remaining;
  memcpy(readBuf, rep->readData, rep->data_length);

  smb2->endSendReceive();
  return 0;
}
