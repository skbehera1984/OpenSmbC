#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <string.h>
#include "Smb2Ioctl.h"

Smb2Ioctl::Smb2Ioctl(Smb2ContextPtr smb2,
                     AppData         *ioctlData)
  : Smb2Pdu(smb2, SMB2_IOCTL, ioctlData)
{
}

Smb2Ioctl::~Smb2Ioctl()
{
}

int
Smb2Ioctl::encodeRequest(Smb2ContextPtr smb2, void *Req)
{
  int len;
  uint8_t *buf;
  struct smb2_ioctl_request *req = (struct smb2_ioctl_request *)Req;

  len = SMB2_IOCTL_REQUEST_SIZE & 0xfffffffe;
  buf = (uint8_t*)malloc(len);
  if (buf == NULL) {
    smb2->smb2_set_error("Failed to allocate ioctl param buffer");
    return -1;
  }
  memset(buf, 0, len);

  uint32_t InputOffset = SMB2_HEADER_SIZE + sizeof(struct smb2_ioctl_request) - (1 * sizeof(uint8_t *));

  smb2_iovec iov(buf, len, free);
  out.smb2_add_iovector(iov);

  iov.smb2_set_uint16(0, SMB2_IOCTL_REQUEST_SIZE);
  iov.smb2_set_uint16(2, req->reserved);
  iov.smb2_set_uint32(4, req->ctl_code);
  iov.smb2_set_uint64(8, req->file_id.persistent_id);
  iov.smb2_set_uint64(16, req->file_id.volatile_id);
  iov.smb2_set_uint32(24, InputOffset);
  iov.smb2_set_uint32(28, req->input_count);
  iov.smb2_set_uint32(32, req->max_input_response);
  iov.smb2_set_uint32(36, InputOffset);
  iov.smb2_set_uint32(40, req->output_count);
  iov.smb2_set_uint32(44, req->max_output_response);
  iov.smb2_set_uint32(48, req->flags);
  iov.smb2_set_uint32(52, req->reserved2);

  buf = (uint8_t*)malloc(req->input_count);
  if (buf == NULL) {
    smb2->smb2_set_error("Failed to allocate ioctl payload");
    return -1;
  }
  memset(buf, 0, req->input_count);

  iov.buf = buf; iov.len = req->input_count; iov.free = free;
  out.smb2_add_iovector(iov);
  memcpy(iov.buf, req->input_buffer, req->input_count);

  return 0;
}

Smb2Pdu *
Smb2Ioctl::createPdu(Smb2ContextPtr            smb2,
                     struct smb2_ioctl_request *req,
                     AppData                   *ioctlData)
{
  Smb2Pdu *pdu;

  pdu = new Smb2Ioctl(smb2, ioctlData);
  if (pdu == NULL) {
    return NULL;
  }

  if (pdu->encodeRequest(smb2, req)) {
    delete pdu;
    return NULL;
  }

  pdu->out.smb2_pad_to_64bit();

  /* Adjust credit charge for large payloads */
  uint32_t actual_payload = MAX((req->input_count + req->output_count),
                                (req->max_input_response + req->max_output_response));
  if (smb2->supports_multi_credit) {
    pdu->header.credit_charge = (actual_payload - 1) / 65536 + 1; // 3.1.5.2 of [MS-SMB2]
  }

  return pdu;
}

#define IOV_OFFSET (rep->output_offset - SMB2_HEADER_SIZE - \
                    (SMB2_IOCTL_REPLY_SIZE & 0xfffe))

int
Smb2Ioctl::smb2ReplyProcessFixed(Smb2ContextPtr smb2)
{
  if (smb2_is_error_response()) {
    return smb2_process_error_fixed(smb2);
  }

  struct smb2_ioctl_reply *rep;
  smb2_iovec &iov = in.iovs.back();
  uint16_t struct_size;

  rep = (struct smb2_ioctl_reply *)malloc(sizeof(*rep));
  if (rep == NULL) {
    smb2->smb2_set_error("Failed to allocate buffer for ioctl response");
    return -1;
  }
  this->payload = rep;

  iov.smb2_get_uint16(0, &struct_size);
  if (struct_size != SMB2_IOCTL_REPLY_SIZE || (struct_size & 0xfffe) != iov.len)
  {
    smb2->smb2_set_error("Unexpected size of IOCTL reply. Expected %d, got %d", SMB2_IOCTL_REPLY_SIZE, (int)iov.len);
    return -1;
  }

  iov.smb2_get_uint16(2, &rep->reserved);
  iov.smb2_get_uint32(4, &rep->ctl_code);
  iov.smb2_get_uint64(8, &rep->file_id.persistent_id);
  iov.smb2_get_uint64(16, &rep->file_id.volatile_id);
  iov.smb2_get_uint32(24, &rep->input_offset);
  iov.smb2_get_uint32(28, &rep->input_count);
  iov.smb2_get_uint32(32, &rep->output_offset);
  iov.smb2_get_uint32(36, &rep->output_count);
  iov.smb2_get_uint32(40, &rep->flags);
  iov.smb2_get_uint32(44, &rep->reserved2);

  if (rep->output_count == 0) {
    smb2->smb2_set_error("No output buffer in Ioctl response");
    return -1;
  }
  if (rep->output_offset < SMB2_HEADER_SIZE + (SMB2_IOCTL_REPLY_SIZE & 0xfffe))
  {
    smb2->smb2_set_error("Output buffer overlaps with Ioctl reply header");
    return -1;
  }

  /* Return the amount of data that the output buffer will take up.
   * Including any padding before the output buffer itself.
   */
  return IOV_OFFSET + rep->output_count;
}

int
Smb2Ioctl::smb2ReplyProcessVariable(Smb2ContextPtr smb2)
{
  if (smb2_is_error_response()) {
    return smb2_process_error_variable(smb2);
  }

  struct smb2_ioctl_reply *rep = (struct smb2_ioctl_reply *)this->payload;
  smb2_iovec &iov = in.iovs.back();

  rep->output_buffer = &iov.buf[IOV_OFFSET];

  return 0;
}

int
Smb2Ioctl::smb2ProcessReplyAndAppData(Smb2ContextPtr smb2)
{
  uint32_t status = header_resp.status;
  struct smb2_ioctl_reply *rep = (struct smb2_ioctl_reply *)payload;

  appData->setNtStatus(status);

  if (status != SMB2_STATUS_SUCCESS)
  {
    string err = stringf("IOCTL failed with (0x%08x) %s", status, nterror_to_str(status));
    appData->setErrorMsg(err);
    smb2->endSendReceive();
    return 0;
  }

  uint8_t *buf = appData->getOutBuf();
  uint32_t *buflen = appData->getOutBufLen();

  memcpy(buf, rep->output_buffer, rep->output_count);
  *(buflen) = rep->output_count;

  smb2->endSendReceive();
  return 0;
}
