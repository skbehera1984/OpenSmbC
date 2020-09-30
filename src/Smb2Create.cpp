#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <string.h>
#include "Smb2Create.h"

Smb2Create::Smb2Create(Smb2ContextPtr  smb2,
                       AppData         *createData)
  : Smb2Pdu(smb2, SMB2_CREATE, createData)
{
}

Smb2Create::~Smb2Create()
{
}

int
Smb2Create::encodeRequest(Smb2ContextPtr smb2, void *Req)
{
  int len;
  uint8_t *buf;
  uint16_t ch;
  struct ucs2 *name = NULL;
  struct smb2_create_request *req = (struct smb2_create_request *)Req;

  len = SMB2_CREATE_REQUEST_SIZE & 0xfffffffe;
  buf = (uint8_t*)malloc(len);
  if (buf == NULL) {
    smb2->smb2_set_error("Failed to allocate create buffer");
    return -1;
  }
  memset(buf, 0, len);

  smb2_iovec iov(buf, len, free);;
  out.smb2_add_iovector(iov);

  /* Name */
  if (req->name && req->name[0])
  {
    name = utf8_to_ucs2(req->name);
    if (name == NULL)
    {
      smb2->smb2_set_error("Could not convert name into UCS2");
      return -1;
    }
    /* name length */
    iov.smb2_set_uint16(46, 2 * name->len);
  }

  iov.smb2_set_uint16(0, SMB2_CREATE_REQUEST_SIZE);
  iov.smb2_set_uint8(2, req->security_flags);
  iov.smb2_set_uint8(3, req->requested_oplock_level);
  iov.smb2_set_uint32(4, req->impersonation_level);
  iov.smb2_set_uint64(8, req->smb_create_flags);
  iov.smb2_set_uint32(24, req->desired_access);
  iov.smb2_set_uint32(28, req->file_attributes);
  iov.smb2_set_uint32(32, req->share_access);
  iov.smb2_set_uint32(36, req->create_disposition);
  iov.smb2_set_uint32(40, req->create_options);
  /* name offset */
  iov.smb2_set_uint16(44, SMB2_HEADER_SIZE + 56);
  iov.smb2_set_uint32(52, req->create_context_length);

  /* Name */
  if (name)
  {
    buf = (uint8_t*)malloc(2 * name->len);
    if (buf == NULL)
    {
      smb2->smb2_set_error("Failed to allocate create name");
      free(name);
      return -1;
    }
    memcpy(buf, &name->val[0], 2 * name->len);

    iov.buf = buf; iov.len = (2 * name->len); iov.free = free;
    out.smb2_add_iovector(iov);
    /* Convert '/' to '\' */
    for (int i = 0; i < name->len; i++)
    {
      iov.smb2_get_uint16(i * 2, &ch);
      if (ch == 0x002f)
      {
        iov.smb2_set_uint16(i * 2, 0x005c);
      }
    }
  }
  free(name);

  /* Create Context */
  if (req->create_context_length)
  {
    smb2->smb2_set_error("Create context not implemented, yet");
    return -1;
  }

  /* The buffer must contain at least one byte, even if name is ""
   * and there is no create context.
   */
  if (name == NULL && !req->create_context_length)
  {
    static uint8_t zero;
    iov.buf = &zero; iov.len = 1; iov.free = NULL;
    out.smb2_add_iovector(iov);
  }

  return 0;
}

Smb2Pdu *
Smb2Create::createPdu(Smb2ContextPtr             smb2,
                      struct smb2_create_request *req,
                      AppData                    *createData)
{
  Smb2Pdu *pdu;

  pdu = new Smb2Create(smb2, createData);
  if (pdu == NULL) {
    return NULL;
  }

  if (pdu->encodeRequest(smb2, req)) {
    delete pdu;
    return NULL;
  }

  pdu->out.smb2_pad_to_64bit();

  return pdu;
}

#define IOV_OFFSET (rep->create_context_offset - SMB2_HEADER_SIZE - \
                    (SMB2_CREATE_REPLY_SIZE & 0xfffe))

int
Smb2Create::smb2ReplyProcessFixed(Smb2ContextPtr smb2)
{
  if (smb2_is_error_response()) {
    return smb2_process_error_fixed(smb2);
  }

  struct smb2_create_reply *rep;
  smb2_iovec &iov = in.iovs.back();
  uint16_t struct_size;

  rep = (struct smb2_create_reply*)malloc(sizeof(*rep));
  if (rep == NULL)
  {
    appData->setErrorMsg("Failed to allocate create reply");
    return -1;
  }
  this->payload = rep;

  iov.smb2_get_uint16(0, &struct_size);
  if (struct_size != SMB2_CREATE_REPLY_SIZE || (struct_size & 0xfffe) != iov.len)
  {
    string err = stringf("Unexpected size of Create. Expected %d, got %d",
                         SMB2_CREATE_REPLY_SIZE, (int)iov.len);
    appData->setErrorMsg(err);
    return -1;
  }

  iov.smb2_get_uint8(2, &rep->oplock_level);
  iov.smb2_get_uint8(3, &rep->flags);
  iov.smb2_get_uint32(4, &rep->create_action);
  iov.smb2_get_uint64(8, &rep->creation_time);
  iov.smb2_get_uint64(16, &rep->last_access_time);
  iov.smb2_get_uint64(24, &rep->last_write_time);
  iov.smb2_get_uint64(32, &rep->change_time);
  iov.smb2_get_uint64(40, &rep->allocation_size);
  iov.smb2_get_uint64(48, &rep->end_of_file);
  iov.smb2_get_uint32(56, &rep->file_attributes);
  iov.smb2_get_uint64(64, &rep->file_id.persistent_id);
  iov.smb2_get_uint64(72, &rep->file_id.volatile_id);
  iov.smb2_get_uint32(80, &rep->create_context_offset);
  iov.smb2_get_uint32(84, &rep->create_context_length);

  if (rep->create_context_length == 0) {
    return 0;
  }

  if (rep->create_context_offset < SMB2_HEADER_SIZE + (SMB2_CREATE_REPLY_SIZE & 0xfffe))
  {
    appData->setErrorMsg("Create context overlaps with reply header");
    return -1;
  }

  /* Return the amount of data that the security buffer will take up.
   * Including any padding before the security buffer itself.
   */
  return IOV_OFFSET + rep->create_context_length;
}

int
Smb2Create::smb2ReplyProcessVariable(Smb2ContextPtr smb2)
{
  if (smb2_is_error_response()) {
    return smb2_process_error_variable(smb2);
  }

  struct smb2_create_reply *rep = (struct smb2_create_reply*)this->payload;

  /* No support for createcontext yet*/
  /* Create Context */
  if (rep->create_context_length)
  {
    appData->setErrorMsg("Create context not implemented, yet");
    return -1;
  }

  return 0;
}

int
Smb2Create::smb2ProcessReplyAndAppData(Smb2ContextPtr smb2)
{
  uint32_t status = header_resp.status;
  smb2fh *fh = appData->getFH();
  struct smb2_create_reply *rep = (struct smb2_create_reply *)payload;

  appData->setNtStatus(status);

  if (status != SMB2_STATUS_SUCCESS)
  {
    string err = stringf("SMB2_CREATE failed - %x, %s", status, nterror_to_str(status));
    appData->setErrorMsg(err);
    smb2->endSendReceive();
    delete fh;
    return 0;
  }

  if (fh == NULL)
  {
    // in a compound req we aren't interested in the fh
    return 0;
  }

  fh->file_id.persistent_id = rep->file_id.persistent_id;
  fh->file_id.volatile_id = rep->file_id.volatile_id;

  fh->oplock_level = rep->oplock_level;
  fh->create_action = rep->create_action;
  fh->creation_time = rep->creation_time;
  fh->lastAccess_time = rep->last_access_time;
  fh->lastWrite_time = rep->last_write_time;
  fh->change_time = rep->change_time;
  fh->allocation_size = rep->allocation_size;
  fh->end_of_file = rep->end_of_file;
  fh->file_attributes = rep->file_attributes;

  smb2->endSendReceive();

  return 0;
}
