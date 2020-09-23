#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <string.h>
#include "Smb2SetInfo.h"

Smb2SetInfo::Smb2SetInfo(Smb2ContextPtr  smb2,
                         AppData         *setInfoData)
  : Smb2Pdu(smb2, SMB2_SET_INFO, setInfoData)
{
}

Smb2SetInfo::~Smb2SetInfo()
{
}

int
Smb2SetInfo::encodeRequest(Smb2ContextPtr smb2, void *Req)
{
  int i, len;
  uint16_t ch;
  uint8_t *buf;
  struct smb2_set_info_request *req = (struct smb2_set_info_request *)Req;

  len = SMB2_SET_INFO_REQUEST_SIZE & 0xfffffffe;
  buf = (uint8_t*)malloc(len);
  if (buf == NULL) {
    smb2->smb2_set_error("Failed to allocate set info buffer");
    return -1;
  }
  memset(buf, 0, len);

  smb2_iovec iov(buf, len, free);
  out.smb2_add_iovector(iov);

  iov.smb2_set_uint16(0, SMB2_SET_INFO_REQUEST_SIZE);
  iov.smb2_set_uint8(2, req->info_type);
  iov.smb2_set_uint8(3, req->file_info_class);
  iov.smb2_set_uint16(8, SMB2_HEADER_SIZE + 32); /* buffer offset */
  iov.smb2_set_uint32(12, req->additional_information);
  iov.smb2_set_uint64(16, req->file_id.persistent_id);
  iov.smb2_set_uint64(24, req->file_id.volatile_id);

  switch (req->info_type)
  {
    case SMB2_0_INFO_FILE:
    {
      switch (req->file_info_class)
      {
        case SMB2_FILE_END_OF_FILE_INFORMATION:
        {
          struct smb2_file_end_of_file_info *eofi;
          len = 8;
          iov.smb2_set_uint32(4, len); /* buffer length */

          buf = (uint8_t*)malloc(len);
          if (buf == NULL) {
            smb2->smb2_set_error("Failed to allocate setinfo EOF data buffer");
            return -1;
          }
          memset(buf, 0, len);
          iov.buf = buf; iov.len = len; iov.free = free;
          out.smb2_add_iovector(iov);

          eofi = (struct smb2_file_end_of_file_info *)req->input_data;
          iov.smb2_set_uint64(0, eofi->end_of_file);
        }
        break;
        case SMB2_FILE_RENAME_INFORMATION:
        {
          struct smb2_file_rename_info *rni;
          rni = (struct smb2_file_rename_info *)req->input_data;

          struct ucs2 *name = utf8_to_ucs2((char *)(rni->file_name));
          if (name == NULL) {
            smb2->smb2_set_error("Could not convert name into UCS2");
            return -1;
          }
          /* Convert '/' to '\' */
          for (i = 0; i < name->len; i++) {
            iov.smb2_get_uint16(i * 2, &ch);
            if (ch == 0x002f) {
              iov.smb2_set_uint16(i * 2, 0x005c);
            }
          }

          len = 20 + name->len * 2;
          iov.smb2_set_uint32(4, len); /* buffer length */

          buf = (uint8_t*)malloc(len);
          if (buf == NULL) {
            smb2->smb2_set_error("Failed to allocate setinfo rename data buffer");
            free(name);
            return -1;
          }
          memset(buf, 0, len);

          iov.buf = buf; iov.len = len; iov.free = free;
          out.smb2_add_iovector(iov);

          iov.smb2_set_uint8(0, rni->replace_if_exist);
          iov.smb2_set_uint64(8, 0u);
          iov.smb2_set_uint32(16, name->len * 2);
          memcpy(iov.buf + 20, name->val, name->len * 2);
          free(name);
        }
        break;
        case SMB2_FILE_BASIC_INFORMATION:
        {
          struct smb2_file_basic_info *basic_info = NULL;
          basic_info = (struct smb2_file_basic_info *)req->input_data;

          len = sizeof(struct smb2_file_basic_info) + 4;

          iov.smb2_set_uint32(4, len); /* buffer length */
          buf = (uint8_t*)malloc(len);
          if (buf == NULL) {
            smb2->smb2_set_error("Failed to allocate setinfo basic-info buffer");
            return -1;
          }
          memset(buf, 0, len);

          iov.buf = buf; iov.len = len; iov.free = free;
          out.smb2_add_iovector(iov);

          if (basic_info->creation_time !=0) {
            iov.smb2_set_uint64(0, basic_info->creation_time);
          }
          if (basic_info->last_access_time !=0) {
            iov.smb2_set_uint64(8, basic_info->last_access_time);
          }
          if (basic_info->last_write_time !=0) {
            iov.smb2_set_uint64(16, basic_info->last_write_time);
          }
          if (basic_info->change_time !=0) {
            iov.smb2_set_uint64(24, basic_info->change_time);
          }
          iov.smb2_set_uint32(32, basic_info->file_attributes);
        }
        break;
        case SMB2_FILE_FULL_EA_INFORMATION:
        {
          struct smb2_file_full_extended_info *info = NULL;
          info = (struct smb2_file_full_extended_info *)req->input_data;

          iov.smb2_set_uint32(4, info->eabuf_len); /* buffer length */

          buf = (uint8_t*)malloc(info->eabuf_len);
          if (buf == NULL) {
            smb2->smb2_set_error("Failed to allocate set info data buffer");
            return -1;
          }
          memset(buf, 0, info->eabuf_len);

          iov.buf = buf; iov.len = info->eabuf_len; iov.free = free;
          out.smb2_add_iovector(iov);
          memcpy(iov.buf, info->eabuf, info->eabuf_len);
          free(info->eabuf);
        }
        break;
        default:
          smb2->smb2_set_error("Can not encode info_type/info_class %d/%d yet", req->info_type, req->file_info_class);
          return -1;
      }
    }
    break;
    case SMB2_0_INFO_SECURITY:
    {
      struct smb2_file_security_info *info = NULL;
      info = (struct smb2_file_security_info*)req->input_data;

      iov.smb2_set_uint32(4, info->secbuf_len); /* buffer length */

      buf = (uint8_t*)malloc(info->secbuf_len);
      if (buf == NULL) {
        smb2->smb2_set_error("Failed to allocate setinfo security data buffer");
        return -1;
      }
      memset(buf, 0, info->secbuf_len);

      iov.buf = buf; iov.len = info->secbuf_len; iov.free = free;
      out.smb2_add_iovector(iov);
      memcpy(iov.buf, info->secbuf, info->secbuf_len);
    }
    break;
    default:
      smb2->smb2_set_error("Can not encode file info_type %d yet", req->info_type);
      return -1;
  }

  return 0;
}

Smb2Pdu *
Smb2SetInfo::createPdu(Smb2ContextPtr               smb2,
                       struct smb2_set_info_request *req,
                       AppData                      *setInfoData)
{
  Smb2Pdu *pdu;

  pdu = new Smb2SetInfo(smb2, setInfoData);
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

int
Smb2SetInfo::smb2ReplyProcessFixed(Smb2ContextPtr smb2)
{
  if (smb2_is_error_response()) {
    return smb2_process_error_fixed(smb2);
  }

  return 0;
}

int
Smb2SetInfo::smb2ReplyProcessVariable(Smb2ContextPtr smb2)
{
  if (smb2_is_error_response()) {
    return smb2_process_error_variable(smb2);
  }
  return 0;
}

int
Smb2SetInfo::smb2ProcessReplyAndAppData(Smb2ContextPtr smb2)
{
  uint32_t status = header_resp.status;

  appData->setNtStatus(status);

  if (status != SMB2_STATUS_SUCCESS)
  {
    string err = stringf("SetInfo failed with (0x%08x) %s.", status, nterror_to_str(status));
    appData->setErrorMsg(err);
  }

  smb2->endSendReceive();
  return 0;
}
