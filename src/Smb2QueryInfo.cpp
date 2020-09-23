#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <string.h>
#include "Smb2QueryInfo.h"
#include "Smb2FileData.h"

Smb2QueryInfo::Smb2QueryInfo(Smb2ContextPtr  smb2,
                             AppData         *qInfoData)
  : Smb2Pdu(smb2, SMB2_QUERY_INFO, qInfoData)
{
  requestedInfoType  = 0;
  requestedInfoClass = 0;
}

Smb2QueryInfo::~Smb2QueryInfo()
{
}

int
Smb2QueryInfo::encodeRequest(Smb2ContextPtr smb2, void *Req)
{
  int len;
  uint8_t *buf;
  struct smb2_query_info_request *req = (struct smb2_query_info_request *)Req;

  if (req->input_buffer_length > 0) {
    smb2->smb2_set_error("No support for input buffers, yet");
    return -1;
  }

  len = SMB2_QUERY_INFO_REQUEST_SIZE & 0xfffffffe;
  buf = (uint8_t*)malloc(len);
  if (buf == NULL) {
    smb2->smb2_set_error("Failed to allocate query buffer");
    return -1;
  }
  memset(buf, 0, len);

  smb2_iovec iov(buf, len, free);
  out.smb2_add_iovector(iov);

  iov.smb2_set_uint16(0, SMB2_QUERY_INFO_REQUEST_SIZE);
  iov.smb2_set_uint8(2, req->info_type);
  iov.smb2_set_uint8(3, req->file_info_class);
  iov.smb2_set_uint32(4, req->output_buffer_length);
  iov.smb2_set_uint32(12, req->input_buffer_length);
  iov.smb2_set_uint32(16, req->additional_information);
  iov.smb2_set_uint32(20, req->flags);
  iov.smb2_set_uint64(24, req->file_id.persistent_id);
  iov.smb2_set_uint64(32, req->file_id.volatile_id);

  /* Remember what we asked for so that we can unmarshall the reply */
  this->requestedInfoType  = req->info_type;
  this->requestedInfoClass = req->file_info_class;

  return 0;
}

Smb2Pdu *
Smb2QueryInfo::createPdu(Smb2ContextPtr                 smb2,
                         struct smb2_query_info_request *req,
                         AppData                        *qInfoData)
{
  Smb2Pdu *pdu;

  pdu = new Smb2QueryInfo(smb2, qInfoData);
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

#define IOV_OFFSET (rep->output_buffer_offset - SMB2_HEADER_SIZE - \
                    (SMB2_QUERY_INFO_REPLY_SIZE & 0xfffe))

int
Smb2QueryInfo::smb2ReplyProcessFixed(Smb2ContextPtr smb2)
{
  if (smb2_is_error_response()) {
    return smb2_process_error_fixed(smb2);
  }

  struct smb2_query_info_reply *rep;
  smb2_iovec &iov = in.iovs.back();
  uint16_t struct_size;

  rep = (struct smb2_query_info_reply *)malloc(sizeof(*rep));
  if (rep == NULL) {
    smb2->smb2_set_error("Failed to allocate query info reply");
    return -1;
  }
  this->payload = rep;

  iov.smb2_get_uint16(0, &struct_size);
  if (struct_size != SMB2_QUERY_INFO_REPLY_SIZE || (struct_size & 0xfffe) != iov.len)
  {
    smb2->smb2_set_error("Unexpected size of Query Info reply. Expected %d, got %d", SMB2_QUERY_INFO_REPLY_SIZE, (int)iov.len);
    return -1;
  }

  iov.smb2_get_uint16(2, &rep->output_buffer_offset);
  iov.smb2_get_uint32(4, &rep->output_buffer_length);

  if (rep->output_buffer_length == 0) {
    smb2->smb2_set_error("No output buffer in Query Info response");
    return -1;
  }
  if (rep->output_buffer_offset < SMB2_HEADER_SIZE + (SMB2_QUERY_INFO_REPLY_SIZE & 0xfffe))
  {
    smb2->smb2_set_error("Output buffer overlaps with Query Info reply header");
    return -1;
  }

  /* Return the amount of data that the output buffer will take up.
   * Including any padding before the output buffer itself.
   */
  return IOV_OFFSET + rep->output_buffer_length;
}

int
Smb2QueryInfo::smb2ReplyProcessVariable(Smb2ContextPtr smb2)
{
  if (smb2_is_error_response()) {
    return smb2_process_error_variable(smb2);
  }

  struct smb2_query_info_reply *rep = (struct smb2_query_info_reply *)this->payload;
  smb2_iovec &iov = in.iovs.back();
  smb2_iovec vec;
  vec.buf = &(iov.buf[IOV_OFFSET]);
  vec.len = iov.len - IOV_OFFSET;
  vec.free = NULL;
  void *ptr;

  switch (this->requestedInfoType)
  {
    case SMB2_0_INFO_FILE:
    {
      switch (this->requestedInfoClass)
      {
        case SMB2_FILE_BASIC_INFORMATION:
          ptr = malloc(sizeof(struct smb2_file_basic_info));
          if (smb2_decode_file_basic_info((struct smb2_file_basic_info *)ptr, &vec))
          {
            smb2->smb2_set_error("could not decode file basic info. %s", smb2->smb2_get_error());
            return -1;
          }
        break;
        case SMB2_FILE_STANDARD_INFORMATION:
          ptr = malloc(sizeof(struct smb2_file_standard_info));
          if (smb2_decode_file_standard_info((struct smb2_file_standard_info *)ptr, &vec))
          {
            smb2->smb2_set_error("could not decode file standard info. %s", smb2->smb2_get_error());
            return -1;
          }
        break;
        case SMB2_FILE_FULL_EA_INFORMATION:
          if (header_resp.status == SMB2_STATUS_NO_EAS_ON_FILE)
            return 0;
          ptr = malloc(sizeof(struct smb2_file_extended_info));
          if (smb2_decode_file_extended_info(smb2, (struct smb2_file_extended_info*)ptr, &vec))
          {
            smb2->smb2_set_error("could not decode file full ea info. %s", smb2->smb2_get_error());
            return -1;
          }
        break;
        case SMB2_FILE_STREAM_INFORMATION:
          ptr = malloc(sizeof(struct smb2_file_stream_info));
          if (smb2_decode_file_stream_info(smb2, (struct smb2_file_stream_info*)ptr, &vec))
          {
            smb2->smb2_set_error("could not decode file stream info. %s", smb2->smb2_get_error());
            return -1;
          }
        break;
        case SMB2_FILE_ALL_INFORMATION:
          ptr = malloc(sizeof(struct smb2_file_all_info));
          if (smb2_decode_file_all_info((struct smb2_file_all_info*)ptr, &vec))
          {
            smb2->smb2_set_error("could not decode file all info. %s", smb2->smb2_get_error());
            return -1;
          }
        break;
        default:
          smb2->smb2_set_error("Can not decode InfoType/InfoClass %d/%d yet", this->requestedInfoType, this->requestedInfoClass);
          return -1;
      }
    }
    break;
    case SMB2_0_INFO_SECURITY:
    {
      smb2_security_descriptor *sd = nullptr;
      sd = new smb2_security_descriptor();
      if (sd == nullptr)
      {
        smb2->smb2_set_error("Failed to allocate memory for secutiry");
        return -1;
      }
      ptr = sd;

      string err2;
      if (smb2DecodeSecDescInternal(sd, &vec, err2) < 0)
      {
        smb2->smb2_set_error("could not decode security descriptor. %s", err2.c_str());
        return -1;
      }
    }
    break;
    case SMB2_0_INFO_FILESYSTEM:
    {
      switch (this->requestedInfoClass)
      {
        case SMB2_FILE_FS_SIZE_INFORMATION:
          ptr = malloc(sizeof(struct smb2_file_fs_size_info));
          if (smb2_decode_file_fs_size_info((struct smb2_file_fs_size_info*)ptr, &vec))
          {
            smb2->smb2_set_error("could not decode file fs size info. %s", smb2->smb2_get_error());
            return -1;
          }
        break;
        case SMB2_FILE_FS_DEVICE_INFORMATION:
          ptr = malloc(sizeof(struct smb2_file_fs_device_info));
          if (smb2_decode_file_fs_device_info((struct smb2_file_fs_device_info*)ptr, &vec))
          {
            smb2->smb2_set_error("could not decode file fs device info. %s", smb2->smb2_get_error());
            return -1;
          }
        break;
        case SMB2_FILE_FS_CONTROL_INFORMATION:
          ptr = malloc(sizeof(struct smb2_file_fs_control_info));
          if (smb2_decode_file_fs_control_info((struct smb2_file_fs_control_info*)ptr, &vec))
          {
            smb2->smb2_set_error("could not decode file fs control info. %s", smb2->smb2_get_error());
            return -1;
          }
        break;
        case SMB2_FILE_FS_FULL_SIZE_INFORMATION:
          ptr = malloc(sizeof(struct smb2_file_fs_full_size_info));
          if (smb2_decode_file_fs_full_size_info((struct smb2_file_fs_full_size_info*)ptr, &vec))
          {
            smb2->smb2_set_error("could not decode file fs full size info. %s", smb2->smb2_get_error());
            return -1;
          }
        break;
        case SMB2_FILE_FS_SECTOR_SIZE_INFORMATION:
          ptr = malloc(sizeof(struct smb2_file_fs_sector_size_info));
          if (smb2_decode_file_fs_sector_size_info((struct smb2_file_fs_sector_size_info*)ptr, &vec))
          {
            smb2->smb2_set_error("could not decode file fs sector size info. %s", smb2->smb2_get_error());
            return -1;
          }
        break;
        default:
          smb2->smb2_set_error("Can not decode InfoType/InfoClass %d/%d yet",
                               this->requestedInfoType,
                               this->requestedInfoClass);
          return -1;
      }
    }
    break;
    default:
      smb2->smb2_set_error("Can not decode file InfoType %d yet", this->requestedInfoType);
      return -1;
  }

  rep->output_buffer = ptr;

  return 0;
}

int
Smb2QueryInfo::smb2ProcessReplyAndAppData(Smb2ContextPtr smb2)
{
  uint32_t status = header_resp.status;
  struct smb2_query_info_reply *rep = (struct smb2_query_info_reply *)payload;
  smb2_file_info *info = appData->getQInfo();
  string err;

  appData->setNtStatus(status);

  if (status != SMB2_STATUS_SUCCESS)
  {
    err = stringf("QueryFileInfo failed with (0x%08x) %s.", status, nterror_to_str(status));
    appData->setErrorMsg(err);
    smb2->endSendReceive();
    return 0;
  }

  if (info->info_type == SMB2_0_INFO_FILE)
  {
    if (info->file_info_class == SMB2_FILE_BASIC_INFORMATION)
    {
      struct smb2_file_basic_info *basic = (struct smb2_file_basic_info *)rep->output_buffer;
      (info->u_info).basic_info = *basic;
    }
    else if (info->file_info_class == SMB2_FILE_STANDARD_INFORMATION)
    {
      struct smb2_file_standard_info *standard = (struct smb2_file_standard_info *)rep->output_buffer;
      (info->u_info).standard_info = *standard;
    }
    else if (info->file_info_class == SMB2_FILE_FULL_EA_INFORMATION)
    {
      struct smb2_file_extended_info *extended = (struct smb2_file_extended_info *)rep->output_buffer;
      (info->u_info).extended_info = extended;
    rep->output_buffer = NULL; // DONOT free here, it will be used and freed by caller.
    }
    else if (info->file_info_class == SMB2_FILE_STREAM_INFORMATION)
    {
      struct smb2_file_stream_info *stream = (struct smb2_file_stream_info *)rep->output_buffer;
      (info->u_info).stream_info = stream;
      rep->output_buffer = NULL; // DONOT free here, it will be used and freed by caller.
    }
    else if (info->file_info_class == SMB2_FILE_ALL_INFORMATION)
    {
      struct smb2_file_all_info *all_info = (struct smb2_file_all_info *)rep->output_buffer;
      (info->u_info).all_info = *all_info;
    }
    else if (info->file_info_class == SMB2_FILE_RENAME_INFORMATION)
    {
    }
    else if (info->file_info_class == SMB2_FILE_END_OF_FILE_INFORMATION)
    {
    }
  }
  else if (info->info_type == SMB2_0_INFO_FILESYSTEM)
  {
    if (info->file_info_class == SMB2_FILE_FS_SIZE_INFORMATION)
    {
      struct smb2_file_fs_size_info *fsize = (struct smb2_file_fs_size_info *)rep->output_buffer;
      (info->u_info).fs_size_info = *fsize;
    }
    else if (info->file_info_class == SMB2_FILE_FS_DEVICE_INFORMATION)
    {
      struct smb2_file_fs_device_info *fs_device = (struct smb2_file_fs_device_info *)rep->output_buffer;
      (info->u_info).fs_device_info = *fs_device;
    }
    else if (info->file_info_class == SMB2_FILE_FS_CONTROL_INFORMATION)
    {
      struct smb2_file_fs_control_info *fs_control = (struct smb2_file_fs_control_info *)rep->output_buffer;
      (info->u_info).fs_control_info = *fs_control;
    }
    else if (info->file_info_class == SMB2_FILE_FS_SECTOR_SIZE_INFORMATION)
    {
      struct smb2_file_fs_sector_size_info *fs_sector = (struct smb2_file_fs_sector_size_info *)rep->output_buffer;
      (info->u_info).fs_sector_size_info = *fs_sector;
    }
    else if (info->file_info_class == SMB2_FILE_FS_FULL_SIZE_INFORMATION)
    {
      struct smb2_file_fs_full_size_info *vfs = (struct smb2_file_fs_full_size_info *)rep->output_buffer;
      (info->u_info).fs_full_size_info = *vfs;
    }
  }
  else if (info->info_type == SMB2_0_INFO_SECURITY)
  {
    struct smb2_security_descriptor *sd = (struct smb2_security_descriptor *)rep->output_buffer;
    (info->u_info).security_info = sd;
    rep->output_buffer = NULL; // DONOT free here, it will be used and freed by caller.
  }
  else if (info->info_type == SMB2_0_INFO_QUOTA)
  {
  }
  else
  {
    err = "Invalid INFO TYPE";
    appData->setStatusMsg(SMB2_STATUS_INVALID_PARAMETER, err);
    smb2->endSendReceive();
    return 0;
  }

  if (rep->output_buffer != NULL)
  {
    free(rep->output_buffer); rep->output_buffer = NULL;
  }
  smb2->endSendReceive();
  return 0;
}
