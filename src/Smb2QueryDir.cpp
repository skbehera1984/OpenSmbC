#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <string.h>
#include "Smb2QueryDir.h"

Smb2QueryDir::Smb2QueryDir(Smb2ContextPtr  smb2,
                           AppData         *qDirData)
  : Smb2Pdu(smb2, SMB2_QUERY_DIRECTORY, qDirData)
{
}

Smb2QueryDir::~Smb2QueryDir()
{
}

int
smb2_decode_fileidfulldirectoryinformation(
    Smb2ContextPtr smb2,
    struct smb2_fileidfulldirectoryinformation *fs,
    smb2_iovec *vec)
{
        uint32_t name_len;

        /* Make sure the name fits before end of vector.
         * As the name is the final part of this blob this guarantees
         * that all other fields also fit within the remainder of the
         * vector.
         */
        vec->smb2_get_uint32(60, &name_len);
        if (80 + name_len > vec->len) {
                smb2->smb2_set_error("Malformed name in query.\n");
                return -1;
        }

        vec->smb2_get_uint32(0, &fs->next_entry_offset);
        vec->smb2_get_uint32(4, &fs->file_index);
        vec->smb2_get_uint64(40, &fs->end_of_file);
        vec->smb2_get_uint64(48, &fs->allocation_size);
        vec->smb2_get_uint32(56, &fs->file_attributes);
        vec->smb2_get_uint32(64, &fs->ea_size);
        vec->smb2_get_uint64(72, &fs->file_id);

        fs->name = ucs2_to_utf8((uint16_t *)&vec->buf[80], name_len / 2);

        vec->smb2_get_uint64(8, &fs->creation_time);
        vec->smb2_get_uint64(16, &fs->last_access_time);
        vec->smb2_get_uint64(24, &fs->last_write_time);
        vec->smb2_get_uint64(32, &fs->change_time);

        return 0;
}

int
Smb2QueryDir::encodeRequest(Smb2ContextPtr smb2, void *Req)
{
  int len;
  uint8_t *buf;
  struct ucs2 *name = NULL;
  struct smb2_query_directory_request *req = (struct smb2_query_directory_request*)Req;

  len = SMB2_QUERY_DIRECTORY_REQUEST_SIZE & 0xfffffffe;
  buf = (uint8_t*)malloc(len);
  if (buf == NULL) {
    smb2->smb2_set_error("Failed to allocate query buffer");
    return -1;
  }
  memset(buf, 0, len);

  smb2_iovec iov(buf, len, free);
  out.smb2_add_iovector(iov);

  /* Name */
  if (req->name && req->name[0]) {
    name = utf8_to_ucs2(req->name);
    if (name == NULL) {
      smb2->smb2_set_error("Could not convert name into UCS2");
      return -1;
    }
    iov.smb2_set_uint16(26, 2 * name->len);
  }

  iov.smb2_set_uint16(0, SMB2_QUERY_DIRECTORY_REQUEST_SIZE);
  iov.smb2_set_uint8(2, req->file_information_class);
  iov.smb2_set_uint8(3, req->flags);
  iov.smb2_set_uint32(4, req->file_index);
  iov.smb2_set_uint64(8, req->file_id.persistent_id);
  iov.smb2_set_uint64(16, req->file_id.volatile_id);
  iov.smb2_set_uint16(24, SMB2_HEADER_SIZE + 32);
  iov.smb2_set_uint32(28, req->output_buffer_length);

  /* Name */
  if (name) {
    buf = (uint8_t*)malloc(2 * name->len);
    if (buf == NULL) {
      smb2->smb2_set_error("Failed to allocate qdir name");
      free(name);
      return -1;
    }
    memcpy(buf, &name->val[0], 2 * name->len);
    iov.buf = buf; iov.len = (2 * name->len); iov.free = free;
    out.smb2_add_iovector(iov);
  }
  free(name);

  return 0;
}

Smb2Pdu *
Smb2QueryDir::createPdu(Smb2ContextPtr                      smb2,
                        struct smb2_query_directory_request *req,
                        AppData                             *qDirData)
{
  Smb2Pdu *pdu;

  pdu = new Smb2QueryDir(smb2, qDirData);
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
    pdu->header.credit_charge = (req->output_buffer_length - 1) / 65536 + 1; // 3.1.5.2 of [MS-SMB2]
  }

  return pdu;
}

#define IOV_OFFSET (rep->output_buffer_offset - SMB2_HEADER_SIZE - \
                    (SMB2_QUERY_DIRECTORY_REPLY_SIZE & 0xfffe))

int
Smb2QueryDir::smb2ReplyProcessFixed(Smb2ContextPtr smb2)
{
  if (smb2_is_error_response()) {
    return smb2_process_error_fixed(smb2);
  }

  struct smb2_query_directory_reply *rep;
  smb2_iovec &iov = in.iovs.back();
  uint16_t struct_size;

  rep = (struct smb2_query_directory_reply *)malloc(sizeof(*rep));
  if (rep == NULL) {
    smb2->smb2_set_error("Failed to allocate query dir reply");
    return -1;
  }
  this->payload = rep;

  iov.smb2_get_uint16(0, &struct_size);
  if (struct_size != SMB2_QUERY_DIRECTORY_REPLY_SIZE || (struct_size & 0xfffe) != iov.len)
  {
    smb2->smb2_set_error("Unexpected size of Query Dir reply. Expected %d, got %d",
                         SMB2_QUERY_DIRECTORY_REPLY_SIZE, (int)iov.len);
    return -1;
  }

  iov.smb2_get_uint16(2, &rep->output_buffer_offset);
  iov.smb2_get_uint32(4, &rep->output_buffer_length);

  if (rep->output_buffer_length == 0) {
    return 0;
  }

  if (rep->output_buffer_offset < SMB2_HEADER_SIZE + (SMB2_QUERY_INFO_REPLY_SIZE & 0xfffe))
  {
    smb2->smb2_set_error("Output buffer overlaps with Query Dir reply header");
    return -1;
  }

  /* Return the amount of data that the output buffer will take up.
   * Including any padding before the output buffer itself.
   */
  return IOV_OFFSET + rep->output_buffer_length;
}

int
Smb2QueryDir::smb2ReplyProcessVariable(Smb2ContextPtr smb2)
{
  if (smb2_is_error_response()) {
    return smb2_process_error_variable(smb2);
  }

  struct smb2_query_directory_reply *rep = (struct smb2_query_directory_reply *)this->payload;
  smb2_iovec &iov = in.iovs.back();

  rep->output_buffer = &iov.buf[IOV_OFFSET];

  return 0;
}

int
Smb2QueryDir::smb2ProcessReplyAndAppData(Smb2ContextPtr smb2)
{
  uint32_t status = header_resp.status;
  struct smb2_query_directory_reply *rep = (struct smb2_query_directory_reply*)payload;
  smb2dir * dir = appData->getDir();

  string err = stringf("Smb2QueryDir::%s:", __func__);
  appData->setNtStatus(status);

  if (status == SMB2_STATUS_SUCCESS)
  {
    smb2_iovec vec;
    struct smb2_query_directory_request req;
    Smb2Pdu *pdu;

    vec.buf = rep->output_buffer;
    vec.len = rep->output_buffer_length;

    if (decode_dirents(smb2, dir, &vec) < 0)
    {
      err += "Failed to decode directory entries";
      appData->setErrorMsg(err);
      smb2->endSendReceive();
      delete dir;
      return -1;
    }

    /* We need to get more data */
    memset(&req, 0, sizeof(struct smb2_query_directory_request));
    req.file_information_class = SMB2_FILE_ID_FULL_DIRECTORY_INFORMATION;
    req.flags = 0;
    req.file_id.persistent_id = dir->file_id.persistent_id;
    req.file_id.volatile_id   = dir->file_id.volatile_id;
    req.output_buffer_length = 0xffff;
    req.name = appData->getSearchPattern().c_str();

    pdu = Smb2QueryDir::createPdu(smb2, &req, appData);
    if (pdu == NULL)
    {
      err += "Failed to create Smb2QueryDir PDU";
      appData->setErrorMsg(err);
      smb2->endSendReceive();
      delete dir;
      return -1;
    }

    smb2->smb2_queue_pdu(pdu, err);

    return 0;
  }

  if (status == SMB2_STATUS_NO_MORE_FILES)
  {
    /* We have all the data */
    /* dir will be freed in smb2_closedir() */
    appData->setNtStatus(SMB2_STATUS_SUCCESS);
    smb2->endSendReceive();
    return 0;
  }

  err = stringf("Query directory failed with (0x%08x) %s.", status, nterror_to_str(status));
  appData->setErrorMsg(err);
  smb2->endSendReceive();
  delete dir;

  return 0;
}

int Smb2QueryDir::decode_dirents(Smb2ContextPtr smb2, smb2dir *dir, smb2_iovec *vec)
{
  struct smb2_fileidfulldirectoryinformation fs;
  uint32_t offset = 0;

  do
  {
    smb2dirent ent;
    smb2_iovec tmp_vec;

    /* Make sure we do not go beyond end of vector */
    if (offset >= vec->len) {
      smb2->smb2_set_error("Malformed query reply.");
      return -1;
    }

    tmp_vec.buf = &vec->buf[offset];
    tmp_vec.len = vec->len - offset;

    smb2_decode_fileidfulldirectoryinformation(smb2, &fs, &tmp_vec);
    /* steal the name */
    ent.name = std::string(fs.name);
    ent.st.smb2_type = SMB2_TYPE_FILE;
    if (fs.file_attributes & SMB2_FILE_ATTRIBUTE_DIRECTORY)
    {
      ent.st.smb2_type = SMB2_TYPE_DIRECTORY;
    }
    ent.st.smb2_nlink       = 0;
    ent.st.smb2_ino         = fs.file_id;
    ent.st.smb2_size        = fs.end_of_file;
    ent.st.smb2_atime       = fs.last_access_time;
    ent.st.smb2_mtime       = fs.last_write_time;
    ent.st.smb2_ctime       = fs.change_time;
    ent.st.smb2_crtime      = fs.creation_time;
    ent.allocation_size     = fs.allocation_size;
    ent.attributes          = fs.file_attributes;
    ent.ea_size             = fs.ea_size;

    dir->entries.push_back(ent);

    offset += fs.next_entry_offset;
  } while (fs.next_entry_offset);

  return 0;
}
