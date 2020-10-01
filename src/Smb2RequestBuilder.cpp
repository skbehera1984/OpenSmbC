#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "Stringf.h"
#include "Smb2Context.h"
#include "Smb2QueryDir.h"
#include "Smb2TreeConnect.h"
#include "Smb2SessionSetup.h"
#include "Smb2Negotiate.h"
#include "Smb2Close.h"
#include "Smb2Create.h"
#include "Smb2Flush.h"
#include "Smb2Read.h"
#include "Smb2Write.h"
#include "Smb2QueryInfo.h"
#include "Smb2SetInfo.h"
#include "Smb2Ioctl.h"
#include "Smb2TreeDisconnect.h"
#include "Smb2Logoff.h"
#include "Smb2Echo.h"

using namespace std;

#define FUNC stringf("%s: ", __func__)

static const smb2_file_id compound_file_id = {0xffffffffffffffff, 0xffffffffffffffff};

static void
Smb2AddPreAuthIntegContext(Smb2ContextPtr smb2, struct smb2_negotiate_request *req)
{
  int i = 0;
  req->neg_ctx_flags |= SMB2_NEG_PREAUTH;

  req->preauth_ctx.hdr.ContextType        = SMB2_PREAUTH_INTEGRITY_CAPABILITIES;
  req->preauth_ctx.hdr.DataLength         = sizeof(smb2_preauth_integ_context) - sizeof(smb2_neg_ctx_hdr);
  req->preauth_ctx.hdr.Reserved           = 0;
  req->preauth_ctx.HashAlgorithmCount     = 1;
  req->preauth_ctx.SaltLength             = SMB2_PREAUTH_INTEGRITY_SALT_SIZE;
  req->preauth_ctx.HashAlgorithms         = HASH_ALGORITHM_SHA_512;

  for (; i< 32; i++)
    req->preauth_ctx.Salt[i] = random();
}

static void
Smb2AddEncryptionContext(Smb2ContextPtr smb2, struct smb2_negotiate_request *req)
{
  req->neg_ctx_flags |= SMB2_NEG_ENC_CAP;

  req->enc_ctx.hdr.ContextType = SMB2_ENCRYPTION_CAPABILITIES;
  req->enc_ctx.hdr.DataLength  = sizeof(smb2_enc_cap_context) - sizeof(smb2_neg_ctx_hdr);
  req->enc_ctx.hdr.Reserved    = 0;
  req->enc_ctx.CipherCount     = 2;
  req->enc_ctx.Ciphers[0]      = SMB2_ENC_CIPHER_AES_128_GCM;
  req->enc_ctx.Ciphers[1]      = SMB2_ENC_CIPHER_AES_128_CCM;
}

static void
Smb2AddNegotiateContexts(Smb2ContextPtr smb2, struct smb2_negotiate_request *req)
{
  if (req->max_dialect != SMB2_VERSION_0311)
    return;

  Smb2AddPreAuthIntegContext(smb2, req);

  if (smb2->smb2IsEncryptionEnabled())
  {
    Smb2AddEncryptionContext(smb2, req);
  }
}

int
Smb2Context::Smb2BuildConnectRequest(std::string& server,
                                     std::string& share,
                                     std::string& user,
                                     AppData      *connData)
{
  struct smb2_negotiate_request req;
  Smb2Pdu *pdu = NULL;
  string error;

  memset(&req, 0, sizeof(struct smb2_negotiate_request));

  /* use these by default */
  if (this->sec == SMB2_SEC_KRB5)
    this->use_cached_creds = true;

  this->version = SMB2_VERSION_ANY;

  switch (this->version)
  {
    case SMB2_VERSION_ANY:
    case SMB2_VERSION_MAX_311:
      req.dialect_count = 5;
      req.dialects[0] = SMB2_VERSION_0202;
      req.dialects[1] = SMB2_VERSION_0210;
      req.dialects[2] = SMB2_VERSION_0300;
      req.dialects[3] = SMB2_VERSION_0302;
      req.dialects[4] = SMB2_VERSION_0311;
      req.max_dialect = req.dialects[4];
    break;
    case SMB2_VERSION_ANY2:
    case SMB2_VERSION_MAX_210:
      req.dialect_count = 2;
      req.dialects[0] = SMB2_VERSION_0202;
      req.dialects[1] = SMB2_VERSION_0210;
      req.max_dialect = req.dialects[1];
    break;
    case SMB2_VERSION_ANY3:
      req.dialect_count = 3;
      req.dialects[0] = SMB2_VERSION_0300;
      req.dialects[1] = SMB2_VERSION_0302;
      req.dialects[2] = SMB2_VERSION_0311;
      req.max_dialect = req.dialects[2];
    break;
    case SMB2_VERSION_MAX_300:
      req.dialect_count = 3;
      req.dialects[0] = SMB2_VERSION_0202;
      req.dialects[1] = SMB2_VERSION_0210;
      req.dialects[2] = SMB2_VERSION_0300;
      req.max_dialect = req.dialects[2];
    break;
    case SMB2_VERSION_MAX_302:
      req.dialect_count = 4;
      req.dialects[0] = SMB2_VERSION_0202;
      req.dialects[1] = SMB2_VERSION_0210;
      req.dialects[2] = SMB2_VERSION_0300;
      req.dialects[3] = SMB2_VERSION_0302;
      req.max_dialect = req.dialects[3];
    break;
    case SMB2_VERSION_0202:
    case SMB2_VERSION_0210:
    case SMB2_VERSION_0300:
    case SMB2_VERSION_0302:
    case SMB2_VERSION_0311:
      req.dialect_count = 1;
      req.dialects[0] = this->version;
      req.max_dialect = req.dialects[0];
    break;
  }

  char client_guid[SMB2_GUID_SIZE];
  snprintf(client_guid, SMB2_GUID_SIZE, "OpenSmbC-%d", getpid());
  memcpy(req.client_guid, client_guid, SMB2_GUID_SIZE);

  req.security_mode = this->security_mode;

  if (req.max_dialect >= SMB2_VERSION_0210)
  {
    req.capabilities |= SMB2_GLOBAL_CAP_LARGE_MTU;
  }
  if (req.max_dialect >= SMB2_VERSION_0311)
  {
    req.capabilities |= SMB2_GLOBAL_CAP_ENCRYPTION;
  }
  Smb2AddNegotiateContexts(this, &req);

  pdu = Smb2Negotiate::createPdu(this, &req, connData);
  if (pdu == NULL)
  {
    error = FUNC + connData->getErrorMsg();
    connData->setErrorMsg(error);
    return -1;
  }

  if (!smb2_queue_pdu(pdu, error))
  {
    connData->setErrorMsg(error);
    return -1;
  }

  return 0;
}

int
Smb2Context::Smb2BuildQueryDirectoryRequest(smb2fh  *fh,
                                            string&  pattern,
                                            AppData *qDirData)
{
  struct smb2_query_directory_request req;
  smb2dir *dir = nullptr;
  Smb2Pdu *pdu;
  string error;

  dir = new smb2dir();
  if (dir == nullptr)
  {
    error = FUNC + "Failed to allocate smb2dir";
    delete qDirData;
    qDirData->setErrorMsg(error);
    return -1;
  }

  dir->file_id.persistent_id = fh->file_id.persistent_id;
  dir->file_id.volatile_id   = fh->file_id.volatile_id;

  qDirData->setDir(dir);
  qDirData->setSearchPattern(pattern);

  memset(&req, 0, sizeof(struct smb2_query_directory_request));
  req.file_information_class = SMB2_FILE_ID_FULL_DIRECTORY_INFORMATION;
  req.flags = 0;
  req.file_id.persistent_id = dir->file_id.persistent_id;
  req.file_id.volatile_id = dir->file_id.volatile_id;
  req.output_buffer_length = 0xffff;
  req.name = pattern.c_str();

  pdu = Smb2QueryDir::createPdu(this, &req, qDirData);
  if (pdu == NULL)
  {
    error = FUNC + qDirData->getErrorMsg();
    qDirData->setErrorMsg(error);
    delete dir;
    delete qDirData;
    return -1;
  }

  if (!this->smb2_queue_pdu(pdu, error))
  {
    qDirData->setErrorMsg(error);
    return -1;
  }

  return 0;
}

int
Smb2Context::Smb2BuildCreateRequest(std::string& path,
                                    uint8_t  security_flags,
                                    uint32_t impersonation_level,
                                    uint64_t smb_create_flags,
                                    uint32_t desired_access,
                                    uint32_t file_attributes,
                                    uint32_t share_access,
                                    uint32_t create_disposition,
                                    uint32_t create_options,
                                    AppData  *createData)
{
  struct smb2_create_request req;
  Smb2Pdu *pdu;
  string error;

  smb2fh *fh = new smb2fh();
  if (fh == nullptr)
  {
    error = FUNC + "Failed to allocate smb2fh";
    createData->setErrorMsg(error);
    return -ENOMEM;
  }

  createData->setFH(fh);

  if (this->userInBackUpOperatorsGrp)
  {
    create_options |= SMB2_FILE_OPEN_FOR_BACKUP_INTENT;
  }

  memset(&req, 0, sizeof(struct smb2_create_request));
  req.security_flags         = security_flags;
  req.requested_oplock_level = SMB2_OPLOCK_LEVEL_NONE;
  req.impersonation_level    = impersonation_level;
  req.smb_create_flags       = smb_create_flags;
  req.desired_access         = desired_access;
  req.file_attributes        = file_attributes;
  req.share_access           = share_access;
  req.create_disposition     = create_disposition;
  req.create_options         = create_options;
  req.name = path.c_str();

  pdu = Smb2Create::createPdu(this, &req, createData);
  if (pdu == NULL)
  {
    error = FUNC + createData->getErrorMsg();
    createData->setErrorMsg(error);
    delete createData;
    return -ENOMEM;
  }

  if (!smb2_queue_pdu(pdu, error))
  {
    createData->setErrorMsg(error);
    return -1;
  }

  return 0;
}

int
Smb2Context::Smb2BuildCloseRequest(smb2fh *fh, AppData *closeData)
{
  struct smb2_close_request req;
  Smb2Pdu *pdu;
  string error;

  closeData->setFH(fh);

  memset(&req, 0, sizeof(struct smb2_close_request));
  req.flags = SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB;
  req.file_id.persistent_id = fh->file_id.persistent_id;
  req.file_id.volatile_id = fh->file_id.volatile_id;

  pdu = Smb2Close::createPdu(this, &req, closeData);
  if (pdu == NULL)
  {
    error = FUNC + closeData->getErrorMsg();
    closeData->setErrorMsg(error);
    delete closeData;
    return -ENOMEM;
  }

  if (!smb2_queue_pdu(pdu, error))
  {
    closeData->setErrorMsg(error);
    return -1;
  }

  return 0;
}

int
Smb2Context::Smb2BuildFlushRequest(smb2fh *fh, AppData *flushData)
{
  struct smb2_flush_request req;
  Smb2Pdu *pdu;
  string error;

  memset(&req, 0, sizeof(struct smb2_flush_request));
  req.file_id.persistent_id = fh->file_id.persistent_id;
  req.file_id.volatile_id = fh->file_id.volatile_id;

  pdu = Smb2Flush::createPdu(this, &req, flushData);
  if (pdu == NULL)
  {
    error = FUNC + flushData->getErrorMsg();
    flushData->setErrorMsg(error);
    return -ENOMEM;
  }

  if (!smb2_queue_pdu(pdu, error))
  {
    flushData->setErrorMsg(error);
    delete pdu;
    return -1;
  }

  return 0;
}

int
Smb2Context::Smb2BuildReadRequest(smb2fh   *fh,
                                  uint8_t  *buf,
                                  uint32_t count,
                                  uint64_t offset,
                                  AppData *readData)
{
  struct smb2_read_request req;
  Smb2Pdu *pdu;
  string error;
  uint32_t needed_credits = (count - 1) / 65536 + 1;

  if (count > this->max_read_size)
  {
    count = this->max_read_size;
  }
  if (this->dialect > SMB2_VERSION_0202)
  {
    if (needed_credits > MAX_CREDITS - 16)
    {
      count =  (MAX_CREDITS - 16) * 65536;
    }
    needed_credits = (count - 1) / 65536 + 1;
    if (needed_credits > this->credits)
    {
      count = this->credits * 65536;
    }
  }
  else
  {
    if (count > 65536)
      count = 65536;
  }

  fh->offset = offset;

  readData->setFH(fh);
  readData->setReadBuf(buf); // buffer sent by application

  memset(&req, 0, sizeof(struct smb2_read_request));
  req.flags = 0;
  req.length = count;
  req.offset = offset;
  req.file_id.persistent_id = fh->file_id.persistent_id;
  req.file_id.volatile_id = fh->file_id.volatile_id;
  req.minimum_count = 0;
  req.channel = SMB2_CHANNEL_NONE;
  req.remaining_bytes = 0;

  pdu = Smb2Read::createPdu(this, &req, readData);
  if (pdu == NULL)
  {
    error = FUNC + readData->getErrorMsg();
    readData->setErrorMsg(error);
    return -1;
  }

  if (!smb2_queue_pdu(pdu, error))
  {
    readData->setErrorMsg(error);
    return -1;
  }

  return 0;
}

int
Smb2Context::Smb2BuildWriteRequest(smb2fh    *fh,
                                   uint8_t   *buf,
                                   uint32_t  count,
                                   uint64_t  offset,
                                   AppData   *writeData)
{
  struct smb2_write_request req;
  Smb2Pdu *pdu;
  string error;
  uint32_t needed_credits = (count - 1) / 65536 + 1;

  if (count > this->max_write_size)
  {
    count = this->max_write_size;
  }
  if (this->dialect > SMB2_VERSION_0202)
  {
    if (needed_credits > MAX_CREDITS - 16)
    {
      count =  (MAX_CREDITS - 16) * 65536;
    }
    needed_credits = (count - 1) / 65536 + 1;
    if (needed_credits > this->credits)
    {
      count = this->credits * 65536;
    }
  }
  else
  {
    if (count > 65536)
      count = 65536;
  }

  fh->offset = offset;

  writeData->setFH(fh);

  memset(&req, 0, sizeof(struct smb2_write_request));
  req.length = count;
  req.offset = offset;
  req.buf = buf;
  req.file_id.persistent_id = fh->file_id.persistent_id;
  req.file_id.volatile_id = fh->file_id.volatile_id;
  req.channel = SMB2_CHANNEL_NONE;
  req.remaining_bytes = 0;
  req.flags = 0;

  pdu = Smb2Write::createPdu(this, &req, writeData);
  if (pdu == NULL)
  {
    error = FUNC + writeData->getErrorMsg();
    writeData->setErrorMsg(error);
    return -ENOMEM;
  }

  if (!smb2_queue_pdu(pdu, error))
  {
    writeData->setErrorMsg(error);
    return -1;
  }

  return 0;
}

int
Smb2Context::Smb2BuildQueryInfoRequest(smb2fh         *fh,
                                       smb2_file_info *info,
                                       AppData        *qiData)
{
  struct smb2_query_info_request qi_req;
  Smb2Pdu *pdu;
  string error;

  if (fh == NULL)
  {
    error = FUNC + "FileHandle is not provided";
    qiData->setErrorMsg(error);
    return -1;
  }

  if (info == NULL)
  {
    error = FUNC + "No info type provided for query";
    qiData->setErrorMsg(error);
    return -1;
  }

  qiData->setQInfo(info);

  memset(&qi_req, 0, sizeof(struct smb2_query_info_request));
  qi_req.info_type = info->info_type;
  qi_req.file_info_class = info->file_info_class;
  qi_req.output_buffer_length = 65535;
  qi_req.additional_information = 0;
  if (info->info_type == SMB2_0_INFO_SECURITY)
  {
    qi_req.file_info_class = 0;
    qi_req.additional_information = SMB2_OWNER_SECURITY_INFORMATION |
                                    SMB2_GROUP_SECURITY_INFORMATION |
                                    SMB2_DACL_SECURITY_INFORMATION;
  }
  qi_req.flags = 0;
  qi_req.file_id.persistent_id = fh->file_id.persistent_id;
  qi_req.file_id.volatile_id= fh->file_id.volatile_id;

  pdu = Smb2QueryInfo::createPdu(this, &qi_req, qiData);
  if (pdu == NULL)
  {
    error = FUNC + qiData->getErrorMsg();
    qiData->setErrorMsg(error);
    return -1;
  }

  if (!smb2_queue_pdu(pdu, error))
  {
    qiData->setErrorMsg(error);
    return -1;
  }

  return 0;
}

int
Smb2Context::Smb2BuildQueryInfoRequest(std::string    &path,
                                       smb2_file_info *info,
                                       AppData        *qiData)
{
  struct smb2_create_request cr_req;
  struct smb2_query_info_request qi_req;
  struct smb2_close_request cl_req;
  Smb2Pdu *pdu, *next_pdu;
  string error;

  if (info == NULL)
  {
    error = FUNC + "No info type provided for query";
    qiData->setErrorMsg(error);
    return -1;
  }

  AppData *createData = new CreateData();
  if (createData == nullptr)
  {
    error = FUNC + "Failed to allocate CreateData";
    qiData->setErrorMsg(error);
    return -1;
  }
  createData->setDelete(true); // should it be deferred till the pdu is created??

  /* CREATE command */
  memset(&cr_req, 0, sizeof(struct smb2_create_request));
  cr_req.requested_oplock_level = SMB2_OPLOCK_LEVEL_NONE;
  cr_req.impersonation_level = SMB2_IMPERSONATION_IMPERSONATION;
  cr_req.desired_access = SMB2_FILE_READ_ATTRIBUTES | SMB2_FILE_READ_EA;
  if (info->info_type == SMB2_0_INFO_SECURITY)
  {
    cr_req.desired_access = SMB2_READ_CONTROL;
  }
  cr_req.file_attributes = 0;
  cr_req.share_access = SMB2_FILE_SHARE_READ | SMB2_FILE_SHARE_WRITE;
  cr_req.create_disposition = SMB2_FILE_OPEN;
  cr_req.create_options = 0;
  cr_req.name = path.c_str();

  if (this->userInBackUpOperatorsGrp)
    cr_req.create_options |= SMB2_FILE_OPEN_FOR_BACKUP_INTENT;

  pdu = Smb2Create::createPdu(this, &cr_req, createData);
  if (pdu == NULL)
  {
    error = FUNC + createData->getErrorMsg();
    qiData->setErrorMsg(error);
    delete createData;
    return -1;
  }

  qiData->setQInfo(info);

  /* QUERY INFO command */
  memset(&qi_req, 0, sizeof(struct smb2_query_info_request));
  qi_req.info_type = info->info_type;
  qi_req.file_info_class = info->file_info_class;
  qi_req.output_buffer_length = 65535;
  qi_req.additional_information = 0;
  if (info->info_type == SMB2_0_INFO_SECURITY)
  {
    qi_req.file_info_class = 0;
    qi_req.additional_information = SMB2_OWNER_SECURITY_INFORMATION |
                                    SMB2_GROUP_SECURITY_INFORMATION |
                                    SMB2_DACL_SECURITY_INFORMATION;
  }
  qi_req.flags = 0;
  qi_req.file_id.persistent_id = compound_file_id.persistent_id;
  qi_req.file_id.volatile_id= compound_file_id.volatile_id;

  next_pdu = Smb2QueryInfo::createPdu(this, &qi_req, qiData);
  if (next_pdu == NULL)
  {
    error = FUNC + qiData->getErrorMsg();
    qiData->setErrorMsg(error);
    delete pdu;
    return -1;
  }
  pdu->smb2AddCompoundPdu(next_pdu);

  AppData *closeData = new CloseData();
  if (closeData == nullptr)
  {
    error = FUNC + "Failed to allocate CloseData";
    qiData->setErrorMsg(error);
    delete pdu;
    return -1;
  }
  closeData->setDelete(true); // TODO - should it be deferred??

  /* CLOSE command */
  memset(&cl_req, 0, sizeof(struct smb2_close_request));
  cl_req.flags = SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB;
  cl_req.file_id.persistent_id = compound_file_id.persistent_id;
  cl_req.file_id.volatile_id= compound_file_id.volatile_id;

  next_pdu = Smb2Close::createPdu(this, &cl_req, closeData);
  if (next_pdu == NULL)
  {
    error = FUNC + closeData->getErrorMsg();
    qiData->setErrorMsg(error);
    delete closeData;
    delete pdu;
    return -1;
  }

  pdu->smb2AddCompoundPdu(next_pdu);

  if (!smb2_queue_pdu(pdu, error))
  {
    qiData->setErrorMsg(error);
    delete pdu;
    return -1;
  }

  return 0;
}

int
Smb2Context::Smb2BuildDisConnectRequest(AppData *disConData)
{
  Smb2Pdu *pdu;
  std::string error;

  pdu = Smb2TreeDisconnect::createPdu(this, disConData);
  if (pdu == NULL)
  {
    error = FUNC + disConData->getErrorMsg();
    disConData->setErrorMsg(error);
    return -ENOMEM;
  }

  if (!smb2_queue_pdu(pdu, error))
  {
    disConData->setErrorMsg(error);
    delete pdu;
    return -1;
  }

  return 0;
}

int
Smb2Context::Smb2BuildEchoRequest(AppData *echoData)
{
  Smb2Pdu *pdu;
  string error;

  pdu = Smb2Echo::createPdu(this, echoData);
  if (pdu == NULL)
  {
    error = FUNC + echoData->getErrorMsg();
    echoData->setErrorMsg(error);
    return -1;
  }

  if (!smb2_queue_pdu(pdu, error))
  {
    echoData->setErrorMsg(error);
    delete pdu;
    return -1;
  }

  return 0;
}

int
Smb2Context::Smb2BuildIoctlRequest(smb2fh   *fh,
                                   uint32_t ioctl_ctl,
                                   uint32_t ioctl_flags,
                                   uint8_t  *input_buffer,
                                   uint32_t input_count,
                                   uint8_t  *output_buffer,
                                   uint32_t *output_count,
                                   AppData  *ioctlData)
{
  struct smb2_ioctl_request req;
  Smb2Pdu *pdu;
  string error;

  if (input_count > this->max_transact_size)
  {
    error = FUNC + stringf("Ioctl count %d larger than max_transact_size %d",
                           input_count, this->max_transact_size);
    ioctlData->setErrorMsg(error);
    return -EIO;
  }

  ioctlData->setOutBuf(output_buffer, output_count);

  memset(&req, 0, sizeof(struct smb2_ioctl_request));
  req.ctl_code = ioctl_ctl;
  req.input_count = input_count;
  req.input_buffer = input_buffer;
  req.file_id.persistent_id = fh->file_id.persistent_id;
  req.file_id.volatile_id= fh->file_id.volatile_id;
  req.flags = ioctl_flags;
  req.max_input_response = 0;
  /* it works somehow with - 108 bytes */
  //req.max_output_response = smb2GetMaxTransactSize() - 108;

  uint64_t payload = this->credits * (64 * 1024);
  if (payload > this->smb2GetMaxTransactSize())
  {
    payload = this->smb2GetMaxTransactSize() - 1024;
  }
  /* use user provided payload count */
  if (*output_count < payload)
  {
    payload = *output_count;
  }
  req.max_output_response = payload;

  pdu = Smb2Ioctl::createPdu(this, &req, ioctlData);
  if (pdu == NULL)
  {
    error = FUNC + ioctlData->getErrorMsg();
    ioctlData->setErrorMsg(error);
    return -1;
  }

  if (!smb2_queue_pdu(pdu, error))
  {
    ioctlData->setErrorMsg(error);
    delete pdu;
    return -1;
  }

  return 0;
}

int
Smb2Context::Smb2BuildSetInforequest(smb2fh         *fh,
                                     smb2_file_info *info,
                                     AppData        *setinfoData)
{
  struct smb2_set_info_request si_req;
  Smb2Pdu *pdu;
  string error;

  if (fh == NULL)
  {
    error = FUNC + "no FileHandle provided";
    setinfoData->setErrorMsg(error);
    return -1;
  }

  if (info == NULL)
  {
    error = FUNC + "no info provided";
    setinfoData->setErrorMsg(error);
    return -1;
  }

  if (info->info_type != SMB2_0_INFO_FILE && info->info_type != SMB2_0_INFO_SECURITY)
  {
    error = FUNC + "Invalid INFOTYPE to set";
    setinfoData->setErrorMsg(error);
    return -1;
  }

  if (info->info_type == SMB2_0_INFO_SECURITY)
    info->file_info_class = 0;

  memset(&si_req, 0, sizeof(struct smb2_set_info_request));
  si_req.info_type = info->info_type;
  si_req.file_info_class = info->file_info_class;
  si_req.file_id.persistent_id = fh->file_id.persistent_id;
  si_req.file_id.volatile_id= fh->file_id.volatile_id;

  if (info->file_info_class == SMB2_FILE_RENAME_INFORMATION)
  {
    si_req.input_data = &((info->u_info).rename_info);
  }
  else if(info->file_info_class == SMB2_FILE_END_OF_FILE_INFORMATION)
  {
    si_req.input_data = &((info->u_info).eof_info);
  }
  else if (info->file_info_class == SMB2_FILE_BASIC_INFORMATION)
  {
    si_req.input_data = &((info->u_info).basic_info);
  }
  else if (info->file_info_class == SMB2_FILE_FULL_EA_INFORMATION)
  {
    si_req.input_data = &((info->u_info).extended_info);
  }

  if (info->info_type == SMB2_0_INFO_SECURITY)
  {
    si_req.additional_information = SMB2_OWNER_SECURITY_INFORMATION |
                                    SMB2_GROUP_SECURITY_INFORMATION |
                                    SMB2_DACL_SECURITY_INFORMATION;
    si_req.input_data = &((info->u_info).sec_info);
  }

  pdu = Smb2SetInfo::createPdu(this, &si_req, setinfoData);
  if (pdu == NULL)
  {
    error = FUNC + setinfoData->getErrorMsg();
    setinfoData->setErrorMsg(error);
    return -1;
  }

  if (!smb2_queue_pdu(pdu, error))
  {
    setinfoData->setErrorMsg(error);
    delete pdu;
    return -1;
  }

  return 0;
}

int
Smb2Context::Smb2BuildSetInforequest(string&        path,
                                     smb2_file_info *info,
                                     AppData        *setinfoData)
{
  struct smb2_create_request cr_req;
  struct smb2_set_info_request si_req;
  struct smb2_close_request cl_req;
  Smb2Pdu *pdu, *next_pdu;
  string error;

  if (info == NULL)
  {
    error = FUNC + "No info provided to set";
    setinfoData->setErrorMsg(error);
    return -1;
  }

  if (info->info_type != SMB2_0_INFO_FILE && info->info_type != SMB2_0_INFO_SECURITY)
  {
    error = FUNC + "Invalid INFOTYPE to set";
    setinfoData->setErrorMsg(error);
    return -1;
  }

  if (info->info_type == SMB2_0_INFO_SECURITY)
    info->file_info_class = 0;

  AppData *createData = new CreateData();
  if (createData == nullptr)
  {
    error = FUNC + "Failed to allocate CreateData";
    setinfoData->setErrorMsg(error);
    return -1;
  }
  createData->setDelete(true);

  /* CREATE command */
  memset(&cr_req, 0, sizeof(struct smb2_create_request));
  cr_req.requested_oplock_level = SMB2_OPLOCK_LEVEL_NONE;
  cr_req.impersonation_level = SMB2_IMPERSONATION_IMPERSONATION;

  /* set the proper desired access */
  if (info->file_info_class == SMB2_FILE_END_OF_FILE_INFORMATION)
  {
    cr_req.desired_access = SMB2_GENERIC_WRITE;
  }
  else if (info->file_info_class == SMB2_FILE_BASIC_INFORMATION)
  {
    cr_req.desired_access = SMB2_FILE_WRITE_ATTRIBUTES | SMB2_FILE_WRITE_EA;
  }
  else if (info->file_info_class == SMB2_FILE_FULL_EA_INFORMATION)
  {
    cr_req.desired_access = SMB2_FILE_WRITE_ATTRIBUTES | SMB2_FILE_WRITE_EA;
  }
  else if (info->file_info_class == SMB2_FILE_RENAME_INFORMATION)
  {
    cr_req.desired_access = SMB2_GENERIC_READ | SMB2_FILE_READ_ATTRIBUTES | SMB2_DELETE;
  }
  if (info->info_type == SMB2_0_INFO_SECURITY)
  {
    cr_req.desired_access= SMB2_WRITE_DACL | SMB2_WRITE_OWNER;
  }

  cr_req.file_attributes = 0;
  cr_req.share_access = SMB2_FILE_SHARE_READ | SMB2_FILE_SHARE_WRITE;
  if (info->file_info_class == SMB2_FILE_RENAME_INFORMATION)
  {
    cr_req.share_access = SMB2_FILE_SHARE_READ | SMB2_FILE_SHARE_WRITE | SMB2_FILE_SHARE_DELETE;
  }
  cr_req.create_disposition = SMB2_FILE_OPEN;
  cr_req.create_options = 0;
  cr_req.name = path.c_str();

  if (this->userInBackUpOperatorsGrp)
    cr_req.create_options |= SMB2_FILE_OPEN_FOR_BACKUP_INTENT;

  pdu = Smb2Create::createPdu(this, &cr_req, createData);
  if (pdu == NULL)
  {
    error = FUNC + createData->getErrorMsg();
    setinfoData->setErrorMsg(error);
    delete createData;
    return -1;
  }

  /* SET INFO command */
  memset(&si_req, 0, sizeof(struct smb2_set_info_request));
  si_req.info_type = info->info_type;
  si_req.file_info_class = info->file_info_class;
  si_req.file_id.persistent_id = compound_file_id.persistent_id;
  si_req.file_id.volatile_id= compound_file_id.volatile_id;

  if (info->file_info_class == SMB2_FILE_RENAME_INFORMATION)
  {
    si_req.input_data = &((info->u_info).rename_info);
  }
  else if(info->file_info_class == SMB2_FILE_END_OF_FILE_INFORMATION)
  {
    si_req.input_data = &((info->u_info).eof_info);
  }
  else if (info->file_info_class == SMB2_FILE_BASIC_INFORMATION)
  {
    si_req.input_data = &((info->u_info).basic_info);
  }
  else if (info->file_info_class == SMB2_FILE_FULL_EA_INFORMATION)
  {
    si_req.input_data = &((info->u_info).extended_info);
  }

  if (info->info_type == SMB2_0_INFO_SECURITY)
  {
    si_req.additional_information = SMB2_OWNER_SECURITY_INFORMATION |
                                    SMB2_GROUP_SECURITY_INFORMATION |
                                    SMB2_DACL_SECURITY_INFORMATION;
    si_req.input_data = &((info->u_info).sec_info);
  }

  next_pdu = Smb2SetInfo::createPdu(this, &si_req, setinfoData);
  if (next_pdu == NULL)
  {
    error = FUNC + setinfoData->getErrorMsg();
    setinfoData->setErrorMsg(error);
    delete pdu;
    return -1;
  }

  pdu->smb2AddCompoundPdu(next_pdu);

  AppData *closeData = new CloseData();
  if (closeData == nullptr)
  {
    error = FUNC + "Failed to allocate CloseData";
    setinfoData->setErrorMsg(error);
    delete pdu;
    return -1;
  }
  closeData->setDelete(true);

  /* CLOSE command */
  memset(&cl_req, 0, sizeof(struct smb2_close_request));
  cl_req.flags = SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB;
  cl_req.file_id.persistent_id = compound_file_id.persistent_id;
  cl_req.file_id.volatile_id= compound_file_id.volatile_id;

  next_pdu = Smb2Close::createPdu(this, &cl_req, closeData);
  if (next_pdu == NULL)
  {
    error = FUNC + closeData->getErrorMsg();
    setinfoData->setErrorMsg(error);
    delete closeData;
    delete pdu;
    return -1;
  }

  pdu->smb2AddCompoundPdu(next_pdu);

  if (!smb2_queue_pdu(pdu, error))
  {
    setinfoData->setErrorMsg(error);
    delete pdu;
    return -1;
  }

  return 0;
}
