#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <string.h>
#include <syslog.h>
#include <stdint.h>
#include <fcntl.h>

#include "smb2.h"
#include "Smb2Socket.h"
#include "Smb2Context.h"
#include "DceRpc.h"
#include "Stringf.h"
#include "util.h"
#include "Smb2FileData.h"

#define FUNC stringf("%s: ", __func__)

using namespace std;
/*
 * Connect to the server and mount the share.
 */
uint32_t
Smb2Context::smb2_connect_share(string&   server,
                                string&   share,
                                string&   user,
                                string&   error)
{
  if (smb2Socket->connect(this, server, error) != 0)
  {
    error = FUNC + error;
    return SMB2_STATUS_SOCKET_ERROR;
  }

  this->server = server;
  this->share = share;
  this->smb2SetUser(user);

  AppData connData;

  if (Smb2BuildConnectRequest(server, share, user, &connData) != 0)
  {
    error = FUNC + connData.getErrorMsg();
    return SMB2_STATUS_PAYLOAD_FAILED;
  }

  if (this->wait_for_reply(error) < 0)
  {
    error = FUNC + error;
    return SMB2_STATUS_SOCKET_ERROR;
  }

  error = FUNC + connData.getErrorMsg();
  return connData.ntStatus;
}

/*
 * Disconnect from share
 */
uint32_t
Smb2Context::smb2_disconnect_share()
{
  string error;

  /* check to see if connected or just need to close the fd */
  if (!isConnected())
  {
    smb2Socket->close();
    return SMB2_STATUS_SUCCESS;
  }

  AppData disConData;
  if (Smb2BuildDisConnectRequest(&disConData) != 0)
  {
    this->smb2_set_error("Smb2BuildDisConnectRequest failed");
    return SMB2_STATUS_PAYLOAD_FAILED;
  }

  if (this->wait_for_reply(error) < 0)
  {
    return SMB2_STATUS_SOCKET_ERROR;
  }

  return disConData.ntStatus;
}

/*
 * opendir()
 */
smb2dir *
Smb2Context::smb2_querydir(string& path, string& pattern, string& error)
{
  smb2fh *fh = NULL;

  if (!isConnected())
  {
    error = FUNC + string("Not Connected to Server");
    return NULL;
  }

  if (path.empty())
    path = "";

  fh = smb2_open_file(path, 0, 0,
                      SMB2_FILE_LIST_DIRECTORY | SMB2_FILE_READ_ATTRIBUTES,
                      SMB2_FILE_ATTRIBUTE_DIRECTORY,
                      SMB2_FILE_SHARE_READ | SMB2_FILE_SHARE_WRITE,
                      SMB2_FILE_OPEN,
                      SMB2_FILE_DIRECTORY_FILE,
                      error);
  if (fh == NULL)
  {
    error = FUNC + error;
    return NULL;
  }

  smb2dir *dir = nullptr;
  dir = smb2_fquerydir(fh, pattern, error);
  if (dir == nullptr)
  {
    error = FUNC + error;
  }

  smb2_close(fh, error);

  return dir;
}

smb2dir *
Smb2Context::smb2_fquerydir(smb2fh *fh, string& pattern, string& error)
{
  if (!isConnected())
  {
    error = FUNC + string("Not Connected to Server");
    return NULL;
  }

  if (fh == NULL)
  {
    error = FUNC + string("Directory NOT opened to query");
    return NULL;
  }

  QueryDirData qDirData;

  if (Smb2BuildQueryDirectoryRequest(fh, pattern, &qDirData) != 0)
  {
    error = FUNC + qDirData.getErrorMsg();
    return NULL;
  }

  if (this->wait_for_reply(error) < 0)
  {
    error = FUNC + error;
    return NULL;
  }

  error = FUNC + qDirData.getErrorMsg();
  return qDirData.getDir();
}

/*
 * open()
 */
smb2fh *
Smb2Context::smb2_open_file(string&  path,
                            uint8_t  security_flags,
                            uint64_t smb_create_flags,
                            uint32_t desired_access,
                            uint32_t file_attributes,
                            uint32_t share_access,
                            uint32_t create_disposition,
                            uint32_t create_options,
                            string&  error)
{
  if (!isConnected())
  {
    error = FUNC + string("Not Connected to Server");
    return NULL;
  }

  CreateData createData;

  if (Smb2BuildCreateRequest(path, security_flags,
                             SMB2_IMPERSONATION_IMPERSONATION,
                             smb_create_flags,
                             desired_access,
                             file_attributes,
                             share_access,
                             create_disposition,
                             create_options,
                             &createData) != 0)
  {
    error = FUNC + createData.getErrorMsg();
    return NULL;
  }

  if (this->wait_for_reply(error) < 0)
  {
    error = FUNC + error;
    return NULL;
  }

  error = FUNC + createData.getErrorMsg();
  return createData.getFH();
}

smb2fh *
Smb2Context::smb2_open(string& path, int flags, string& error)
{
  if (!isConnected())
  {
    error = FUNC + string("Not Connected to Server");
    return NULL;
  }

  uint8_t  security_flags = 0;
  uint64_t smb_create_flags = 0;
  uint32_t desired_access = 0;
  uint32_t file_attributes = 0;
  uint32_t share_access = 0;
  uint32_t create_disposition = 0;
  uint32_t create_options = 0;

  /* Create disposition */
  if (flags & O_CREAT)
  {
    if (flags & O_EXCL)
      create_disposition = SMB2_FILE_CREATE;
    else
      create_disposition = SMB2_FILE_OVERWRITE_IF;
  }
  else
  {
    if (flags & (O_WRONLY | O_RDWR))
      create_disposition = SMB2_FILE_OPEN_IF;
    else
      create_disposition = SMB2_FILE_OPEN;
  }

        /* desired access */
  if (flags & (O_RDWR | O_WRONLY))
  {
    desired_access |= SMB2_FILE_WRITE_DATA | SMB2_FILE_WRITE_EA | SMB2_FILE_WRITE_ATTRIBUTES;
  }
  if (flags & O_RDWR || !(flags & O_WRONLY))
  {
    desired_access |= SMB2_FILE_READ_DATA | SMB2_FILE_READ_EA | SMB2_FILE_READ_ATTRIBUTES;
  }

  /* create options */
  create_options |= SMB2_FILE_NON_DIRECTORY_FILE;

  if (flags & O_SYNC)
  {
    desired_access |= SMB2_SYNCHRONIZE;
    create_options |= SMB2_FILE_NO_INTERMEDIATE_BUFFERING;
  }

  share_access = SMB2_FILE_SHARE_READ | SMB2_FILE_SHARE_WRITE;

  CreateData createData;

  int ret = Smb2BuildCreateRequest(path, security_flags,
                                   SMB2_IMPERSONATION_IMPERSONATION,
                                   smb_create_flags,
                                   desired_access,
                                   file_attributes,
                                   share_access,
                                   create_disposition,
                                   create_options,
                                   &createData);
  if (ret < 0)
  {
    error = FUNC + createData.getErrorMsg();
    return NULL;
  }

  if (this->wait_for_reply(error) < 0)
  {
    error = FUNC + error;
    return NULL;
  }

  error = FUNC + createData.getErrorMsg();
  return createData.getFH();
}

/* open_pipe()
 */
smb2fh *
Smb2Context::smb2_open_pipe(string& pipe, string& error)
{
  if (!isConnected())
  {
    error = FUNC + string("Not Connected to Server");
    return NULL;
  }

  if (pipe.empty())
  {
    error = FUNC + string("no pipe path provided");
    return NULL;
  }

  uint8_t  security_flags = 0;
  uint64_t smb_create_flags = 0;
  uint32_t desired_access = 0;
  uint32_t file_attributes = 0;
  uint32_t share_access = 0;
  uint32_t create_disposition = 0;
  uint32_t create_options = 0;
  uint32_t impersonation_level = 0;

  create_disposition = SMB2_FILE_OPEN;
  create_options = SMB2_FILE_OPEN_NO_RECALL | SMB2_FILE_NON_DIRECTORY_FILE;
  desired_access |= SMB2_FILE_WRITE_DATA | SMB2_FILE_WRITE_EA | SMB2_FILE_WRITE_ATTRIBUTES;

  if (pipe == std::string("srvsvc"))
  {
    impersonation_level = SMB2_IMPERSONATION_IMPERSONATION;
    desired_access = 0x0012019f;
    share_access = SMB2_FILE_SHARE_READ | SMB2_FILE_SHARE_WRITE | SMB2_FILE_SHARE_DELETE;
  }
  else if (pipe == std::string("wkssvc"))
  {
    impersonation_level = SMB2_IMPERSONATION_IDENTIFICATION;
    desired_access = 0x0012019f;
    share_access = SMB2_FILE_SHARE_READ | SMB2_FILE_SHARE_WRITE | SMB2_FILE_SHARE_DELETE;
  }
  else if (pipe == std::string("lsarpc"))
  {
    impersonation_level = SMB2_IMPERSONATION_IMPERSONATION;
    desired_access = 0x0002019f;
    share_access = SMB2_FILE_SHARE_READ | SMB2_FILE_SHARE_WRITE;
    create_options = 0x00000000;
  }

  CreateData createData;

  int ret = Smb2BuildCreateRequest(pipe, security_flags,
                                   impersonation_level,
                                   smb_create_flags,
                                   desired_access,
                                   file_attributes,
                                   share_access,
                                   create_disposition,
                                   create_options,
                                   &createData);
  if (ret < 0)
  {
    error = FUNC + createData.getErrorMsg();
    return NULL;
  }

  if (this->wait_for_reply(error) < 0)
  {
    error = FUNC + error;
    return NULL;
  }

  error = FUNC + createData.getErrorMsg();
  return createData.getFH();
}

/*
 * close()
 */
uint32_t
Smb2Context::smb2_close(smb2fh *fh, std::string& error)
{
  if (!isConnected())
  {
    error = FUNC + string("Not Connected to Server");
    return SMB2_STATUS_CONNECTION_DISCONNECTED;
  }

  CloseData closeData;

  if (Smb2BuildCloseRequest(fh, &closeData) != 0)
  {
    error = FUNC + closeData.getErrorMsg();
    return SMB2_STATUS_PAYLOAD_FAILED;
  }

  if (this->wait_for_reply(error) < 0)
  {
    error = FUNC + error;
    return SMB2_STATUS_SOCKET_ERROR;
  }

  error = FUNC + closeData.getErrorMsg();
  return closeData.ntStatus;
}

/*
 * fsync()
 */
uint32_t
Smb2Context::smb2_fsync(smb2fh *fh, string& error)
{
  if (!isConnected())
  {
    error = FUNC + string("Not Connected to Server");
    return SMB2_STATUS_CONNECTION_DISCONNECTED;
  }

  AppData flushData;
  if (Smb2BuildFlushRequest(fh, &flushData) != 0)
  {
    error = FUNC + flushData.getErrorMsg();
    return SMB2_STATUS_PAYLOAD_FAILED;
  }

  if (this->wait_for_reply(error) < 0)
  {
    error = FUNC + error;
    return SMB2_STATUS_SOCKET_ERROR;
  }

  error = FUNC + flushData.getErrorMsg();
  return flushData.ntStatus;
}

/*
 * pread()
 */
uint32_t
Smb2Context::smb2_pread(smb2fh *fh, uint8_t *buf, uint32_t count, uint64_t offset, string& error)
{
  fh->byte_count = 0;
  fh->bytes_remaining = 0;

  if (!isConnected())
  {
    error = FUNC + string("Not Connected to Server");
    return SMB2_STATUS_CONNECTION_DISCONNECTED;
  }

  if (count ==0)
  {
    /* don't send a 0 byte read, the server doesn't reply */
    return SMB2_STATUS_SUCCESS;
  }

  ReadData readData;
  if (Smb2BuildReadRequest(fh, buf, count, offset, &readData) != 0)
  {
    error = FUNC + readData.getErrorMsg();
    return SMB2_STATUS_PAYLOAD_FAILED;
  }

  if (this->wait_for_reply(error) < 0)
  {
    error = FUNC + error;
    return SMB2_STATUS_SOCKET_ERROR;
  }

  error = FUNC + readData.getErrorMsg();
  return readData.ntStatus;
}

uint32_t
Smb2Context::smb2_pwrite(smb2fh *fh, uint8_t *buf, uint32_t count, uint64_t offset, string& error)
{
  fh->byte_count = 0;
  fh->bytes_remaining = 0;

  if (!isConnected())
  {
    error = FUNC + string("Not Connected to Server");
    return SMB2_STATUS_CONNECTION_DISCONNECTED;
  }

  if (count ==0)
  {
    /* don't send a 0 byte write, the server doesn't reply */
    return SMB2_STATUS_SUCCESS;
  }

  WriteData writeData;
  if (Smb2BuildWriteRequest(fh, buf, count, offset, &writeData) != 0)
  {
    error = FUNC + writeData.getErrorMsg();
    return SMB2_STATUS_PAYLOAD_FAILED;
  }

  if (this->wait_for_reply(error) < 0)
  {
    error = FUNC + error;
    return SMB2_STATUS_SOCKET_ERROR;
  }

  error = FUNC + writeData.getErrorMsg();
  return writeData.ntStatus;
}

uint32_t
Smb2Context::smb2_read(smb2fh *fh, uint8_t *buf, uint32_t count, string& error)
{
  fh->byte_count = 0;
  fh->bytes_remaining = 0;

  if (!isConnected())
  {
    error = FUNC + string("Not Connected to Server");
    return SMB2_STATUS_CONNECTION_DISCONNECTED;
  }

  if (count ==0)
  {
    /* don't send a 0 byte read, the server doesn't reply */
    return SMB2_STATUS_SUCCESS;
  }

  ReadData readData;
  if (Smb2BuildReadRequest(fh, buf, count, fh->offset, &readData) != 0)
  {
    error = FUNC + readData.getErrorMsg();
    return SMB2_STATUS_PAYLOAD_FAILED;
  }

  if (this->wait_for_reply(error) < 0)
  {
    error = FUNC + error;
    return SMB2_STATUS_SOCKET_ERROR;
  }

  error = FUNC + readData.getErrorMsg();
  return readData.ntStatus;
}

uint32_t
Smb2Context::smb2_write(smb2fh *fh, uint8_t *buf, uint32_t count, string& error)
{
  fh->byte_count = 0;
  fh->bytes_remaining = 0;

  if (!isConnected())
  {
    error = FUNC + string("Not Connected to Server");
    return SMB2_STATUS_CONNECTION_DISCONNECTED;
  }

  if (count ==0)
  {
    /* don't send a 0 byte write, the server doesn't reply */
    return SMB2_STATUS_SUCCESS;
  }

  WriteData writeData;
  if (Smb2BuildWriteRequest(fh, buf, count, fh->offset, &writeData) != 0)
  {
    error = FUNC + writeData.getErrorMsg();
    return SMB2_STATUS_PAYLOAD_FAILED;
  }

  if (this->wait_for_reply(error) < 0)
  {
    error = FUNC + error;
    return SMB2_STATUS_SOCKET_ERROR;
  }

  error = FUNC + writeData.getErrorMsg();
  return writeData.ntStatus;
}

uint32_t
Smb2Context::smb2_unlink(string& path, string& error)
{
  if (!isConnected())
  {
    error = FUNC + string("Not Connected to Server");
    return SMB2_STATUS_CONNECTION_DISCONNECTED;
  }

  uint32_t file_attributes = 0;
  uint32_t desired_access = 0;
  uint32_t share_access = 0;
  uint32_t create_disposition = 0;
  uint32_t create_options = 0;
  uint64_t smb_create_flags = 0;

  desired_access = SMB2_DELETE;
  file_attributes = SMB2_FILE_ATTRIBUTE_NORMAL;
  share_access = SMB2_FILE_SHARE_READ | SMB2_FILE_SHARE_WRITE | SMB2_FILE_SHARE_DELETE;
  create_disposition = SMB2_FILE_OPEN;
  create_options = SMB2_FILE_DELETE_ON_CLOSE;

  CreateData createData;

  int ret = Smb2BuildCreateRequest(path, 0,
                                   SMB2_IMPERSONATION_IMPERSONATION,
                                   smb_create_flags,
                                   desired_access,
                                   file_attributes,
                                   share_access,
                                   create_disposition,
                                   create_options,
                                   &createData);
  if (ret < 0)
  {
    error = FUNC + createData.getErrorMsg();
    return SMB2_STATUS_PAYLOAD_FAILED;
  }

  if (this->wait_for_reply(error) < 0)
  {
    error = FUNC + error;
    return SMB2_STATUS_SOCKET_ERROR;
  }

  smb2fh *fh = nullptr;
  fh = createData.getFH();
  if (fh == nullptr)
  {
    error = FUNC + createData.getErrorMsg();
    return createData.ntStatus;
  }

  smb2_close(fh, error);

  return createData.ntStatus;
}

uint32_t
Smb2Context::smb2_rmdir(string& path, string& error)
{
  if (!isConnected())
  {
    error = FUNC + string("Not Connected to Server");
    return SMB2_STATUS_CONNECTION_DISCONNECTED;
  }

  uint32_t file_attributes = 0;
  uint32_t desired_access = 0;
  uint32_t share_access = 0;
  uint32_t create_disposition = 0;
  uint32_t create_options = 0;
  uint64_t smb_create_flags = 0;

  desired_access = SMB2_DELETE;
  file_attributes = SMB2_FILE_ATTRIBUTE_DIRECTORY;
  share_access = SMB2_FILE_SHARE_READ | SMB2_FILE_SHARE_WRITE | SMB2_FILE_SHARE_DELETE;
  create_disposition = SMB2_FILE_OPEN;
  create_options = SMB2_FILE_DELETE_ON_CLOSE;

  CreateData createData;
  int ret = Smb2BuildCreateRequest(path,  0,
                                   SMB2_IMPERSONATION_IMPERSONATION,
                                   smb_create_flags,
                                   desired_access,
                                   file_attributes,
                                   share_access,
                                   create_disposition,
                                   create_options,
                                   &createData);
  if (ret < 0)
  {
    error = FUNC + createData.getErrorMsg();
    return SMB2_STATUS_PAYLOAD_FAILED;
  }

  if (this->wait_for_reply(error) < 0)
  {
    error = FUNC + error;
    return SMB2_STATUS_SOCKET_ERROR;
  }

  smb2fh *fh = nullptr;
  fh = createData.getFH();
  if (fh == nullptr)
  {
    error = FUNC + createData.getErrorMsg();
    return createData.ntStatus;
  }

  smb2_close(fh, error);

  return createData.ntStatus;
}

uint32_t
Smb2Context::smb2_mkdir(string& path, string& error)
{
  if (!isConnected())
  {
    error = FUNC + string("Not Connected to Server");
    return SMB2_STATUS_CONNECTION_DISCONNECTED;
  }

  uint32_t file_attributes = 0;
  uint32_t desired_access = 0;
  uint32_t share_access = 0;
  uint32_t create_disposition = 0;
  uint32_t create_options = 0;
  uint64_t smb_create_flags = 0;

  desired_access = SMB2_FILE_READ_ATTRIBUTES;
  file_attributes = SMB2_FILE_ATTRIBUTE_DIRECTORY;
  share_access = SMB2_FILE_SHARE_READ | SMB2_FILE_SHARE_WRITE;
  create_disposition = SMB2_FILE_CREATE;
  create_options = SMB2_FILE_DIRECTORY_FILE;

  CreateData createData;
  int ret = Smb2BuildCreateRequest(path, 0,
                                   SMB2_IMPERSONATION_IMPERSONATION,
                                   smb_create_flags,
                                   desired_access,
                                   file_attributes,
                                   share_access,
                                   create_disposition,
                                   create_options,
                                   &createData);

  if (ret < 0)
  {
    error = FUNC + createData.getErrorMsg();
    return SMB2_STATUS_PAYLOAD_FAILED;
  }

  if (this->wait_for_reply(error) < 0)
  {
    error = FUNC + error;
    return SMB2_STATUS_SOCKET_ERROR;
  }

  smb2fh *fh = nullptr;
  fh = createData.getFH();
  if (fh == nullptr)
  {
    error = FUNC + createData.getErrorMsg();
    return createData.ntStatus;
  }

  smb2_close(fh, error);

  return createData.ntStatus;
}

uint32_t
Smb2Context::smb2_fstat(smb2fh          *fh,
                    struct smb2_stat_64 *st,
                    string&             error)
{
  smb2_file_info info;

  if (!isConnected())
  {
    error = FUNC + string("Not Connected to Server");
    return SMB2_STATUS_CONNECTION_DISCONNECTED;
  }

  info.info_type = SMB2_0_INFO_FILE;
  info.file_info_class = SMB2_FILE_ALL_INFORMATION;

  QueryInfoData qiData;
  if (Smb2BuildQueryInfoRequest(fh, &info, &qiData) != 0)
  {
    error = FUNC + qiData.getErrorMsg();
    return SMB2_STATUS_PAYLOAD_FAILED;
  }

  if (this->wait_for_reply(error) < 0)
  {
    error = FUNC + error;
    return SMB2_STATUS_SOCKET_ERROR;
  }

  st->smb2_type = SMB2_TYPE_FILE;
  if (info.u_info.all_info.basic.file_attributes & SMB2_FILE_ATTRIBUTE_DIRECTORY)
  {
    st->smb2_type = SMB2_TYPE_DIRECTORY;
  }
  st->smb2_nlink  = info.u_info.all_info.standard.number_of_links;
  st->smb2_ino    = info.u_info.all_info.index_number;
  st->smb2_size   = info.u_info.all_info.standard.end_of_file;
  st->smb2_atime  = info.u_info.all_info.basic.last_access_time;
  st->smb2_mtime  = info.u_info.all_info.basic.last_write_time;
  st->smb2_ctime  = info.u_info.all_info.basic.change_time;
  st->smb2_crtime = info.u_info.all_info.basic.creation_time;

  return qiData.ntStatus;
}

uint32_t
Smb2Context::smb2_stat(string&             path,
                       struct smb2_stat_64 *st,
                       string&             error)
{
  smb2_file_info info;

  if (!isConnected())
  {
    error = FUNC + string("Not Connected to Server");
    return SMB2_STATUS_CONNECTION_DISCONNECTED;
  }

  info.info_type = SMB2_0_INFO_FILE;
  info.file_info_class = SMB2_FILE_ALL_INFORMATION;

  QueryInfoData qiData;
  if (Smb2BuildQueryInfoRequest(path, &info, &qiData) != 0)
  {
    error = FUNC + qiData.getErrorMsg();
    return SMB2_STATUS_PAYLOAD_FAILED;
  }

  if (this->wait_for_reply(error) < 0)
  {
    error = FUNC + error;
    return SMB2_STATUS_SOCKET_ERROR;
  }

  st->smb2_type = SMB2_TYPE_FILE;
  if (info.u_info.all_info.basic.file_attributes & SMB2_FILE_ATTRIBUTE_DIRECTORY)
  {
    st->smb2_type = SMB2_TYPE_DIRECTORY;
  }
  st->smb2_nlink  = info.u_info.all_info.standard.number_of_links;
  st->smb2_ino    = info.u_info.all_info.index_number;
  st->smb2_size   = info.u_info.all_info.standard.end_of_file;
  st->smb2_atime  = info.u_info.all_info.basic.last_access_time;
  st->smb2_mtime  = info.u_info.all_info.basic.last_write_time;
  st->smb2_ctime  = info.u_info.all_info.basic.change_time;
  st->smb2_crtime = info.u_info.all_info.basic.creation_time;

  return qiData.ntStatus;
}

uint32_t
Smb2Context::smb2_statvfs(string&             path,
                          struct smb2_statvfs *st,
                          string&             error)
{
  smb2_file_info info;

  if (!isConnected())
  {
    error = FUNC + string("Not Connected to Server");
    return SMB2_STATUS_CONNECTION_DISCONNECTED;
  }

  info.info_type = SMB2_0_INFO_FILESYSTEM;
  info.file_info_class = SMB2_FILE_FS_FULL_SIZE_INFORMATION;

  QueryInfoData qiData;
  if (Smb2BuildQueryInfoRequest(path, &info, &qiData) != 0)
  {
    error = FUNC + qiData.getErrorMsg();
    return SMB2_STATUS_PAYLOAD_FAILED;
  }

  if (this->wait_for_reply(error) < 0)
  {
    error = FUNC + error;
    return SMB2_STATUS_SOCKET_ERROR;
  }

  memset(st, 0, sizeof(struct smb2_statvfs));
  st->f_bsize = st->f_frsize = info.u_info.fs_full_size_info.bytes_per_sector *
                               info.u_info.fs_full_size_info.sectors_per_allocation_unit;
  st->f_blocks = info.u_info.fs_full_size_info.total_allocation_units;
  st->f_bfree = st->f_bavail = info.u_info.fs_full_size_info.caller_available_allocation_units;

  return qiData.ntStatus;
}

uint32_t
Smb2Context::smb2_getinfo_all(string&        path,
                              struct smb2_file_info_all *all_info,
                              string&        error)
{
  smb2_file_info info;

  if (!isConnected())
  {
    error = FUNC + string("Not Connected to Server");
    return SMB2_STATUS_CONNECTION_DISCONNECTED;
  }

  info.info_type = SMB2_0_INFO_FILE;
  info.file_info_class = SMB2_FILE_ALL_INFORMATION;

  QueryInfoData qiData;
  if (Smb2BuildQueryInfoRequest(path, &info, &qiData) != 0)
  {
    error = FUNC + qiData.getErrorMsg();
    return SMB2_STATUS_PAYLOAD_FAILED;
  }

  if (this->wait_for_reply(error) < 0)
  {
    error = FUNC + error;
    return SMB2_STATUS_SOCKET_ERROR;
  }

  all_info->smb2_type = SMB2_TYPE_FILE;
  if (info.u_info.all_info.basic.file_attributes & SMB2_FILE_ATTRIBUTE_DIRECTORY)
  {
    all_info->smb2_type = SMB2_TYPE_DIRECTORY;
  }
  all_info->smb2_ino           = info.u_info.all_info.index_number;
  all_info->ea_size            = info.u_info.all_info.ea_size;

  all_info->smb2_atime         = info.u_info.all_info.basic.last_access_time;
  all_info->smb2_mtime         = info.u_info.all_info.basic.last_write_time;
  all_info->smb2_ctime         = info.u_info.all_info.basic.change_time;
  all_info->smb2_crtime        = info.u_info.all_info.basic.creation_time;
  all_info->file_attributes    = info.u_info.all_info.basic.file_attributes;

  all_info->smb2_size          = info.u_info.all_info.standard.end_of_file;
  all_info->smb2_nlink         = info.u_info.all_info.standard.number_of_links;
  all_info->allocation_size    = info.u_info.all_info.standard.allocation_size;
  all_info-> end_of_file       = info.u_info.all_info.standard.end_of_file;
  all_info-> delete_pending    = info.u_info.all_info.standard.delete_pending;
  all_info-> directory         = info.u_info.all_info.standard.directory;
  all_info->access_flags       = info.u_info.all_info.access_flags;
  all_info->mode               = info.u_info.all_info.mode;

  return qiData.ntStatus;
}

uint32_t
Smb2Context::smb2_fgetinfo_all(smb2fh         *fh,
                               struct smb2_file_info_all *all_info,
                               string&        error)
{
  smb2_file_info info;

  if (!isConnected())
  {
    error = FUNC + string("Not Connected to Server");
    return SMB2_STATUS_CONNECTION_DISCONNECTED;
  }

  info.info_type = SMB2_0_INFO_FILE;
  info.file_info_class = SMB2_FILE_ALL_INFORMATION;

  QueryInfoData qiData;
  if (Smb2BuildQueryInfoRequest(fh, &info, &qiData) != 0)
  {
    error = FUNC + qiData.getErrorMsg();
    return SMB2_STATUS_PAYLOAD_FAILED;
  }

  if (this->wait_for_reply(error) < 0)
  {
    error = FUNC + error;
    return SMB2_STATUS_SOCKET_ERROR;
  }

  all_info->smb2_type = SMB2_TYPE_FILE;
  if (info.u_info.all_info.basic.file_attributes & SMB2_FILE_ATTRIBUTE_DIRECTORY)
  {
    all_info->smb2_type = SMB2_TYPE_DIRECTORY;
  }
  all_info->smb2_ino           = info.u_info.all_info.index_number;
  all_info->ea_size            = info.u_info.all_info.ea_size;

  all_info->smb2_atime         = info.u_info.all_info.basic.last_access_time;
  all_info->smb2_mtime         = info.u_info.all_info.basic.last_write_time;
  all_info->smb2_ctime         = info.u_info.all_info.basic.change_time;
  all_info->smb2_crtime        = info.u_info.all_info.basic.creation_time;

  all_info->smb2_size          = info.u_info.all_info.standard.end_of_file;
  all_info->smb2_nlink         = info.u_info.all_info.standard.number_of_links;
  all_info->allocation_size    = info.u_info.all_info.standard.allocation_size;
  all_info->end_of_file        = info.u_info.all_info.standard.end_of_file;
  all_info->delete_pending     = info.u_info.all_info.standard.delete_pending;
  all_info->directory          = info.u_info.all_info.standard.directory;
  all_info->access_flags       = info.u_info.all_info.access_flags;
  all_info->mode               = info.u_info.all_info.mode;

  return qiData.ntStatus;
}

uint32_t
Smb2Context::smb2_setinfo_basic(string&        path,
                                struct smb2_file_basic_info *basic_info,
                                string&        error)
{
  smb2_file_info info;

  if (!isConnected())
  {
    error = FUNC + string("Not Connected to Server");
    return SMB2_STATUS_CONNECTION_DISCONNECTED;
  }

  if (basic_info == NULL)
  {
    error = FUNC + string("no info to set");
    return SMB2_STATUS_INVALID_ARGUMENT;
  }

  memset(&info, 0, sizeof(smb2_file_info));
  info.info_type = SMB2_0_INFO_FILE;
  info.file_info_class = SMB2_FILE_BASIC_INFORMATION;
  info.u_info.basic_info = *basic_info;

  AppData setInfoData;
  if (Smb2BuildSetInforequest(path, &info, &setInfoData) != 0)
  {
    error = FUNC + setInfoData.getErrorMsg();
    return SMB2_STATUS_PAYLOAD_FAILED;
  }

  if (this->wait_for_reply(error) < 0)
  {
    error = FUNC + error;
    return SMB2_STATUS_SOCKET_ERROR;
  }

  return setInfoData.ntStatus;
}

uint32_t
Smb2Context::smb2_fsetinfo_basic(smb2fh         *fh,
                                 struct smb2_file_basic_info *basic_info,
                                 string&        error)
{
  smb2_file_info info;

  if (!isConnected())
  {
     error = FUNC + string("Not Connected to Server");
     return SMB2_STATUS_CONNECTION_DISCONNECTED;
  }

  if (basic_info == NULL)
  {
    error = FUNC + string("No info to set");
    return SMB2_STATUS_INVALID_ARGUMENT;
  }

  memset(&info, 0, sizeof(smb2_file_info));
  info.info_type = SMB2_0_INFO_FILE;
  info.file_info_class = SMB2_FILE_BASIC_INFORMATION;
  info.u_info.basic_info = *basic_info;

  AppData setInfoData;
  if (Smb2BuildSetInforequest(fh, &info, &setInfoData) != 0)
  {
    error = FUNC + setInfoData.getErrorMsg();
    return SMB2_STATUS_PAYLOAD_FAILED;
  }

  if (this->wait_for_reply(error) < 0)
  {
    error = FUNC + error;
    return SMB2_STATUS_SOCKET_ERROR;
  }

  return setInfoData.ntStatus;
}

uint32_t
Smb2Context::smb2_rename(string& oldpath, string& newpath, string& error)
{
  smb2_file_info info;

  if (!isConnected())
  {
    error = FUNC + string("Not Connected to Server");
    return SMB2_STATUS_CONNECTION_DISCONNECTED;
  }

  memset(&info, 0, sizeof(smb2_file_info));
  info.info_type = SMB2_0_INFO_FILE;
  info.file_info_class = SMB2_FILE_RENAME_INFORMATION;
  info.u_info.rename_info.replace_if_exist = 0;
  info.u_info.rename_info.file_name = (uint8_t*)newpath.c_str();

  AppData setInfoData;
  if (Smb2BuildSetInforequest(oldpath, &info, &setInfoData) != 0)
  {
    error = FUNC + setInfoData.getErrorMsg();
    return SMB2_STATUS_PAYLOAD_FAILED;
  }

  if (this->wait_for_reply(error) < 0)
  {
    error = FUNC + error;
    return SMB2_STATUS_SOCKET_ERROR;
  }

  return setInfoData.ntStatus;
}

uint32_t
Smb2Context::smb2_truncate(string& path, uint64_t length, string& error)
{
  smb2_file_info info;

  if (!isConnected())
  {
    error = FUNC + string("Not Connected to Server");
    return SMB2_STATUS_CONNECTION_DISCONNECTED;
  }

  memset(&info, 0, sizeof(smb2_file_info));
  info.info_type = SMB2_0_INFO_FILE;
  info.file_info_class = SMB2_FILE_END_OF_FILE_INFORMATION;
  info.u_info.eof_info.end_of_file = length;

  AppData setInfoData;
  if (Smb2BuildSetInforequest(path, &info, &setInfoData) != 0)
  {
    error = FUNC + setInfoData.getErrorMsg();
    return SMB2_STATUS_PAYLOAD_FAILED;
  }

  if (this->wait_for_reply(error) < 0)
  {
    error = FUNC + error;
    return SMB2_STATUS_SOCKET_ERROR;
  }

  return setInfoData.ntStatus;
}

uint32_t
Smb2Context::smb2_ftruncate(smb2fh *fh, uint64_t length, string& error)
{
  smb2_file_info info;

  if (!isConnected())
  {
    error = FUNC + string("Not Connected to Server");
    return SMB2_STATUS_CONNECTION_DISCONNECTED;
  }

  memset(&info, 0, sizeof(smb2_file_info));
  info.info_type = SMB2_0_INFO_FILE;
  info.file_info_class = SMB2_FILE_END_OF_FILE_INFORMATION;
  info.u_info.eof_info.end_of_file = length;

  AppData setInfoData;
  if (Smb2BuildSetInforequest(fh, &info, &setInfoData) != 0)
  {
    error = FUNC + setInfoData.getErrorMsg();
    return SMB2_STATUS_PAYLOAD_FAILED;
  }

  if (this->wait_for_reply(error) < 0)
  {
    error = FUNC + error;
    return SMB2_STATUS_SOCKET_ERROR;
  }

  if (setInfoData.ntStatus != SMB2_STATUS_SUCCESS)
    error = FUNC + setInfoData.getErrorMsg();

  return setInfoData.ntStatus;
}

uint32_t
Smb2Context::smb2_echo(string& error)
{
  if (!isConnected())
  {
    error = FUNC + string("Not Connected to Server");
    return SMB2_STATUS_CONNECTION_DISCONNECTED;
  }

  AppData echoData;
  if (Smb2BuildEchoRequest(&echoData) != 0)
  {
    error = FUNC + echoData.getErrorMsg();
    return SMB2_STATUS_PAYLOAD_FAILED;
  }

  if (this->wait_for_reply(error) < 0)
  {
    error = FUNC + error;
    return SMB2_STATUS_SOCKET_ERROR;
  }

  return echoData.ntStatus;
}

#define DEBUG

uint32_t
Smb2Context::smb2_get_security(string& path, uint8_t **buf, uint32_t *buf_len, string& error)
{
  int sts = 0;
  smb2_file_info info;

  uint8_t *relative_sec = NULL;
  uint32_t relative_sec_size = 1024;

  if (!isConnected())
  {
    error = FUNC + string("Not Connected to Server");
    return SMB2_STATUS_CONNECTION_DISCONNECTED;
  }

  info.info_type = SMB2_0_INFO_SECURITY;
  info.u_info.security_info = NULL;

  QueryInfoData qiData;
  if (Smb2BuildQueryInfoRequest(path, &info, &qiData) != 0)
  {
    error = FUNC + qiData.getErrorMsg();
    return SMB2_STATUS_PAYLOAD_FAILED;
  }

  if (this->wait_for_reply(error) < 0)
  {
    error = FUNC + error;
    return SMB2_STATUS_SOCKET_ERROR;
  }

  if (qiData.ntStatus != SMB2_STATUS_SUCCESS)
  {
    error = FUNC + qiData.getErrorMsg();
    return qiData.ntStatus;
  }

#ifdef DEBUG
  printSecurityDescriptor(info.u_info.security_info);
#endif

  relative_sec = (uint8_t *) calloc(1, relative_sec_size);
  if (relative_sec == NULL)
  {
    error = FUNC + string("No memory to get security descriptor");
    return SMB2_STATUS_NO_MEMORY;
  }
retry:
  if ((sts = smb2EncodeSecurityDescriptor(info.u_info.security_info,
                                          relative_sec,
                                          &relative_sec_size,
                                          error)) < 0)
  {
    if (sts == -9)
    {
      relative_sec_size *= 2;
      relative_sec = (uint8_t *) realloc(relative_sec, relative_sec_size);
      if (relative_sec == NULL)
      {
        error = FUNC + string("Failed to allocate memory for security descriptor");
        return SMB2_STATUS_NO_MEMORY;
      }
      goto retry;
    }

    error = FUNC + error;
    return SMB2_STATUS_INTERNAL_ERROR;
  }

  smb2FreeSecurityDescriptor(info.u_info.security_info);
  info.u_info.security_info= NULL;

  *buf = relative_sec;
  *buf_len = relative_sec_size;

  return qiData.ntStatus;
}

uint32_t
Smb2Context::smb2_fget_security(smb2fh *fh, uint8_t **buf, uint32_t *buf_len, string& error)
{
  int sts = 0;
  smb2_file_info info;

  uint8_t *relative_sec = NULL;
  uint32_t relative_sec_size = 1024;

  if (!isConnected())
  {
    error = FUNC + string("Not Connected to Server");
    return SMB2_STATUS_CONNECTION_DISCONNECTED;
  }

  info.info_type = SMB2_0_INFO_SECURITY;
  info.u_info.security_info = NULL;

  QueryInfoData qiData;
  if (Smb2BuildQueryInfoRequest(fh, &info, &qiData) != 0)
  {
    error = FUNC + qiData.getErrorMsg();
    return SMB2_STATUS_PAYLOAD_FAILED;
  }

  if (this->wait_for_reply(error) < 0)
  {
    error = FUNC + error;
    return SMB2_STATUS_SOCKET_ERROR;
  }

  if (qiData.ntStatus != SMB2_STATUS_SUCCESS)
  {
    error = FUNC + qiData.getErrorMsg();
    return qiData.ntStatus;
  }

#ifdef DEBUG
  printSecurityDescriptor(info.u_info.security_info);
#endif

  relative_sec = (uint8_t *) calloc(1, relative_sec_size);
  if (relative_sec == NULL)
  {
    error = FUNC + string("No memory to get security descriptor");
    return SMB2_STATUS_NO_MEMORY;
  }
retry:
  syslog(LOG_NOTICE, "Using buffer, length - %d\n", relative_sec_size);
  if ((sts = smb2EncodeSecurityDescriptor(info.u_info.security_info,
                                          relative_sec,
                                          &relative_sec_size,
                                          error)) < 0)
  {
    if (sts == -9)
    {
      relative_sec_size *= 2;
      relative_sec = (uint8_t *) realloc(relative_sec, relative_sec_size);
      if (relative_sec == NULL)
      {
        error = FUNC + string("Failed to allocate memory for security descriptor");
        return SMB2_STATUS_NO_MEMORY;
      }
      goto retry;
    }

    error = FUNC + error;
    return SMB2_STATUS_INTERNAL_ERROR;
  }

  smb2FreeSecurityDescriptor(info.u_info.security_info);
  info.u_info.security_info= NULL;

  *buf = relative_sec;
  *buf_len = relative_sec_size;

  return qiData.ntStatus;
}

uint32_t
Smb2Context::smb2_set_security(string& path, uint8_t *buf, uint32_t buf_len, string& error)
{
  smb2_file_info info;

  if (!isConnected())
  {
    error = FUNC + string("Not Connected to Server");
    return SMB2_STATUS_CONNECTION_DISCONNECTED;
  }

#ifdef DEBUG
  smb2_iovec vec;
  smb2_security_descriptor *secdesc = nullptr;
  vec.buf = buf;
  vec.len = buf_len;

  secdesc = new smb2_security_descriptor();
  if (smb2DecodeSecDescInternal(secdesc, &vec, error))
  {
    error = FUNC + error;
    return SMB2_STATUS_INTERNAL_ERROR;
  }
  printSecurityDescriptor(secdesc);
  smb2FreeSecurityDescriptor(secdesc); secdesc = NULL;
#endif

  memset(&info, 0, sizeof(smb2_file_info));
  info.info_type = SMB2_0_INFO_SECURITY;
  info.file_info_class = 0;
  info.u_info.sec_info.secbuf = buf;
  info.u_info.sec_info.secbuf_len = buf_len;

  AppData setInfoData;
  if (Smb2BuildSetInforequest(path, &info, &setInfoData) != 0)
  {
    error = FUNC + setInfoData.getErrorMsg();
    return SMB2_STATUS_PAYLOAD_FAILED;
  }

  if (this->wait_for_reply(error) < 0)
  {
    error = FUNC + error;
    return SMB2_STATUS_SOCKET_ERROR;
  }

  if (setInfoData.ntStatus != SMB2_STATUS_SUCCESS)
    error = FUNC + setInfoData.getErrorMsg();

  return setInfoData.ntStatus;
}

uint32_t
Smb2Context::smb2_fset_security(smb2fh *fh, uint8_t *buf, uint32_t buf_len, string& error)
{
  smb2_file_info info;

  if (!isConnected())
  {
    error = FUNC + string("Not Connected to Server");
    return SMB2_STATUS_CONNECTION_DISCONNECTED;
  }

#ifdef DEBUG
  smb2_iovec vec;
  smb2_security_descriptor *secdesc = nullptr;
  vec.buf = buf;
  vec.len = buf_len;

  secdesc = new smb2_security_descriptor();
  if (smb2DecodeSecDescInternal(secdesc, &vec, error))
  {
    error = FUNC + error;
    return SMB2_STATUS_INTERNAL_ERROR;
  }
  printSecurityDescriptor(secdesc);
  smb2FreeSecurityDescriptor(secdesc); secdesc = NULL;
#endif

  memset(&info, 0, sizeof(smb2_file_info));
  info.info_type = SMB2_0_INFO_SECURITY;
  info.file_info_class = 0;
  info.u_info.sec_info.secbuf = buf;
  info.u_info.sec_info.secbuf_len = buf_len;

  AppData setInfoData;
  if (Smb2BuildSetInforequest(fh, &info, &setInfoData) != 0)
  {
    error = FUNC + setInfoData.getErrorMsg();
    return SMB2_STATUS_PAYLOAD_FAILED;
  }

  if (this->wait_for_reply(error) < 0)
  {
    error = FUNC + error;
    return SMB2_STATUS_SOCKET_ERROR;
  }

  if (setInfoData.ntStatus != SMB2_STATUS_SUCCESS)
    error = FUNC + setInfoData.getErrorMsg();

  return setInfoData.ntStatus;
}

/*
 * Send SMB2_IOCTL command to the server
  */
uint32_t
Smb2Context::smb2_ioctl(smb2fh *fh,
                        uint32_t ioctl_ctl, uint32_t ioctl_flags,
                        uint8_t *input_buffer, uint32_t input_count,
                        uint8_t *output_buffer, uint32_t *output_count,
                        string& error)
{
  if (!isConnected())
  {
    error = FUNC + string("Not Connected to Server");
    return SMB2_STATUS_CONNECTION_DISCONNECTED;
  }

  IoctlData ioctlData;
  if (Smb2BuildIoctlRequest(fh, ioctl_ctl, ioctl_flags,
                            input_buffer, input_count,
                            output_buffer, output_count, &ioctlData) != 0)
  {
    error = FUNC + ioctlData.getErrorMsg();
    return SMB2_STATUS_PAYLOAD_FAILED;
  }

  if (this->wait_for_reply(error) < 0)
  {
    error = FUNC + error;
    return SMB2_STATUS_SOCKET_ERROR;
  }

  if (ioctlData.ntStatus != SMB2_STATUS_SUCCESS)
    error = FUNC + ioctlData.getErrorMsg();

  return ioctlData.ntStatus;
}

/* share_enum()
 */
int
Smb2Context::smb2_list_shares(string& server, string& user, uint32_t shinfo_type, smb2_shares& shares, string& error)
{
  uint32_t  status = 0;
  struct    smb2fh *fh = NULL;
  uint8_t   ioctl_IN[1024] = {0};
  uint32_t  ioctl_IN_Cnt = 0;
  uint8_t   ioctl_OUT[1024] ={0};
  uint32_t  ioctl_OUT_Cnt = 1024;
  struct    rpc_bind_request bind_req;
  struct    context_item dcerpc_ctx;

  struct rpc_header rsp_hdr;
  struct rpc_bind_response ack;
  struct rpc_bind_nack_response nack;

  uint16_t max_xmit_frag = 0;
  uint16_t max_recv_frag = 0;

  string error2;

  if (server.empty())
  {
    error = FUNC + string("server not specified");
    return -1;
  }
  if (user.empty())
  {
    error = FUNC + string("user not specified");
    return -1;
  }

  this->use_cached_creds = true;
  std::string ipc_share = "IPC$";
  if (smb2_connect_share(server, ipc_share, user, error) !=0)
  {
    error = FUNC + error;
    return -ENOMEM;
  }

  std::string srvsvc_pipe = std::string("srvsvc");
  fh = smb2_open_pipe(srvsvc_pipe, error);
  if (fh == NULL)
  {
    error = FUNC + error;
    smb2_disconnect_share();
    return -1;
  }

  dcerpc_create_bind_req(&bind_req, 1);
  dcerpc_init_context(&dcerpc_ctx, CONTEXT_SRVSVC);

  ioctl_IN_Cnt = sizeof(struct rpc_bind_request) + sizeof(struct context_item);
  memcpy(ioctl_IN, &bind_req, sizeof(struct rpc_bind_request));
  memcpy(ioctl_IN+sizeof(struct rpc_bind_request), &dcerpc_ctx, sizeof(struct context_item));

  /* We can achieve BIND doing write and read on the PIPE too, similar to SMB1 */
  status = smb2_ioctl(fh,
                      FSCTL_PIPE_TRANSCEIVE,
                      SMB2_0_IOCTL_IS_FSCTL,
                      ioctl_IN, ioctl_IN_Cnt,
                      ioctl_OUT, &ioctl_OUT_Cnt,
                      error);
  if (status != SMB2_STATUS_SUCCESS)
  {
    error = FUNC + error;
    smb2_close(fh, error2);
    smb2_disconnect_share();
    return -1;
  }

  if (!dcerpc_get_response_header(ioctl_OUT, ioctl_OUT_Cnt, &rsp_hdr))
  {
    error = FUNC + string("Failed to parse dcerpc response header");
    smb2_close(fh, error2);
    smb2_disconnect_share();
    return -1;
  }

  if (rsp_hdr.packet_type == RPC_PACKET_TYPE_BINDNACK)
  {
    if (!dcerpc_get_bind_nack_response(ioctl_OUT, ioctl_OUT_Cnt, &nack))
    {
      error = FUNC + string("Failed to parse dcerpc BINDNACK response");
      smb2_close(fh, error2);
      smb2_disconnect_share();
      return -1;
    }
    error = FUNC + stringf("dcerpc BINDNACK reason : %s", dcerpc_get_reject_reason(nack.reject_reason));
    smb2_close(fh, error2);
    smb2_disconnect_share();
    return -1;
  }
  else if (rsp_hdr.packet_type == RPC_PACKET_TYPE_BINDACK)
  {
    if (!dcerpc_get_bind_ack_response(ioctl_OUT, ioctl_OUT_Cnt, &ack))
    {
      error = FUNC + string("Failed to parse dcerpc BINDACK response");
      smb2_close(fh, error2);
      smb2_disconnect_share();
      return -1;
    }
    /* save the max xmit and recv frag details */
    max_xmit_frag = ack.max_xmit_frag;
    max_recv_frag = ack.max_recv_frag;
  }

  uint32_t resumeHandlePtr = 0;
  uint32_t resumeHandle = 0;
  uint32_t shares_read = 0;
  uint32_t total_share_count = 0;
  uint8_t  *sharesBuff = NULL;
  uint32_t sharesBuffLen = 0;

  uint8_t *fragmentBuf = NULL;

  do
  {
    /* we need to do this in loop till we get all shares */
    uint32_t srvs_sts = 0;
    int last_frag = 1;
    uint8_t  netShareEnumBuf[1024] = {0};
    uint32_t netShareEnumBufLen = 1024;
    struct DceRpcOperationRequest *dceOpReq = NULL;
    uint32_t payloadlen = 0;
    uint32_t offset = 0;

#define MAX_BUF_SIZE	(64 * 1024)
    uint8_t  output_buf[MAX_BUF_SIZE] = {0};
    uint32_t output_count = MAX_BUF_SIZE;
    uint32_t share_count = 0;

    struct DceRpcOperationResponse dceOpRes = {{0}};

    payloadlen = netShareEnumBufLen;
    dceOpReq = (struct DceRpcOperationRequest *)&netShareEnumBuf[0];
    payloadlen -= sizeof(struct DceRpcOperationRequest);
    offset += sizeof(struct DceRpcOperationRequest);

    std::string serverName = std::string("\\\\") + server;

    if (srvsvc_create_NetrShareEnumRequest(serverName,
                                           shinfo_type,
                                           resumeHandle,
                                           netShareEnumBuf+offset,
                                           &payloadlen, error2) < 0)
    {
      error = FUNC + error2;
      goto error;
    }

    offset += payloadlen;
    /* opnum - 15 - for share enumeration */
    dcerpc_create_Operation_Request(dceOpReq, DCE_OP_SHARE_ENUM, payloadlen);

    if (offset > max_xmit_frag)
    {
      error = FUNC + string("IOCTL : DCE_OP_SHARE_ENUM Payload size is larger than max_xmit_frag");
      goto error;
    }

    status = smb2_ioctl(fh,
                        FSCTL_PIPE_TRANSCEIVE,
                        SMB2_0_IOCTL_IS_FSCTL,
                        netShareEnumBuf, offset,
                        output_buf, &output_count,
                        error2);
    if (status != SMB2_STATUS_SUCCESS)
    {
      error = FUNC + "IOCTL: DCE_OP_SHARE_ENUM  Failed : " + error2;
      goto error;
    }
    offset = 0;

    /* save the shares data */
    sharesBuff = (uint8_t*) malloc(output_count);
    if (sharesBuff == NULL)
    {
      error = FUNC + "Failed to allocate shares buffer";
      goto error;
    }
    memcpy(sharesBuff, &output_buf[0], output_count);
    sharesBuffLen += output_count;

    /* Response parsing */
    if (dcerpc_parse_Operation_Response(sharesBuff, sharesBuffLen, &dceOpRes, &status, error2) < 0)
    {
      error = FUNC + error2 + " For DCE_OP_SHARE_ENUM";
      goto error;
    }

    last_frag = dceOpRes.dceRpcHdr.packet_flags & RPC_FLAG_LAST_FRAG;
    /* read the complete dcerpc data - all frags */
    while (!last_frag)
    {
      uint32_t bytes_read = 0;
      uint32_t frag_len = 0;
      struct DceRpcOperationResponse dceOpRes2 = {{0}};

      fragmentBuf = (uint8_t *)calloc(1, max_recv_frag);
      if (fragmentBuf == NULL)
      {
        error = FUNC + string("Failed to allocate fragmentBuf");
        goto error;
      }
      status = smb2_pread(fh, fragmentBuf, max_recv_frag, 0, error2);
      if (status != SMB2_STATUS_SUCCESS && status != SMB2_STATUS_END_OF_FILE)
      {
        error = FUNC + string("Failed to read remaining frags - ") + error2;
        goto error;
      }
      bytes_read = fh->byte_count;
      if (dcerpc_parse_Operation_Response(fragmentBuf,
                                          bytes_read,
                                          &dceOpRes2,
                                          &status, error2) < 0)
      {
        error = FUNC + error2 + " while reading DCE_OP_SHARE_ENUM fragment";
        goto error;
      }
      last_frag = dceOpRes2.dceRpcHdr.packet_flags & RPC_FLAG_LAST_FRAG;
      frag_len = bytes_read - sizeof(struct DceRpcOperationResponse);

      /* Extend the buffer and Append data */
      sharesBuff = (uint8_t*)realloc(sharesBuff, sharesBuffLen+frag_len);
      if (sharesBuff == NULL)
      {
        error = FUNC + string("Failed to re-allocate sharesBuff");
        goto error;
      }
      memcpy(&sharesBuff[sharesBuffLen],
             fragmentBuf+sizeof(struct DceRpcOperationResponse),
             frag_len);
      sharesBuffLen += frag_len;

      free(fragmentBuf); fragmentBuf= NULL;
    }

    offset = 0;
    payloadlen = sharesBuffLen;
    offset += sizeof(struct DceRpcOperationResponse);
    payloadlen -= sizeof(struct DceRpcOperationResponse);

    srvs_sts = srvsvc_get_NetrShareEnum_status(sharesBuff+offset, payloadlen);
    if ( srvs_sts != 0x00000000 )
    {
      error = FUNC + stringf("SRVSVC NetrShareEnum Failed with error %x", srvs_sts);
      goto error;
    }
    payloadlen -= sizeof(uint32_t);

    if (srvsvc_parse_NetrShareEnumResponse(sharesBuff+offset,
                                           payloadlen,
                                           &share_count,
                                           &total_share_count,
                                           &resumeHandlePtr,
                                           &resumeHandle,
                                           shares, error2) < 0)
    {
      error = FUNC + stringf("srvsvc_parse_NetrShareEnumResponse failed : %s", error2.c_str());
      goto error;
    }
    shares_read += share_count;
  } while (shares_read < total_share_count);

  free(sharesBuff); sharesBuff = NULL;
  /* close the pipe  & disconnect */
  smb2_close(fh, error2);
  smb2_disconnect_share();
  return 0;

error:
  if (sharesBuff) {
    free(sharesBuff);
  }
  if (fragmentBuf) {
    free(fragmentBuf);
  }
  /* close the pipe  & disconnect */
  smb2_close(fh, error2);
  smb2_disconnect_share();
  return -1;
}

uint32_t
Smb2Context::smb2_getinfo_basic(string& path,
                                struct smb2_file_basic_info *basic_info,
                                string& error)
{
  smb2_file_info info;

  if (!isConnected())
  {
    error = FUNC + string("Not Connected to Server");
    return SMB2_STATUS_CONNECTION_DISCONNECTED;
  }

  info.info_type = SMB2_0_INFO_FILE;
  info.file_info_class = SMB2_FILE_BASIC_INFORMATION;

  QueryInfoData qiData;
  if (Smb2BuildQueryInfoRequest(path, &info, &qiData) != 0)
  {
    error = FUNC + qiData.getErrorMsg();
    return SMB2_STATUS_PAYLOAD_FAILED;
  }

  if (this->wait_for_reply(error) < 0)
  {
    error = FUNC + error;
    return SMB2_STATUS_SOCKET_ERROR;
  }

  *basic_info = info.u_info.basic_info;

  if (qiData.ntStatus != SMB2_STATUS_SUCCESS)
    error = FUNC + qiData.getErrorMsg();

  return qiData.ntStatus;
}

uint32_t
Smb2Context::smb2_fgetinfo_basic(smb2fh         *fh,
                                 struct smb2_file_basic_info *basic_info,
                                 string&        error)
{
  smb2_file_info info;

  if (!isConnected())
  {
    error = FUNC + string("Not Connected to Server");
    return SMB2_STATUS_CONNECTION_DISCONNECTED;
  }

  info.info_type = SMB2_0_INFO_FILE;
  info.file_info_class = SMB2_FILE_BASIC_INFORMATION;

  QueryInfoData qiData;
  if (Smb2BuildQueryInfoRequest(fh, &info, &qiData) != 0)
  {
    error = FUNC + qiData.getErrorMsg();
    return SMB2_STATUS_PAYLOAD_FAILED;
  }

  if (this->wait_for_reply(error) < 0)
  {
    error = FUNC + error;
    return SMB2_STATUS_SOCKET_ERROR;
  }

  *basic_info = info.u_info.basic_info;

  if (qiData.ntStatus != SMB2_STATUS_SUCCESS)
    error = FUNC + qiData.getErrorMsg();

  return qiData.ntStatus;
}

uint32_t
Smb2Context::smb2_getinfo_standard(string&   path,
                                   struct smb2_file_standard_info *standard_info,
                                   string&        error)
{
  smb2_file_info info;

  if (!isConnected())
  {
    error = FUNC + string("Not Connected to Server");
    return SMB2_STATUS_CONNECTION_DISCONNECTED;
  }

  info.info_type = SMB2_0_INFO_FILE;
  info.file_info_class = SMB2_FILE_STANDARD_INFORMATION;

  QueryInfoData qiData;
  if (Smb2BuildQueryInfoRequest(path, &info, &qiData) != 0)
  {
    error = FUNC + qiData.getErrorMsg();
    return SMB2_STATUS_PAYLOAD_FAILED;
  }

  if (this->wait_for_reply(error) < 0)
  {
    error = FUNC + error;
    return SMB2_STATUS_SOCKET_ERROR;
  }

  *standard_info = info.u_info.standard_info;
  if (qiData.ntStatus != SMB2_STATUS_SUCCESS)
    error = FUNC + qiData.getErrorMsg();

  return qiData.ntStatus;
}

uint32_t
Smb2Context::smb2_fgetinfo_standard(smb2fh *fh,
                                    struct smb2_file_standard_info *standard_info,
                                    string&        error)
{
  smb2_file_info info;

  if (!isConnected())
  {
    error = FUNC + string("Not Connected to Server");
    return SMB2_STATUS_CONNECTION_DISCONNECTED;
  }

  info.info_type = SMB2_0_INFO_FILE;
  info.file_info_class = SMB2_FILE_STANDARD_INFORMATION;

  QueryInfoData qiData;
  if (Smb2BuildQueryInfoRequest(fh, &info, &qiData) != 0)
  {
    error = FUNC + qiData.getErrorMsg();
    return SMB2_STATUS_PAYLOAD_FAILED;
  }

  if (this->wait_for_reply(error) < 0)
  {
    error = FUNC + error;
    return SMB2_STATUS_SOCKET_ERROR;
  }

  *standard_info = info.u_info.standard_info;
  if (qiData.ntStatus != SMB2_STATUS_SUCCESS)
    error = FUNC + qiData.getErrorMsg();

  return qiData.ntStatus;
}

uint32_t
Smb2Context::smb2_getinfo_extended(string&   path,
                                   struct smb2_file_extended_info **extended_info,
                                   string&        error)
{
  smb2_file_info info;

  if (!isConnected())
  {
    error = FUNC + string("Not Connected to Server");
    return SMB2_STATUS_CONNECTION_DISCONNECTED;
  }

  info.info_type = SMB2_0_INFO_FILE;
  info.file_info_class = SMB2_FILE_FULL_EA_INFORMATION;
  info.u_info.extended_info = NULL;

  QueryInfoData qiData;
  if (Smb2BuildQueryInfoRequest(path, &info, &qiData) != 0)
  {
    error = FUNC + qiData.getErrorMsg();
    return SMB2_STATUS_PAYLOAD_FAILED;
  }

  if (this->wait_for_reply(error) < 0)
  {
    error = FUNC + error;
    return SMB2_STATUS_SOCKET_ERROR;
  }

  if (qiData.ntStatus == SMB2_STATUS_SUCCESS)
  {
    *extended_info = info.u_info.extended_info;
  }

  if (qiData.ntStatus != SMB2_STATUS_SUCCESS)
    error = FUNC + qiData.getErrorMsg();

  return qiData.ntStatus;
}

uint32_t
Smb2Context::smb2_fgetinfo_extended(smb2fh *fh,
                                    struct smb2_file_extended_info **extended_info,
                                    string&         error)
{
  smb2_file_info info;

  if (!isConnected())
  {
    error = FUNC + string("Not Connected to Server");
    return SMB2_STATUS_CONNECTION_DISCONNECTED;
  }

  info.info_type = SMB2_0_INFO_FILE;
  info.file_info_class = SMB2_FILE_FULL_EA_INFORMATION;
  info.u_info.extended_info = NULL;

  QueryInfoData qiData;
  if (Smb2BuildQueryInfoRequest(fh, &info, &qiData) != 0)
  {
    error = FUNC + qiData.getErrorMsg();
    return SMB2_STATUS_PAYLOAD_FAILED;
  }

  if (this->wait_for_reply(error) < 0)
  {
    error = FUNC + error;
    return SMB2_STATUS_SOCKET_ERROR;
  }

  if (qiData.ntStatus == SMB2_STATUS_SUCCESS)
  {
    *extended_info = info.u_info.extended_info;
  }

  if (qiData.ntStatus != SMB2_STATUS_SUCCESS)
    error = FUNC + qiData.getErrorMsg();

  return qiData.ntStatus;
}

static uint32_t
smb2_get_file_extended_size(struct smb2_file_extended_info *info,
                            const int count)
{
        uint32_t size = 0;
        int entries = 0;
        struct smb2_file_extended_info* tmp_info = info;

        while (entries < count) {
                size += sizeof(struct smb2_file_full_ea_info)-
                        (2*sizeof(uint8_t*));
                size += tmp_info->name_len + 1;
                size += tmp_info->value_len;

                if ((size & 0x03) != 0) {
                        uint32_t padlen = 0;
                        padlen = 4 - (size & 0x03);
                        size += padlen;
                }
                tmp_info++;
                entries++;
        };

        return size;
}

uint32_t
Smb2Context::smb2_setinfo_extended(string&   path,
                                   struct smb2_file_extended_info* extended_info,
                                   const int count,
                                   string&   error)
{
  smb2_file_info info;

  if (!isConnected())
  {
    error = FUNC + "Not Connected to Server";
    return SMB2_STATUS_CONNECTION_DISCONNECTED;
  }

  if (extended_info == NULL)
  {
    error = FUNC + "no info to set";
    return SMB2_STATUS_INVALID_ARGUMENT;
  }

  uint32_t eabuf_size = smb2_get_file_extended_size(extended_info, count);

  struct smb2_file_full_extended_info full_extended_info;
  full_extended_info.eabuf = (uint8_t*)malloc(eabuf_size);
  full_extended_info.eabuf_len = 0;
  smb2_encode_file_extended_info(this, extended_info, count,
                                 full_extended_info.eabuf,
                                 &full_extended_info.eabuf_len);

  memset(&info, 0, sizeof(smb2_file_info));
  info.info_type = SMB2_0_INFO_FILE;
  info.file_info_class = SMB2_FILE_FULL_EA_INFORMATION;
  info.u_info.full_extended_info = full_extended_info;

  AppData setInfoData;
  if (Smb2BuildSetInforequest(path, &info, &setInfoData) != 0)
  {
    error = FUNC + setInfoData.getErrorMsg();
    return SMB2_STATUS_PAYLOAD_FAILED;
  }

  if (this->wait_for_reply(error) < 0)
  {
    error = FUNC + error;
    return SMB2_STATUS_SOCKET_ERROR;
  }

  if (setInfoData.ntStatus != SMB2_STATUS_SUCCESS)
    error = FUNC + setInfoData.getErrorMsg();

  return setInfoData.ntStatus;
}

uint32_t
Smb2Context::smb2_fsetinfo_extended(smb2fh         *fh,
                                    struct smb2_file_extended_info* extended_info,
                                    const int      count,
                                    string&        error)
{
  smb2_file_info info;

  if (!isConnected())
  {
    error = FUNC + "Not Connected to Server";
    return SMB2_STATUS_CONNECTION_DISCONNECTED;
  }

  if (extended_info == NULL)
  {
    error = FUNC + string("no info to set");
    return SMB2_STATUS_INVALID_ARGUMENT;
  }

  uint32_t eabuf_size = smb2_get_file_extended_size(extended_info, count);

  struct smb2_file_full_extended_info full_extended_info;
  full_extended_info.eabuf = (uint8_t*)malloc(eabuf_size);
  full_extended_info.eabuf_len = 0;
  smb2_encode_file_extended_info(this, extended_info, count,
                                 full_extended_info.eabuf,
                                 &full_extended_info.eabuf_len);

  memset(&info, 0, sizeof(smb2_file_info));
  info.info_type = SMB2_0_INFO_FILE;
  info.file_info_class = SMB2_FILE_FULL_EA_INFORMATION;
  info.u_info.full_extended_info = full_extended_info;

  AppData setInfoData;
  if (Smb2BuildSetInforequest(fh, &info, &setInfoData) != 0)
  {
    error = FUNC + setInfoData.getErrorMsg();
    return SMB2_STATUS_PAYLOAD_FAILED;
  }

  if (this->wait_for_reply(error) < 0)
  {
    error = FUNC + error;
    return SMB2_STATUS_SOCKET_ERROR;
  }

  if (setInfoData.ntStatus != SMB2_STATUS_SUCCESS)
    error = FUNC + setInfoData.getErrorMsg();

  return setInfoData.ntStatus;
}

uint32_t
Smb2Context::smb2_getinfo_stream(string&   path,
                                 struct smb2_file_stream_info **stream_info,
                                 string&        error)
{
  smb2_file_info info;

  if (!isConnected())
  {
    error = FUNC + string("Not Connected to Server");
    return SMB2_STATUS_CONNECTION_DISCONNECTED;
  }

  info.info_type = SMB2_0_INFO_FILE;
  info.file_info_class = SMB2_FILE_STREAM_INFORMATION;
  info.u_info.stream_info = NULL;

  QueryInfoData qiData;
  if (Smb2BuildQueryInfoRequest(path, &info, &qiData) != 0)
  {
    error = FUNC + qiData.getErrorMsg();
    return SMB2_STATUS_PAYLOAD_FAILED;
  }

  if (this->wait_for_reply(error) < 0)
  {
    error = FUNC + error;
    return SMB2_STATUS_SOCKET_ERROR;
  }

  if (qiData.ntStatus == SMB2_STATUS_SUCCESS)
  {
    *stream_info = info.u_info.stream_info;
  }

  if (qiData.ntStatus != SMB2_STATUS_SUCCESS)
    error = FUNC + qiData.getErrorMsg();

  return qiData.ntStatus;
}

uint32_t
Smb2Context::smb2_fgetinfo_stream(smb2fh         *fh,
                                  struct smb2_file_stream_info **stream_info,
                                  string&        error)
{
  smb2_file_info info;

  if (!isConnected())
  {
    error = FUNC + string("Not Connected to Server");
    return SMB2_STATUS_CONNECTION_DISCONNECTED;
  }

  info.info_type = SMB2_0_INFO_FILE;
  info.file_info_class = SMB2_FILE_STREAM_INFORMATION;
  info.u_info.stream_info = NULL;

  QueryInfoData qiData;
  if (Smb2BuildQueryInfoRequest(fh, &info, &qiData) != 0)
  {
    error = FUNC + qiData.getErrorMsg();
    return SMB2_STATUS_PAYLOAD_FAILED;
  }

  if (this->wait_for_reply(error) < 0)
  {
    error = FUNC + error;
    return SMB2_STATUS_SOCKET_ERROR;
  }

  if (qiData.ntStatus == SMB2_STATUS_SUCCESS)
  {
    *stream_info = info.u_info.stream_info;
  }

  if (qiData.ntStatus != SMB2_STATUS_SUCCESS)
    error = FUNC + qiData.getErrorMsg();

  return qiData.ntStatus;
}

int
Smb2Context::smb2_lookUpSid(string& user, string& domain, string& server, uint8_t **sid, string& error)
{
#define	MAX_IN_BUF_SIZE		(1 * 1024)
#define	MAX_OUT_BUF_SIZE	(64 * 1024)
  uint32_t   status = 0;
  struct     smb2fh *fh = NULL;
  uint8_t    dceRpcBuf[MAX_IN_BUF_SIZE] = {0};
  uint32_t   bindReqSize = 0;
  struct     rpc_bind_request bind_req;
  struct     context_item dcerpc_ctx;

  struct rpc_header rsp_hdr;
  struct rpc_bind_response ack;
  struct rpc_bind_nack_response nack;

  uint16_t max_xmit_frag = 0;
  uint16_t max_recv_frag = 0;

  struct DceRpcOperationRequest *dceOpReq = NULL;
  struct DceRpcOperationResponse dceOpRes2 = {{0}};
  uint32_t offset = 0;
  uint32_t bytes_used = 0;

  uint8_t  output_buf[MAX_OUT_BUF_SIZE] = {0};
  uint32_t output_count = MAX_OUT_BUF_SIZE;

  PolicyHandle pHandle = {0};

  if (server.empty())
  {
    error = FUNC + string("server not specified");
    return -1;
  }
  if (user.empty())
  {
    error = FUNC + string("user not specified");
    return -1;
  }
  if (domain.empty())
  {
    error = FUNC + string("domain not specified");
    return -1;
  }

  std::string error2;

  this->use_cached_creds = true;
  std::string ipc_share = "IPC$";
  if (smb2_connect_share(server, ipc_share, user, error2) !=0)
  {
    error = FUNC + error2;
    return -ENOMEM;
  }

  std::string lsarpc_pipe = std::string("lsarpc");
  fh = smb2_open_pipe(lsarpc_pipe, error2);
  if (fh == NULL)
  {
    error = FUNC + "Failed to open LSARPC pipe: " + error2;
    smb2_disconnect_share();
    return -1;
  }

  dcerpc_create_bind_req(&bind_req, 1);
  dcerpc_init_context(&dcerpc_ctx, CONTEXT_LSARPC);

  bindReqSize = sizeof(struct rpc_bind_request) + sizeof(struct context_item);
  memcpy(dceRpcBuf, &bind_req, sizeof(struct rpc_bind_request));
  memcpy(dceRpcBuf+sizeof(struct rpc_bind_request), &dcerpc_ctx, sizeof(struct context_item));

  status = smb2_ioctl(fh,
                      FSCTL_PIPE_TRANSCEIVE,
                      SMB2_0_IOCTL_IS_FSCTL,
                      dceRpcBuf, bindReqSize,
                      output_buf, &output_count, error2);
  if (status != SMB2_STATUS_SUCCESS)
  {
    error = FUNC + "IOCTL Failed for bind:" + error2;
    goto error;
  }

  if (!dcerpc_get_response_header(output_buf, output_count, &rsp_hdr))
  {
    error = FUNC + string("Failed to parse dcerpc response header");
    goto error;
  }

  if (rsp_hdr.packet_type == RPC_PACKET_TYPE_BINDNACK)
  {
    if (!dcerpc_get_bind_nack_response(output_buf, output_count, &nack))
    {
      error = FUNC + string("Failed to parse dcerpc BINDNACK response");
      goto error;
    }
    error = FUNC + stringf("dcerpc BINDNACK reason : %s", dcerpc_get_reject_reason(nack.reject_reason));
    goto error;
  }
  else if (rsp_hdr.packet_type == RPC_PACKET_TYPE_BINDACK)
  {
    if (!dcerpc_get_bind_ack_response(output_buf, output_count, &ack))
    {
      error = FUNC + string("Failed to parse dcerpc BINDACK response");
      goto error;
    }
    /* save the max xmit and recv frag details */
    max_xmit_frag = ack.max_xmit_frag;
    max_recv_frag = ack.max_recv_frag;
    max_recv_frag = max_recv_frag;
  }

  memset(&dceRpcBuf[0], 0, MAX_IN_BUF_SIZE);
  memset(&output_buf[0], 0, MAX_OUT_BUF_SIZE);
  output_count = MAX_OUT_BUF_SIZE;

  /* BIND is done send OpenPolicy request */
  dceOpReq = (struct DceRpcOperationRequest *)&dceRpcBuf[0];
  offset += sizeof(struct DceRpcOperationRequest);

  lsarpc_create_OpenPolicy2Req(server, RIGHT_TO_LOOKUP_NAMES,
                               dceRpcBuf+offset,
                               MAX_IN_BUF_SIZE-offset,
                               &bytes_used, error2);
  offset += bytes_used;

  /* opnum - 44 - for OpenPolicy2 */
  dcerpc_create_Operation_Request(dceOpReq, DCE_OP_OPEN_POLICY2, bytes_used);

  if (offset > max_xmit_frag)
  {
    error = FUNC + string("IOCTL: DCE_OP_OPEN_POLICY2 Payload size is larger than max_xmit_frag");
    goto error;
  }

  status = smb2_ioctl(fh,
                      FSCTL_PIPE_TRANSCEIVE,
                      SMB2_0_IOCTL_IS_FSCTL,
                      dceRpcBuf, offset,
                      output_buf, &output_count, error2);
  if (status != SMB2_STATUS_SUCCESS)
  {
    error = FUNC + "IOCTL Failed for OpenPolicy2:" + error2;
    goto error;
  }
  if (dcerpc_parse_Operation_Response(output_buf,
                                      output_count,
                                      &dceOpRes2,
                                      &status, error2) < 0)
  {
    error = FUNC + error2 + " for OpenPolicy2";
    goto error;
  }

  offset = 0;
  offset +=sizeof(struct DceRpcOperationResponse);

  if (lsarpc_parse_OpenPolicy2Res(output_buf+offset,
                                  output_count-offset,
                                  &pHandle,
                                  &status) < 0)
  {
    error = FUNC + stringf("lsarpc_parse_OpenPolicy2Res failed : %x", status);
    goto error;
  }

  /* LookUp names now */
  memset(&dceRpcBuf[0], 0, MAX_IN_BUF_SIZE);
  memset(&output_buf[0], 0, MAX_OUT_BUF_SIZE);
  output_count = MAX_OUT_BUF_SIZE;
  offset = 0;

  dceOpReq = (struct DceRpcOperationRequest *)&dceRpcBuf[0];
  offset += sizeof(struct DceRpcOperationRequest);

  if (lsarpc_create_LookUpNamesReq(&pHandle, user, domain,
                                   dceRpcBuf+offset,
                                   MAX_IN_BUF_SIZE-offset,
                                   &bytes_used, error2) < 0)
  {
    error = FUNC + string("Create LookupNames req failed:") + error2;
    goto error;
  }
  offset += bytes_used;

  /* opnum - 14 - for LookupNames */
  dcerpc_create_Operation_Request(dceOpReq, DCE_OP_LOOKUP_NAMES, bytes_used);

  if (offset > max_xmit_frag)
  {
    error = FUNC + string("IOCTL : LookupNames Payload size is larger than max_xmit_frag");
    goto error;
  }

  status = smb2_ioctl(fh,
                      FSCTL_PIPE_TRANSCEIVE,
                      SMB2_0_IOCTL_IS_FSCTL,
                      dceRpcBuf, offset,
                      output_buf, &output_count, error2);
  if (status != SMB2_STATUS_SUCCESS)
  {
    error = FUNC + stringf("IOCTL Failed for LookupNames : %s", error2.c_str());
    goto error;
  }
  if (dcerpc_parse_Operation_Response(output_buf,
                                      output_count,
                                      &dceOpRes2,
                                      &status, error2) < 0)
  {
    error = FUNC + error2 + " for LookupNames";
    goto error;
  }

  offset = 0;
  offset +=sizeof(struct DceRpcOperationResponse);
  if (lsarpc_parse_LookupNamesRes(output_buf+offset,
                                  output_count-offset,
                                  sid,
                                  &status, error2) < 0)
  {
    error = FUNC + stringf("lsarpc_parse_LookupNamesRes failed : status = %x, error = %s",
                   status, error2.c_str());
    goto error;
  }

  /* Close the policy handle */
  memset(&dceRpcBuf[0], 0, MAX_IN_BUF_SIZE);
  memset(&output_buf[0], 0, MAX_OUT_BUF_SIZE);
  output_count = MAX_OUT_BUF_SIZE;
  offset = 0;

#if 0
  dceOpReq = (struct DceRpcOperationRequest *)&dceRpcBuf[0];
  offset += sizeof(struct DceRpcOperationRequest);

  lsarpc_create_ClosePolicy2eq(&pHandle, dceRpcBuf+offset, MAX_IN_BUF_SIZE-offset, &bytes_used);
  offset += bytes_used;

  /* opnum - 0 - for ClosePolicy */
  dcerpc_create_Operation_Request(dceOpReq, DCE_OP_CLOSE_POLICY, bytes_used);

  if (offset > max_xmit_frag) {
    error = FUNC + string("IOCTL:DCE_OP_CLOSE_POLICY Payload size is larger than max_xmit_frag");
    goto error;
  }

  status = smb2_ioctl(fh,
                      FSCTL_PIPE_TRANSCEIVE,
                      SMB2_0_IOCTL_IS_FSCTL,
                      dceRpcBuf, offset,
                      output_buf, &output_count error2);
  if (status != SMB2_STATUS_SUCCESS) {
    error = FUNC + stringf("IOCTL Failed for close policy: %s", error2.c_str());
    goto error;
  }
  if (dcerpc_parse_Operation_Response(output_buf,
                                      output_count,
                                      &dceOpRes2,
                                      &status, error2) < 0) {
    error = FUNC + error2 + " for ClosePolicy";
    goto error;
  }
#endif

  /* close the pipe & disconnect */
  smb2_close(fh, error2);
  smb2_disconnect_share();
  return 0;

error:
  /* close the pipe & disconnect */
  smb2_close(fh, error2);
  smb2_disconnect_share();

  if (*sid != NULL) {
    free(*sid);
  }

  return -1;
}

void
Smb2Context::smb2_closedir(smb2dir *dir)
{
  delete dir;
}

void smb2FreeFileExtendedInfo(struct smb2_file_extended_info *extended_info)
{
  struct smb2_file_extended_info *tmp_info = NULL;
  if (extended_info == NULL)
    return;

  tmp_info = extended_info;

  while (tmp_info)
  {
    struct smb2_file_extended_info *node = tmp_info;
    free(node->name);
    free(node->value);
    tmp_info = tmp_info->next;
    free(node);
  }
}

void smb2FreeFileStreamInfo(struct smb2_file_stream_info *stream_info)
{
  struct smb2_file_stream_info *tmp_info = NULL;
  if (stream_info == NULL)
    return;

  tmp_info = stream_info;

  while (tmp_info)
  {
    struct smb2_file_stream_info *node = tmp_info;
    tmp_info = tmp_info->next;
    free(node);
  }
}
