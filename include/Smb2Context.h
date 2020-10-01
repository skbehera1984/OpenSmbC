#ifndef _SMB2_CONTEXT_H_
#define _SMB2_CONTEXT_H_

#include <map>
#include <string>
#include <stdint.h>
#include "DataTypes.h"
#include "AppData.h"
#include "smb2.h"
#include "SmartPtr.h"

using namespace std;

#define MAX_CREDITS 1024

class Smb2Pdu;
class Smb2Socket;
class Smb2AuthProvider;
class Smb2Context;
typedef SmartPtr<Smb2Context> Smb2ContextPtr;

class Smb2Context : public SmartRef
{
public:
  Smb2Context();
  ~Smb2Context();

  static Smb2ContextPtr create(void);
  void                  close();

  void smb2SetUser(std::string& user);
  void smb2SetPassword(std::string password);
  void smb2SetDomain(std::string domain);
  void smb2SetWorkstation(std::string& workstation);
  void smb2SetAuthMode(enum smb2_sec mode);
  void smb2SetSecurityMode(uint16_t security_mode);
  void smb2SetUsrInBackUpOpsGrp(bool val);

  bool     isConnected();
  uint32_t smb2GetMaxReadSize();
  uint32_t smb2GetMaxWriteSize();
  uint32_t smb2GetMaxTransactSize();

  uint8_t smb2IsEncryptionSupported(); // server support
  uint8_t smb2IsEncryptionEnabled();
  void    smb2EnableEncryption(bool enable);

  bool smb2_queue_pdu(Smb2Pdu *pdu, std::string& err);
  Smb2Pdu* smb2_find_pdu(uint64_t messageId);
  void smb2_remove_pdu(uint64_t messageId);
  void smb2_pdu_add_to_waitqueue(Smb2Pdu *pdu);

  int wait_for_reply(std::string& error);
  void endSendReceive();

private:
  void set_password_from_file();

public:
  /* APIs */
  /* User must free up all the buffers returned by these APIs */
  uint32_t smb2_connect_share(string& server, string& share, string& user, string& err);
  uint32_t smb2_disconnect_share();
  smb2dir *smb2_querydir(string& path, string& pattern, string& err);
  smb2dir* smb2_fquerydir(smb2fh *fh, string& pattern, string& err);
  void     smb2_closedir(smb2dir *smb2dir);

  smb2fh * smb2_open(string& path, int flags, string& err);
  smb2fh * smb2_open_file(string& path,
                          uint8_t  security_flags,
                          uint64_t smb_create_flags,
                          uint32_t desired_access,
                          uint32_t file_attributes,
                          uint32_t share_access,
                          uint32_t create_disposition,
                          uint32_t create_options,
                          std::string& err);
  smb2fh * smb2_open_pipe(string& pipe, string& err);
  uint32_t smb2_close(smb2fh *fh, string& err);
  uint32_t smb2_echo(std::string& error);

  uint32_t smb2_fsync(smb2fh *fh, string& err);
  uint32_t smb2_pread(smb2fh *fh, uint8_t *buf, uint32_t count, uint64_t offset, string& err);
  uint32_t smb2_pwrite(smb2fh *fh, uint8_t *buf, uint32_t count, uint64_t offset, string& err);
  uint32_t smb2_read(smb2fh *fh, uint8_t *buf, uint32_t count, string& err);
  uint32_t smb2_write(smb2fh *fh, uint8_t *buf, uint32_t count, string& err);
  uint32_t smb2_unlink(std::string& path, std::string& err);
  uint32_t smb2_rmdir(std::string& path, std::string& err);
  uint32_t smb2_mkdir(std::string& path, std::string& err);
  uint32_t smb2_fstat(smb2fh *fh, struct smb2_stat_64 *st, string& err);
  uint32_t smb2_stat(string& path, struct smb2_stat_64 *st, string& error);
  uint32_t smb2_statvfs(string& path, struct smb2_statvfs *statvfs, string& error);
  uint32_t smb2_get_security(string& path, uint8_t **buf, uint32_t *buf_len, string& error);
  uint32_t smb2_fget_security(smb2fh *fh,  uint8_t **buf, uint32_t *buf_len, string& error);
  uint32_t smb2_getinfo_all(string& path, struct smb2_file_info_all *all_info, string& error);
  uint32_t smb2_fgetinfo_all(smb2fh *fh, struct smb2_file_info_all *all_info, string& error);
  uint32_t smb2_rename(string& oldpath, string& newpath, string& error);
  uint32_t smb2_truncate(string& path, uint64_t length, string& error);
  uint32_t smb2_ftruncate(smb2fh *fh, uint64_t length, string& error);
  uint32_t smb2_set_security(string& path, uint8_t *buf, uint32_t buf_len, string& error);
  uint32_t smb2_fset_security(smb2fh *fh, uint8_t *buf, uint32_t buf_len, string& error);
  uint32_t smb2_setinfo_basic(string& path, struct smb2_file_basic_info *info, string& error);
  uint32_t smb2_fsetinfo_basic(smb2fh *fh, struct smb2_file_basic_info *info, string& error);
  uint32_t smb2_getinfo_basic(string& path, struct smb2_file_basic_info *basic_info, string& error);
  uint32_t smb2_fgetinfo_basic(smb2fh *fh, struct smb2_file_basic_info *basic_info, string& error);
  uint32_t smb2_getinfo_standard(string& path, struct smb2_file_standard_info *standard_info, string& error);
  uint32_t smb2_fgetinfo_standard(smb2fh *fh, struct smb2_file_standard_info *standard_info, string& error);
  uint32_t smb2_getinfo_extended(string& path, struct smb2_file_extended_info **extended_info, string& error);
  uint32_t smb2_fgetinfo_extended(smb2fh *fh, struct smb2_file_extended_info **extended_info, string& error);
  uint32_t smb2_setinfo_extended(string& path, struct smb2_file_extended_info *extended_info, const int count, string& error);
  uint32_t smb2_fsetinfo_extended(smb2fh *fh, struct smb2_file_extended_info* extended_info, const int count, string& error);
  uint32_t smb2_getinfo_stream(string& path, struct smb2_file_stream_info **stream_info, string& error);
  uint32_t smb2_fgetinfo_stream(smb2fh *fh, struct smb2_file_stream_info **stream_info, string& error);


  int      smb2_lookUpSid(string& user, string& domain, string& server, uint8_t **sid, string& error);
  int      smb2_list_shares(string& server, string& user, uint32_t shinfo_type, smb2_shares& shares, string& error);
  uint32_t smb2_ioctl(smb2fh *fh,
                      uint32_t ioctl_ctl, uint32_t ioctl_flags,
                      uint8_t *input_buffer, uint32_t input_count,
                      uint8_t *output_buffer, uint32_t *output_count,
                      string&  error);


public:
  int Smb2BuildConnectRequest(std::string& server,
                              std::string& share,
                              std::string& user,
                              AppData      *connData);
  int Smb2BuildQueryDirectoryRequest(smb2fh *fh, std::string& pattern, AppData *qDirData);
  int Smb2BuildCreateRequest(std::string& path,
                             uint8_t  security_flags,
                             uint32_t impersonation_level,
                             uint64_t smb_create_flags,
                             uint32_t desired_access,
                             uint32_t file_attributes,
                             uint32_t share_access,
                             uint32_t create_disposition,
                             uint32_t create_options,
                             AppData  *createData);
  int Smb2BuildCloseRequest(smb2fh *fh, AppData *closeData);
  int Smb2BuildFlushRequest(smb2fh *fh, AppData *flushData);
  int Smb2BuildReadRequest(smb2fh      *fh,
                           uint8_t     *buf,
                           uint32_t    count,
                           uint64_t    offset,
                           AppData     *readData);

  int Smb2BuildWriteRequest(smb2fh     *fh,
                            uint8_t    *buf,
                            uint32_t   count,
                            uint64_t   offset,
                            AppData    *writeData);
  int Smb2BuildQueryInfoRequest(smb2fh         *fh,
                                smb2_file_info *info,
                                AppData        *qiData);
  int Smb2BuildQueryInfoRequest(std::string&   path,
                                smb2_file_info *info,
                                AppData        *qiData);
  int Smb2BuildDisConnectRequest(AppData *disConData);
  int Smb2BuildEchoRequest(AppData *echoData);
  int Smb2BuildIoctlRequest(smb2fh   *fh,
                            uint32_t ioctl_ctl,
                            uint32_t ioctl_flags,
                            uint8_t  *input_buffer,
                            uint32_t input_count,
                            uint8_t  *output_buffer,
                            uint32_t *output_count,
                            AppData  *ioctlData);
  int Smb2BuildSetInforequest(smb2fh         *fh,
                              smb2_file_info *info,
                              AppData        *setInfoData);
  int Smb2BuildSetInforequest(std::string&   path,
                              smb2_file_info *info,
                              AppData        *setInfoData);
public:
  Smb2Socket *smb2Socket;

  enum smb2_sec sec;
  Smb2AuthProvider *authenticator;

  uint16_t security_mode;
  bool use_cached_creds;

  enum smb2_negotiate_version version;

  std::string server;
  std::string share;
  std::string  user;

  /* Only used with --without-libkrb5 */
  std::string password;
  std::string domain;
  std::string workstation;
  char client_challenge[8];

  uint32_t credits;

  uint32_t tree_id;
  uint64_t message_id;
  uint64_t session_id;
  uint8_t *session_key;
  uint8_t session_key_size;

  uint8_t signing_required;
  uint8_t signing_key[SMB2_KEY_SIZE];

  /* SMB 3.11 support */
  uint16_t hashAlgorithm;
  uint16_t CipherId;
  bool     clientSupportEncryption;
  uint8_t  serverSupportEncryption;
  uint8_t  *PreauthIntegrityHash;
  uint32_t preauthIntegrityHashLength;

  /* For sending PDUs */
  std::map<uint64_t, Smb2Pdu *>outqueue;
  std::map<uint64_t, Smb2Pdu *>waitqueue;

  /* Server capabilities */
  bool supports_multi_credit;

  uint32_t max_transact_size;
  uint32_t max_read_size;
  uint32_t max_write_size;
  uint16_t dialect;

  // this is used to terminate send and wait loop
  bool     isComplete;

  char errorMsg[MAX_ERROR_SIZE];

  bool userInBackUpOperatorsGrp;
};

#endif //_SMB2_CONTEXT_H_
