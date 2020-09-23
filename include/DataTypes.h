#ifndef _DATA_TYPES_H_
#define _DATA_TYPES_H_

#include <string>
#include <vector>

#include "smb2.h"

class smb2_url
{
public:
  std::string domain;
  std::string user;
  std::string server;
  std::string share;
  std::string path;
};

struct smb2_timeval
{
  uint32_t tv_sec;
  uint32_t tv_usec;
};

enum smb2_sec
{
  SMB2_SEC_UNDEFINED = 0,
  SMB2_SEC_NTLMSSP,
  SMB2_SEC_KRB5,
};

class smb2fh
{
public:
  smb2fh();
  smb2_file_id file_id;
  int64_t offset;

  uint32_t byte_count;
  uint32_t bytes_remaining;

  uint8_t oplock_level;
  uint32_t create_action;
  uint64_t creation_time;
  uint64_t lastAccess_time;
  uint64_t lastWrite_time;
  uint64_t change_time;
  uint64_t allocation_size;
  uint64_t end_of_file;
  uint32_t file_attributes;
};

/* Stat structure */
#define SMB2_TYPE_FILE      0x00000000
#define SMB2_TYPE_DIRECTORY 0x00000001

struct smb2_stat_64
{
  uint32_t smb2_type;
  uint32_t smb2_nlink;
  uint64_t smb2_ino;
  uint64_t smb2_size;
  uint64_t smb2_atime;
  uint64_t smb2_mtime;
  uint64_t smb2_ctime;
  uint64_t smb2_crtime;
};

struct smb2_statvfs
{
  uint32_t	f_bsize;
  uint32_t	f_frsize;
  uint64_t	f_blocks;
  uint64_t	f_bfree;
  uint64_t	f_bavail;
  uint32_t	f_files;
  uint32_t	f_ffree;
  uint32_t	f_favail;
  uint32_t	f_fsid;
  uint32_t	f_flag;
  uint32_t	f_namemax;
};

struct smb2_file_info_all
{
  uint32_t smb2_type;

  uint32_t smb2_nlink;
  uint64_t smb2_ino;
  uint64_t smb2_size;

  uint64_t smb2_atime;
  uint64_t smb2_atime_nsec;
  uint64_t smb2_mtime;
  uint64_t smb2_mtime_nsec;
  uint64_t smb2_ctime;
  uint64_t smb2_ctime_nsec;
  uint64_t smb2_crtime;
  uint64_t smb2_crtime_nsec;

  uint32_t file_attributes;

  uint64_t allocation_size;
  uint64_t end_of_file;
  uint8_t delete_pending;
  uint8_t directory;

  uint32_t ea_size;
  uint32_t access_flags;
  uint32_t mode;
};

struct smb2_file_extended_info;

struct smb2_file_extended_info
{
  uint8_t* name;
  uint8_t name_len;
  uint8_t* value;
  uint16_t value_len;
  struct smb2_file_extended_info *next;
};

struct smb2_file_full_extended_info
{
  uint8_t *eabuf;
  uint32_t eabuf_len;
};

struct smb2_file_stream_info;

struct smb2_file_stream_info
{
  char name[4096];
  uint64_t size;
  uint64_t allocation_size;
  struct smb2_file_stream_info *next;
};

typedef union _file_info_union
{
  struct smb2_file_basic_info           basic_info;
  struct smb2_file_standard_info        standard_info;
  struct smb2_file_extended_info        *extended_info;
  struct smb2_file_stream_info          *stream_info;
  struct smb2_file_all_info             all_info;
  struct smb2_security_descriptor       *security_info;
  struct smb2_file_fs_size_info         fs_size_info;
  struct smb2_file_fs_device_info       fs_device_info;
  struct smb2_file_fs_control_info      fs_control_info;
  struct smb2_file_fs_full_size_info    fs_full_size_info;
  struct smb2_file_fs_sector_size_info  fs_sector_size_info;
  /* specific to SMB2_SET_INFO only */
  struct smb2_file_end_of_file_info     eof_info;
  struct smb2_file_rename_info          rename_info;
  struct smb2_file_security_info        sec_info;
  struct smb2_file_full_extended_info   full_extended_info;
} smb2_file_info_U;

typedef struct _file_info
{
  uint8_t info_type;
  uint8_t file_info_class;
  smb2_file_info_U u_info;
} smb2_file_info;

class smb2dirent
{
public:
  smb2dirent()
  {
    name.clear();
    allocation_size = 0;
    attributes = 0;
    ea_size = 0;
  }
  std::string name;
  uint64_t    allocation_size;
  uint32_t    attributes;
  uint32_t    ea_size;
  struct smb2_stat_64 st;
};

class smb2dir
{
public:
  smb2dir()
  {
    file_id.persistent_id =0;
    file_id.volatile_id=0;
    entries.clear();
  }
  ~smb2dir()
  {
    entries.clear();
  }

  smb2_file_id file_id;
  std::vector<smb2dirent> entries;
};

#define SHARE_STYPE_DISKTREE    0x00000000
#define SHARE_STYPE_PRINTQ      0x00000001
#define SHARE_STYPE_DEVICE      0x00000002
#define SHARE_STYPE_IPC         0x00000003
#define SHARE_STYPE_TEMPORARY   0x40000000
#define SHARE_STYPE_SPECIAL     0x80000000
#define SHARE_STYPE_UNKNOWN     0xFFFFFFFF

#define SMB2_SHARE_NAME_MAX	257
#define SMB2_SHARE_REMARK_MAX	257

class smb2_shareinfo
{
public:
  smb2_shareinfo();
  std::string name;       // info 1
  uint32_t    share_type; // info 1
  std::string remark;     // info 1
  uint32_t    permissions;
  uint32_t    max_uses;
  uint32_t    current_uses;
  std::string path;
  std::string password;
};

class smb2_shares
{
public:
  smb2_shares();
  uint32_t share_info_type;
  std::vector<smb2_shareinfo> sharelist;
};

class Smb2Status
{
public:
  Smb2Status();
  Smb2Status(uint32_t sts, std::string m);

  Smb2Status(const Smb2Status &obj);
  Smb2Status& operator=(const Smb2Status &obj);
  bool operator==(uint32_t val)const;

public:
  uint32_t    status;
  std::string msg;
};

#endif
