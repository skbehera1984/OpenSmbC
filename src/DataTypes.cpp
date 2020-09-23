#include "DataTypes.h"
#include "PrivateData.h"
#include <string.h>

using namespace std;

smb2fh::smb2fh()
{
  file_id.persistent_id=0;
  file_id.volatile_id=0;
  byte_count = 0;
  bytes_remaining = 0;
  oplock_level = 0;
  create_action = 0;
  creation_time = 0;
  lastAccess_time = 0;
  lastWrite_time = 0;
  change_time = 0;
  allocation_size = 0;
  end_of_file = 0;
  file_attributes = 0;
}

smb2_shareinfo::smb2_shareinfo()
{
  name.clear();
  share_type = 0;
  remark.clear();
  permissions = 0;
  max_uses = 0;
  current_uses = 0;
  path.clear();
  password.clear();
}

smb2_shares::smb2_shares()
{
  share_info_type = 0;
  sharelist.clear();
}

smb2_sid::smb2_sid()
{
  revision = 0;
  sub_auth_count = 0;
  memset(id_auth, 0, SID_ID_AUTH_LEN);
  sub_auth = NULL;
}

smb2_sid::smb2_sid(uint8_t sb_auth_cnt)
{
  revision = 0;
  sub_auth_count = 0;
  memset(id_auth, 0, SID_ID_AUTH_LEN);
  sub_auth = nullptr;
  sub_auth = new uint32_t[sb_auth_cnt];
  if (sub_auth == nullptr)
    throw std::string("Failed to allocate SID sub_auth");
  memset(sub_auth, 0, sb_auth_cnt);
}

smb2_sid::~smb2_sid()
{
  memset(this->id_auth, 0, SID_ID_AUTH_LEN);
  delete[] this->sub_auth;
}

smb2_ace::smb2_ace()
{
  ace_type = 0;
  ace_flags = 0;
  ace_size = 0;
  mask = 0;
  flags = 0;
  sid = nullptr;
  memset(&(object_type[0]), 0, SMB2_OBJECT_TYPE_SIZE);
  memset(&(inherited_object_type[0]), 0, SMB2_OBJECT_TYPE_SIZE);

  ad_len = 0;
  ad_data = nullptr;
  raw_len = 0;
  raw_data = nullptr;
}

smb2_ace::~smb2_ace()
{
  if (sid)
    delete sid;

  if (ad_data)
  {
    free(ad_data); ad_data = NULL;
  }
  if (raw_data)
  {
    free(raw_data); raw_data = NULL;
  }
}

smb2_acl::smb2_acl()
{
  revision = 0;
  acl_size = 0;
  ace_count = 0;
  aces.clear();
}

smb2_acl::~smb2_acl()
{
  vector<smb2_ace *>::iterator it = aces.begin();
  for( ; it != aces.end(); )
  {
    delete *it;
    it = aces.erase(it);
  }
}

smb2_security_descriptor::smb2_security_descriptor()
{
  revision = 0;
  control = 0;
  owner = nullptr;
  group = nullptr;
  dacl = nullptr;
}

smb2_security_descriptor::~smb2_security_descriptor()
{
  delete owner;
  delete group;
  delete dacl;
}

smb2_iovec::smb2_iovec(uint8_t *buf, size_t len, void (*free)(void *))
{
  this->buf = buf;
  this->len = len;
  this->free = free;
}

smb2_iovec::smb2_iovec(size_t size)
{
  buf = NULL;
  len = 0;
  free = NULL;

  if (size > 0)
  {
    buf = (uint8_t*)calloc(1, size);
    len = size;
    this->free = free;
  }
}

smb2_iovec& smb2_iovec::operator=(const smb2_iovec& obj)
{
  this->buf = obj.buf;
  this->len = obj.len;
  this->free= obj.free;
  return (*this);
}

int smb2_iovec::smb2_set_uint8(int offset, uint8_t value)
{
  if (offset + sizeof(uint8_t) > this->len)
  {
    return -1;
  }
  this->buf[offset] = value;
  return 0;
}

int smb2_iovec::smb2_set_uint16(int offset, uint16_t value)
{
  if (offset + sizeof(uint16_t) > this->len)
  {
    return -1;
  }
  *(uint16_t *)(this->buf + offset) = htole16(value);
  return 0;
}

int smb2_iovec::smb2_set_uint32(int offset, uint32_t value)
{
  if (offset + sizeof(uint32_t) > this->len)
  {
    return -1;
  }
  *(uint32_t *)(this->buf + offset) = htole32(value);
  return 0;
}

int smb2_iovec::smb2_set_uint64(int offset, uint64_t value)
{
  if (offset + sizeof(uint64_t) > this->len)
  {
    return -1;
  }
  *(uint64_t *)(this->buf + offset) = htole64(value);
  return 0;
}

int smb2_iovec::smb2_get_uint8(int offset, uint8_t *value)
{
  if (offset + sizeof(uint8_t) > this->len)
  {
    return -1;
  }
  *value = this->buf[offset];
  return 0;
}

int smb2_iovec::smb2_get_uint16(int offset, uint16_t *value)
{
  uint16_t tmp;

  if (offset + sizeof(uint16_t) > this->len)
  {
    return -1;
  }
  memcpy(&tmp, this->buf + offset, sizeof(uint16_t));
  *value = le16toh(tmp);
  return 0;
}

int smb2_iovec::smb2_get_uint32(int offset, uint32_t *value)
{
  uint32_t tmp;

  if (offset + sizeof(uint32_t) > this->len)
  {
    return -1;
  }
  memcpy(&tmp, this->buf + offset, sizeof(uint32_t));
  *value = le32toh(tmp);
  return 0;
}

int smb2_iovec::smb2_get_uint64(int offset, uint64_t *value)
{
  uint64_t tmp;

  if (offset + sizeof(uint64_t) > this->len)
  {
    return -1;
  }
  memcpy(&tmp, this->buf + offset, sizeof(uint64_t));
  *value = le64toh(tmp);
  return 0;
}

smb2_io_vectors::smb2_io_vectors()
{
  total_size = 0;
  iovs.clear();
}

smb2_io_vectors& smb2_io_vectors::operator=(const smb2_io_vectors& obj)
{
  this->total_size = obj.total_size;
  this->iovs = obj.iovs;

  return (*this);
}

void smb2_io_vectors::clear()
{
  iovs.clear();
  total_size = 0;
}

void smb2_io_vectors::smb2_free_iovector()
{
  for (smb2_iovec iov : iovs)
  {
    if (iov.free)
      iov.free(iov.buf);
    iov.len = 0;
  }
  iovs.clear();
  total_size = 0;
}

void smb2_io_vectors::smb2_add_iovector(uint8_t *buf, int len, void (*free)(void *))
{
  smb2_iovec iov;

  iov.buf = buf;
  iov.len = len;
  iov.free = free;
  iovs.push_back(iov);

  total_size += len;
}

void smb2_io_vectors::smb2_add_iovector(smb2_iovec &vec)
{
  total_size += vec.len;
  iovs.push_back(vec);
}

void smb2_io_vectors::smb2_append_iovectors(smb2_io_vectors &iovecs)
{
  for (smb2_iovec iov : iovecs.iovs)
    this->smb2_add_iovector(iov);
}

void smb2_io_vectors::smb2_pad_to_64bit()
{
  static uint8_t zero_bytes[7];
  int len = 0;

  for (smb2_iovec iov : iovs)
  {
    len += iov.len;
  }
  if ((len & 0x07) == 0)
    return;

  smb2_add_iovector(&zero_bytes[0], 8 - (len & 0x07), NULL);

  return;
}

Smb2Status::Smb2Status(uint32_t sts, std::string m)
{
  status = sts;
  msg    = m;
}

Smb2Status::Smb2Status(const Smb2Status &obj)
{
  this->status = obj.status;
  this->msg    = obj.msg;
}

Smb2Status& Smb2Status::operator=(const Smb2Status &obj)
{
  status = obj.status;
  msg    =   obj.msg;
  return (*this);
}

bool Smb2Status::operator==(uint32_t val) const
{
  if (status == val)
    return true;
  else
    return false;
}
