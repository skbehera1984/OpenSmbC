#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <inttypes.h>

#include "Smb2FileData.h"
#include "Stringf.h"

#define FUNC stringf("%s: ", __func__)

typedef struct _SID {
        uint8_t Revision;
        uint8_t SubAuthorityCount;
        uint8_t IdentifierAuthority[6];
        uint32_t SubAuthority[];
} SID, *PSID;

typedef struct _ACE_HEADER {
        uint8_t  AceType;
        uint8_t  AceFlags;
        uint16_t AceSize;
} ACE_HEADER, *PACE_HEADER;

typedef struct _ACCESS_ALLOWED_ACE_HEADER {
        ACE_HEADER ace_hdr;
        uint32_t   Mask;
        uint8_t    Sid[];
} ACCESS_ALLOWED_ACE_HDR, *PACCESS_ALLOWED_ACE_HDR;

typedef struct _ACCESS_ALLOWED_OBJECT_ACE_HEADER {
        ACE_HEADER ace_hdr;
        uint32_t   Mask;
        uint32_t   Flags;
        uint8_t    ObjectType[SMB2_OBJECT_TYPE_SIZE];
        uint8_t    InheritedObjectType[SMB2_OBJECT_TYPE_SIZE];
        uint8_t    Sid[];
} ACCESS_ALLOWED_OBJ_ACE_HDR, *PACCESS_ALLOWED_OBJ_ACE_HDR;

typedef struct _ACCESS_ALLOWED_CALLBACK_ACE_HEADER {
        ACE_HEADER ace_hdr;
        uint32_t   Mask;
        uint8_t    Sid[];
        /*uint8_t    ApplicationData[];*/
} ACCESS_ALLOWED_CALLBACK_ACE_HDR, *PACCESS_ALLOWED_CALLBACK_ACE_HDR;

typedef struct _ACL_HEADER {
        uint8_t  AclRevision;
        uint8_t  Sbz1; /* Padding (should be 0) */
        uint16_t AclSize;
        uint16_t AceCount;
        uint16_t Sbz2; /* Padding (should be 0) */
} ACL_HDR, *PACL_HDR;

typedef struct _SECURITY_DESCRIPTOR_RELATIVE_HEADER {
        uint8_t   Revision;
        uint8_t   Sbz1;     /* Padding (should be 0 unless SE_RM_CONTROL_VALID) */
        uint16_t  Control;
        uint32_t  OffsetOwner;    /* offset to Owner SID */
        uint32_t  OffsetGroup;    /* offset to Group SID */
        uint32_t  OffsetSacl;     /* offset to system ACL */
        uint32_t  OffsetDacl;     /* offset to discretional ACL */
        /* Owner, Group, Sacl, and Dacl data follows */
} SECURITY_DESCRIPTOR_RELATIVE_HDR, *PSECURITY_DESCRIPTOR_RELATIVE_HDR;

static uint32_t
smb2_get_sid_size(smb2_sid *sid)
{
  uint32_t sid_size = 0;
  sid_size = sizeof(uint8_t) + sizeof(uint8_t) +
                    (SID_ID_AUTH_LEN * sizeof(uint8_t)) +
                    (sid->sub_auth_count * sizeof(uint32_t));
  return sid_size;
}

uint32_t
smb2_get_ace_size(smb2_ace *ace)
{
  return ace->ace_size;
}

static uint32_t
smb2_get_acl_size(smb2_acl *acl)
{
  uint32_t acl_size = 0;

  acl_size = sizeof(ACL_HDR);

  for (smb2_ace *ace : acl->aces)
  {
    acl_size += ace->ace_size;
  }
  return acl_size;
}

uint32_t
smb2_get_security_descriptor_size(smb2_security_descriptor *sd)
{
  uint32_t sec_size = 0;

  sec_size += (5 * sizeof(uint32_t));
  if (sd->owner)
  {
    sec_size += smb2_get_sid_size(sd->owner);
  }
  if (sd->group)
  {
    sec_size += smb2_get_sid_size(sd->group);
  }
  if (sd->dacl)
  {
    sec_size += smb2_get_acl_size(sd->dacl);
  }
  return sec_size;
}

static smb2_sid *
decode_sid(smb2_iovec v, string& error)
{
  uint8_t revision = 0, sub_auth_count = 0;
  int i;
  smb2_sid *sid = nullptr;

  if (v.len < 8)
  {
    error = FUNC + "SID must be at least 8 bytes";
    return nullptr;
  }

  v.smb2_get_uint8(0, &revision);
  if (revision != 1)
  {
    error = FUNC + stringf("can not decode sid with revision %d", revision);
    return nullptr;
  }
  v.smb2_get_uint8(1, &sub_auth_count);

  if (v.len < 8 + sub_auth_count * sizeof(uint32_t))
  {
    error = FUNC + "SID is bigger than the buffer";
    return nullptr;
  }

  sid = new smb2_sid(sub_auth_count);
  if (!sid)
  {
    error = FUNC + "Failed to allocate sid";
    return nullptr;
  }

  sid->revision = revision;
  sid->sub_auth_count = sub_auth_count;
  memcpy(&sid->id_auth[0], &v.buf[2], SID_ID_AUTH_LEN);
  for (i = 0; i < sub_auth_count; i++)
  {
    v.smb2_get_uint32(8 + i * sizeof(uint32_t), &sid->sub_auth[i]);
  }

  v.len -= 8 + sub_auth_count * sizeof(uint32_t);
  v.buf += 8 + sub_auth_count * sizeof(uint32_t);

  return sid;
}

static smb2_ace *
decode_ace(smb2_iovec v, string& error)
{
  uint8_t ace_type = 0, ace_flags = 0;
  uint16_t ace_size = 0;
  smb2_ace * ace = nullptr;

  if (v.len < 4)
  {
    error = FUNC + "not enough data for ace header";
    return nullptr;
  }

  v.smb2_get_uint8(0, &ace_type);
  v.smb2_get_uint8(1, &ace_flags);
  v.smb2_get_uint16(2, &ace_size);

  ace = new smb2_ace();
  if (ace == nullptr)
  {
    error = FUNC + "Failed to allocate ace";
    return nullptr;
  }

  ace->ace_type  = ace_type;
  ace->ace_flags = ace_flags;
  ace->ace_size  = ace_size;

  /* Skip past the header */
  if (ace_size < 4)
  {
    error = FUNC + "not enough data for ace data";
    delete ace;
    return nullptr;
  }
  if (v.len < ace_size)
  {
    error = FUNC + "not enough data for ace data";
    delete ace;
    return nullptr;
  }
  v.len -= 4;
  v.buf = &v.buf[4];

  /* decode the content of the ace */
  /* TODO: have a default case where we just keep the raw blob */
  switch (ace_type)
  {
    case SMB2_ACCESS_ALLOWED_ACE_TYPE:
    case SMB2_ACCESS_DENIED_ACE_TYPE:
    case SMB2_SYSTEM_AUDIT_ACE_TYPE:
    case SMB2_SYSTEM_MANDATORY_LABEL_ACE_TYPE:
    case SMB2_SYSTEM_SCOPED_POLICY_ID_ACE_TYPE:
    {
      v.smb2_get_uint32(0, &ace->mask);

      if (v.len < 4)
      {
        error = FUNC + "not enough data for ace data.";
        delete ace;
        return nullptr;
      }
      v.len -= 4;
      v.buf = &v.buf[4];
      ace->sid = decode_sid(v, error);
      if (ace->sid == nullptr)
      {
        error = FUNC + stringf("Failed to decode sid. ace_type %x - ", ace_type) + error;
        delete ace;
        return nullptr;
      }
    }
    break;
    case SMB2_ACCESS_ALLOWED_OBJECT_ACE_TYPE:
    case SMB2_ACCESS_DENIED_OBJECT_ACE_TYPE:
    case SMB2_SYSTEM_AUDIT_OBJECT_ACE_TYPE:
    {
      if (v.len < 40)
      {
        error = FUNC + "not enough data for ace data.";
        delete ace;
        return nullptr;
      }
      v.smb2_get_uint32(0, &ace->mask);

      v.len -= 4;
      v.buf = &v.buf[4];
      v.smb2_get_uint32(0, &ace->flags);

      v.len -= 4;
      v.buf = &v.buf[4];
      memcpy(ace->object_type, v.buf, SMB2_OBJECT_TYPE_SIZE);

      v.len -= SMB2_OBJECT_TYPE_SIZE;
      v.buf = &v.buf[SMB2_OBJECT_TYPE_SIZE];
      memcpy(ace->inherited_object_type, v.buf, SMB2_OBJECT_TYPE_SIZE);

      v.len -= SMB2_OBJECT_TYPE_SIZE;
      v.buf = &v.buf[SMB2_OBJECT_TYPE_SIZE];
      ace->sid = decode_sid(v, error);
      if (ace->sid == nullptr)
      {
        error = FUNC + stringf("Failed to decode sid. ace_type %x - ", ace_type) + error;
        delete ace;
        return nullptr;
      }
    }
    break;
    case SMB2_ACCESS_ALLOWED_CALLBACK_ACE_TYPE:
    case SMB2_ACCESS_DENIED_CALLBACK_ACE_TYPE:
    case SMB2_SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE:
    {
      v.smb2_get_uint32(0, &ace->mask);

      if (v.len < 4)
      {
        error = FUNC + "not enough data for ace data.";
        delete ace;
        return nullptr;
      }
      v.len -= 4;
      v.buf = &v.buf[4];
      ace->sid = decode_sid(v, error);
      if (ace->sid == nullptr)
      {
        error = FUNC + stringf("Failed to decode sid. ace_type %x - ", ace_type) + error;
        delete ace;
        return nullptr;
      }

      ace->ad_len = v.len;
      ace->ad_data = (char*)malloc(ace->ad_len);
      if (ace->ad_data == NULL)
      {
        error = FUNC + "Failed to allocate ad_data";
        return nullptr;
      }
      memcpy(ace->ad_data, v.buf, v.len);
    }
    break;
    default:
      ace->raw_len = v.len;
      ace->raw_data = (char*)malloc(ace->raw_len);
      if (ace->raw_data == NULL)
      {
        error = FUNC + "Failed to allocate raw_data";
        delete ace;
        return nullptr;
      }
      memcpy(ace->raw_data, v.buf, v.len);
  }

  return ace;
}

static smb2_acl *
decode_acl(smb2_iovec v, string& error)
{
  uint8_t revision = 0;
  uint16_t acl_size = 0, ace_count = 0;
  int i = 0;
  smb2_acl * acl = nullptr;

  if (v.len < 8)
  {
    error = FUNC + "not enough data for acl header";
    return nullptr;
  }

  v.smb2_get_uint8(0, &revision);
  v.smb2_get_uint16(2, &acl_size);
  v.smb2_get_uint16(4, &ace_count);

  switch (revision)
  {
    case SMB2_ACL_REVISION:
    case SMB2_ACL_REVISION_DS:
      break;
    default:
      error = FUNC + stringf("can not decode acl with revision %d", revision);
      return nullptr;
  }
  v.smb2_get_uint16(2, &acl_size);
  if (v.len > acl_size)
  {
    v.len = acl_size;
  }
  if (v.len < acl_size)
  {
    error = FUNC + "not enough data for acl";
    return nullptr;
  }

  acl = new smb2_acl();
  if (!acl)
  {
    error = FUNC + "Failed to allocate acl";
    return nullptr;
  }

  acl->revision  = revision;
  acl->acl_size  = acl_size;
  acl->ace_count = ace_count;

  /* Skip past the ACL header to the first ace. */
  v.len -= 8;
  v.buf = &v.buf[8];

  for (i = 0; i < ace_count; i++)
  {
    smb2_ace *ace = nullptr;
    ace = decode_ace(v, error);
    if (!ace)
    {
      error = FUNC + stringf("Failed to decode ace # %d: %s", i, error.c_str());
      return nullptr;
    }
    /* skip to the next ace */
    if (ace->ace_size > v.len)
    {
      error = FUNC + "not enough data for ace";
      delete ace;
      return nullptr;
    }
    v.len -= ace->ace_size;
    v.buf = &v.buf[ace->ace_size];

    acl->aces.push_back(ace);
  }

  return acl;
}

int
smb2DecodeSecDescInternal(smb2_security_descriptor *sd,
                          smb2_iovec               *vec,
                          string&                  error)
{
  smb2_iovec v;
  uint32_t offset_owner = 0, offset_group = 0, offset_sacl = 0, offset_dacl = 0;

  if (vec->len < 20)
  {
    error = FUNC + stringf("Invalid buffer length for security descriptor %ld", vec->len);
    return -1;
  }

  v.buf = &vec->buf[0];
  v.len = 20;

  v.smb2_get_uint8(0, &sd->revision);
  if (sd->revision != 1)
  {
    error = FUNC + stringf("can't decode security descriptor with revision %d", sd->revision);
    return -1;
  }
  v.smb2_get_uint16(2, &sd->control);

  v.smb2_get_uint32(4, &offset_owner);
  v.smb2_get_uint32(8, &offset_group);
  v.smb2_get_uint32(12, &offset_sacl);
  v.smb2_get_uint32(16, &offset_dacl);

  /* Owner */
  if (offset_owner > 0 && offset_owner + 2 + SID_ID_AUTH_LEN < vec->len)
  {
    v.buf = &vec->buf[offset_owner];
    v.len = vec->len - offset_owner;

    sd->owner = decode_sid(v, error);
    if (sd->owner == nullptr)
    {
      error = FUNC + "Failed to decode owner sid: " + error;
      return -1;
    }
  }

  /* Group */
  if (offset_group > 0 && offset_group + 2 + SID_ID_AUTH_LEN < vec->len)
  {
    v.buf = &vec->buf[offset_group];
    v.len = vec->len - offset_group;

    sd->group = decode_sid(v, error);
    if (sd->group == nullptr)
    {
      error = FUNC + "Failed to decode group sid: " + error;
      return -1;
    }
  }

  /* DACL */
  if (offset_dacl > 0 && offset_dacl + 8 < vec->len)
  {
    v.buf = &vec->buf[offset_dacl];
    v.len = vec->len - offset_dacl;

    sd->dacl = decode_acl(v, error);
    if (sd->dacl == nullptr)
    {
      error = FUNC + "Failed to decode dacl: " + error;
      return -1;
    }
  }

  return 0;
}

int
smb2DecodeSecurityDescriptor(struct smb2_security_descriptor **sd,
                             uint8_t                         *buf,
                             uint32_t                        buf_len,
                             string&                         err)
{
  smb2_iovec vec;
  smb2_security_descriptor* ptr = nullptr;
  vec.buf = buf;
  vec.len = buf_len;

  ptr = new smb2_security_descriptor();
  if (ptr == nullptr)
  {
    err = stringf("%s:Failed to allocate memory for smb2_security_descriptor", __func__);
    return -1;
  }

  string err2;
  if (smb2DecodeSecDescInternal(ptr, &vec, err2))
  {
    err = stringf("smb2DecodeSecDescInternal: Failed - %s", err2.c_str());
    delete ptr;
    return -1;
  }

  *sd = ptr;

  return 0;
}

static int
encode_sid(const smb2_sid *sid,
           uint8_t        *buffer,
           uint32_t        buffer_len,
           uint32_t       *size_used,
           string         &error)
{
  PSID le_sid = NULL;
  uint32_t size_required = 0;
  int i = 0;

  le_sid = (PSID) buffer;

  size_required = sizeof(uint8_t) + sizeof(uint8_t) +
                  (SID_ID_AUTH_LEN * sizeof(uint8_t)) +
                  (sid->sub_auth_count * sizeof(uint32_t));

  if (buffer_len < size_required)
  {
    error = FUNC + "not enough memory to encode SID";
    return -1;
  }

  le_sid->Revision = sid->revision;
  le_sid->SubAuthorityCount = sid->sub_auth_count;
  for (i=0; i < SID_ID_AUTH_LEN; i++)
  {
    le_sid->IdentifierAuthority[i] = sid->id_auth[i];
  }

  for (i=0; i < sid->sub_auth_count; i++)
  {
    le_sid->SubAuthority[i] = htole32(sid->sub_auth[i]);
  }

  *size_used = size_required;

  return 0;
}

#define SMB2_ACE_HDR_SIZE	4
static int
encode_ace(const smb2_ace *ace,
           uint8_t        *buffer,
           uint32_t        buffer_len,
           uint32_t       *size_used,
           string         &error)
{
  uint32_t offset = 0;
  PACE_HEADER le_ace_hdr = NULL;

  if (buffer_len < ace->ace_size)
  {
    error = FUNC + "Not enough buffer to encode ACE";
    return -1;
  }

  le_ace_hdr = (PACE_HEADER) buffer;

  le_ace_hdr->AceType = ace->ace_type;
  le_ace_hdr->AceFlags = ace->ace_flags;
  le_ace_hdr->AceSize = htole16(ace->ace_size);

  switch (ace->ace_type)
  {
    case SMB2_ACCESS_ALLOWED_ACE_TYPE:
    case SMB2_ACCESS_DENIED_ACE_TYPE:
    case SMB2_SYSTEM_AUDIT_ACE_TYPE:
    case SMB2_SYSTEM_MANDATORY_LABEL_ACE_TYPE:
    case SMB2_SYSTEM_SCOPED_POLICY_ID_ACE_TYPE:
    {
      uint32_t sid_size = 0;
      PACCESS_ALLOWED_ACE_HDR le_access_hdr = (PACCESS_ALLOWED_ACE_HDR) buffer;
      le_access_hdr->Mask = htole32(ace->mask);
      offset += sizeof(ACCESS_ALLOWED_ACE_HDR);

      if (encode_sid(ace->sid,
                     le_access_hdr->Sid,
                     buffer_len - offset, /*buffer+offset is same*/
                     &sid_size,
                     error) < 0)
      {
        error = FUNC + stringf("Failed to encode SID/ACE type %x: ", ace->ace_type) + error;
        return -1;
      }
      offset += sid_size;
      sid_size = 0;
    }
    break;
    case SMB2_ACCESS_ALLOWED_OBJECT_ACE_TYPE:
    case SMB2_ACCESS_DENIED_OBJECT_ACE_TYPE:
    case SMB2_SYSTEM_AUDIT_OBJECT_ACE_TYPE:
    {
      uint32_t sid_size = 0;
      int i =0;
      PACCESS_ALLOWED_OBJ_ACE_HDR le_access_obj_hdr = (PACCESS_ALLOWED_OBJ_ACE_HDR) buffer;

      le_access_obj_hdr->Mask = htole32(ace->mask);
      le_access_obj_hdr->Flags = htole32(ace->flags);
      for (i=0; i< SMB2_OBJECT_TYPE_SIZE; i++)
      {
        le_access_obj_hdr->ObjectType[i] = ace->object_type[i];
      }
      for (i=0; i< SMB2_OBJECT_TYPE_SIZE; i++)
      {
        le_access_obj_hdr->InheritedObjectType[i] = ace->inherited_object_type[i];
      }

      offset += sizeof(ACCESS_ALLOWED_OBJ_ACE_HDR);

      if (encode_sid(ace->sid,
                     le_access_obj_hdr->Sid,
                     buffer_len - offset,
                     &sid_size, error) < 0)
      {
        error = FUNC + stringf("Failed to encode SID/ACE type %x : ", ace->ace_type) + error;
        return -1;
      }
      offset += sid_size;
      sid_size = 0;
    }
    break;
    case SMB2_ACCESS_ALLOWED_CALLBACK_ACE_TYPE:
    case SMB2_ACCESS_DENIED_CALLBACK_ACE_TYPE:
    case SMB2_SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE:
    {
      uint32_t sid_size = 0;
      int i =0;
      PACCESS_ALLOWED_CALLBACK_ACE_HDR le_acess_callback_hdr = (PACCESS_ALLOWED_CALLBACK_ACE_HDR) buffer;

      le_acess_callback_hdr->Mask = htole32(ace->mask);

      offset += sizeof(ACCESS_ALLOWED_CALLBACK_ACE_HDR);

      if (encode_sid(ace->sid,
                     le_acess_callback_hdr->Sid,
                     buffer_len - offset,
                     &sid_size, error) < 0)
      {
        error = FUNC + stringf("Failed to encode SID/ACE type %x : ", ace->ace_type) + error;
        return -1;
      }
      offset += sid_size;
      sid_size = 0;

      for (i=0; i < ace->ad_len; i++)
      {
        *(buffer + offset + i) = ace->ad_data[i];
      }
      offset += ace->ad_len;
    }
    break;
    default:
    {
      int i = 0;
      offset += sizeof(ACE_HEADER);

      for (i=0; i < ace->raw_len; i++)
      {
        *(buffer + offset + i) = ace->raw_data[i];
      }
      offset += ace->raw_len;
    }
    break;
  }

  *size_used = offset;

  return 0;
}

#define SMB2_ACL_HDR_SIZE	8
static int
encode_acl(const smb2_acl *acl,
           uint8_t        *buffer,
           uint32_t        buffer_len,
           uint32_t       *size_used,
           string         &error)
{
  PACL_HDR le_acl_hdr = NULL;
  uint32_t acl_size = 0;
  uint32_t offset = 0;

  acl_size = sizeof(ACL_HDR);

  for (smb2_ace *ace : acl->aces)
  {
    acl_size += ace->ace_size;
    if (acl_size < ace->ace_size)
    {
      error = FUNC + "ACL overflow detected";
      return -1;
    }
    if (acl_size > acl->acl_size)
    {
      error = FUNC + "Invalid ACL";
      return -1;
    }
  }

  if (buffer_len < acl_size)
  {
    error = FUNC + "Not enough memory to encode ACL";
    return -1;
  }

  le_acl_hdr = (PACL_HDR) buffer;

  le_acl_hdr->AclRevision = acl->revision;
  le_acl_hdr->Sbz1 = 0;
  le_acl_hdr->AclSize = htole16(acl->acl_size);
  le_acl_hdr->AceCount = htole16(acl->ace_count);
  le_acl_hdr->Sbz2 = 0;

  offset = sizeof(ACL_HDR);

  for (smb2_ace *ace : acl->aces)
  {
    uint32_t ace_size_used = 0;
    if (encode_ace(ace, buffer+offset, buffer_len - offset, &ace_size_used, error) < 0)
    {
      error = FUNC + "Failed to encode ACE : " + error;
      return -1;
    }

    offset += ace_size_used; /* should this be ace->ace_size ?? */
    ace_size_used= 0;
  }

  *size_used = offset;

  return 0;
}

#define SMB2_SEC_DESC_HDR_SIZE	20
int
smb2EncodeSecurityDescriptor(smb2_security_descriptor *sd,
                             uint8_t                  *buffer,
                             uint32_t                 *buffer_len,
                             string                   &error)
{
  uint32_t size = 0;
  uint32_t offset = 0;
  PSECURITY_DESCRIPTOR_RELATIVE_HDR le_sec_desc = NULL;

  if (buffer == NULL || buffer_len == NULL)
  {
    error = FUNC + "Buffer not allocated for security descriptor";
    return -1;
  }

  size = *buffer_len;
  if (size < smb2_get_security_descriptor_size(sd))
  {
    error = FUNC + "Buffer too small to encode security descriptor";
    return -9; /* it represents buffer is insufficient */
  }

  le_sec_desc = (PSECURITY_DESCRIPTOR_RELATIVE_HDR) buffer;
  le_sec_desc->Revision = sd->revision;
  le_sec_desc->Sbz1     = 0;
  le_sec_desc->Control  = htole16(sd->control);

  /* default offset to 0 */
  le_sec_desc->OffsetOwner = htole32(0);
  le_sec_desc->OffsetGroup = htole32(0);
  le_sec_desc->OffsetSacl  = htole32(0);
  le_sec_desc->OffsetDacl  = htole32(0);

  offset += (5 * sizeof(uint32_t));

  if (sd->owner)
  {
    uint32_t size_used = 0;
    if (encode_sid(sd->owner, buffer+offset, size - offset, &size_used, error) < 0)
    {
      error = FUNC + "Failed to encode owner SID : " + error;
      return -1;
    }
    le_sec_desc->OffsetOwner = htole32(offset);
    offset += size_used;
  }
  if (sd->group)
  {
    uint32_t size_used = 0;
    if (encode_sid(sd->group, buffer+offset, size - offset, &size_used, error) < 0)
    {
      error = FUNC + "Failed to encode group SID : " + error;
      return -1;
    }
    le_sec_desc->OffsetGroup = htole32(offset);
    offset += size_used;
  }
  if (sd->dacl)
  {
    uint32_t size_used = 0;
    if (encode_acl(sd->dacl, buffer+offset, size - offset, &size_used, error) < 0)
    {
      error = FUNC + "Failed to encode DACL : " + error;
      return -1;
    }
    le_sec_desc->OffsetDacl = htole32(offset);
    offset += size_used;
  }

  *buffer_len = offset;

  return 0;
}

void
smb2FreeSecurityDescriptor(smb2_security_descriptor *sd)
{
  if (sd)
    delete sd;
}

static void
print_sid(smb2_sid *sid)
{
  int i;
  uint64_t ia = 0;

  printf("S-1");
  for (i = 0; i < SID_ID_AUTH_LEN; i++)
  {
    ia <<= 8;
    ia |= sid->id_auth[i];
  }
  if (ia <= 0xffffffff)
  {
    printf("-%" PRIu64, ia);
  }
  else
  {
    printf("-0x%012" PRIx64, ia);
  }
  for (i = 0; i < sid->sub_auth_count; i++)
  {
    printf("-%u", sid->sub_auth[i]);
  }
}

static void
print_ace(smb2_ace *ace)
{
  printf("ACE: ");
  printf("Type:%d ", ace->ace_type);
  printf("Flags:0x%02x ", ace->ace_flags);
  switch (ace->ace_type)
  {
    case SMB2_ACCESS_ALLOWED_ACE_TYPE:
    case SMB2_ACCESS_DENIED_ACE_TYPE:
    case SMB2_SYSTEM_AUDIT_ACE_TYPE:
    case SMB2_SYSTEM_MANDATORY_LABEL_ACE_TYPE:
      printf("Mask:0x%08x ", ace->mask);
      print_sid(ace->sid);
    break;
    default:
      printf("can't print this type");
  }
  printf("\n");
}

static void
print_acl(smb2_acl *acl)
{
  printf("Revision: %d\n", acl->revision);
  printf("Ace count: %d\n", acl->ace_count);
  for (smb2_ace *ace : acl->aces)
  {
    print_ace(ace);
  }
};

void
printSecurityDescriptor(smb2_security_descriptor *sd)
{
        printf("=============================================\n");
        printf("Revision: %d\n", sd->revision);
        printf("Control: (0x%08x) ", sd->control);
        if (sd->control & SMB2_SD_CONTROL_SR) {
                printf("SR ");
        }
        if (sd->control & SMB2_SD_CONTROL_RM) {
                printf("RM ");
        }
        if (sd->control & SMB2_SD_CONTROL_PS) {
                printf("PS ");
        }
        if (sd->control & SMB2_SD_CONTROL_PD) {
                printf("PD ");
        }
        if (sd->control & SMB2_SD_CONTROL_SI) {
                printf("SI ");
        }
        if (sd->control & SMB2_SD_CONTROL_DI) {
                printf("DI ");
        }
        if (sd->control & SMB2_SD_CONTROL_SC) {
                printf("SC ");
        }
        if (sd->control & SMB2_SD_CONTROL_DC) {
                printf("DC ");
        }
        if (sd->control & SMB2_SD_CONTROL_DT) {
                printf("DT ");
        }
        if (sd->control & SMB2_SD_CONTROL_SS) {
                printf("SS ");
        }
        if (sd->control & SMB2_SD_CONTROL_SD) {
                printf("SD ");
        }
        if (sd->control & SMB2_SD_CONTROL_SP) {
                printf("SP ");
        }
        if (sd->control & SMB2_SD_CONTROL_DD) {
                printf("DD ");
        }
        if (sd->control & SMB2_SD_CONTROL_DP) {
                printf("DP ");
        }
        if (sd->control & SMB2_SD_CONTROL_GD) {
                printf("GD ");
        }
        if (sd->control & SMB2_SD_CONTROL_OD) {
                printf("OD ");
        }
        printf("\n");

        if (sd->owner) {
                printf("Owner SID: ");
                print_sid(sd->owner);
                printf("\n");
        }
        if (sd->group) {
                printf("Group SID: ");
                print_sid(sd->group);
                printf("\n");
        }
        if (sd->dacl) {
                printf("DACL:\n");
                print_acl(sd->dacl);
        }
        printf("=============================================\n");
}
