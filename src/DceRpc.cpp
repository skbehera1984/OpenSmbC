#include <locale.h>
#include <stdio.h>

#include "smb2.h"
#include "DceRpc.h"
#include "util.h"
#include "Stringf.h"

static uint64_t global_call_id = 1;

#define SRVSVC_UUID_A	0x4b324fc8
#define SRVSVC_UUID_B	0x1670
#define SRVSVC_UUID_C	0x01d3
static const uint8_t SRVSVC_UUID_D[] = { 0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88 };

#define	LSARPC_UUID_A	0x12345778
#define	LSARPC_UUID_B	0x1234
#define	LSARPC_UUID_C	0xabcd
static const uint8_t LSARPC_UUID_D[] = {0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab};

#define TRANSFER_SYNTAX_NDR_UUID_A	0x8a885d04
#define TRANSFER_SYNTAX_NDR_UUID_B	0x1ceb
#define TRANSFER_SYNTAX_NDR_UUID_C	0x11c9
static const uint8_t TRANSFER_SYNTAX_NDR_UUID_D[] = { 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60 };

#define FUNC stringf("%s: ", __func__)

uint8_t
get_byte_order_dr(struct rpc_data_representation data)
{
  return data.byte_order;
}

uint8_t
get_byte_order_hdr(struct rpc_header hdr)
{
  return hdr.data_rep.byte_order;
}

static void
set_context_uuid(struct context_uuid *ctx,
                 uint32_t a,
                 uint16_t b,
                 uint16_t c,
                 const uint8_t d[8]
                )
{
  unsigned int i = 0;
  ctx->a = htole32(a);
  ctx->b = htole16(b);
  ctx->c = htole16(c);
  for (i = 0; i < sizeof(ctx->d); ++i)
  {
    (ctx->d)[i] = d[i];
  }
}

static void
init_rpc_data_representation(struct rpc_data_representation *data)
{
  data->byte_order     = RPC_BYTE_ORDER_LE;
  data->char_encoding  = RPC_CHAR_ENCODING_ASCII;
  data->floating_point = RPC_FLOAT_ENCODING_IEEE;
  data->padding        = 0x00;
}

static void
init_rpc_header(struct rpc_header *hdr)
{
  hdr->version_major = 5;
  hdr->version_minor = 0;
  hdr->packet_type = 0;
  hdr->packet_flags = 0;
  init_rpc_data_representation(&(hdr->data_rep));
  hdr->frag_length = 0;
  hdr->auth_length = 0;
  hdr->call_id = 0;
}

static void
init_rpc_bind_request(struct rpc_bind_request *bnd)
{
  /* Constant values from ethereal. */
  init_rpc_header(&(bnd->dceRpcHdr));
  bnd->max_xmit_frag = 32 * 1024; /* was 4280 */
  bnd->max_recv_frag = 32 * 1024; /* was 4280 */
  bnd->assoc_group = 0;
  bnd->num_context_items = 0;
  memset(bnd->padding, 0, sizeof(bnd->padding));
}

void dcerpc_init_context(struct context_item* ctx, ContextType type)
{
  union uuid syntax_id;

  ctx->num_trans_items = htole16(1);

  if (type == CONTEXT_SRVSVC)
  {
    union uuid srvsvc_id;

    ctx->context_id = htole16(SRVSVC_CONTEXT_ID);

    set_context_uuid(&srvsvc_id.s_id,
                     SRVSVC_UUID_A,
                     SRVSVC_UUID_B,
                     SRVSVC_UUID_C,
                     SRVSVC_UUID_D);
    memcpy(&(ctx->interface_uuid), &(srvsvc_id.id), 16);
    ctx->interface_version_major = htole16(SRVSVC_INTERFACE_VERSION_MAJOR);
    ctx->interface_version_minor = htole16(SRVSVC_INTERFACE_VERSION_MINOR);
  }
  else if (type == CONTEXT_LSARPC)
  {
    union uuid lsarpc_id;

    ctx->context_id = htole16(LSARPC_CONTEXT_ID);

    set_context_uuid(&lsarpc_id.s_id,
                     LSARPC_UUID_A,
                     LSARPC_UUID_B,
                     LSARPC_UUID_C,
                     LSARPC_UUID_D);
    memcpy(&(ctx->interface_uuid), &(lsarpc_id.id), 16);
    ctx->interface_version_major = htole16(LSARPC_INTERFACE_VERSION_MAJOR);
    ctx->interface_version_minor = htole16(LSARPC_INTERFACE_VERSION_MINOR);
  }

  set_context_uuid(&syntax_id.s_id,
                   TRANSFER_SYNTAX_NDR_UUID_A,
                   TRANSFER_SYNTAX_NDR_UUID_B,
                   TRANSFER_SYNTAX_NDR_UUID_C,
                   TRANSFER_SYNTAX_NDR_UUID_D);
  memcpy(&(ctx->transfer_syntax), &(syntax_id.id), 16);
  ctx->syntax_version_major = htole16(TRANSFER_SYNTAX_VERSION_MAJOR);
  ctx->syntax_version_minor = htole16(TRANSFER_SYNTAX_VERSION_MINOR);
}

void dcerpc_create_bind_req(struct rpc_bind_request *bnd, int num_context_items)
{
  init_rpc_bind_request(bnd);
  bnd->dceRpcHdr.packet_type = RPC_PACKET_TYPE_BIND;
  bnd->dceRpcHdr.packet_flags = RPC_FLAG_FIRST_FRAG | RPC_FLAG_LAST_FRAG;
  bnd->dceRpcHdr.frag_length = sizeof(struct rpc_bind_request) +
                                     (num_context_items * sizeof(struct context_item));
  bnd->dceRpcHdr.call_id = global_call_id++;
  bnd->num_context_items = num_context_items; /* atleast one context */
}

bool
dcerpc_get_response_header(uint8_t *buf,
                           uint32_t buf_len,
                           struct rpc_header *hdr)
{
  if (buf == NULL|| hdr == NULL)
    return false;

  if (buf_len < sizeof(struct rpc_header))
    return false;

  memcpy(hdr, buf, sizeof(struct rpc_header));
  return true;
}

bool
dcerpc_get_bind_ack_response(uint8_t *buf, uint32_t buf_len,
                             struct rpc_bind_response *rsp)
{
  if (buf == NULL|| rsp == NULL)
    return false;

  if (buf_len < sizeof(struct rpc_bind_response))
    return false;

  memcpy(rsp, buf, sizeof(struct rpc_bind_response));
  return true;
}

bool
dcerpc_get_bind_nack_response(uint8_t *buf,
                              uint32_t buf_len,
                              struct rpc_bind_nack_response *rsp)
{
  if (buf == NULL|| rsp == NULL)
    return false;

  if (buf_len < sizeof(struct rpc_bind_nack_response))
    return false;

  memcpy(rsp, buf, sizeof(struct rpc_bind_nack_response));
  return true;
}

static void
dcerpc_init_Operation_Request(struct DceRpcOperationRequest *dceOpReq, uint16_t opnum)
{
  init_rpc_header(&(dceOpReq->dceRpcHdr));
  dceOpReq->alloc_hint = 0;

  if (opnum == DCE_OP_SHARE_ENUM)
  {
    dceOpReq->context_id = 1;
  }
  else if (opnum == DCE_OP_CLOSE_POLICY)
  {
    dceOpReq->context_id = 0;
  }
  else
  {
    dceOpReq->context_id = 0;
  }
  dceOpReq->opnum = htole16(opnum);
}

void
dcerpc_create_Operation_Request(struct DceRpcOperationRequest *dceOpReq,
                                uint16_t opnum,
                                uint32_t payload_size)
{
  dcerpc_init_Operation_Request(dceOpReq, opnum);
  dceOpReq->dceRpcHdr.packet_type  = RPC_PACKET_TYPE_REQUEST;
  dceOpReq->dceRpcHdr.packet_flags = RPC_FLAG_FIRST_FRAG | RPC_FLAG_LAST_FRAG;
  dceOpReq->dceRpcHdr.frag_length  =  sizeof(struct DceRpcOperationRequest) + payload_size;
  dceOpReq->dceRpcHdr.call_id      =  global_call_id++;
  dceOpReq->alloc_hint             =  payload_size;/* some add 2 more bytes ?*/
}

int
dcerpc_parse_Operation_Response(const uint8_t *buffer,
                                const uint32_t buf_len,
                                struct DceRpcOperationResponse *dceOpRes,
                                uint32_t      *status,
                                std::string&   error)
{
  struct DceRpcOperationResponse *inrep = NULL;

  if (buf_len < sizeof(struct DceRpcOperationResponse))
  {
    error = FUNC + "Response too small for DceRpcOperationResponse";
    return -1;
  }

  inrep = (struct DceRpcOperationResponse *)buffer;

  dceOpRes->alloc_hint   = le32toh(inrep->alloc_hint);
  dceOpRes->context_id   = le16toh(inrep->context_id);
  dceOpRes->cancel_count = inrep->cancel_count;
  dceOpRes->padding      = inrep->padding;

  dceOpRes->dceRpcHdr.version_major = inrep->dceRpcHdr.version_major;
  dceOpRes->dceRpcHdr.version_minor = inrep->dceRpcHdr.version_minor;
  dceOpRes->dceRpcHdr.packet_type   = inrep->dceRpcHdr.packet_type;
  dceOpRes->dceRpcHdr.packet_flags  = inrep->dceRpcHdr.packet_flags;
  dceOpRes->dceRpcHdr.frag_length   = le16toh(inrep->dceRpcHdr.frag_length);
  dceOpRes->dceRpcHdr.auth_length   = le16toh(inrep->dceRpcHdr.auth_length);
  dceOpRes->dceRpcHdr.call_id       = le32toh(inrep->dceRpcHdr.call_id);

  dceOpRes->dceRpcHdr.data_rep      = inrep->dceRpcHdr.data_rep;

  if ((buf_len - sizeof(struct DceRpcOperationResponse)) <= 8)
  {
    /* the OP failed */
    uint32_t *stsptr = (uint32_t*)(buffer+sizeof(struct DceRpcOperationResponse));
    if (status)
    {
      *status = le32toh(*stsptr);
      error = FUNC + stringf("Got Error Response, status - %x", *status);
    }
    return -1;
  }

  return 0;
}

const char *
dcerpc_get_reject_reason(uint16_t reason)
{
  switch (reason)
  {
    case RPC_REASON_NOT_SPECIFIED:
      return "Reason not specified";
    case RPC_REASON_TEMPORARY_CONGESTION:
      return "Temporary congestion";
    case RPC_REASON_LOCAL_LIMIT_EXCEEDED:
      return "Local limit exceeded";
    case RPC_REASON_CALLED_PADDR_UNKNOWN:
      return "Called paddr unknown";
    case RPC_REASON_BAD_PROTOCOL_VERSION:
      return "Protocol version not supported";
    case RPC_REASON_DEFAULT_CTX_UNSUPPORTED:
      return "Default context not supported";
    case RPC_REASON_USER_DATA_UNREADABLE:
      return "User data not readable";
    case RPC_REASON_NO_PSAP_AVAILABLE:
      return "No PSAP available";
    case RPC_REASON_AUTH_TYPE_NOT_RECOGNIZED:
      return "Authentication type not recognized";
    case RPC_REASON_INVALID_CHECKSUM:
      return "Invalid checksum";
    default: break;
  }
  return "UNKNOWN Reject Reason";
}

/******************************** SRVSVC ********************************/
static int
dcerpc_init_stringValue(std::string&    String,
                        int             bTerminateNull,
                        uint8_t        *buf,
                        uint32_t        buf_len,
                        uint32_t       *buf_used,
                        std::string&    err)
{
        struct ucs2 *name = NULL;
        struct   stringValue *stringVal = NULL;
        uint32_t size_required = 0;
        uint32_t offset = 0;
        uint32_t len = 0;

        if (bTerminateNull) {
                /* For NetrShareEnum we need the terminating null */
                len = String.length()+1;
        } else {
                /* For LsaLookupNames we don't need the terminating null */
                len = String.length();
        }

        size_required = sizeof(struct stringValue) + len*2;

        name = utf8_to_ucs2(String.c_str());
        if (name == NULL) {
                err = std::string("dcerpc_init_stringValue: failed to convert server name to ucs2");
                return -1;
        }

        if (buf_len < size_required) {
                free(name);
                err = std::string("dcerpc_init_stringValue: buffer too small");
                return -1;
        }

        stringVal = (struct stringValue *)buf;

        stringVal->max_length  = htole32(len);
        stringVal->offset      = 0;
        stringVal->length      = stringVal->max_length;
        offset += sizeof(struct stringValue);

        memcpy(buf+offset, &name->val[0], 2 * name->len);

        free(name);

        *buf_used = size_required;

        return 0;
}

static int
dcerpc_init_serverName(uint32_t        refid,
                       std::string&    name,
                       uint8_t        *buf,
                       uint32_t        buf_len,
                       uint32_t       *buf_used,
                       std::string    &err)
{
        struct serverName *srv = NULL;
        uint32_t offset = 0;
        uint32_t size_name = 0;

        srv = (struct serverName *)buf;

        srv->referent_id = htole32(refid);
        offset += sizeof(uint32_t);

        if (dcerpc_init_stringValue(name, 1,
                                    buf+offset, buf_len - offset,
                                    &size_name, err) < 0) {
                return -1;
        }
        offset += size_name;

        *buf_used = offset;

        return 0;
}

static void
srvsvc_init_InfoStruct(uint32_t infolevel, uint32_t id,
                       uint32_t entries, uint32_t arrayId,
                       uint8_t *buffer, uint32_t buf_len)
{
  struct InfoStruct *info = NULL;

  info = (struct InfoStruct *)buffer;

  info->info_level   = htole32(infolevel);
  info->switch_value = info->info_level;
  info->referent_id  = htole32(id);
  info->num_entries  = htole32(entries);
  info->array_referent_id = htole32(arrayId);
}

int
srvsvc_create_NetrShareEnumRequest(std::string& server_name,
                                   uint32_t   shinfo_type,
                                   uint64_t   resumeHandle,
                                   uint8_t    *buffer,
                                   uint32_t   *buffer_len,
                                   std::string& err)
{
        uint32_t  buf_len = 0;
        uint32_t  offset = 0;
        uint32_t  size_used = 0;
        uint32_t  padlen = 0;
        uint32_t  *PreferedMaximumLength = NULL;
        uint32_t  preferred_max_length = 0xffffffff;
        uint32_t  *ResumeHandle = NULL;

        buf_len = *buffer_len;

        if (dcerpc_init_serverName(0x0026e53c, server_name,
                                   buffer, buf_len, &size_used, err) < 0) {
                return -1;
        }

        offset += size_used;

        /* padding of 0 or more bytes are needed after the name buf */
        if ((size_used & 0x03) != 0) {
                padlen = 4 - (size_used & 0x03);
                offset += padlen;
        }

        srvsvc_init_InfoStruct(shinfo_type, 0x01fbf3e8, 0, 0, buffer+offset, buf_len - offset);

        offset += sizeof(struct InfoStruct);

        PreferedMaximumLength = (uint32_t *)(buffer+offset);
        *PreferedMaximumLength = htole32(preferred_max_length);
        offset += sizeof(uint32_t);

        ResumeHandle = (uint32_t *) (buffer+offset);
        *ResumeHandle = htole32(resumeHandle);
        offset += sizeof(uint32_t);

        *buffer_len = offset;

        return 0;
}

uint32_t
srvsvc_get_NetrShareEnum_status(const uint8_t *buffer, const uint32_t buf_len)
{
  uint32_t sts = 0;

  uint32_t *pstatus = (uint32_t *) (buffer +(buf_len - 4));
  sts = le32toh(*pstatus);

  return sts;
}

static int
srvsvc_parse_NetrShareEnum_InfoStruct(const uint8_t *buffer,
                                      const uint32_t buf_len,
                                      struct InfoStruct *info,
                                      std::string &err)
{
        struct InfoStruct *rsp_info = NULL;

        if (buf_len < sizeof(struct InfoStruct)) {
                err = std::string("srvsvc_parse_NetrShareEnum_InfoStruct:response too small for InfoStruct");
                return -1;
        }

        rsp_info = (struct InfoStruct *)buffer;

        info->info_level = le32toh(rsp_info->info_level);
        info->switch_value = le32toh(rsp_info->switch_value);
        info->referent_id = le32toh(rsp_info->referent_id);
        info->num_entries = le32toh(rsp_info->num_entries);
        info->array_referent_id = le32toh(rsp_info->array_referent_id);

        return 0;
}

static int
srvsvc_parse_NetrShareEnum_buffer(const uint8_t *in_buffer,
                                  uint32_t       in_buffer_len,
                                  uint32_t       buffer_consumed,
                                  const uint32_t share_count,
                                  smb2_shares&   shares,
                                  uint32_t      *total_entries,
                                  uint32_t      *resumeHandlePtr,
                                  uint32_t      *resumeHandle)
{
  const uint8_t *buffer = NULL;
  uint32_t buffer_offset = 0;
  const uint8_t *payload = NULL;
  uint32_t payload_offset = 0;
  uint32_t i = 0;

  shares.share_info_type = 1;

  buffer = in_buffer + buffer_consumed;
  payload = buffer + (share_count * sizeof (struct ShareInfo1));

  for (i = 0; i < share_count; i++)
  {
    struct ShareInfo1 share_info, *infoptr = NULL;
    struct stringValue share_name, *name_ptr = NULL;
    struct stringValue share_remark, *remark_ptr = NULL;
    char *shi_name = NULL;
    char *shi_remark = NULL;
    uint32_t padlen = 0;
    smb2_shareinfo shi01;

    infoptr = (struct ShareInfo1 *) (buffer + buffer_offset);
    share_info.name_referent_id   = le32toh(infoptr->name_referent_id);
    share_info.type               = le32toh(infoptr->type);
    share_info.remark_referent_id = le32toh(infoptr->remark_referent_id);
    buffer_offset += sizeof(struct ShareInfo1);

    /* the payload buffer is 4 byte multiple.
     * while packing each element it is padded if not multiple of 4 byte.
     * the buffer size count starts from the payload.
     */
    padlen = 0;
    if ((payload_offset & 0x03) != 0)
    {
      padlen = 4 - (payload_offset & 0x03);
      payload_offset += padlen;
    }

    name_ptr = (struct stringValue *) (payload + payload_offset);
    share_name.max_length = le32toh(name_ptr->max_length);
    share_name.offset     = le32toh(name_ptr->offset);
    share_name.length     = le32toh(name_ptr->length);
    payload_offset += sizeof(struct stringValue);

    shi_name = ucs2_to_utf8((uint16_t *)(payload+payload_offset), share_name.length);

    payload_offset += (2 * share_name.length);

    padlen = 0;
    if ((payload_offset & 0x03) != 0)
    {
      padlen = 4 - (payload_offset & 0x03);
      payload_offset += padlen;
    }

    remark_ptr = (struct stringValue *) (payload + payload_offset);
    share_remark.max_length = le32toh(remark_ptr->max_length);
    share_remark.offset     = le32toh(remark_ptr->offset);
    share_remark.length     = le32toh(remark_ptr->length);
    payload_offset += sizeof(struct stringValue);

    if (share_remark.length > 1)
    {
      shi_remark = ucs2_to_utf8((uint16_t *)(payload+payload_offset), share_remark.length);
    }
    payload_offset += (2 * share_remark.length);

    /* Fill the details */
    shi01.share_type      = share_info.type;
    if (shi_name)
    {
      shi01.name            = std::string(shi_name);
      free(shi_name);
    }
    if (shi_remark)
    {
      shi01.remark          = std::string(shi_remark);
      free(shi_remark);
    }
    shares.sharelist.push_back(shi01);
  }

  buffer_offset += buffer_consumed + payload_offset;
  if ((buffer_offset & 0x03) != 0)
  {
    uint32_t padlen = 4 - (buffer_offset & 0x03);
    buffer_offset += padlen;
  }

  *total_entries = le32toh(*(uint32_t *)(in_buffer+buffer_offset));
  buffer_offset += sizeof(uint32_t);

  if ( (in_buffer_len - buffer_offset) == 8 )
  {
    *resumeHandlePtr  = le32toh(*(uint32_t *)(in_buffer+buffer_offset));
    buffer_offset += sizeof(uint32_t);
    *resumeHandle  = le32toh(*(uint32_t *)(in_buffer+buffer_offset));
    buffer_offset += sizeof(uint32_t);
  }
  else
  {
    /* pointer to NULL - 4 bytes */
    *resumeHandlePtr  = le32toh(*(uint32_t *)(in_buffer+buffer_offset));
    buffer_offset += sizeof(uint32_t);
    *resumeHandle  = 0;
  }

  return 0;
}

static int
srvsvc_parse_NetrShareEnum_buffer2(const uint8_t *in_buffer,
                                   uint32_t       in_buffer_len,
                                   uint32_t       buffer_consumed,
                                   const uint32_t share_count,
                                   smb2_shares&   shares,
                                   uint32_t      *total_entries,
                                   uint32_t      *resumeHandlePtr,
                                   uint32_t      *resumeHandle)
{
  const uint8_t *buffer = NULL;
  uint32_t buffer_offset = 0;
  const uint8_t *payload = NULL;
  uint32_t payload_offset = 0;
  uint32_t i = 0;

  shares.share_info_type = 2;

  buffer = in_buffer + buffer_consumed;
  payload = buffer + (share_count * sizeof (struct ShareInfo2));

  for (i = 0; i < share_count; i++)
  {
    struct ShareInfo2 share_info, *infoptr = NULL;
    struct stringValue share_name, *name_ptr = NULL;
    struct stringValue share_remark, *remark_ptr = NULL;
    struct stringValue share_path, *path_ptr = NULL;
    struct stringValue share_passwd, *passwd_ptr = NULL;
    char *shi_name = NULL;
    char *shi_remark = NULL;
    char *shi_path = NULL;
    char *shi_passwd = NULL;
    uint32_t padlen = 0;
    smb2_shareinfo shi02;

    infoptr = (struct ShareInfo2 *) (buffer + buffer_offset);
    share_info.name_referent_id   = le32toh(infoptr->name_referent_id);
    share_info.type               = le32toh(infoptr->type);
    share_info.remark_referent_id = le32toh(infoptr->remark_referent_id);
    share_info.permissions        = le32toh(infoptr->permissions);
    share_info.max_uses           = le32toh(infoptr->max_uses);
    share_info.current_uses       = le32toh(infoptr->current_uses);
    share_info.path_referent_id   = le32toh(infoptr->path_referent_id);
    share_info.passwd_referent_id = le32toh(infoptr->passwd_referent_id);
    buffer_offset += sizeof(struct ShareInfo2);

    /* the payload buffer is 4 byte multiple.
     * while packing each element it is padded if not multiple of 4 byte.
     * the buffer size count starts from the payload.
     */
    padlen = 0;
    if ((payload_offset & 0x03) != 0)
    {
      padlen = 4 - (payload_offset & 0x03);
      payload_offset += padlen;
    }

    name_ptr = (struct stringValue *) (payload + payload_offset);
    share_name.max_length = le32toh(name_ptr->max_length);
    share_name.offset     = le32toh(name_ptr->offset);
    share_name.length     = le32toh(name_ptr->length);
    payload_offset += sizeof(struct stringValue);

    shi_name = ucs2_to_utf8((uint16_t *)(payload+payload_offset), share_name.length);

    payload_offset += (2 * share_name.length);

    padlen = 0;
    if ((payload_offset & 0x03) != 0)
    {
      padlen = 4 - (payload_offset & 0x03);
      payload_offset += padlen;
    }

    remark_ptr = (struct stringValue *) (payload + payload_offset);
    share_remark.max_length = le32toh(remark_ptr->max_length);
    share_remark.offset     = le32toh(remark_ptr->offset);
    share_remark.length     = le32toh(remark_ptr->length);
    payload_offset += sizeof(struct stringValue);

    if (share_remark.length > 1)
    {
      shi_remark = ucs2_to_utf8((uint16_t *)(payload+payload_offset), share_remark.length);
    }
    payload_offset += (2 * share_remark.length);

    padlen = 0;
    if ((payload_offset & 0x03) != 0)
    {
      padlen = 4 - (payload_offset & 0x03);
      payload_offset += padlen;
    }

    path_ptr = (struct stringValue *) (payload + payload_offset);
    share_path.max_length = le32toh(path_ptr->max_length);
    share_path.offset     = le32toh(path_ptr->offset);
    share_path.length     = le32toh(path_ptr->length);
    payload_offset += sizeof(struct stringValue);

    if (share_path.length > 1)
    {
      shi_path = ucs2_to_utf8((uint16_t *)(payload+payload_offset), share_path.length);
    }
    payload_offset += (2 * share_path.length);

    padlen = 0;
    if ((payload_offset & 0x03) != 0)
    {
      padlen = 4 - (payload_offset & 0x03);
      payload_offset += padlen;
    }

    if (share_info.passwd_referent_id != 0)
    {
      passwd_ptr = (struct stringValue *) (payload + payload_offset);
      share_passwd.max_length = le32toh(passwd_ptr->max_length);
      share_passwd.offset     = le32toh(passwd_ptr->offset);
      share_passwd.length     = le32toh(passwd_ptr->length);
      payload_offset += sizeof(struct stringValue);

      if (share_passwd.length > 1)
      {
        shi_passwd = ucs2_to_utf8((uint16_t *)(payload+payload_offset), share_passwd.length);
      }
      payload_offset += (2 * share_passwd.length);
    }

    /* Fill the details */
    shi02.share_type      = share_info.type;
    if (shi_name)
    {
      shi02.name            = std::string(shi_name);
      free(shi_name);
    }
    if (shi_remark)
    {
      shi02.remark          = std::string(shi_remark);
      free(shi_remark);
    }
    shi02.permissions     = share_info.permissions;
    shi02.max_uses        = share_info.max_uses;
    shi02.current_uses    = share_info.current_uses;
    if (shi_path)
    {
      shi02.path            = std::string(shi_path);
      free(shi_path);
    }
    if (shi_passwd)
    {
      shi02.password        = std::string(shi_passwd);
      free(shi_passwd);
    }
    shares.sharelist.push_back(shi02);
  }

  buffer_offset += buffer_consumed + payload_offset;
  if ((buffer_offset & 0x03) != 0) {
                uint32_t padlen = 4 - (buffer_offset & 0x03);
                buffer_offset += padlen;
  }

  *total_entries = le32toh(*(uint32_t *)(in_buffer+buffer_offset));
  buffer_offset += sizeof(uint32_t);

  if ( (in_buffer_len - buffer_offset) == 8 )
  {
    *resumeHandlePtr  = le32toh(*(uint32_t *)(in_buffer+buffer_offset));
    buffer_offset += sizeof(uint32_t);
    *resumeHandle  = le32toh(*(uint32_t *)(in_buffer+buffer_offset));
    buffer_offset += sizeof(uint32_t);
  }
  else
  {
    /* pointer to NULL - 4 bytes */
    *resumeHandlePtr  = le32toh(*(uint32_t *)(in_buffer+buffer_offset));
    buffer_offset += sizeof(uint32_t);
    *resumeHandle  = 0;
  }

  return 0;
}

int
srvsvc_parse_NetrShareEnumResponse(const uint8_t *buffer,
                                   const uint32_t buf_len,
                                   uint32_t *num_entries,
                                   uint32_t *total_entries,
                                   uint32_t *resumeHandlePtr,
                                   uint32_t *resumeHandle,
                                   smb2_shares& shares,
                                   std::string& err)
{
        uint32_t offset = 0;
        struct InfoStruct info;

        if (srvsvc_parse_NetrShareEnum_InfoStruct(buffer, buf_len, &info, err) < 0) {
                return -1;
        }

        offset += sizeof(struct InfoStruct);
        offset += sizeof(uint32_t); /* Size - num array elements */

        *num_entries = info.num_entries;

        if (info.info_level == 1) {
                if (srvsvc_parse_NetrShareEnum_buffer(buffer, buf_len,
                                              offset,
                                              info.num_entries,
                                              shares,
                                              total_entries,
                                              resumeHandlePtr,
                                              resumeHandle) < 0) {
                        return -1;
                }
        } else if (info.info_level == 2) {
                if (srvsvc_parse_NetrShareEnum_buffer2(buffer, buf_len,
                                              offset,
                                              info.num_entries,
                                              shares,
                                              total_entries,
                                              resumeHandlePtr,
                                              resumeHandle) < 0) {
                        return -1;
                }
        } else {
                err = stringf("%s: unsupported share info type", __func__);
                return -1;
        }

        return 0;
}

/******************************** LSARPC ********************************/

/* An openPolicy/OpenPolicy2 has the following
   - servername in unicode
   - padding if required
   - ObjectAttributes filled with 0's
   - access mask
 */
int
lsarpc_create_OpenPolicy2Req(std::string& server_name,
                             uint32_t    access_mask,
                             uint8_t    *buffer,
                             uint32_t    buffer_len,
                             uint32_t   *used,
                             std::string& err)
{
    uint32_t  buf_len = 0;
    uint32_t  offset = 0;
    uint32_t  size_used = 0;
    uint32_t  *accessright = NULL;

    buf_len = buffer_len;

    if (dcerpc_init_serverName(0x01414938, server_name,
                               buffer, buf_len, &size_used, err) < 0) {
        return -1;
    }

    offset += size_used;

    /* No padding required after this for lsaOpenPolicy2 opnum 44,
     * but padding will be required for lsaOpenPolicy opnum 6
     */
    if ((offset & 0x03) != 0) {
        uint32_t padlen = 0;
        padlen = 4 - (offset & 0x03);
        offset += padlen; /* padding is required for opnum 44 too */
    }


    /* ObjectAttributes is not used so set them to 0, only set the len to 24 i.e
     * size of ObjectAttributes
     */
    ObjectAttributes *attr = (ObjectAttributes *) (buffer + offset);
    memset(attr, 0, sizeof(ObjectAttributes));
    attr->m_length = htole32(24);
    offset += sizeof(ObjectAttributes);

    accessright = (uint32_t*) (buffer + offset);
    *accessright = htole32(access_mask);
    offset += sizeof(uint32_t);

    *used = offset;

    return 0;
}

int
lsarpc_parse_OpenPolicy2Res(uint8_t      *buffer,
                            uint32_t      bufLen,
                            PolicyHandle *handle,
                            uint32_t     *status)
{
  uint32_t *stsptr = NULL;
  PolicyHandle *inhandle = NULL;

  stsptr = (uint32_t*)(buffer+(bufLen-4));
  *status = le32toh(*stsptr);
  if(*status)
    return -1;

  inhandle = (PolicyHandle *)buffer;
  handle->ContextType = le32toh(inhandle->ContextType);
  handle->ContextUuid.s_id.a = le32toh(inhandle->ContextUuid.s_id.a);
  handle->ContextUuid.s_id.b = le16toh(inhandle->ContextUuid.s_id.b);
  handle->ContextUuid.s_id.c = le16toh(inhandle->ContextUuid.s_id.c);
  memcpy(handle->ContextUuid.s_id.d, inhandle->ContextUuid.s_id.d, 8);

  return 0;
}


int
lsarpc_create_ClosePolicy2eq(PolicyHandle *handle,
                             uint8_t      *buffer,
                             uint32_t      buffer_len,
                             uint32_t     *used)
{
  PolicyHandle *outHandle = (PolicyHandle*)buffer;
  union uuid policyHandle;

  if (buffer_len < sizeof(PolicyHandle))
    return -1;

  set_context_uuid(&policyHandle.s_id,
                   handle->ContextUuid.s_id.a,
                   handle->ContextUuid.s_id.b,
                   handle->ContextUuid.s_id.c,
                   handle->ContextUuid.s_id.d);

  outHandle->ContextType = htole32(handle->ContextType);
  memcpy(outHandle->ContextUuid.id, policyHandle.id, 16);
  *used = sizeof(PolicyHandle);

  return 0;
}

/*
NTSTATUS LsarLookupNames(
   [in] LSAPR_HANDLE PolicyHandle,
   [in, range(0,1000)] unsigned long Count,
   [in, size_is(Count)] PRPC_UNICODE_STRING Names,
   [out] PLSAPR_REFERENCED_DOMAIN_LIST* ReferencedDomains,
   [in, out] PLSAPR_TRANSLATED_SIDS TranslatedSids,
   [in] LSAP_LOOKUP_LEVEL LookupLevel,
   [in, out] unsigned long* MappedCount
 );
*/

int
lsarpc_create_LookUpNamesReq(PolicyHandle *handle,
                             std::string&  user,
                             std::string&  domain,
                             uint8_t      *buffer,
                             uint32_t      buffer_len,
                             uint32_t     *used,
                             std::string&  err)
{
    PolicyHandle *outHandle = (PolicyHandle*)buffer;
    union uuid policyHandle;
    char name[1024] = {0};
    uint32_t nameLen = 0;
    uint32_t offset = 0;
    uint32_t *pUint32 = NULL;
    uint16_t *pUint16 = NULL;

    /* must provide the name as domain\user */
    sprintf(name, "%s\\%s", domain.c_str(), user.c_str());
    std::string nameString = domain + "\\" + user;

    set_context_uuid(&policyHandle.s_id,
                     handle->ContextUuid.s_id.a,
                     handle->ContextUuid.s_id.b,
                     handle->ContextUuid.s_id.c,
                     handle->ContextUuid.s_id.d);

    outHandle->ContextType = htole32(handle->ContextType);
    memcpy(outHandle->ContextUuid.id, policyHandle.id, 16);
    offset += sizeof(PolicyHandle);

    pUint32  = (uint32_t*) (buffer+offset);
    *pUint32 = htole32(1); /* set the size/count of names */
    offset  += sizeof(uint32_t);

    /* Now set the Names Array */
    pUint32  = (uint32_t*) (buffer+offset);
    *pUint32 = htole32(1); /* set the MaxCount of names */
    offset  += sizeof(uint32_t);

    if ((offset & 0x03) != 0) {
        uint32_t padlen = 4 - (offset & 0x03);
        offset += padlen;
    }

    pUint16  = (uint16_t*) (buffer+offset);
    *pUint16 = htole16(strlen(name)*2); /* set the Length of name */
    offset  += sizeof(uint16_t);

    pUint16  = (uint16_t*) (buffer+offset);
    *pUint16 = htole16(strlen(name)*2); /* set the MaximumLength of name */
    offset  += sizeof(uint16_t);

    pUint32  = (uint32_t*) (buffer+offset);
    *pUint32 = htole32(0x0141afb8); /* set the BufferPtr */
    offset  += sizeof(uint32_t);

    //if (dcerpc_init_stringValue(name, 0, buffer+offset,
    if (dcerpc_init_stringValue(nameString, 0, buffer+offset,
                                buffer_len - offset, &nameLen, err) < 0) {
        return -1;
    }
    offset += nameLen;

    if ((offset & 0x03) != 0) {
        uint32_t padlen = 4 - (offset & 0x03);
        offset += padlen;
    }

    pUint32  = (uint32_t*) (buffer+offset);
    *pUint32 = htole32(0); /* set the Entries of TranslatedSids */
    offset  += sizeof(uint32_t);

    pUint32  = (uint32_t*) (buffer+offset);
    *pUint32 = htole32(0); /* set the SidsPtr of TranslatedSids */
    offset  += sizeof(uint32_t);

    pUint16  = (uint16_t*) (buffer+offset);
    *pUint16 = htole16(1); /* set the LookupLevel */
    offset  += sizeof(uint16_t);

    if ((offset & 0x03) != 0) {
        uint32_t padlen = 4 - (offset & 0x03);
        offset += padlen;
    }

    pUint32  = (uint32_t*) (buffer+offset);
    *pUint32 = htole32(0); /* set the MappedCount */
    offset  += sizeof(uint32_t);

    *used = offset;
    return 0;
}

uint32_t
lsarpc_get_LookupNames_status(uint8_t *buffer, uint32_t bufLen)
{
  uint32_t *stsptr = NULL;
  uint32_t status = 0;

  stsptr = (uint32_t*)(buffer+(bufLen-4));
  status = le32toh(*stsptr);

  return status;
}

int
lsarpc_parse_LookupNamesRes(uint8_t             *buffer,
                            uint32_t             bufLen,
                            uint8_t            **sid,
                            uint32_t            *status,
                            std::string&         err)
{
    uint8_t  *sidbuf = NULL;
    struct smb2_sid *mysid = NULL;
    uint32_t *stsptr = NULL;
    uint32_t offset = 0;
    uint32_t numEntries = 0, MaxEntries = 0, MaxCount = 0;
    uint32_t Length = 0, MaxLength = 0;
    uint32_t maxSubAuthCount = 0;
    uint8_t  revision = 0, sub_auth_count = 0;
    uint32_t *pUint32 = NULL;
    uint16_t *pUint16 = NULL;

    uint32_t ridEntries = 0, ridMaxCount = 0, RID = 0, domainIndex = 0;
    uint16_t sidTypeValue = 0;

    stsptr = (uint32_t*)(buffer+(bufLen-4));
    *status = le32toh(*stsptr);
    if(*status) {
        return -1;
    }

    offset += 4; // skip the ReferentID

    pUint32 = (uint32_t*) (buffer+offset);
    numEntries = le32toh(*pUint32);
    offset += sizeof(uint32_t);

    offset += 4; // skip the ReferentID again

    pUint32 = (uint32_t*) (buffer+offset);
    MaxEntries = le32toh(*pUint32);
    offset += sizeof(uint32_t);

    pUint32 = (uint32_t*) (buffer+offset);
    MaxCount = le32toh(*pUint32);
    offset += sizeof(uint32_t);

    if ((offset & 0x03) != 0) {
        uint32_t padlen = 4 - (offset & 0x03);
        offset += padlen;
    }

    pUint16 = (uint16_t*) (buffer+offset);
    Length = le16toh(*pUint16);
    offset += sizeof(uint16_t);

    pUint16 = (uint16_t*) (buffer+offset);
    MaxLength = le16toh(*pUint16);
    offset += sizeof(uint16_t);

    offset += 4; // skip BufferPtr
    offset += 4; // skip SidPtr

    /* may be this block needs to be looped for num of elements MaxCount */
    {
        struct stringValue domainName, *namePtr = NULL;
        //char *domName = NULL;

        namePtr = (struct stringValue *) (buffer+offset);
        domainName.max_length = le32toh(namePtr->max_length);
        domainName.offset     = le32toh(namePtr->offset);
        domainName.length     = le32toh(namePtr->length);
        offset += sizeof(struct stringValue);
        //domName = ucs2_to_utf8((uint16_t *)(buffer+offset), domainName.length);
        offset += (2 * domainName.length);
    }

    if ((offset & 0x03) != 0) {
        uint32_t padlen = 4 - (offset & 0x03);
        offset += padlen;
    }

    /* Now get the SID */
    pUint32 = (uint32_t*) (buffer+offset);
    maxSubAuthCount = le32toh(*pUint32);
    offset += sizeof(uint32_t);

    revision = *(uint8_t*)(buffer+offset);
    offset += 1;
    sub_auth_count = *(uint8_t*)(buffer+offset);
    offset += 1;

    if (maxSubAuthCount != sub_auth_count) {
        err = stringf("%s: Mismatch of sub-auth counts", __func__);
        return -1;
    }

    sidbuf = (uint8_t*)malloc(8+ (sub_auth_count*sizeof(uint32_t)));
    if (sidbuf == NULL) {
        err = stringf("%s: failed to allocate memory for sid", __func__);
        return -1;
    }

    mysid = (struct smb2_sid*)sidbuf;
    mysid->revision = revision;
    mysid->sub_auth_count = sub_auth_count;
    memcpy(mysid->id_auth, buffer+offset, SID_ID_AUTH_LEN);
    offset += SID_ID_AUTH_LEN;

    if ((offset & 0x03) != 0) {
        uint32_t padlen = 4 - (offset & 0x03);
        offset += padlen;
    }

    /* copy the sub-authorities */
    int i = 0; uint32_t localOffset = offset;
    uint32_t *subAuth  = (uint32_t*)(sidbuf+8);
    for (; i< sub_auth_count; i++) {
        pUint32 = (uint32_t*) (buffer+localOffset);
        subAuth[i] = le32toh(*pUint32);
        localOffset += sizeof(uint32_t);
    }
    offset += sub_auth_count*sizeof(uint32_t);

    if ((offset & 0x03) != 0) {
        uint32_t padlen = 4 - (offset & 0x03);
        offset += padlen;
    }

    /* get the RID here and append them to subAuth incrementing the sub_auth_count */
    pUint32 = (uint32_t*)(buffer+offset);
    ridEntries = le32toh(*pUint32);
    offset += sizeof(uint32_t);
    offset += sizeof(uint32_t); /* skip the SidsPtr */

    pUint32 = (uint32_t*)(buffer+offset);
    ridMaxCount = le32toh(*pUint32);
    offset += sizeof(uint32_t);

    pUint16 = (uint16_t*)(buffer+offset);
    sidTypeValue = le16toh(*pUint16);
    offset += sizeof(uint16_t);

    if ((offset & 0x03) != 0) {
        uint32_t padlen = 4 - (offset & 0x03);
        offset += padlen;
    }

    pUint32 = (uint32_t*)(buffer+offset);
    RID = le32toh(*pUint32);
    offset += sizeof(uint32_t);

    pUint32 = (uint32_t*)(buffer+offset);
    domainIndex = le32toh(*pUint32);
    offset += sizeof(uint32_t);

    uint8_t old_sub_auth_count = sub_auth_count;
    sub_auth_count += ridEntries;
    sidbuf = (uint8_t*)realloc(sidbuf, 8+(sub_auth_count*sizeof(uint32_t)));
    if (sidbuf == NULL) {
        err = stringf("%s: failed to allocate2 memory for sid", __func__);
        return -1;
    }

    mysid = (struct smb2_sid*)sidbuf;
    mysid->revision = revision;
    mysid->sub_auth_count = sub_auth_count;
    /* get the place to copy the rid */
    uint32_t *prid = (uint32_t *)(sidbuf+(8+(old_sub_auth_count*sizeof(uint32_t))));
    *prid = RID;

    /* to avoid build failure */
    numEntries = numEntries; MaxEntries = MaxEntries; MaxCount = MaxCount;
    Length = Length; MaxLength = MaxLength;
    sidTypeValue = sidTypeValue; ridMaxCount = ridMaxCount; domainIndex = domainIndex;

    *sid = sidbuf;
    return 0;
}
