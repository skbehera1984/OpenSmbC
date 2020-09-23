#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifndef _DCERPC_H_
#define _DCERPC_H_

#include <string>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "DataTypes.h"
#include "PrivateData.h"
#include "Endian.h"

/* MACRO definitions */
#define RPC_BYTE_ORDER_LE			0x10
#define RPC_BYTE_ORDER_BE			0x01

#define RPC_PACKET_TYPE_REQUEST		0x00
#define RPC_PACKET_TYPE_RESPONSE	0x02
#define RPC_PACKET_TYPE_FAULT		0x03
#define RPC_PACKET_TYPE_BIND		0x0b
#define RPC_PACKET_TYPE_BINDACK		0x0c
#define RPC_PACKET_TYPE_BINDNACK	0x0d
#define RPC_PACKET_TYPE_ALTCONT		0x0e
#define RPC_PACKET_TYPE_AUTH3		0x0f
#define RPC_PACKET_TYPE_BINDCONT	0x10

#define RPC_FLAG_FIRST_FRAG			0x01
#define RPC_FLAG_LAST_FRAG			0x02
#define RPC_FLAG_CANCEL_PENDING		0x04
#define RPC_FLAG_RESERVED			0x08
#define RPC_FLAG_MULTIPLEX			0x10
#define RPC_FLAG_DID_NOT_EXECUTE	0x20
#define RPC_FLAG_MAYBE				0x40
#define RPC_FLAG_OBJECT				0x80


#define RPC_CHAR_ENCODING_ASCII		0x00
#define RPC_FLOAT_ENCODING_IEEE		0x00

/* Structs */
struct rpc_data_representation
{
        uint8_t byte_order;
		uint8_t char_encoding;
		uint8_t floating_point;
		uint8_t padding;
} __attribute__((packed));

struct rpc_header
{
		uint8_t version_major;       /* Always 5 */
		uint8_t version_minor;       /* Always 0 */
		uint8_t packet_type;
		uint8_t packet_flags;
		struct rpc_data_representation data_rep;

		/* Total size of the header (i.e. 16 bytes plus the following data
		   up to (but not including) the next header. */
		uint16_t frag_length;
		/* Size of the optional authentication (normally zero) */
		uint16_t auth_length;
		/* Incremental sequent numbers. Used to match up responses and requests. */
		uint32_t call_id;
} __attribute__((packed));

#define RPC_REASON_NOT_SPECIFIED			0
#define RPC_REASON_TEMPORARY_CONGESTION		1
#define RPC_REASON_LOCAL_LIMIT_EXCEEDED		2
#define RPC_REASON_CALLED_PADDR_UNKNOWN		3
#define RPC_REASON_BAD_PROTOCOL_VERSION		4
#define RPC_REASON_DEFAULT_CTX_UNSUPPORTED	5
#define RPC_REASON_USER_DATA_UNREADABLE		6
#define RPC_REASON_NO_PSAP_AVAILABLE		7
#define RPC_REASON_AUTH_TYPE_NOT_RECOGNIZED	8
#define RPC_REASON_INVALID_CHECKSUM			9

struct rpc_bind_request
{
		struct rpc_header dceRpcHdr;
		uint16_t max_xmit_frag;
		uint16_t max_recv_frag;
		uint32_t assoc_group;
		uint8_t num_context_items;
		uint8_t padding[3];
} __attribute__((packed));

struct rpc_bind_response
{
		struct rpc_header dceRpcHdr;
		uint16_t max_xmit_frag;
		uint16_t max_recv_frag;
} __attribute__((packed));


struct rpc_bind_nack_response
{
		struct rpc_header dceRpcHdr;
		uint16_t reject_reason;
} __attribute__((packed));

/* RPC contexts*/
#define SRVSVC_CONTEXT_ID	1
#define SRVSVC_INTERFACE_VERSION_MAJOR	3
#define SRVSVC_INTERFACE_VERSION_MINOR	0

#define TRANSFER_SYNTAX_VERSION_MAJOR	2
#define TRANSFER_SYNTAX_VERSION_MINOR	0

typedef enum _contextType {
    CONTEXT_SRVSVC = 0,
    CONTEXT_LSARPC
} ContextType;

struct context_uuid
{
    uint32_t           a;
    uint16_t           b;
    uint16_t           c;
    uint8_t            d[8];
} __attribute__((packed));

union uuid {
	uint8_t id[16];
	struct context_uuid s_id;
};

struct context_item
{
		uint16_t  context_id;
		uint16_t  num_trans_items;
		uint8_t   interface_uuid[16];
		uint16_t  interface_version_major;
		uint16_t  interface_version_minor;
		uint8_t   transfer_syntax[16];
		uint16_t  syntax_version_major;
		uint16_t  syntax_version_minor;
} __attribute__((packed));

/* APIs */
void dcerpc_init_context(struct context_item* ctx, ContextType type);

void
dcerpc_create_bind_req(struct rpc_bind_request *bnd,
                       int num_context_items);
int
dcerpc_get_response_header(uint8_t *buf,
                           uint32_t buf_len,
                           struct rpc_header *dceRpcHdr);
int
dcerpc_get_bind_ack_response(uint8_t *buf,
                             uint32_t buf_len,
                             struct rpc_bind_response *rsp);

int
dcerpc_get_bind_nack_response(uint8_t *buf,
                              uint32_t buf_len,
                              struct rpc_bind_nack_response *rsp);

const char *
dcerpc_get_reject_reason(uint16_t reason);

typedef enum _DceRpcOpType {
        DCE_OP_CLOSE_POLICY = 0,
        DCE_OP_LOOKUP_NAMES = 14,
        DCE_OP_SHARE_ENUM   = 15,
        DCE_OP_OPEN_POLICY2 = 44
} DceRpcOpType;

struct DceRpcOperationRequest
{
        struct rpc_header dceRpcHdr;
        uint32_t alloc_hint;
        uint16_t context_id;
        uint16_t opnum;
} __attribute__((packed));

struct DceRpcOperationResponse
{
        struct rpc_header dceRpcHdr;
        /* in the response alloc_hint can be more than
           frag_length, and we receive only one frag data and the
           flag LAST_FRAG is not set.
         */
        uint32_t alloc_hint;
        uint16_t context_id;
        uint8_t cancel_count;
        uint8_t padding;
} __attribute__((packed));

int
dcerpc_create_Operation_Request(struct DceRpcOperationRequest *dceOpReq,
                                uint16_t opnum,
                                uint32_t payload_size);
int
dcerpc_parse_Operation_Response(const uint8_t *buffer,
                                const uint32_t buf_len,
                                struct DceRpcOperationResponse *dceOpRes,
                                uint32_t *status,
                                std::string& err);


/************************ SRVSVC ************************/
struct stringValue
{
        /* Maximum length of this string */
        uint32_t max_length;
        /* Offset to this string relative to (char*)(&length + 1) */
        uint32_t offset;
        /* length of string (including the null terminator) */
        uint32_t length;
} __attribute__((packed));

struct serverName
{
        uint32_t referent_id;
        struct stringValue server;
} __attribute__((packed));

struct ShareInfo1
{
        uint32_t name_referent_id;
        uint32_t type;
        uint32_t remark_referent_id;
} __attribute__((packed));

struct ShareInfo2
{
        uint32_t name_referent_id;
        uint32_t type;
        uint32_t remark_referent_id;
        uint32_t permissions;
        uint32_t max_uses;
        uint32_t current_uses;
        uint32_t path_referent_id;
        uint32_t passwd_referent_id;
}  __attribute__((packed));

struct InfoStruct
{
        uint32_t info_level;
        uint32_t switch_value;
        uint32_t referent_id;
        uint32_t num_entries;
        uint32_t array_referent_id;
} __attribute__((packed));

int
srvsvc_create_NetrShareEnumRequest(std::string& server_name,
                                   uint32_t   shinfo_type,
                                   uint64_t  resumeHandle,
                                   uint8_t   *buffer,
                                   uint32_t  *buffer_len,
                                   std::string& err);

uint32_t
srvsvc_get_NetrShareEnum_status(const uint8_t *buffer,
                                const uint32_t buf_len);

int
srvsvc_parse_NetrShareEnumResponse(const uint8_t *buffer,
                                   const uint32_t buf_len,
                                   uint32_t *num_entries,
                                   uint32_t *total_entries,
                                   uint32_t *resumeHandlePtr,
                                   uint32_t *resumeHandle,
                                   smb2_shares& shares,
                                   std::string& err);

/************************ LSARPC ************************/
#define LSARPC_CONTEXT_ID	0
#define LSARPC_INTERFACE_VERSION_MAJOR	0
#define LSARPC_INTERFACE_VERSION_MINOR	0

typedef struct _ObjectAttributes {
        uint32_t m_length;
        uint32_t m_lsPtr;
        uint32_t m_namePtr;
        uint32_t m_attributes;
        uint32_t m_securityDescriptorPtr;
        uint32_t m_qualityOfServicePtr;
} __attribute__((packed)) ObjectAttributes;

typedef struct _PolicyHandle {
        uint32_t ContextType;
        union uuid ContextUuid;
} __attribute__((packed)) PolicyHandle;

/* Policy rights */
#define RIGHT_TO_LOOKUP_NAMES	0x00000800

/* used for LookUpNames Req */
typedef struct _Names {
    uint32_t   MaxCount;
    // padding if required
    uint16_t   Length; //ucs length
    uint16_t   MaximumLength; //same as Length
    uint32_t   ReferentId;
    // StringDef of name
} Names;

typedef struct _TranslatedSids {
    uint32_t    Entries;
    uint32_t    SidsPtr;
} TranslatedSids;

int
lsarpc_create_OpenPolicy2Req(std::string& server_name,
                             uint32_t    access_mask,
                             uint8_t    *buffer,
                             uint32_t    buffer_len,
                             uint32_t   *used,
                             std::string& err);

int
lsarpc_parse_OpenPolicy2Res(uint8_t *buffer,
                            uint32_t bufLen,
                            PolicyHandle *handle,
                            uint32_t *status);

int
lsarpc_create_ClosePolicy2eq(PolicyHandle *handle,
                             uint8_t    *buffer,
                             uint32_t    buffer_len,
                             uint32_t   *used);

int
lsarpc_create_LookUpNamesReq(PolicyHandle *handle,
                             std::string& user,
                             std::string& domain,
                             uint8_t      *buffer,
                             uint32_t      buffer_len,
                             uint32_t     *used,
                             std::string&  err);

uint32_t
lsarpc_get_LookupNames_status(uint8_t             *buffer,
                              uint32_t             buffer_len);

int
lsarpc_parse_LookupNamesRes(uint8_t             *buffer,
                            uint32_t             buffer_len,
                            uint8_t            **sid,
                            uint32_t            *status,
                            std::string&         err);

#endif /* _DCERPC_H_ */
