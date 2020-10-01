#ifndef _SMB2_PDU_H
#define _SMB2_PDU_H

#include <stdint.h>
#include <string>
#include "util.h"
#include "smb2.h"
#include "AppData.h"
#include "Stringf.h"
#include "PrivateData.h"

#ifdef HAVE_OPENSSL_LIBS

#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/opensslv.h>

#define OPENSSL_VER_101 0x1000109fL
#define OPENSSL_VER_102 0x10002100L

#endif

class Smb2Pdu;

class Smb2Pdu
{
public:
  Smb2Pdu();
  Smb2Pdu(Smb2ContextPtr    smb2,
          enum smb2_command command,
          AppData           *appData);
  virtual ~Smb2Pdu();

  void     setResponseHeader(struct smb2_header *rhdr);
  uint32_t getReqNBLength();
  uint32_t getReqCreditCharge();
  smb2_io_vectors getAllComOutVecs();

  void encodeHeader(Smb2ContextPtr smb2);
  static int decodeHeader(smb2_iovec         *iov,
                          struct smb2_header *hdr,
                          std::string&        err);

  void smb2AddCompoundPdu(Smb2Pdu *next_pdu);

  // the following are specific to each command
  virtual int encodeRequest(Smb2ContextPtr smb2, void *req) = 0;
  int         smb2ReplyGetFixedSize();
  virtual int smb2ReplyProcessFixed(Smb2ContextPtr smb2) = 0;
  virtual int smb2ReplyProcessVariable(Smb2ContextPtr smb2) = 0;
  virtual int smb2ProcessReplyAndAppData(Smb2ContextPtr smb2) = 0;

protected:
  int smb2UpdatePreauthIntegrityHash(Smb2ContextPtr  smb2,
                                     smb2_io_vectors *iovs,
                                     std::string     &error);
  bool smb2ReplyIsError();
  int  smb2ProcessErrorReplyFixed(Smb2ContextPtr smb2);
  int  smb2ProcessErrorReplyVariable(Smb2ContextPtr smb2);

public:
  /********** REQUEST PART ***********/
  struct smb2_header header;
  /* buffer to avoid having to malloc the headers */
  uint8_t hdr[SMB2_HEADER_SIZE];
  // io vectors for the packet we are writing, without NBIOS
  smb2_io_vectors out;

  Smb2Pdu *next_compound;

  /********** RESPONSE PART ***********/
  uint32_t respNBLength;
  /* this is the reply header */
  struct smb2_header header_resp;
  /* pointer to the unmarshalled payload in a reply */
  void *payload;
  // io vectors for the in packet we are reading, without NBIOS
  smb2_io_vectors in;

  /********** COMMON PART ***********/
  AppData *appData;
  bool bIsLastInCompound;
};

#endif // _SMB2_PDU_H
