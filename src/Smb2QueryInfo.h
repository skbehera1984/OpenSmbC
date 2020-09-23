#ifndef _SMB2_QUERY_INFO_H_
#define _SMB2_QUERY_INFO_H_

#include "Smb2Pdu.h"
#include "Smb2Context.h"

class Smb2QueryInfo : public Smb2Pdu
{
public:
  Smb2QueryInfo();
  Smb2QueryInfo(Smb2ContextPtr  smb2,
                AppData         *queryInfoData);
  virtual ~Smb2QueryInfo();

  static Smb2Pdu* createPdu(Smb2ContextPtr smb2,
                            struct smb2_query_info_request *req,
                            AppData *qInfoData);

  virtual int encodeRequest(Smb2ContextPtr smb2, void *req);
  virtual int smb2ReplyProcessFixed(Smb2ContextPtr smb2);
  virtual int smb2ReplyProcessVariable(Smb2ContextPtr smb2);
  virtual int smb2ProcessReplyAndAppData(Smb2ContextPtr smb2);

public:
  uint8_t requestedInfoType;
  uint8_t requestedInfoClass;
};

#endif // _SMB2_QUERY_INFO_H_
