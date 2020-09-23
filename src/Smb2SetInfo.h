#ifndef _SMB2_SET_INFO_H_
#define _SMB2_SET_INFO_H_

#include "Smb2Pdu.h"
#include "Smb2Context.h"

class Smb2SetInfo : public Smb2Pdu
{
public:
  Smb2SetInfo();
  Smb2SetInfo(Smb2ContextPtr  smb2,
              AppData         *setInfoData);
  virtual ~Smb2SetInfo();

  static Smb2Pdu* createPdu(Smb2ContextPtr smb2,
                            struct smb2_set_info_request *req,
                            AppData *setInfoData);

  virtual int encodeRequest(Smb2ContextPtr smb2, void *req);
  virtual int smb2ReplyProcessFixed(Smb2ContextPtr smb2);
  virtual int smb2ReplyProcessVariable(Smb2ContextPtr smb2);
  virtual int smb2ProcessReplyAndAppData(Smb2ContextPtr smb2);
};

#endif // _SMB2_SET_INFO_H_
