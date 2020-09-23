#ifndef _SMB2_CREATE_H_
#define _SMB2_CREATE_H_

#include "Smb2Pdu.h"
#include "Smb2Context.h"

class Smb2Create : public Smb2Pdu
{
public:
  Smb2Create();
  Smb2Create(Smb2ContextPtr  smb2,
             AppData         *createData);
  virtual ~Smb2Create();

  static Smb2Pdu* createPdu(Smb2ContextPtr smb2,
                            struct smb2_create_request *req,
                            AppData *createData);

  virtual int encodeRequest(Smb2ContextPtr smb2, void *req);
  virtual int smb2ReplyProcessFixed(Smb2ContextPtr smb2);
  virtual int smb2ReplyProcessVariable(Smb2ContextPtr smb2);
  virtual int smb2ProcessReplyAndAppData(Smb2ContextPtr smb2);
};

#endif // _SMB2_CREATE_H_
