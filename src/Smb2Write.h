#ifndef _SMB2_WRITE_H_
#define _SMB2_WRITE_H_

#include "Smb2Pdu.h"
#include "Smb2Context.h"

class Smb2Write : public Smb2Pdu
{
public:
  Smb2Write();
  Smb2Write(Smb2ContextPtr  smb2,
            AppData         *writeData);
  virtual ~Smb2Write();

  static Smb2Pdu* createPdu(Smb2ContextPtr smb2,
                            struct smb2_write_request *req,
                            AppData *writeData);

  virtual int encodeRequest(Smb2ContextPtr smb2, void *req);
  virtual int smb2ReplyProcessFixed(Smb2ContextPtr smb2);
  virtual int smb2ReplyProcessVariable(Smb2ContextPtr smb2);
  virtual int smb2ProcessReplyAndAppData(Smb2ContextPtr smb2);
};

#endif // _SMB2_WRITE_H_
