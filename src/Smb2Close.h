#ifndef _SMB2_CLOSE_H_
#define _SMB2_CLOSE_H_

#include "Smb2Pdu.h"
#include "Smb2Context.h"

class Smb2Close : public Smb2Pdu
{
public:
  Smb2Close();
  Smb2Close(Smb2ContextPtr  smb2,
            AppData         *closeData);
  virtual ~Smb2Close();

  static Smb2Pdu* createPdu(Smb2ContextPtr smb2,
                            struct smb2_close_request *req,
                            AppData *closeData);

  virtual int encodeRequest(Smb2ContextPtr smb2, void *req);
  virtual int smb2ReplyProcessFixed(Smb2ContextPtr smb2);
  virtual int smb2ReplyProcessVariable(Smb2ContextPtr smb2);
  virtual int smb2ProcessReplyAndAppData(Smb2ContextPtr smb2);
};

#endif // _SMB2_CLOSE_H_
