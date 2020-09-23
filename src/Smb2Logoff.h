#ifndef _SMB2_LOGOFF_H_
#define _SMB2_LOGOFF_H_

#include "Smb2Pdu.h"
#include "Smb2Context.h"

class Smb2Logoff : public Smb2Pdu
{
public:
  Smb2Logoff();
  Smb2Logoff(Smb2ContextPtr  smb2,
             AppData         *logOffData);
  virtual ~Smb2Logoff();

  static Smb2Pdu* createPdu(Smb2ContextPtr smb2,
                            AppData *logOffData);

  virtual int encodeRequest(Smb2ContextPtr smb2, void *req);
  virtual int smb2ReplyProcessFixed(Smb2ContextPtr smb2);
  virtual int smb2ReplyProcessVariable(Smb2ContextPtr smb2);
  virtual int smb2ProcessReplyAndAppData(Smb2ContextPtr smb2);
};

#endif // _SMB2_LOGOFF_H_
