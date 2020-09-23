#ifndef _SMB2_ECHO_H_
#define _SMB2_ECHO_H_

#include "Smb2Pdu.h"
#include "Smb2Context.h"

class Smb2Echo : public Smb2Pdu
{
public:
  Smb2Echo();
  Smb2Echo(Smb2ContextPtr  smb2,
           AppData         *echoData);
  virtual ~Smb2Echo();

  static Smb2Pdu* createPdu(Smb2ContextPtr smb2,
                            AppData *echoData);

  virtual int encodeRequest(Smb2ContextPtr smb2, void *req);
  virtual int smb2ReplyProcessFixed(Smb2ContextPtr smb2);
  virtual int smb2ReplyProcessVariable(Smb2ContextPtr smb2);
  virtual int smb2ProcessReplyAndAppData(Smb2ContextPtr smb2);
};

#endif // _SMB2_ECHO_H_
