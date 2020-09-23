#ifndef _SMB2_READ_H_
#define _SMB2_READ_H_

#include "Smb2Pdu.h"
#include "Smb2Context.h"

class Smb2Read : public Smb2Pdu
{
public:
  Smb2Read();
  Smb2Read(Smb2ContextPtr  smb2,
           AppData         *readData);
  virtual ~Smb2Read();

  static Smb2Pdu* createPdu(Smb2ContextPtr smb2,
                            struct smb2_read_request *req,
                            AppData *readData);

  virtual int encodeRequest(Smb2ContextPtr smb2, void *req);
  virtual int smb2ReplyProcessFixed(Smb2ContextPtr smb2);
  virtual int smb2ReplyProcessVariable(Smb2ContextPtr smb2);
  virtual int smb2ProcessReplyAndAppData(Smb2ContextPtr smb2);
};

#endif // _SMB2_READ_H_
