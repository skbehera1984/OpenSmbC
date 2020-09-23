#ifndef _SMB2_FLUSH_H_
#define _SMB2_FLUSH_H_

#include "Smb2Pdu.h"
#include "Smb2Context.h"

class Smb2Flush : public Smb2Pdu
{
public:
  Smb2Flush();
  Smb2Flush(Smb2ContextPtr  smb2,
            AppData         *flushData);
  virtual ~Smb2Flush();

  static Smb2Pdu* createPdu(Smb2ContextPtr smb2,
                            struct smb2_flush_request *req,
                            AppData *flushData);

  virtual int encodeRequest(Smb2ContextPtr smb2, void *req);
  virtual int smb2ReplyProcessFixed(Smb2ContextPtr smb2);
  virtual int smb2ReplyProcessVariable(Smb2ContextPtr smb2);
  virtual int smb2ProcessReplyAndAppData(Smb2ContextPtr smb2);
};

#endif // _SMB2_FLUSH_H_
