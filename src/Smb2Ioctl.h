#ifndef _SMB2_IOCTL_H_
#define _SMB2_IOCTL_H_

#include "Smb2Pdu.h"
#include "Smb2Context.h"

class Smb2Ioctl : public Smb2Pdu
{
public:
  Smb2Ioctl();
  Smb2Ioctl(Smb2ContextPtr  smb2,
            AppData         *ioctlData);
  virtual ~Smb2Ioctl();

   static Smb2Pdu* createPdu(Smb2ContextPtr smb2,
                             struct smb2_ioctl_request *req,
                             AppData *ioctlData);

  virtual int encodeRequest(Smb2ContextPtr smb2, void *req);
  virtual int smb2ReplyProcessFixed(Smb2ContextPtr smb2);
  virtual int smb2ReplyProcessVariable(Smb2ContextPtr smb2);
  virtual int smb2ProcessReplyAndAppData(Smb2ContextPtr smb2);
};

#endif // _SMB2_IOCTL_H_
