#ifndef _SMB2_TREE_DISCONNECT_H_
#define _SMB2_TREE_DISCONNECT_H_

#include "Smb2Pdu.h"
#include "Smb2Context.h"

class Smb2TreeDisconnect : public Smb2Pdu
{
public:
  Smb2TreeDisconnect();
  Smb2TreeDisconnect(Smb2ContextPtr  smb2,
                     AppData         *treeDisConData);
  virtual ~Smb2TreeDisconnect();

  static Smb2Pdu* createPdu(Smb2ContextPtr smb2,
                            AppData *treeDisConData);

  virtual int encodeRequest(Smb2ContextPtr smb2, void *req);
  virtual int smb2ReplyProcessFixed(Smb2ContextPtr smb2);
  virtual int smb2ReplyProcessVariable(Smb2ContextPtr smb2);
  virtual int smb2ProcessReplyAndAppData(Smb2ContextPtr smb2);
};

#endif // _SMB2_TREE_DISCONNECT_H_
