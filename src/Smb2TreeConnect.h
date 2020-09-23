#ifndef _SMB2_TREE_CONNECT_H_
#define _SMB2_TREE_CONNECT_H_

#include "Smb2Pdu.h"
#include "Smb2Context.h"

class Smb2TreeConnect : public Smb2Pdu
{
public:
  Smb2TreeConnect();
  Smb2TreeConnect(Smb2ContextPtr  smb2,
                  AppData         *treeConData);
  virtual ~Smb2TreeConnect();

  static Smb2Pdu* createPdu(Smb2ContextPtr smb2,
                            struct smb2_tree_connect_request *req,
                            AppData *treeConData);

  virtual int encodeRequest(Smb2ContextPtr smb2, void *req);
  virtual int smb2ReplyProcessFixed(Smb2ContextPtr smb2);
  virtual int smb2ReplyProcessVariable(Smb2ContextPtr smb2);
  virtual int smb2ProcessReplyAndAppData(Smb2ContextPtr smb2);
};

#endif // _SMB2_TREE_CONNECT_H_
