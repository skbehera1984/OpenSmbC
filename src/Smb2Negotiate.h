#ifndef _SMB2_NEGOTIATE_H_
#define _SMB2_NEGOTIATE_H_

#include "Smb2Pdu.h"
#include "Smb2Context.h"

class Smb2Negotiate : public Smb2Pdu
{
public:
  Smb2Negotiate();
  Smb2Negotiate(Smb2ContextPtr  smb2,
                AppData         *negotiateData);
  virtual ~Smb2Negotiate();

  static Smb2Pdu* createPdu(Smb2ContextPtr smb2,
                            struct smb2_negotiate_request *req,
                            AppData *negotiateData);

  virtual int encodeRequest(Smb2ContextPtr smb2, void *req);
  virtual int smb2ReplyProcessFixed(Smb2ContextPtr smb2);
  virtual int smb2ReplyProcessVariable(Smb2ContextPtr smb2);
  virtual int smb2ProcessReplyAndAppData(Smb2ContextPtr smb2);

private:
  int encodeNegotiateContexts(Smb2ContextPtr                smb2,
                              struct smb2_negotiate_request *req,
                              uint16_t                      *num_ctx);
  int decodePreauthIntegContext(Smb2ContextPtr              smb2,
                                smb2_iovec                  *iov,
                                struct smb2_negotiate_reply *rep);

  int decodeEncryptionContext(Smb2ContextPtr              smb2,
                              smb2_iovec                  *iov,
                              struct smb2_negotiate_reply *rep);
  int decodeNegotiateContexts(Smb2ContextPtr              smb2,
                              smb2_iovec                  *iov,
                              struct smb2_negotiate_reply *rep);
};

#endif // _SMB2_NEGOTIATE_H_
