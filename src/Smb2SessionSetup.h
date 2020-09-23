#ifndef _SMB2_SESSION_SETUP_H_
#define _SMB2_SESSION_SETUP_H_

#include "Smb2Pdu.h"
#include "Smb2Context.h"

class Smb2SessionSetup : public Smb2Pdu
{
public:
  Smb2SessionSetup();
  Smb2SessionSetup(Smb2ContextPtr  smb2,
                   AppData         *sessionData);
  virtual ~Smb2SessionSetup();

  static Smb2Pdu* createPdu(Smb2ContextPtr smb2,
                            struct smb2_session_setup_request *req,
                            AppData *sessionData);

  virtual int encodeRequest(Smb2ContextPtr smb2, void *req);
  virtual int smb2ReplyProcessFixed(Smb2ContextPtr smb2);
  virtual int smb2ReplyProcessVariable(Smb2ContextPtr smb2);
  virtual int smb2ProcessReplyAndAppData(Smb2ContextPtr smb2);

private:
  void smb2_derive_key(uint8_t     *derivation_key,
                       uint32_t    derivation_key_len,
                       const char  *label,
                       uint32_t    label_len,
                       const char  *context,
                       uint32_t    context_len,
                       uint8_t     derived_key[SMB2_KEY_SIZE]);
};

#endif // _SMB2_SESSION_SETUP_H_
