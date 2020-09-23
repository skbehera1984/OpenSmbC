#ifndef _SMB2_AUTH_PROVIDER_H_
#define _SMB2_AUTH_PROVIDER_H_

#include <string>
#include <stdint.h>
#include "SmartPtr.h"

class Smb2Context;
typedef SmartPtr<Smb2Context> Smb2ContextPtr;

class Smb2AuthProvider
{
public:
  Smb2AuthProvider() {}
  virtual ~Smb2AuthProvider() {}

  virtual int negotiateReply(Smb2ContextPtr smb2, std::string& err) = 0;
  virtual int sessionRequest(Smb2ContextPtr smb2,
                             unsigned char  *inBuf,
                             int            inBufLen,
                             unsigned char  **OutBuf,
                             uint16_t       *OutBufLen,
                             std::string&   err) = 0;
  virtual int getSessionKey(Smb2ContextPtr  smb2,
                            uint8_t         **key,
                            uint8_t         *key_size,
                            std::string&    err) = 0;
};

#endif // _SMB2_AUTH_PROVIDER_H_
