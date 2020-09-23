#ifndef _SMB2_QUERY_DIR_H_
#define _SMB2_QUERY_DIR_H_

#include "Smb2Pdu.h"
#include "Smb2Context.h"

class Smb2QueryDir : public Smb2Pdu
{
public:
  Smb2QueryDir();
  Smb2QueryDir(Smb2ContextPtr  smb2,
               AppData         *qDirData);
  virtual ~Smb2QueryDir();

  static Smb2Pdu* createPdu(Smb2ContextPtr smb2,
                            struct smb2_query_directory_request *req,
                            AppData *qDirData);

  virtual int encodeRequest(Smb2ContextPtr smb2, void *req);
  virtual int smb2ReplyProcessFixed(Smb2ContextPtr smb2);
  virtual int smb2ReplyProcessVariable(Smb2ContextPtr smb2);
  virtual int smb2ProcessReplyAndAppData(Smb2ContextPtr smb2);

private:
  int decode_dirents(Smb2ContextPtr smb2, smb2dir *dir, smb2_iovec *vec);
};

#endif // _SMB2_QUERY_DIR_H_
