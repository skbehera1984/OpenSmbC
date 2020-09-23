#ifdef HAVE_OPENSSL_LIBS

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifndef _SMB2_SIGNING_H_
#define _SMB2_SIGNING_H_

#include "Smb2Context.h"

bool smb2_pdu_add_signature(Smb2ContextPtr smb2, Smb2Pdu *pdu, std::string& err);
bool smb2_pdu_check_signature(Smb2ContextPtr smb2, Smb2Pdu *pdu, std::string& err);

#endif /* _SMB2_SIGNING_H_ */
#endif /* HAVE_OPENSSL_LIBS */
