#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <string.h>
#include "Smb2Socket.h"
#include "Smb2Logoff.h"

Smb2Logoff::Smb2Logoff(Smb2ContextPtr smb2,
                       AppData         *logOffData)
  : Smb2Pdu(smb2, SMB2_LOGOFF, logOffData)
{
}

Smb2Logoff::~Smb2Logoff()
{
}

int
Smb2Logoff::encodeRequest(Smb2ContextPtr smb2, void *Req)
{
  uint8_t *buf;
  int len;

  len = 4;

  buf = (uint8_t*)malloc(len);
  if (buf == NULL)
  {
    smb2->smb2_set_error("Failed to allocate logoff buffer");
    return -1;
  }
  memset(buf, 0, len);

  smb2_iovec iov(buf, len, free);
  out.smb2_add_iovector(iov);

  iov.smb2_set_uint16(0, SMB2_LOGOFF_REQUEST_SIZE);

  return 0;
}

Smb2Pdu *
Smb2Logoff::createPdu(Smb2ContextPtr smb2, AppData *logOffData)
{
  Smb2Pdu *pdu;

  pdu = new Smb2Logoff(smb2, logOffData);
  if (pdu == NULL)
    return NULL;

  if (pdu->encodeRequest(smb2, NULL))
  {
    delete pdu;
    return NULL;
  }

  pdu->out.smb2_pad_to_64bit();

  return pdu;
}

int
Smb2Logoff::smb2ReplyProcessFixed(Smb2ContextPtr smb2)
{
  if (smb2_is_error_response()) {
    return smb2_process_error_fixed(smb2);
  }

  return 0;
}

int
Smb2Logoff::smb2ReplyProcessVariable(Smb2ContextPtr smb2)
{
  if (smb2_is_error_response()) {
    return smb2_process_error_variable(smb2);
  }
  return 0;
}

int
Smb2Logoff::smb2ProcessReplyAndAppData(Smb2ContextPtr smb2)
{
  appData->setNtStatus(header_resp.status);
  smb2->endSendReceive();
  smb2->close();
  return 0;
}
