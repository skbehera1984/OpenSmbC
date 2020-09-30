#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <string.h>
#include "Smb2Echo.h"

Smb2Echo::Smb2Echo(Smb2ContextPtr smb2,
                   AppData         *echoData)
  : Smb2Pdu(smb2, SMB2_ECHO, echoData)
{
}

Smb2Echo::~Smb2Echo()
{
}

int
Smb2Echo::encodeRequest(Smb2ContextPtr smb2, void *Req)
{
  uint8_t *buf;
  int len;

  len = 4;

  buf = (uint8_t*)malloc(len);
  if (buf == NULL)
  {
    appData->setErrorMsg("Smb2Echo::encodeRequest:Failed to allocate echo buffer");
    return -1;
  }
  memset(buf, 0, len);

  smb2_iovec iov(buf, len, free);
  out.smb2_add_iovector(iov);

  iov.smb2_set_uint16(0, SMB2_ECHO_REQUEST_SIZE);

  return 0;
}

Smb2Pdu *
Smb2Echo::createPdu(Smb2ContextPtr smb2, AppData *echoData)
{
  Smb2Pdu *pdu;

  pdu = new Smb2Echo(smb2, echoData);
  if (pdu == NULL)
  {
    echoData->setErrorMsg("Failed to allocate Smb2Echo PDU");
    return NULL;
  }

  if (pdu->encodeRequest(smb2, NULL))
  {
    delete pdu;
    return NULL;
  }

  pdu->out.smb2_pad_to_64bit();

  return pdu;
}

int
Smb2Echo::smb2ReplyProcessFixed(Smb2ContextPtr smb2)
{
  if (smb2_is_error_response()) {
    return smb2_process_error_fixed(smb2);
  }
  return 0;
}

int
Smb2Echo::smb2ReplyProcessVariable(Smb2ContextPtr smb2)
{
  if (smb2_is_error_response()) {
    return smb2_process_error_variable(smb2);
  }
  return 0;
}

int
Smb2Echo::smb2ProcessReplyAndAppData(Smb2ContextPtr smb2)
{
  uint32_t status = header_resp.status;
  appData->setNtStatus(status);
  smb2->endSendReceive();
  return 0;
}
