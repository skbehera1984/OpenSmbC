#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <string.h>

#include "Smb2TreeDisconnect.h"
#include "Smb2Logoff.h"

Smb2TreeDisconnect::Smb2TreeDisconnect(Smb2ContextPtr  smb2,
                                       AppData         *treeDisConData)
  : Smb2Pdu(smb2, SMB2_TREE_DISCONNECT, treeDisConData)
{
}

Smb2TreeDisconnect::~Smb2TreeDisconnect()
{
}

int
Smb2TreeDisconnect::encodeRequest(Smb2ContextPtr smb2, void *Req)
{
  uint8_t *buf;
  int len;

  len = 4;

  buf = (uint8_t*)malloc(len);
  if (buf == NULL)
  {
    appData->setErrorMsg("Smb2TreeDisconnect::encodeRequest:Failed to allocate tree disconnect buffer");
    return -1;
  }
  memset(buf, 0, len);

  smb2_iovec iov( buf, len, free);
  out.smb2_add_iovector(iov);

  iov.smb2_set_uint16(0, SMB2_TREE_DISCONNECT_REQUEST_SIZE);

  return 0;
}

Smb2Pdu *
Smb2TreeDisconnect::createPdu(Smb2ContextPtr smb2, AppData *treeDisConData)
{
  Smb2Pdu *pdu;

  pdu = new Smb2TreeDisconnect(smb2, treeDisConData);
  if (pdu == NULL)
  {
    treeDisConData->setErrorMsg("Failed to allocate Smb2TreeDisconnect PDU");
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
Smb2TreeDisconnect::smb2ReplyProcessFixed(Smb2ContextPtr smb2)
{
  if (smb2_is_error_response()) {
    return smb2_process_error_fixed(smb2);
  }

  return 0;
}

int Smb2TreeDisconnect::smb2ReplyProcessVariable(Smb2ContextPtr smb2)
{
  if (smb2_is_error_response()) {
    return smb2_process_error_variable(smb2);
  }
  return 0;
}

int
Smb2TreeDisconnect::smb2ProcessReplyAndAppData(Smb2ContextPtr smb2)
{
  std::string err;
  Smb2Pdu *pdu;

  appData->setNtStatus(header_resp.status);

  pdu = Smb2Logoff::createPdu(smb2, appData);
  if (pdu == NULL)
  {
    smb2->endSendReceive();
    return 0;
  }

  smb2->smb2_queue_pdu(pdu, err);
  return 0;
}
