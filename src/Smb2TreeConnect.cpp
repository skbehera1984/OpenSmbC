#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <string.h>

#include "Smb2TreeConnect.h"

Smb2TreeConnect::Smb2TreeConnect(Smb2ContextPtr  smb2,
                                 AppData         *treeConData)
  : Smb2Pdu(smb2, SMB2_TREE_CONNECT, treeConData)
{
}

Smb2TreeConnect::~Smb2TreeConnect()
{
}

int
Smb2TreeConnect::encodeRequest(Smb2ContextPtr smb2, void *Req)
{
  int len;
  uint8_t *buf;
  struct smb2_tree_connect_request *req = (struct smb2_tree_connect_request *)Req;

  len = SMB2_TREE_CONNECT_REQUEST_SIZE & 0xfffffffe;
  buf = (uint8_t*)malloc(len);
  if (buf == NULL)
  {
    appData->setErrorMsg("Smb2TreeConnect::encodeRequest:Failed to allocate tree connect buffer");
    return -1;
  }
  memset(buf, 0, len);

  smb2_iovec iov(buf, len, free);
  out.smb2_add_iovector(iov);

  iov.smb2_set_uint16(0, SMB2_TREE_CONNECT_REQUEST_SIZE);
  iov.smb2_set_uint16(2, req->flags);
  /* path offset */
  iov.smb2_set_uint16(4, SMB2_HEADER_SIZE + len);
  iov.smb2_set_uint16(6, req->path_length);

  /* Path */
  buf = (uint8_t*)malloc(req->path_length);
  if (buf == NULL)
  {
    appData->setErrorMsg("Smb2TreeConnect::encodeRequest:Failed to allocate tcon path");
    return -1;
  }
  memcpy(buf, req->path, req->path_length);

  out.smb2_add_iovector(buf, req->path_length, free);

  return 0;
}

Smb2Pdu *
Smb2TreeConnect::createPdu(Smb2ContextPtr                   smb2,
                           struct smb2_tree_connect_request *req,
                           AppData                          *treeConData)
{
  Smb2Pdu *pdu;

  pdu = new Smb2TreeConnect(smb2, treeConData);
  if (pdu == NULL)
  {
    treeConData->setErrorMsg("Failed to allocate Smb2TreeConnect PDU");
    return NULL;
  }

  if (pdu->encodeRequest(smb2, req))
  {
    delete pdu;
    return NULL;
  }

  pdu->out.smb2_pad_to_64bit();

  return pdu;
}

int
Smb2TreeConnect::smb2ReplyProcessFixed(Smb2ContextPtr smb2)
{
  if (smb2ReplyIsError()) {
    return smb2ProcessErrorReplyFixed(smb2);
  }

  struct smb2_tree_connect_reply *rep;
  smb2_iovec &iov = in.iovs.back();
  uint16_t struct_size;

  rep = (struct smb2_tree_connect_reply *)malloc(sizeof(*rep));
  if (rep == NULL)
  {
    appData->setErrorMsg("Failed to allocate tcon reply");
    return -1;
  }
  this->payload = rep;

  iov.smb2_get_uint16(0, &struct_size);
  if (struct_size != SMB2_TREE_CONNECT_REPLY_SIZE || (struct_size & 0xfffe) != iov.len)
  {
    string err = stringf("Unexpected size of Negotiate reply. Expected %d, got %d",
                         SMB2_TREE_CONNECT_REPLY_SIZE, (int)iov.len);
    appData->setErrorMsg(err);
    return -1;
  }

  iov.smb2_get_uint8(2, &rep->share_type);
  iov.smb2_get_uint32(4, &rep->share_flags);
  iov.smb2_get_uint32(8, &rep->capabilities);
  iov.smb2_get_uint32(12, &rep->maximal_access);

  /* Update tree ID to use for future PDUs */
  smb2->tree_id = header_resp.sync.tree_id;

  return 0;
}

int
Smb2TreeConnect::smb2ReplyProcessVariable(Smb2ContextPtr smb2)
{
  if (smb2ReplyIsError())
    return smb2ProcessErrorReplyVariable(smb2);

  return 0;
}

int
Smb2TreeConnect::smb2ProcessReplyAndAppData(Smb2ContextPtr smb2)
{
  uint32_t status = header_resp.status;
  appData->setNtStatus(status);

  if (status != SMB2_STATUS_SUCCESS)
  {
    smb2->close();
    string err = stringf("TreeConnect failed with (0x%08x) %s", status, nterror_to_str(status));
    appData->setErrorMsg(err);
  }


  smb2->endSendReceive();
  return 0;
}
