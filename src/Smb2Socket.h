#ifndef _SMB2_SOCKET_H_
#define _SMB2_SOCKET_H_

#include <vector>
#include <string>
#include "PrivateData.h"
#include "SmartPtr.h"

class Smb2Pdu;
class Smb2Context;
typedef SmartPtr<Smb2Context> Smb2ContextPtr;


/* States that we transition when we read data back from the server :
 * 1: SMB2_RECV_SPL        SPL
 * 2: SMB2_RECV_HEADER     SMB2 Header
 * 3: SMB2_RECV_FIXED      The fixed part of the payload.
 * 4: SMB2_RECV_VARIABLE   Optional variable part of the payload.
 * 5: SMB2_RECV_PAD        Optional padding
 *
 * 2-5 will be repeated for compound commands.
 * 4-5 are optional and may or may not be present depending on the type of command.
 */
enum smb2_recv_state
{
  SMB2_RECV_SPL = 0,
  SMB2_RECV_HEADER,
  SMB2_RECV_FIXED,
  SMB2_RECV_VARIABLE,
  SMB2_RECV_PAD,
};

class Smb2Socket
{
public:
  Smb2Socket();
  Smb2Socket(Smb2Context *ctx);
  ~Smb2Socket();

  void close();
  int  connect(Smb2ContextPtr smb2, std::string& server, std::string& err);
  bool isConnected() { return bConnected; }

  /* The following three functions are used to integrate OpenSmbC in an event system. */
  int smb2_get_fd() { return fd; }
  int smb2_which_events(Smb2ContextPtr smb2);
  int smb2_service(Smb2ContextPtr smb2, int revents, std::string& error);

private:
  void setNonBlocking();
  int  setSockopt(int optname, int value);
  int  writeIovec(Smb2ContextPtr smb2, smb2_iovec &v, std::string& error);
  int  sendPdu(Smb2ContextPtr smb2, Smb2Pdu *pdu, std::string& error);
  int  sendPdus(Smb2ContextPtr smb2, std::string& error);
  int  readIovec(Smb2ContextPtr smb2, struct smb2_iovec &v, std::string& error);
  int  receivePdus(Smb2ContextPtr smb2, std::string& error);

public:
  int            fd;
  bool           bConnected;
  Smb2Context*   context;
};

#endif // _SMB2_SOCKET_H_
