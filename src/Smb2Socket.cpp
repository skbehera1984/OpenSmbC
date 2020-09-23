#include "Smb2Socket.h"

#include <netdb.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>

#include "Smb2Pdu.h"
#include "Smb2Context.h"
#include "Stringf.h"

using namespace std;

#define CIFS_PORT 445

Smb2Socket::Smb2Socket()
{
  fd = -1;
  bConnected = false;
  context = nullptr;
}

Smb2Socket::Smb2Socket(Smb2Context* ctx)
{
  fd = -1;
  bConnected = false;
  context = ctx;
}

Smb2Socket::~Smb2Socket()
{
  if (fd != -1)
  {
    ::close(fd); fd = -1;
  }
  bConnected = false;
  context = nullptr;
}

void Smb2Socket::close()
{
  if (fd != -1)
  {
    ::close(fd); fd = -1;
  }
  bConnected = false;
}

void Smb2Socket::setNonBlocking()
{
  unsigned v;
  v = fcntl(fd, F_GETFL, 0);
  fcntl(fd, F_SETFL, v | O_NONBLOCK);
}

int Smb2Socket::setSockopt(int optname, int value)
{
  int level;
#ifndef SOL_TCP
  struct protoent *buf;

  if ((buf = getprotobyname("tcp")) != NULL)
  {
    level = buf->p_proto;
  }
  else
  {
    return -1;
  }
#else
  level = SOL_TCP;
#endif

  return setsockopt(fd, level, optname, (char *)&value, sizeof(value));
}

int Smb2Socket::smb2_which_events(Smb2ContextPtr smb2)
{
  int events = bConnected ? POLLIN : POLLOUT;

  if (!smb2->outqueue.empty())
    events |= POLLOUT;

  return events;
}

// this function will write one iovec completely
int Smb2Socket::writeIovec(Smb2ContextPtr smb2, smb2_iovec &v)
{
  if (fd == -1)
  {
    smb2->smb2_set_error("trying to write but not connected");
    return -1;
  }

  struct  iovec iov;
  ssize_t bytesWritten = 0;
  size_t  totalBytesWritten = 0;

  while (totalBytesWritten < v.len)
  {
    iov.iov_base = v.buf + totalBytesWritten;
    iov.iov_len  = v.len - totalBytesWritten;

    bytesWritten = writev(fd, &iov, 1);
    if (bytesWritten == -1)
    {
      if (errno == EAGAIN || errno == EWOULDBLOCK)
      {
        usleep(100000);
        continue;
      }
      smb2->smb2_set_error("Error when writing to socket :%d %s", errno, smb2->smb2_get_error());
      return -1;
    }
    totalBytesWritten += bytesWritten;
  }
  return totalBytesWritten;
}

int Smb2Socket::sendPdu(Smb2ContextPtr smb2, Smb2Pdu *pdu)
{
  size_t bytesWritten = 0, totalBytesWritten = 0;

  uint32_t netbiosLen = pdu->getReqNBLength();
  uint32_t creditCharge = pdu->getReqCreditCharge();

  if (smb2->dialect > SMB2_VERSION_0202)
  {
    if (creditCharge > smb2->credits)
    {
      smb2->smb2_set_error("Insufficient credits to send request");
      return -1;
    }
  }

  // write the netbios header
  uint32_t spl = htobe32(netbiosLen);
  smb2_iovec NBvec= smb2_iovec((uint8_t *)&spl, SMB2_SPL_SIZE, NULL);

  bytesWritten = writeIovec(smb2, NBvec);
  if (bytesWritten < 0)
    return bytesWritten;
  totalBytesWritten += bytesWritten;

  // write all the io vecs
  smb2_io_vectors compoundIoVecs = pdu->getAllComOutVecs();
  for (smb2_iovec &v : compoundIoVecs.iovs)
  {
    bytesWritten = writeIovec(smb2, v);
    if (bytesWritten <= 0)
      return bytesWritten;

    totalBytesWritten += bytesWritten;
  }

  if (totalBytesWritten != (SMB2_SPL_SIZE + netbiosLen))
  {
    smb2->smb2_set_error("Couldn't send the entire pdu");
    return -1;
  }

  return 0;
}

int Smb2Socket::sendPdus(Smb2ContextPtr smb2)
{
  std::map<uint64_t, Smb2Pdu*>::iterator it = smb2->outqueue.begin();

  for (; it != smb2->outqueue.end(); )
  {
    Smb2Pdu* pdu = it->second;

    // remove the pdu from outqueue
    it = smb2->outqueue.erase(it);

    // send the pdu
    if (sendPdu(smb2, pdu) < 0)
    {
      // add back the pdu on failure
      smb2->outqueue[pdu->header.message_id] = pdu;
      smb2->smb2_set_error("Failed to send PDU - %s", smb2->smb2_get_error());
      return -1;
    }
    smb2->smb2_pdu_add_to_waitqueue(pdu);
  }
  return 0;
}

int Smb2Socket::readIovec(Smb2ContextPtr smb2, struct smb2_iovec &v)
{
  struct iovec iov;
  size_t bytesRead = 0, totalBytesRead = 0;

  while (totalBytesRead < v.len)
  {
    iov.iov_base = v.buf + totalBytesRead;
    iov.iov_len  = v.len - totalBytesRead;

    bytesRead = readv(fd, &iov, 1);
    if (bytesRead < 0)
    {
      int err = errno;
      if (err == EINTR || err == EAGAIN)
      {
        usleep(100000);
        continue;
      }
      smb2->smb2_set_error("Read from socket failed, errno:%d. Closing socket.", err);
      return -1;
    }
    if (bytesRead == 0)
    {
      smb2->smb2_set_error("Remote side has closed the socket");
      return -1;
    }
    totalBytesRead += bytesRead;
  }
  return totalBytesRead;
}

// this function will read one compound response and return
int Smb2Socket::receivePdus(Smb2ContextPtr smb2)
{
  std::string err;
  enum smb2_recv_state recv_state = SMB2_RECV_SPL;
  static uint32_t spl = 0;
  struct smb2_header hdr;
  size_t payload_offset = 0; // offset of header of each pdu in the compound chain
  static char magic[4] = {0xFE, 'S', 'M', 'B'};
  Smb2Pdu *pdu = NULL;

  ssize_t totalBytesRead = 0;
  smb2_iovec readVec;

  recv_state = SMB2_RECV_SPL;
  readVec = smb2_iovec((uint8_t *)&spl, SMB2_SPL_SIZE, NULL);

read_more_data:

  ssize_t bytesRead = 0;
  bytesRead = readIovec(smb2, readVec);
  if (bytesRead < 0)
    return bytesRead;

  totalBytesRead += bytesRead;

  /* At this point we have all the data we need for the current phase */
  switch (recv_state)
  {
    case SMB2_RECV_SPL:
    {
      spl = be32toh(spl);
      recv_state = SMB2_RECV_HEADER;
      readVec = smb2_iovec((uint8_t*)malloc(SMB2_HEADER_SIZE), SMB2_HEADER_SIZE, free);
      goto read_more_data;
    }
    case SMB2_RECV_HEADER:
    {
      /* Record the offset for the start of payload data. */
      payload_offset = totalBytesRead;

      if (Smb2Pdu::decodeHeader(&readVec, &hdr, err) != 0)
      {
        smb2->smb2_set_error("Failed to decode smb2 header");
        return -1;
      }

      if (memcmp(&hdr.protocol_id, magic, 4))
      {
        smb2->smb2_set_error("received non-SMB2 blob");
        return -1;
      }
      if (!(hdr.flags & SMB2_FLAGS_SERVER_TO_REDIR))
      {
        smb2->smb2_set_error("received non-reply");
        return -1;
      }

      pdu = smb2->smb2_find_pdu(hdr.message_id);
      if (pdu == NULL)
      {
        smb2->smb2_set_error("no matching PDU found");
        return -1;
      }

      pdu->respNBLength = spl;
      pdu->setResponseHeader(&hdr);
      // save the hdr vector
      pdu->in.smb2_add_iovector(readVec);

      smb2->credits += hdr.credit_request_response;

      if (hdr.status == SMB2_STATUS_PENDING)
      {
        /* Pending. Just treat the rest of the data as
         * padding then check for and skip processing below.
         * We will eventually receive a proper reply for this
         * request sometime later.
         */
        ssize_t padBytes = spl + SMB2_SPL_SIZE - totalBytesRead;

        /* Add padding before the next PDU */
        recv_state = SMB2_RECV_PAD;
        readVec = smb2_iovec((uint8_t*)malloc(padBytes), padBytes, free);
        goto read_more_data;
      }

      ssize_t fixedSize = pdu->smb2ReplyGetFixedSize();
      if (fixedSize < 0)
      {
        smb2->smb2_set_error("can not determine fixed size");
        return -1;
      }

      recv_state = SMB2_RECV_FIXED;
      readVec = smb2_iovec((uint8_t*)malloc(fixedSize), fixedSize, free);
      goto read_more_data;
    }
    case SMB2_RECV_FIXED:
    {
      // save the fixed payload
      pdu->in.smb2_add_iovector(readVec);

      ssize_t varSize = pdu->smb2ReplyProcessFixed(smb2);
      if (varSize < 0)
      {
        smb2->smb2_set_error("Failed to parse fixed part of command payload. %s", smb2->smb2_get_error());
        return -1;
      }

      if (varSize > 0)
      {
        recv_state = SMB2_RECV_VARIABLE;
        readVec = smb2_iovec((uint8_t*)malloc(varSize), varSize, free);
        goto read_more_data;
      }

      /* Check for padding */
      ssize_t padBytes = 0;
      if (hdr.next_command)
        padBytes = hdr.next_command - (SMB2_HEADER_SIZE + totalBytesRead - payload_offset);
      else
        padBytes = spl + SMB2_SPL_SIZE - totalBytesRead;

      if (padBytes < 0)
      {
        smb2->smb2_set_error("Negative number of PAD bytes encountered during PDU decode of fixed payload");
        return -1;
      }
      if (padBytes > 0)
      {
        /* Add padding before the next PDU */
        recv_state = SMB2_RECV_PAD;
        readVec = smb2_iovec((uint8_t*)malloc(padBytes), padBytes, free);
        goto read_more_data;
      }
      /* If padBytes == 0 it means there is no padding and we are finished reading this PDU */
    }
    break;
    case SMB2_RECV_VARIABLE:
    {
      // save the variable payload
      pdu->in.smb2_add_iovector(readVec);

      if (pdu->smb2ReplyProcessVariable(smb2) < 0)
      {
        smb2->smb2_set_error("Failed to parse variable part of command payload. %s", smb2->smb2_get_error());
        return -1;
      }

      /* Check for padding */
      ssize_t padBytes = 0;
      if (hdr.next_command)
        padBytes = hdr.next_command - (SMB2_HEADER_SIZE + totalBytesRead - payload_offset);
      else
        padBytes = spl + SMB2_SPL_SIZE - totalBytesRead;

      if (padBytes < 0)
      {
        smb2->smb2_set_error("Negative number of PAD bytes encountered during PDU decode of variable payload");
        return -1;
      }
      if (padBytes > 0)
      {
        /* Add padding before the next PDU */
        recv_state = SMB2_RECV_PAD;
        readVec = smb2_iovec((uint8_t*)malloc(padBytes), padBytes, free);
        goto read_more_data;
      }

      /* If padBytes == 0 it means there is no padding and we are finished reading this PDU */
    }
    break;
    case SMB2_RECV_PAD:
    {
      // save the padding
      pdu->in.smb2_add_iovector(readVec);
      /* We are finished reading all the data and padding for this PDU. Break out of the switch and invoke the callback. */
    }
    break;
  }

  if (hdr.status == SMB2_STATUS_PENDING)
  {
    /* This was a pending command. Just ignore it and proceed to read the next chain. */
    return 0;
  }

  bool is_chained = false;
  if (hdr.next_command)
  {
    is_chained = true;
    pdu->bIsLastInCompound = false; // there are more pdus in this compound chain
  }

  {
    // put this block in try catch
    /* process the complete response and app data */
    pdu->smb2ProcessReplyAndAppData(smb2);
    delete pdu;
    pdu = NULL;
  }

  if (is_chained)
  {
    recv_state = SMB2_RECV_HEADER;
    readVec = smb2_iovec((uint8_t*)malloc(SMB2_HEADER_SIZE), SMB2_HEADER_SIZE, free);
    goto read_more_data;
  }

  /* We are all done now with this chain. */
  return 0;
}

int Smb2Socket::smb2_service(Smb2ContextPtr smb2, int revents)
{
  if (fd < 0)
    return 0;

  if (revents & POLLERR)
  {
    int err = 0;
    socklen_t err_size = sizeof(err);

    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (char *)&err, &err_size) != 0 || err != 0)
    {
      if (err == 0)
      {
        err = errno;
      }
      smb2->smb2_set_error("smb2_service: socket error %s(%d).", strerror(err), err);
    }
    else
    {
      smb2->smb2_set_error("smb2_service: POLLERR, Unknown socket error.");
    }
    return -1;
  }
  if (revents & POLLHUP)
  {
    smb2->smb2_set_error("smb2_service: POLLHUP, socket error.");
    return -1;
  }

  if (bConnected == false && revents & POLLOUT)
  {
    int err = 0;
    socklen_t err_size = sizeof(err);

    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (char *)&err, &err_size) != 0 || err != 0)
    {
      if (err == 0)
      {
        err = errno;
      }
      smb2->smb2_set_error("smb2_service: socket error %s(%d) while connecting.", strerror(err), err);
      return -1;
    }

    bConnected = true;
    return 0;
  }

  if (revents & POLLIN)
  {
    if (receivePdus(smb2) != 0)
    {
      return -1;
    }
  }

  if (revents & POLLOUT && !smb2->outqueue.empty())
  {
    if (sendPdus(smb2) != 0)
    {
      return -1;
    }
  }

  return 0;
}

int Smb2Socket::connect(Smb2ContextPtr smb2, std::string& server, std::string& err)
{
  struct addrinfo *ai = NULL;
  struct sockaddr_storage ss;
  socklen_t socksize;
  int family;
  string host = server;

  err += stringf("%s:", __func__);

  if (fd != -1)
  {
    err += string("Trying to connect but already connected.");
    return -1;
  }

  /* if ipv6 in [...] form ? FIX it */
  size_t pos = 0;
  if ((pos = server.find("[")) != std::string::npos)
  {
    string tmp = server.substr(pos+1);
    if ((pos = tmp.find("]")) == std::string::npos)
    {
      err += stringf("Invalid address:%s Missing ']' in IPv6 address", server.c_str());
      return -1;
    }
    host = tmp.substr(0, pos);
  }

  /* is it a hostname ? */
  if (getaddrinfo(host.c_str(), NULL, NULL, &ai) != 0)
  {
    err += stringf("Invalid address:%s Can not resolv into IPv4/v6.", server.c_str());
    return -1;
  }

  memset(&ss, 0, sizeof(ss));
  switch (ai->ai_family)
  {
    case AF_INET:
      socksize = sizeof(struct sockaddr_in);
      memcpy(&ss, ai->ai_addr, socksize);
      ((struct sockaddr_in *)&ss)->sin_port = htons(CIFS_PORT);
#ifdef HAVE_SOCK_SIN_LEN
      ((struct sockaddr_in *)&ss)->sin_len = socksize;
#endif
    break;
    case AF_INET6:
      socksize = sizeof(struct sockaddr_in6);
      memcpy(&ss, ai->ai_addr, socksize);
      ((struct sockaddr_in6 *)&ss)->sin6_port = htons(CIFS_PORT);
#ifdef HAVE_SOCK_SIN_LEN
      ((struct sockaddr_in6 *)&ss)->sin6_len = socksize;
#endif
    break;
    default:
      err += stringf("Unknown address family :%d. Only IPv4/IPv6 supported so far.", ai->ai_family);
      freeaddrinfo(ai);
      return -1;
  }
  family = ai->ai_family;
  freeaddrinfo(ai);

  fd = socket(family, SOCK_STREAM, 0);
  if (fd == -1)
  {
    err += stringf("Failed to open smb2 socket. Errno:%s(%d).", strerror(errno), errno);
    return -1;
  }

  setNonBlocking();
  setSockopt(TCP_NODELAY, 1);

  if (::connect(fd, (struct sockaddr *)&ss, socksize) != 0 && errno != EINPROGRESS)
  {
    err += stringf("Connect failed with errno : %s(%d)", strerror(errno), errno);
    close();
    return -1;
  }

  bConnected = true;

  return 0;
}
