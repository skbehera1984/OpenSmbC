#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <stdarg.h>
#include <poll.h>

#include "Smb2Context.h"
#include "PrivateData.h"
#include "Stringf.h"
#include "Smb2Pdu.h"
#include "Smb2Socket.h"
#include "Smb2AuthProvider.h"
#include "Smb2Signing.h"

#define FUNC stringf("%s: ", __func__)

Smb2Context::Smb2Context()
{
  smb2Socket = nullptr;
  smb2Socket = new Smb2Socket();
  if (smb2Socket == nullptr)
    throw std::string("Failed to create Smb2Socket");

  sec = SMB2_SEC_UNDEFINED;
  authenticator = nullptr;
  security_mode = 0;
  use_cached_creds = false;
  version = SMB2_VERSION_ANY;
  server.clear();
  share.clear();
  user.clear();
  std::string sysuser = std::string(getlogin());
  smb2SetUser(sysuser);
  password.clear();
  domain.clear();
  workstation.clear();

  for (int i = 0; i < 8; i++)
  {
    client_challenge[i] = random()&0xff;
  }

  credits = 0;

  tree_id = 0;
  message_id = 0;
  session_id = 0;
  session_key = NULL;
  session_key_size = 0;
  signing_required = 0;
  memset(signing_key, 0, SMB2_KEY_SIZE);

  hashAlgorithm = 0;
  CipherId      = 0;
  clientSupportEncryption = false;
  serverSupportEncryption = 0;
  PreauthIntegrityHash    = NULL;
  preauthIntegrityHashLength = 0;

  outqueue.clear();
  waitqueue.clear();

  supports_multi_credit = false;

  max_transact_size = 0;
  max_read_size = 0;
  max_write_size = 0;

  isComplete = false;
  userInBackUpOperatorsGrp = false;

  setlogmask(LOG_UPTO(LOG_NOTICE));
  openlog("OpenSmbC", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);
}

Smb2Context::~Smb2Context()
{
  if (authenticator)
  {
    delete authenticator; authenticator = nullptr;
  }

  if (smb2Socket)
  {
    delete smb2Socket; smb2Socket = nullptr;
  }

  std::map<uint64_t, Smb2Pdu*>::iterator it = outqueue.begin();
  for (; it != outqueue.end(); )
  {
    delete it->second;
    it = outqueue.erase(it);
  }
  it = waitqueue.begin();
  for (; it != waitqueue.end(); )
  {
    delete it->second;
    it = waitqueue.erase(it);
  }

  free(session_key);
  session_key = NULL;

  if (PreauthIntegrityHash)
  {
    free(PreauthIntegrityHash); PreauthIntegrityHash = NULL;
  }

  isComplete = false;

  closelog();
}

Smb2ContextPtr Smb2Context::create(void)
{
  Smb2ContextPtr smb2 = nullptr;
  smb2 = new Smb2Context();
  return smb2;
}

void Smb2Context::close()
{
  if (authenticator)
  {
    delete authenticator;
    authenticator = nullptr;
  }

  smb2Socket->close();
  message_id = 0;
  session_id = 0;
  tree_id = 0;
  memset(signing_key, 0, SMB2_KEY_SIZE);
  if (session_key)
  {
    free(session_key);
    session_key = NULL;
  }
  session_key_size = 0;
}

bool Smb2Context::isConnected()
{
  return smb2Socket->isConnected();
}

void Smb2Context::endSendReceive()
{
  isComplete = true;
}

/*
 * Set the security mode for the connection.
 * This is a combination of the flags SMB2_NEGOTIATE_SIGNING_ENABLED
 * and  SMB2_NEGOTIATE_SIGNING_REQUIRED
 * Default is 0.
 */
void Smb2Context::smb2SetSecurityMode(uint16_t security_mode)
{
  this->security_mode = security_mode;
}

void Smb2Context::smb2SetUser(std::string& user)
{
  this->user = user;
  Smb2Context::set_password_from_file();
}

void Smb2Context::smb2SetPassword(std::string password)
{
  this->password = password;
}

void Smb2Context::smb2SetDomain(std::string domain)
{
  this->domain = domain;
}

void Smb2Context::smb2SetWorkstation(std::string& workstation)
{
  this->workstation = workstation;
}

void Smb2Context::set_password_from_file()
{
  char *name = NULL;
  FILE *fh;
  char buf[256];
  char *domain, *user, *password;
  int finished;

  name = getenv("NTLM_USER_FILE");
  if (name == NULL) {
    return;
  }
  fh = fopen(name, "r");
  while (!feof(fh))
  {
    if (fgets(buf, 256, fh) == NULL)
      break;

    buf[255] = 0;
    finished = 0;
    while (!finished)
    {
      switch (buf[strlen(buf) - 1])
      {
      case '\n':
        buf[strlen(buf) - 1] = 0;
      default:
        finished = 1;
      }

      if (strlen(buf) == 0)
        break;
    }

    if (buf[0] == 0)
      break;

    domain = buf;
    user = strchr(domain, ':');
    if (user == NULL)
      continue;

    *user++ = 0;
    password = strchr(user, ':');
    if (password == NULL)
      continue;

    *password++ = 0;

    if (this->user != std::string(user))
      continue;

    std::string passwd = std::string(password);
    smb2SetPassword(passwd);
  }
  fclose(fh);
}

void Smb2Context::smb2SetAuthMode(enum smb2_sec mode)
{
  sec = mode;
}

void Smb2Context::smb2SetUsrInBackUpOpsGrp(bool val)
{
  userInBackUpOperatorsGrp = val;
}

void Smb2Context::smb2EnableEncryption(bool enable)
{
  clientSupportEncryption = enable;
}

uint8_t Smb2Context::smb2IsEncryptionEnabled()
{
  return clientSupportEncryption;
}

uint8_t Smb2Context::smb2IsEncryptionSupported()
{
  return serverSupportEncryption;
}

uint32_t Smb2Context::smb2GetMaxReadSize()
{
  return max_read_size;
}

uint32_t Smb2Context::smb2GetMaxWriteSize()
{
  return max_write_size;
}

uint32_t Smb2Context::smb2GetMaxTransactSize()
{
  return max_transact_size;
}

bool Smb2Context::smb2_queue_pdu(Smb2Pdu *pdu, std::string& error)
{
  Smb2Pdu *p;

  /* Update all the PDU headers in this chain */
  for (p = pdu; p; p = p->next_compound)
  {
    p->encodeHeader(this);
    if (this->signing_required)
    {
#if defined(HAVE_OPENSSL_LIBS)
      if (!smb2_pdu_add_signature(this, p, error))
      {
        return false;
      }
#else
      error = FUNC + "Signing Required. OpenSSL support not available";
      return false;
#endif
    }
  }

  outqueue[pdu->header.message_id] = pdu;
  return true;
}

void Smb2Context::smb2_remove_pdu(uint64_t messageId)
{
  std::map<uint64_t, Smb2Pdu*>::iterator it = outqueue.find(messageId);
  if (it != outqueue.end())
  {
    outqueue.erase(it);
  }
}

Smb2Pdu* Smb2Context::smb2_find_pdu(uint64_t messageId)
{
  Smb2Pdu *pdu = nullptr;
  std::map<uint64_t, Smb2Pdu*>::iterator it = waitqueue.find(messageId);
  if (it != waitqueue.end())
  {
    pdu = it->second;
    waitqueue.erase(it);
  }
  return pdu;
}

void Smb2Context::smb2_pdu_add_to_waitqueue(Smb2Pdu *pdu)
{
  while (pdu)
  {
    Smb2Pdu *tmp_pdu = pdu->next_compound;

    /* As we have now sent all the PDUs we can remove the chaining.
     * On the receive side we will treat all PDUs as individual PDUs. */
    pdu->next_compound = NULL;
    credits -= pdu->header.credit_charge;

    waitqueue[pdu->header.message_id] = pdu;
    pdu = tmp_pdu;
  }
}

int Smb2Context::sendAndReceive(string& error)
{
  isComplete = false;

  while (!isComplete)
  {
    struct pollfd pfd;

    pfd.fd = smb2Socket->smb2_get_fd();
    pfd.events = smb2Socket->smb2_which_events(this);

    if (pfd.fd == -1)
    {
      error = FUNC + "Socket Not Connected";
      return -1;
    }

    if (poll(&pfd, 1, 1000) < 0)
    {
      error = FUNC + "Poll failed";
      return -1;
    }
    if (pfd.revents == 0)
    {
      continue;
    }
    if (smb2Socket->smb2_service(this, pfd.revents, error) < 0)
    {
      return -1;
    }
  }

  return 0;
}
