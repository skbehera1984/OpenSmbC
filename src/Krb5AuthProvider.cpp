#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <string.h>
#include <unistd.h>
#include <string>
#include <stdio.h>

#include <krb5/krb5.h>
#include <gssapi/gssapi_krb5.h>
#include <gssapi/gssapi.h>

#include "Stringf.h"
#include "PrivateData.h"
#include "Smb2Context.h"

#include "Krb5AuthProvider.h"

#ifndef discard_const
#define discard_const(ptr) ((void *)((intptr_t)(ptr)))
#endif

std::string gss_mech_spnego_str     = std::string ("\x2b\x06\x01\x05\x05\x02");
std::string spnego_mech_krb5_str    = std::string ("\x2a\x86\x48\x86\xf7\x12\x01\x02\x02");
std::string spnego_mech_ntlmssp_str = std::string ("\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a");

static const gss_OID_desc gss_mech_spnego = {
    6, (void*)&gss_mech_spnego_str[0]
};

static const gss_OID_desc spnego_mech_krb5 = {
    9, (void*)&spnego_mech_krb5_str[0]
};

static const gss_OID_desc spnego_mech_ntlmssp = {
   10, (void*)&spnego_mech_ntlmssp_str[0]
};

Krb5AuthProvider::~Krb5AuthProvider()
{
  krb5_free_auth_data();
}

void
Krb5AuthProvider::krb5_free_auth_data()
{
  uint32_t maj, min;

  if (!krb5AuthData)
    return;

  /* Delete context */
  if (krb5AuthData->context)
  {
    maj = gss_delete_sec_context(&min, &krb5AuthData->context, &krb5AuthData->output_token);
    if (maj != GSS_S_COMPLETE)
    {
      /* No logging, yet. Do we care? */
    }
  }

  gss_release_buffer(&min, &krb5AuthData->output_token);
  gss_release_cred(&min, &krb5AuthData->cred);

  if (krb5AuthData->target_name)
  {
    gss_release_name(&min, &krb5AuthData->target_name);
  }

  if (krb5AuthData->user_name)
  {
    gss_release_name(&min, &krb5AuthData->user_name);
  }

  free(krb5AuthData->g_server);
  free(krb5AuthData);
}

static
std::string display_status(int type, uint32_t err)
{
  std::string msg;
  gss_buffer_desc text;
  uint32_t msg_ctx = 0;
  uint32_t maj = 0, min = 0;

  do
  {
    maj = gss_display_status(&min, err, type, GSS_C_NO_OID, &msg_ctx, &text);
    if (maj != GSS_S_COMPLETE)
    {
      return std::string("");
    }

    if (msg == "")
    {
      msg = stringf("%*s", (int)text.length, (char *)text.value);
    }
    else
    {
      msg += "," + stringf(" %*s", (int)text.length, (char *)text.value);
    }

    gss_release_buffer(&min, &text);
  } while (msg_ctx != 0);

  return msg;
}

std::string Krb5AuthProvider::krb5_get_gss_error(std::string function, uint32_t maj, uint32_t min)
{
  std::string err_maj = display_status(GSS_C_GSS_CODE, maj);
  std::string err_min = display_status(GSS_C_MECH_CODE, min);

  std::string err = function + ":" + " (" + err_maj + "," + err_min + ")";
  return err;
}

int
Krb5AuthProvider::krb5_negotiate_reply(string&       server,
                                       string&       domain,
                                       string&       user_name,
                                       string&       password,
                                       bool          use_cached_creds,
                                       std::string&  err)
{
  gss_buffer_desc target = GSS_C_EMPTY_BUFFER;
  uint32_t maj, min;
  gss_buffer_desc user;
  char user_principal[2048];
  gss_OID_set_desc mechOidSet;

  krb5_context    krb5_cctx = NULL;
  krb5_ccache     krb5cache = NULL;
  krb5_creds      krb5_ccreds;
  krb5_principal  client_princ = NULL;
  krb5_get_init_creds_opt *options = NULL;

  if (use_cached_creds)
  {
    /* Validate the parameters */
    if (user_name.empty()) {
      err = std::string("user_name must be provided while using krb5cc mode");
      return -1;
    }
    if (domain.empty()) {
      err = std::string("domain must be set while using krb5cc mode");
      return -1;
    }
    if (password.empty()) {
      err = std::string("password must be set while using krb5cc mode");
      return -1;
    }
  }

  krb5AuthData = (struct private_auth_data *)malloc(sizeof(struct private_auth_data));
  if (krb5AuthData == NULL) {
    err = std::string("Failed to allocate private_auth_data");
    return -1;
  }
  memset(krb5AuthData, 0, sizeof(struct private_auth_data));
  krb5AuthData->context = GSS_C_NO_CONTEXT;

  if (asprintf(&krb5AuthData->g_server, "cifs@%s", server.c_str()) < 0)
  {
    err = std::string("Failed to allocate server string");
    return -1;
  }

  target.value = krb5AuthData->g_server;
  target.length = strlen(krb5AuthData->g_server);

  maj = gss_import_name(&min, &target, GSS_C_NT_HOSTBASED_SERVICE, &krb5AuthData->target_name);
  if (maj != GSS_S_COMPLETE) {
    err = krb5_get_gss_error("gss_import_name", maj, min);
    return -1;
  }

  if (use_cached_creds)
  {
    memset(&user_principal[0], 0, 2048);
    if (sprintf(&user_principal[0], "%s@%s", user_name.c_str(), domain.c_str()) < 0)
    {
      err = std::string("Failed to allocate user principal");
      return -1;
    }

    user.value = discard_const(user_principal);
    user.length = strlen(user_principal);
  }
  else
  {
    user.value = discard_const(user_name.c_str());
    user.length = user_name.length();
  }

  /* create a name for the user */
  maj = gss_import_name(&min, &user, GSS_C_NT_USER_NAME, &krb5AuthData->user_name);
  if (maj != GSS_S_COMPLETE)
  {
    err = krb5_get_gss_error("gss_import_name", maj, min);
    return -1;
  }

  /* TODO: the proper mechanism (SPNEGO vs NTLM vs KRB5) should be
   * selected based on the SMB negotiation flags */
  krb5AuthData->mech_type = &spnego_mech_krb5;
  krb5AuthData->cred = GSS_C_NO_CREDENTIAL;

  /* Create creds for the user */
  mechOidSet.count = 1;
  mechOidSet.elements = (gss_OID)discard_const(&spnego_mech_krb5);

  if (use_cached_creds)
  {
    krb5_error_code ret = 0;

    ret = krb5_init_context(&krb5_cctx);
    if (ret)
    {
      err = stringf("Failed to initialize krb5 context - %s", krb5_get_error_message(krb5_cctx, ret));
      goto error;
    }
    memset(&krb5_ccreds, 0, sizeof(krb5_ccreds));

    ret = krb5_set_default_realm(krb5_cctx, domain.c_str());
    if (ret)
    {
      err = stringf("Failed to set default realm - %s", krb5_get_error_message(krb5_cctx, ret));
      goto error;
    }
    ret = krb5_parse_name_flags(krb5_cctx, user_name.c_str(), 0, &client_princ);
    if (ret)
    {
      err = stringf("Failed to parse principal name - %s", krb5_get_error_message(krb5_cctx, ret));
      goto error;
    }
    ret = krb5_cc_new_unique(krb5_cctx, "MEMORY", NULL, &krb5cache);
    if (ret)
    {
      err = stringf("Failed create cache - %s", krb5_get_error_message(krb5_cctx, ret));
      goto error;
    }

    ret = krb5_get_init_creds_opt_alloc(krb5_cctx, &options);
    ret = krb5_get_init_creds_opt_set_out_ccache(krb5_cctx, options, krb5cache);
    ret = krb5_get_init_creds_password(krb5_cctx, &krb5_ccreds,
                                       client_princ, password.c_str(),
                                       NULL, NULL, 0, NULL, options);
    if (ret != 0)
    {
      err = stringf("krb5_get_init_creds_password: Failed to init credentials - %d, %s", ret, krb5_get_error_message(krb5_cctx, ret));
      goto error;
    }

    maj = gss_krb5_import_cred(&min, krb5cache, client_princ, 0, &krb5AuthData->cred);
    if (maj != GSS_S_COMPLETE) {
      err = krb5_get_gss_error("gss_krb5_import_cred", maj, min);
      goto error;
    }
  }
  else
  {
    maj = gss_acquire_cred(&min, krb5AuthData->user_name, 0,
                           &mechOidSet, GSS_C_INITIATE,
                           &krb5AuthData->cred, NULL, NULL);
    if (maj != GSS_S_COMPLETE) {
      err = krb5_get_gss_error("gss_acquire_cred", maj, min);
      goto error;
    }
  }

  if (client_princ != NULL) {
    krb5_free_principal(krb5_cctx, client_princ);
  }

  if (krb5cache != NULL) {
    krb5_cc_close(krb5_cctx, krb5cache);
  }
  if (options != NULL) {
    krb5_get_init_creds_opt_free(krb5_cctx, options);
  }
  if (krb5_cctx != NULL) {
    krb5_free_context(krb5_cctx);
  }

  return 0;

error:
  if (client_princ != NULL) {
    krb5_free_principal(krb5_cctx, client_princ);
  }

  if (krb5cache != NULL) {
    krb5_cc_close(krb5_cctx, krb5cache);
  }
  if (options != NULL) {
    krb5_get_init_creds_opt_free(krb5_cctx, options);
  }
  if (krb5_cctx != NULL) {
    krb5_free_context(krb5_cctx);
  }

  return -1;
}

int
Krb5AuthProvider::krb5_session_get_session_key(uint8_t       **session_key,
                                               uint8_t       *session_key_size,
                                               std::string&  err)
{
  uint8_t *SessionKey = NULL;
  uint8_t SessionKeySize = 0;

  /* Get the Session Key */
  uint32_t gssMajor, gssMinor;
  gss_buffer_set_t sessionKey = NULL;

  gssMajor = gss_inquire_sec_context_by_oid(
                           &gssMinor,
                           krb5AuthData->context,
                           GSS_C_INQ_SSPI_SESSION_KEY,
                           &sessionKey);
  if (gssMajor != GSS_S_COMPLETE) {
    err = krb5_get_gss_error("gss_inquire_sec_context_by_oid", gssMajor, gssMinor);
    return -1;
  }

  /* The key is in element 0 and the key type OID is in element 1 */
  if (!sessionKey || (sessionKey->count < 1) || !sessionKey->elements[0].value || (0 == sessionKey->elements[0].length))
  {
    err = std::string("Invalid session key");
    return -1;
  }

  SessionKey = (uint8_t *) malloc(sessionKey->elements[0].length);
  if (SessionKey == NULL)
  {
    err = std::string("Failed to allocate SessionKey");
    return -1;
  }
  memset(SessionKey, 0, sessionKey->elements[0].length);
  memcpy(SessionKey, sessionKey->elements[0].value, sessionKey->elements[0].length);
  SessionKeySize = sessionKey->elements[0].length;

  *session_key = SessionKey;
  *session_key_size = SessionKeySize;

  gss_release_buffer_set(&gssMinor, &sessionKey);

  return 0;
}

int
Krb5AuthProvider::krb5_session_request(unsigned char            *buf,
                                       int                       len,
                                       std::string&              err)
{
  uint32_t maj, min;
  gss_buffer_desc *input_token = NULL;
  gss_buffer_desc token = GSS_C_EMPTY_BUFFER;

  if (buf)
  {
    /* release the previous token */
    gss_release_buffer(&min, &krb5AuthData->output_token);
    krb5AuthData->output_token.length = 0;
    krb5AuthData->output_token.value = NULL;

    token.value = buf;
    token.length = len;
    input_token = &token;
  }

  /* TODO return -errno instead of just -1 */
  /* NOTE: this call is not async, a helper thread should be used if that is an issue */
  krb5AuthData->req_flags = GSS_C_SEQUENCE_FLAG | GSS_C_MUTUAL_FLAG | GSS_C_REPLAY_FLAG;
  maj = gss_init_sec_context(&min, krb5AuthData->cred,
                             &krb5AuthData->context,
                             krb5AuthData->target_name,
                             (gss_OID)discard_const(krb5AuthData->mech_type),
                             krb5AuthData->req_flags,
                             GSS_C_INDEFINITE,
                             GSS_C_NO_CHANNEL_BINDINGS,
                             input_token,
                             NULL,
                             &krb5AuthData->output_token,
                             NULL,
                             NULL);

  /* GSS_C_MUTUAL_FLAG expects the acceptor to send a token so
   * a second call to gss_init_sec_context is required to complete the session.
   * A second call is required even if the first call returns GSS_S_COMPLETE
   */
  if (maj & GSS_S_CONTINUE_NEEDED) {
    return 0;
  }
  if (GSS_ERROR(maj)) {
    err = krb5_get_gss_error("gss_init_sec_context", maj, min);
    return -1;
  }

  return 0;
}

int
Krb5AuthProvider::krb5_get_output_token_length()
{
  return krb5AuthData->output_token.length;
}

unsigned char *
Krb5AuthProvider::krb5_get_output_token_buffer()
{
  return (unsigned char *)krb5AuthData->output_token.value;
}

int
Krb5AuthProvider::negotiateReply(Smb2ContextPtr smb2, std::string& err)
{

  return krb5_negotiate_reply(smb2->server,
                              smb2->domain,
                              smb2->user,
                              smb2->password,
                              smb2->use_cached_creds,
                              err);

}

int
Krb5AuthProvider::sessionRequest(Smb2ContextPtr smb2,
                                 unsigned char  *inBuf,
                                 int            inBufLen,
                                 unsigned char  **outBuf,
                                 uint16_t       *outBufLen,
                                 std::string&   err)
{
  int ret = -1;
  ret = krb5_session_request(inBuf, inBufLen, err);
  if (ret < 0)
    return ret;

  if (outBuf)
    *outBufLen = krb5_get_output_token_length();
  if (outBufLen)
    *outBuf    = krb5_get_output_token_buffer();

  return 0;
}

int
Krb5AuthProvider::getSessionKey(Smb2ContextPtr  smb2,
                                uint8_t         **key,
                                uint8_t         *key_size,
                                std::string&    err)
{
  return krb5_session_get_session_key(key, key_size, err);
}
