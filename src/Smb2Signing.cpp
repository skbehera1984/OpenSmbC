#ifdef HAVE_OPENSSL_LIBS

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "Smb2Signing.h"
#include "Smb2Pdu.h"
#include "Stringf.h"

#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/opensslv.h>

#define OPENSSL_VER_101	0x1000109fL
#define OPENSSL_VER_102	0x10002100L

#define AES128_KEY_LEN     16

using namespace std;

#define FUNC stringf("%s: ", __func__)

static
int aes_cmac_shift_left(uint8_t data[AES128_KEY_LEN])
{
        int i = 0;
        int cin = 0;
        int cout = 0;

        for (i = AES128_KEY_LEN - 1; i >= 0; i--) {
            cout = ((int) data[i] & 0x80) >> 7;
            data[i] = (data[i] << 1) | cin;
            cin = cout;
        }

        return cout;
}

static
void aes_cmac_xor(
    uint8_t data[AES128_KEY_LEN],
    const uint8_t value[AES128_KEY_LEN]
    )
{
        int i = 0;

        for (i = 0; i < AES128_KEY_LEN; i++) {
            data[i] ^= value[i];
        }
}

static
void aes_cmac_sub_keys(
    uint8_t key[AES128_KEY_LEN],
    uint8_t sub_key1[AES128_KEY_LEN],
    uint8_t sub_key2[AES128_KEY_LEN]
    )
{
        AES_KEY aes_key;
        static const uint8_t zero[AES128_KEY_LEN] = {0};
        static const uint8_t rb[AES128_KEY_LEN] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x87};

        AES_set_encrypt_key(key, 128, &aes_key);
        AES_encrypt(zero, sub_key1, &aes_key);

        if (aes_cmac_shift_left(sub_key1)) {
                aes_cmac_xor(sub_key1, rb);
        }

        memcpy(sub_key2, sub_key1, AES128_KEY_LEN);

        if (aes_cmac_shift_left(sub_key2)) {
                aes_cmac_xor(sub_key2, rb);
        }
}

void smb3_aes_cmac_128(uint8_t key[AES128_KEY_LEN],
                   uint8_t * msg,
                   uint64_t msg_len,
                   uint8_t mac[AES128_KEY_LEN]
                  )
{
        AES_KEY aes_key;
        uint8_t sub_key1[AES128_KEY_LEN] = {0};
        uint8_t sub_key2[AES128_KEY_LEN] = {0};
        uint8_t scratch[AES128_KEY_LEN] = {0};
        uint64_t n = (msg_len + AES128_KEY_LEN - 1) / AES128_KEY_LEN;
        uint64_t rem = msg_len % AES128_KEY_LEN;
        uint64_t i = 0;
        int is_last_block_complete = n != 0 && rem == 0;

        if (n == 0) {
                n = 1;
        }

        aes_cmac_sub_keys(key, sub_key1, sub_key2);

        memset(mac, 0, AES128_KEY_LEN);

        AES_set_encrypt_key(key, 128, &aes_key);

        for (i = 0; i < n - 1; i++) {
                aes_cmac_xor(mac, &msg[i*AES128_KEY_LEN]);
                AES_encrypt(mac, scratch, &aes_key);
                memcpy(mac, scratch, AES128_KEY_LEN);
        }

        if (is_last_block_complete) {
                memcpy(scratch, &msg[i*AES128_KEY_LEN], AES128_KEY_LEN);
                aes_cmac_xor(scratch, sub_key1);
        } else {
                memcpy(scratch, &msg[i*AES128_KEY_LEN], rem);
                scratch[rem] = 0x80;
                memset(&scratch[rem + 1], 0, AES128_KEY_LEN - (rem + 1));
                aes_cmac_xor(scratch, sub_key2);
        }

        aes_cmac_xor(mac, scratch);
        AES_encrypt(mac, scratch, &aes_key);
        memcpy(mac, scratch, AES128_KEY_LEN);
}

bool
smb2_pdu_add_signature(Smb2ContextPtr smb2, Smb2Pdu *pdu, std::string& error)
{
        struct smb2_header *hdr = NULL;
        uint8_t signature[16];

        if (pdu->header.command == SMB2_SESSION_SETUP) {
                return true;
        }
        if (pdu->out.iovs.size() < 2) {
                error = FUNC + "Too few vectors to sign";
                return false;
        }
        if (pdu->out.iovs[0].len != SMB2_HEADER_SIZE) {
                error = FUNC + "First vector is not same size as smb2 header";
                return false;
        }
        if (smb2->session_id == 0) {
                return true; /* DO NOT sign the PDU if session id is 0 */
        }
        if (smb2->session_key_size == 0) {
                return false;
        }

        hdr = &pdu->header;

        smb2_iovec iov = pdu->out.iovs[0];
        /* Set the flag before calculating signature */
        hdr->flags |= SMB2_FLAGS_SIGNED;
        iov.smb2_set_uint32(16, hdr->flags);

        /* sign the pdu and store the signature in pdu->header.signature
         * if pdu is signed then add SMB2_FLAGS_SIGNED to pdu->header.flags
         */

        if (smb2->dialect > SMB2_VERSION_0210) {
                int offset = 0;
                uint8_t aes_mac[AES_BLOCK_SIZE];
                /* combine the buffers into one */
                uint8_t *msg = NULL;
                msg = (uint8_t *) malloc(4);
                if (msg == NULL) {
                        error = FUNC + "Failed to allocate buffer";
                        return false;
                }

                for (smb2_iovec &v : pdu->out.iovs)
                {
                  msg = (uint8_t *)realloc(msg, offset + v.len);
                  if (msg == NULL) {
                    error = FUNC + "Failed to re-allocate buffer";
                    return false;
                  }
                  memcpy(msg+offset, v.buf, v.len);
                  offset += v.len;
                }
                smb3_aes_cmac_128(smb2->signing_key, msg, offset, aes_mac);
                free(msg);
                memcpy(&signature[0], aes_mac, SMB2_SIGNATURE_SIZE);
        } else {
                uint8_t sha_digest[SHA256_DIGEST_LENGTH];
                unsigned int sha_digest_length = SHA256_DIGEST_LENGTH;
#if (OPENSSL_VERSION_NUMBER <= OPENSSL_VER_102)
                HMAC_CTX ctx;
                HMAC_CTX_init(&ctx);
                HMAC_Init_ex(&ctx, &smb2->signing_key[0], SMB2_KEY_SIZE, EVP_sha256(), NULL);
                for (smb2_iovec &v : pdu->out.iovs)
                {
                  HMAC_Update(&ctx, v.buf, v.len);
                }
                HMAC_Final(&ctx, &sha_digest[0], &sha_digest_length);
                HMAC_CTX_cleanup(&ctx);
#else
                HMAC_CTX *ctx = HMAC_CTX_new();
                HMAC_CTX_reset(ctx);
                HMAC_Init_ex(ctx, &smb2->signing_key[0], SMB2_KEY_SIZE, EVP_sha256(), NULL);
                for (smb2_iovec &v : pdu->out.iovs)
                {
                  HMAC_Update(ctx, v.buf, v.len);
                }
                HMAC_Final(ctx, &sha_digest[0], &sha_digest_length);
                HMAC_CTX_free(ctx); ctx = NULL;
#endif
                memcpy(&signature[0], sha_digest, SMB2_SIGNATURE_SIZE);
        }

        memcpy(&(hdr->signature[0]), signature, SMB2_SIGNATURE_SIZE);
        memcpy(iov.buf + 48, hdr->signature, 16);

        return true;
}

bool
smb2_pdu_check_signature(Smb2ContextPtr smb2, Smb2Pdu *pdu, std::string& err)
{
  return false;
}

#endif /* HAVE_OPENSSL_LIBS */
