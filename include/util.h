#ifndef _UTIL_H_
#define _UTIL_H_

#include "Smb2Context.h"

/*
 * This function is used to parse an SMB2 URL into as smb2_url structure.
 * SMB2 URL format :
 * smb2://[<domain;][<username>@]<host>/<share>/<path>
 *
 * The returned structure is freed by calling smb2_destroy_url()
 */
smb2_url *smb2_parse_url(Smb2ContextPtr smb2, const char *url, std::string& error);
void smb2_destroy_url(smb2_url *url);

void     winEpochToTimeval(uint64_t smb2_time, struct smb2_timeval *tv);
uint64_t timevalToWinEpoch(struct smb2_timeval *tv);
time_t   SMBTimeToUTime(uint64_t smb_time);
uint64_t UTimeToSMBTime(time_t utime);

void printSecurityDescriptor(struct smb2_security_descriptor *sd);

int smb2DecodeSecurityDescriptor(struct smb2_security_descriptor **sd,
                                 uint8_t *buf, uint32_t buf_len,
                                 std::string& error);
int smb2EncodeSecurityDescriptor(smb2_security_descriptor *sd,
                                 uint8_t                  *encoded_sec,
                                 uint32_t                 *encoded_sec_len,
                                 std::string              &error);
void smb2FreeSecurityDescriptor(struct smb2_security_descriptor *sd);

void smb2FreeFileExtendedInfo(struct smb2_file_extended_info *extended_info);
void smb2FreeFileStreamInfo(struct smb2_file_stream_info *stream_info);

#endif // _UTIL_H_
