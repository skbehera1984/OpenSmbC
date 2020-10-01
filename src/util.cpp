#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdio.h>

#include "util.h"
#include "Stringf.h"
#include "smb2.h"
#include "PrivateData.h"

#define MAX_URL_SIZE 256

static int
smb2_parse_args(Smb2ContextPtr smb2, char *args, std::string& error)
{
  while (args && *args != 0)
  {
    char *next, *value;

    next = strchr(args, '&');
    if (next)
    {
      *(next++) = '\0';
    }

    value = strchr(args, '=');
    if (value)
    {
      *(value++) = '\0';
    }

    if (!strcmp(args, "sec"))
    {
      if(!strcmp(value, "krb5"))
      {
        smb2->sec = SMB2_SEC_KRB5;
      }
      else if (!strcmp(value, "krb5cc"))
      {
        smb2->sec = SMB2_SEC_KRB5;
        smb2->use_cached_creds = true;
      }
      else if (!strcmp(value, "ntlmssp"))
      {
        smb2->sec = SMB2_SEC_NTLMSSP;
      }
      else
      {
        error = stringf("Unknown sec= argument: %s", value);
        return -1;
      }
    }
    else if (!strcmp(args, "vers"))
    {
      if(!strcmp(value, "2"))
      {
        smb2->version = SMB2_VERSION_ANY2;
      }
      else if (!strcmp(value, "3"))
      {
        smb2->version = SMB2_VERSION_ANY3;
      }
      else if (!strcmp(value, "2.02"))
      {
        smb2->version = SMB2_VERSION_0202;
      }
      else if (!strcmp(value, "2.10"))
      {
        smb2->version = SMB2_VERSION_0210;
      }
      else if (!strcmp(value, "3.0") || !strcmp(value, "3.00"))
      {
        smb2->version = SMB2_VERSION_0300;
      }
      else if(!strcmp(value, "3.02"))
      {
        smb2->version = SMB2_VERSION_0302;
      }
      else if (!strcmp(value, "3.11"))
      {
        smb2->version = SMB2_VERSION_0311;
      }
      else
      {
        error = stringf("Unknown vers= argument: %s", value);
        return -1;
      }
    }
    else
    {
      error = stringf("Unknown argument: %s", args);
      return -1;
    }
    args = next;
  }

  return 0;
}

smb2_url *smb2_parse_url(Smb2ContextPtr smb2, const char *url, std::string& error)
{
  smb2_url *u;
  char *ptr, *tmp, str[MAX_URL_SIZE];
  char *args;

  if (strncmp(url, "smb://", 6))
  {
    error = "URL does not start with 'smb://'";
    return NULL;
  }
  if (strlen(url + 6) >= MAX_URL_SIZE)
  {
    error = "URL is too long";
    return NULL;
  }
  strncpy(str, url + 6, MAX_URL_SIZE);

  args = strchr(str, '?');
  if (args)
  {
    *(args++) = '\0';
    if (smb2_parse_args(smb2, args, error) != 0)
    {
      return NULL;
    }
  }

  u = new smb2_url();
  if (u == nullptr)
  {
    error = "Failed to allocate smb2_url";
    return NULL;
  }

  ptr = str;

  /* domain */
  if ((tmp = strchr(ptr, ';')) != NULL)
  {
    *(tmp++) = '\0';
    u->domain = std::string(ptr);
    ptr = tmp;
  }
  /* user */
  if ((tmp = strchr(ptr, '@')) != NULL)
  {
    *(tmp++) = '\0';
    u->user = std::string(ptr);
    ptr = tmp;
  }
  /* server */
  if ((tmp = strchr(ptr, '/')) != NULL)
  {
    *(tmp++) = '\0';
    u->server = std::string(ptr);
    ptr = tmp;
  }

  /* Do we just have a share or do we have both a share and an object */
  tmp = strchr(ptr, '/');

  /* We only have a share */
  if (tmp == NULL)
  {
    u->share = std::string(ptr);
    return u;
  }

  /* we have both share and object path */
  *(tmp++) = '\0';
  u->share = std::string(ptr);
  u->path = std::string(tmp);

  return u;
}

void smb2_destroy_url(smb2_url *url)
{
  if (url == nullptr)
    return;

  delete url;
}

uint64_t timevalToWinEpoch(struct smb2_timeval *tv)
{
  return ((uint64_t)tv->tv_sec * 10000000) + 116444736000000000 + tv->tv_usec * 10;
}

void winEpochToTimeval(uint64_t smb2_time, struct smb2_timeval *tv)
{
  tv->tv_usec = (smb2_time / 10) % 1000000;
  tv->tv_sec  = (smb2_time - 116444736000000000) / 10000000;
}

time_t SMBTimeToUTime(uint64_t smb_time)
{
  //return smb_time/10000000 - 116444736000000000;
  return (smb_time - 116444736000000000)/10000000;
}

uint64_t UTimeToSMBTime(time_t utime)
{
  //return (utime + 116444736000000000)*10000000;
  return (utime * 10000000) + 116444736000000000;
}

///////////////////////////// UNICODE /////////////////////

/* Count number of leading 1 bits in the char */
static int l1(char c)
{
  int i = 0;
  while (c & 0x80)
  {
    i++;
    c <<= 1;
  }
  return i;
}

/* Validates that utf8 points to a valid utf8 codepoint.
 * Will update **utf8 to point at the next character in the string.
 * return 0 if the encoding is valid and
 * -1 if not.
 * If the encoding is valid the codepoint will be returned in *cp.
 */
static int
validate_utf8_cp(const char **utf8, uint16_t *cp)
{
  int c = *(*utf8)++;
  int l = l1(c);

  switch (l)
  {
    case 0:
      /* 7-bit ascii is always ok */
      *cp = c & 0x7f;
      return 0;
    case 1:
      /* 10.. .... can never start a new codepoint */
      return -1;
    case 2:
    case 3:
      *cp = c & 0x1f;
      /* 2 and 3 byte sequences must always be followed by exactly
       * 1 or 2 chars matching 10.. ....
       */
      while(--l)
      {
        c = *(*utf8)++;
        if (l1(c) != 1)
        {
          return -1;
        }
        *cp <<= 6;
        *cp |= (c & 0x3f);
      }
      return 0;
  }
  return -1;
}

/* Validate that the given string is properly formated UTF8.
 * Returns >=0 if valid UTF8 and -1 if not.
 */
static int
validate_utf8_str(const char *utf8)
{
  const char *u = utf8;
  int i = 0;
  uint16_t cp;

  while (*u)
  {
    if (validate_utf8_cp(&u, &cp) < 0)
    {
      return -1;
    }
    i++;
  }
  return i;
}

/* Convert a UTF8 string into UCS2 Little Endian */
struct ucs2 *
utf8_to_ucs2(const char *utf8)
{
  struct ucs2 *ucs2;
  int i, len;

  len = validate_utf8_str(utf8);
  if (len < 0)
  {
    return NULL;
  }

  ucs2 = (struct ucs2*)malloc(offsetof(struct ucs2, val) + 2 * len);
  if (ucs2 == NULL)
  {
    return NULL;
  }

  ucs2->len = len;
  for (i = 0; i < len; i++)
  {
    validate_utf8_cp(&utf8, &ucs2->val[i]);
    ucs2->val[i] = htole32(ucs2->val[i]);
  }

  return ucs2;
}

/* Returns how many bytes we need to store a UCS2 codepoint
 */
static int
ucs2_cp_size(uint16_t cp)
{
  if (cp > 0x07ff)
  {
    return 3;
  }
  if (cp > 0x007f)
  {
    return 2;
  }
  return 1;
}

/* Convert a UCS2 string into UTF8
 */
char *
ucs2_to_utf8(const uint16_t *ucs2, int ucs2_len)
{
  int i, utf8_len = 1;
  char *str, *tmp;

  /* How many bytes do we need for utf8 ? */
  for (i = 0; i < ucs2_len; i++)
  {
    utf8_len += ucs2_cp_size(ucs2[i]);
  }
  str = tmp = (char*)malloc(utf8_len);
  if (str == NULL)
  {
    return NULL;
  }
  str[utf8_len - 1] = 0;

  for (i = 0; i < ucs2_len; i++)
  {
    uint16_t c = le32toh(ucs2[i]);
    int l = ucs2_cp_size(c);

    switch (l)
    {
      case 3:
        *tmp++ = 0xe0 |  (c >> 12);
        *tmp++ = 0x80 | ((c >>  6) & 0xbf);
        *tmp++ = 0x80 | ((c      ) & 0xbf);
      break;
      case 2:
        *tmp++ = 0xc0 |  (c >> 6);
        *tmp++ = 0x80 | ((c     ) & 0xbf);
      break;
      case 1:
        *tmp++ = c;
      break;
    }
  }

  return str;
}
