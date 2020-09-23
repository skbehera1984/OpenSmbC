#ifndef _PRIVATE_DATA_H_
#define _PRIVATE_DATA_H_

#include <vector>

#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))

class smb2_iovec
{
public:
  smb2_iovec() {buf=NULL; len=0; free=NULL;}
  smb2_iovec(size_t size);
  smb2_iovec(uint8_t *buf, size_t len, void (*free)(void *));
  smb2_iovec& operator=(const smb2_iovec& obj);

  int smb2_set_uint8(int offset, uint8_t value);
  int smb2_set_uint16(int offset, uint16_t value);
  int smb2_set_uint32(int offset, uint32_t value);
  int smb2_set_uint64(int offset, uint64_t value);
  int smb2_get_uint8(int offset, uint8_t *value);
  int smb2_get_uint16(int offset, uint16_t *value);
  int smb2_get_uint32(int offset, uint32_t *value);
  int smb2_get_uint64(int offset, uint64_t *value);

public:
  uint8_t *buf;
  size_t len;
  void (*free)(void *);
};

class smb2_io_vectors
{
public:
  smb2_io_vectors();
  smb2_io_vectors& operator=(const smb2_io_vectors& obj);
  void smb2_free_iovector();
  void smb2_add_iovector(uint8_t *buf, int len, void (*free)(void *));
  void smb2_add_iovector(smb2_iovec &vec);
  void smb2_append_iovectors(smb2_io_vectors &iovecs);
  void smb2_pad_to_64bit();
  void clear();

public:
  size_t total_size;
  std::vector<smb2_iovec> iovs;
};

/* UCS2 is always in Little Endianness */
struct ucs2
{
  int len;
  uint16_t val[1];
};

/* Returns a string converted to UCS2 format. Use free() to release
 * the ucs2 string.
 */
struct ucs2 *utf8_to_ucs2(const char *utf8);

/* Returns a string converted to UTF8 format. Use free() to release
 * the utf8 string.
 */
char *ucs2_to_utf8(const uint16_t *str, int len);

/* Convert an smb2/nt error code into a string */
const char *nterror_to_str(uint32_t status);

/* Convert an smb2/nt error code into an errno value */
int nterror_to_errno(uint32_t status);

#endif
