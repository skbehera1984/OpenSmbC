#ifndef _APP_DATA_H_
#define _APP_DATA_H_

#include "DataTypes.h"

class AppData
{
public:
  AppData() { ntStatus = 0; bDelete = false; }
  virtual ~AppData() {}

  // common apis
  virtual void    setFH(smb2fh *fh) {}
  virtual smb2fh* getFH() { return nullptr; }
  // query dir
  virtual void setSearchPattern(std::string pattern) {}
  virtual std::string getSearchPattern() { return ""; }
  virtual void setDir(smb2dir *dir) {}
  virtual smb2dir* getDir() { return nullptr; }
  // create
  virtual void setCloseFh(bool bclose) {}
  virtual bool ifCloseFh() { return false; }
  // read
  virtual void setReadBuf(uint8_t *buf) {}
  virtual uint8_t* getReadBuf() { return nullptr; }
  // queryinfo
  virtual void setQInfo(smb2_file_info *info) {}
  virtual smb2_file_info* getQInfo() { return nullptr; }
  // ioctl
  virtual void setOutBuf(uint8_t *buf, uint32_t *bufLen) {}
  virtual uint8_t* getOutBuf() { return nullptr; }
  virtual uint32_t* getOutBufLen() { return nullptr; }

  void     setNtStatus(uint32_t sts) { ntStatus = sts; }
  uint32_t getNtStatus() { return ntStatus; }
  void     setErrorMsg(std::string msg) { errMsg = msg; }
  void     appendErrorMsg(std::string msg) { errMsg += msg; }
  void     setStatusMsg(uint32_t sts, std::string msg) { ntStatus = sts; errMsg = msg; }
  std::string getErrorMsg() { return errMsg; }

  /* App data may be local data from an API i.e not allocated.
   * But in compound requests it may be allocated and needs to be freed
   * pdu deallocation will free it up.
   */
  void     setDelete(bool del) { bDelete = del; }
  bool     isDelete() { return bDelete; }

public:
  uint32_t    ntStatus;
  bool        bDelete;
  std::string errMsg;
};

/* These are data specific to one command
 * Each will hold data/buffers sent by the calling api
 * in order to send or receive data
 *
 * PDU will free this data but not what it holds, they belong to the API
 * there must be a specific data per pdu even if the cmd is recurring
 */
class CreateData : public AppData
{
public:
  CreateData() { fh = nullptr; bCloseFh = false; }
  virtual ~CreateData() {}

  void    setFH(smb2fh *fh) { this->fh = fh; }
  smb2fh* getFH()  { return fh; }
  void    setCloseFh(bool bclose) { this->bCloseFh = bclose; }
  bool    ifCloseFh() { return bCloseFh; }

  smb2fh *fh; // may be set to null in a compound request
  bool   bCloseFh;
};

class ReadData : public AppData
{
public:
  ReadData() { fh = nullptr; readBuf = nullptr; }
  virtual ~ReadData() {}

  void    setFH(smb2fh *fh) { this->fh = fh; }
  smb2fh* getFH()  { return fh; }
  void    setReadBuf(uint8_t *buf) { this->readBuf = buf; }
  uint8_t* getReadBuf() { return readBuf; }

  smb2fh  *fh;
  uint8_t *readBuf;
};

class WriteData : public AppData
{
public:
  WriteData() { fh = nullptr; }
  virtual ~WriteData() {}

  void    setFH(smb2fh *fh) { this->fh = fh; }
  smb2fh* getFH()  { return fh; }

  smb2fh *fh;
};

class CloseData : public AppData
{
public:
  CloseData() { fh = nullptr; }
  virtual ~CloseData() {}

  void    setFH(smb2fh *fh) { this->fh = fh; }
  smb2fh* getFH()  { return fh; }

  smb2fh *fh;
};

class QueryInfoData : public AppData
{
public:
  QueryInfoData() { info = nullptr; }
  virtual ~QueryInfoData() {}

  void setQInfo(smb2_file_info *info) { this->info = info; }
  smb2_file_info* getQInfo() { return info; }

  smb2_file_info *info;
};

class QueryDirData : public AppData
{
public:
  QueryDirData() {}
  virtual ~QueryDirData() {}

  void    setFH(smb2fh *fh) { this->fh = fh; }
  smb2fh* getFH()  { return fh; }
  void    setSearchPattern(std::string pattern) { this->pattern = pattern; }
  std::string getSearchPattern() { return pattern; }
  void    setDir(smb2dir *dir) { this->dir = dir; }
  smb2dir* getDir() { return dir; }

  smb2fh      *fh;
  std::string pattern;
  smb2dir     *dir;
};

class IoctlData : public AppData
{
public:
  IoctlData() { output_buffer = nullptr; output_count = nullptr; }
  virtual ~IoctlData() {}

  void setOutBuf(uint8_t *buf, uint32_t *bufLen)
  {
    output_buffer = buf;
    output_count = bufLen;
  }
  uint8_t* getOutBuf() { return output_buffer; }
  uint32_t* getOutBufLen() { return output_count; }

  uint8_t  *output_buffer;
  uint32_t *output_count;
};

#endif // _APP_DATA_H_
