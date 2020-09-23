#include <errno.h>
#include <stdint.h>
#include <sys/socket.h>

#include "smb2.h"

const char *nterror_to_str(uint32_t status)
{
  switch (status)
  {
    case SMB2_STATUS_SUCCESS:
      return "STATUS_SUCCESS";
    case SMB2_STATUS_PENDING:
      return "STATUS_PENDING";
    case SMB2_STATUS_NO_MORE_FILES:
      return "STATUS_NO_MORE_FILES";
    case SMB2_STATUS_NO_MORE_EAS:
      return "STATUS_NO_MORE_EAS";
    case SMB2_STATUS_INVALID_PARAMETER:
      return "STATUS_INVALID_PARAMETER";
    case SMB2_STATUS_NO_SUCH_FILE:
      return "STATUS_NO_SUCH_FILE";
    case SMB2_STATUS_END_OF_FILE:
      return "STATUS_END_OF_FILE";
    case SMB2_STATUS_MORE_PROCESSING_REQUIRED:
      return "STATUS_MORE_PROCESSING_REQUIRED";
    case SMB2_STATUS_ACCESS_DENIED:
      return "STATUS_ACCESS_DENIED";
    case SMB2_STATUS_OBJECT_NAME_NOT_FOUND:
      return "STATUS_OBJECT_NAME_NOT_FOUND";
    case SMB2_STATUS_OBJECT_NAME_COLLISION:
      return "STATUS_OBJECT_NAME_COLLISION";
    case SMB2_STATUS_OBJECT_PATH_NOT_FOUND:
      return "STATUS_OBJECT_PATH_NOT_FOUND";
    case SMB2_STATUS_SHARING_VIOLATION:
      return "STATUS_SHARING_VIOLATION";
    case SMB2_STATUS_QUOTA_EXCEEDED:
      return "STATUS_QUOTA_EXCEEDED";
    case SMB2_STATUS_NO_EAS_ON_FILE:
      return "STATUS_NO_EAS_ON_FILE";
    case SMB2_STATUS_LOGON_FAILURE:
      return "STATUS_LOGON_FAILURE";
    case SMB2_STATUS_ALLOTTED_SPACE_EXCEEDED:
      return "STATUS_ALLOTTED_SPACE_EXCEEDED";
    case SMB2_STATUS_INSUFFICIENT_RESOURCES:
      return "STATUS_INSUFFICIENT_RESOURCES";
    case SMB2_STATUS_BAD_NETWORK_NAME:
      return "STATUS_BAD_NETWORK_NAME";
    case SMB2_STATUS_NOT_A_DIRECTORY:
      return "STATUS_NOT_A_DIRECTORY";
    case SMB2_STATUS_FILE_CLOSED:
      return "STATUS_FILE_CLOSED";
    case SMB2_STATUS_NO_MEMORY:
      return "STATUS_NO_MEMORY";
    case SMB2_STATUS_INVALID_CONNECTION:
      return "STATUS_INVALID_CONNECTION";
    case SMB2_STATUS_CONNECTION_DISCONNECTED:
      return "STATUS_CONNECTION_DISCONNECTED";
    case SMB2_STATUS_NO_USER_SESSION_KEY:
      return "STATUS_NO_USER_SESSION_KEY";
    case SMB2_STATUS_NOT_SUPPORTED:
      return "STATUS_NOT_SUPPORTED";
    default:
      return "Unknown";
  }
}

int nterror_to_errno(uint32_t status)
{
  switch (status)
  {
    case SMB2_STATUS_SUCCESS:
    case SMB2_STATUS_END_OF_FILE:
      return 0;
    case SMB2_STATUS_BAD_NETWORK_NAME:
    case SMB2_STATUS_OBJECT_NAME_NOT_FOUND:
      return ENOENT;
    case SMB2_STATUS_FILE_CLOSED:
      return EBADF;
    case SMB2_STATUS_MORE_PROCESSING_REQUIRED:
      return EAGAIN;
    case SMB2_STATUS_ACCESS_DENIED:
      return EACCES;
    case SMB2_STATUS_PENDING:
      return EAGAIN;
    case SMB2_STATUS_NO_MORE_FILES:
      return ENODATA;
    case SMB2_STATUS_LOGON_FAILURE:
      return ECONNREFUSED;
    case SMB2_STATUS_NOT_A_DIRECTORY:
      return ENOTDIR;
    case SMB2_STATUS_INVALID_PARAMETER:
      return EINVAL;
    default:
      return EIO;
  }
}
