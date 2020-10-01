#include <fcntl.h>
#include <inttypes.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

#include "smb2.h"
#include "util.h"

int usage(void)
{
  fprintf(stderr, "Usage:\n"
          "smb2-raw-stat-async <smb2-url>\n\n"
          "URL format: "
          "smb://[<domain;][<username>@]<host>/<share>/<path>\n");
  exit(1);
}

int main(int argc, char *argv[])
{
  std::string err;
  Smb2ContextPtr smb2;
  struct smb2_url *url;
  time_t t;

  if (argc < 2) {
    usage();
  }

  smb2 = Smb2Context::create();
  if (smb2 == NULL) {
    fprintf(stderr, "Failed to init context\n");
    exit(0);
  }

  url = smb2_parse_url(smb2, argv[1], err);
  if (url == NULL) {
    fprintf(stderr, "Failed to parse url: %s\n", err.c_str());
    exit(0);
  }

  if (!url->user.empty()) {
    smb2->smb2SetUser(url->user);
  }

  smb2->smb2SetSecurityMode(SMB2_NEGOTIATE_SIGNING_ENABLED);
  smb2->smb2SetPassword("");
  smb2->smb2SetAuthMode(SMB2_SEC_NTLMSSP);

  if (smb2->smb2_connect_share(url->server, url->share, url->user, err) != 0)
  {
    printf("smb2_connect_share failed. %s\n", err.c_str());
    exit(10);
  }

  struct smb2_file_info_all fs;
  if (smb2->smb2_getinfo_all(url->path, &fs, err) != 0)
  {
    printf("failed waiting for a reply. %s\n", err.c_str());
    exit(10);
  }

  /* Print the file_all_info structure */
  printf("Attributes: ");
  if (fs.file_attributes & SMB2_FILE_ATTRIBUTE_READONLY) {
    printf("READONLY ");
  }
  if (fs.file_attributes & SMB2_FILE_ATTRIBUTE_HIDDEN) {
    printf("HIDDEN ");
  }
  if (fs.file_attributes & SMB2_FILE_ATTRIBUTE_SYSTEM) {
    printf("SYSTEM ");
  }
  if (fs.file_attributes & SMB2_FILE_ATTRIBUTE_DIRECTORY) {
    printf("DIRECTORY ");
  }
  if (fs.file_attributes & SMB2_FILE_ATTRIBUTE_ARCHIVE) {
    printf("ARCHIVE ");
  }
  if (fs.file_attributes & SMB2_FILE_ATTRIBUTE_NORMAL) {
    printf("NORMAL ");
  }
  if (fs.file_attributes & SMB2_FILE_ATTRIBUTE_TEMPORARY) {
    printf("TMP ");
  }
  if (fs.file_attributes & SMB2_FILE_ATTRIBUTE_SPARSE_FILE) {
    printf("SPARSE ");
  }
  if (fs.file_attributes & SMB2_FILE_ATTRIBUTE_REPARSE_POINT) {
    printf("REPARSE ");
  }
  if (fs.file_attributes & SMB2_FILE_ATTRIBUTE_COMPRESSED) {
    printf("COMPRESSED ");
  }
  if (fs.file_attributes & SMB2_FILE_ATTRIBUTE_OFFLINE) {
    printf("OFFLINE ");
  }
  if (fs.file_attributes & SMB2_FILE_ATTRIBUTE_NOT_CONTENT_INDEXED) {
    printf("NOT_CONTENT_INDEXED ");
  }
  if (fs.file_attributes & SMB2_FILE_ATTRIBUTE_ENCRYPTED) {
    printf("ENCRYPTED ");
  }
  if (fs.file_attributes & SMB2_FILE_ATTRIBUTE_INTEGRITY_STREAM) {
    printf("INTEGRITY_STREAM ");
  }
  if (fs.file_attributes & SMB2_FILE_ATTRIBUTE_NO_SCRUB_DATA) {
    printf("NO_SCRUB_DATA ");
  }
  printf("\n");

  t = SMBTimeToUTime(fs.smb2_crtime);
  printf("Creation Time:    %s", asctime(localtime(&t)));
  t = SMBTimeToUTime(fs.smb2_atime);
  printf("Last Access Time: %s", asctime(localtime(&t)));
  t = SMBTimeToUTime(fs.smb2_mtime);
  printf("Last Write Time:  %s", asctime(localtime(&t)));
  t = SMBTimeToUTime(fs.smb2_ctime);
  printf("Change Time:      %s", asctime(localtime(&t)));

  printf("Allocation Size: %" PRIu64 "\n", fs.allocation_size);
  printf("End Of File:     %" PRIu64 "\n", fs.end_of_file);
  printf("Number Of Links: %d\n", fs.smb2_nlink);
  printf("Delete Pending:  %s\n", fs.delete_pending ? "YES" : "NO");
  printf("Directory:       %s\n", fs.directory ? "YES" : "NO");

  printf("Inode Number: 0x%016" PRIx64 "\n", fs.smb2_ino);
  printf("EA Size : %d\n", fs.ea_size);

  printf("Access Flags: ");
  if (fs.directory)
  {
    if (fs.access_flags & SMB2_FILE_LIST_DIRECTORY) {
      printf("LIST_DIRECTORY ");
    }
    if (fs.access_flags & SMB2_FILE_ADD_FILE) {
      printf("ADD_FILE ");
    }
    if (fs.access_flags & SMB2_FILE_ADD_SUBDIRECTORY) {
      printf("ADD_SUBDIRECTORY ");
    }
    if (fs.access_flags & SMB2_FILE_TRAVERSE) {
      printf("TRAVERSE ");
    }
  }
  else
  {
    if (fs.access_flags & SMB2_FILE_READ_DATA) {
      printf("READ_DATA ");
    }
    if (fs.access_flags & SMB2_FILE_WRITE_DATA) {
      printf("WRITE_DATA ");
    }
    if (fs.access_flags & SMB2_FILE_APPEND_DATA) {
      printf("APPEND_DATA ");
    }
    if (fs.access_flags & SMB2_FILE_EXECUTE) {
      printf("FILE_EXECUTE ");
    }
  }
  if (fs.access_flags & SMB2_FILE_READ_EA) {
    printf("READ_EA ");
  }
  if (fs.access_flags & SMB2_FILE_WRITE_EA) {
    printf("WRITE_EA ");
  }
  if (fs.access_flags & SMB2_FILE_READ_ATTRIBUTES) {
    printf("READ_ATTRIBUTES ");
  }
  if (fs.access_flags & SMB2_FILE_WRITE_ATTRIBUTES) {
    printf("WRITE_ATTRIBUTES ");
  }
  if (fs.access_flags & SMB2_FILE_DELETE_CHILD) {
    printf("DELETE_CHILD ");
  }
  if (fs.access_flags & SMB2_DELETE) {
    printf("DELETE ");
  }
  if (fs.access_flags & SMB2_READ_CONTROL) {
    printf("READ_CONTROL ");
  }
  if (fs.access_flags & SMB2_WRITE_DACL) {
    printf("WRITE_DACL ");
  }
  if (fs.access_flags & SMB2_WRITE_OWNER) {
    printf("WRITE_OWNER ");
  }
  if (fs.access_flags & SMB2_SYNCHRONIZE) {
    printf("SYNCHRONIZE ");
  }
  if (fs.access_flags & SMB2_ACCESS_SYSTEM_SECURITY) {
    printf("ACCESS_SYSTEM_SECURITY ");
  }
  if (fs.access_flags & SMB2_MAXIMUM_ALLOWED) {
    printf("MAXIMUM_ALLOWED ");
  }
  if (fs.access_flags & SMB2_GENERIC_ALL) {
    printf("GENERIC_ALL ");
  }
  if (fs.access_flags & SMB2_GENERIC_EXECUTE) {
    printf("GENERIC_EXECUTE ");
  }
  if (fs.access_flags & SMB2_GENERIC_WRITE) {
    printf("GENERIC_WRITE ");
  }
  if (fs.access_flags & SMB2_GENERIC_READ) {
    printf("GENERIC_READ ");
  }
  printf("\n");

  printf("Mode: ");
  if (fs.access_flags & SMB2_FILE_WRITE_THROUGH) {
    printf("WRITE_THROUGH ");
  }
  if (fs.access_flags & SMB2_FILE_SEQUENTIAL_ONLY) {
    printf("SEQUENTIAL_ONLY ");
  }
  if (fs.access_flags & SMB2_FILE_NO_INTERMEDIATE_BUFFERING) {
    printf("NO_INTERMEDIATE_BUFFERING ");
  }
  if (fs.access_flags & SMB2_FILE_SYNCHRONOUS_IO_ALERT) {
    printf("SYNCHRONOUS_IO_ALERT ");
  }
  if (fs.access_flags & SMB2_FILE_SYNCHRONOUS_IO_NONALERT) {
    printf("SYNCHRONOUS_IO_NONALERT ");
  }
  if (fs.access_flags & SMB2_FILE_DELETE_ON_CLOSE) {
    printf("DELETE_ON_CLOSE ");
  }
  printf("\n");

  smb2->smb2_disconnect_share();
  smb2_destroy_url(url);

  return 0;
}
