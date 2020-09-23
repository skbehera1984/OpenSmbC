#ifndef _SMB2_DATA_FILE_H
#define _SMB2_DATA_FILE_H

#include <vector>
#include <string>
#include "PrivateData.h"
#include "Smb2Context.h"
#include "smb2.h"
#include "util.h"

int smb2_decode_file_basic_info(struct smb2_file_basic_info *fs, smb2_iovec *vec);
int smb2_decode_file_standard_info(struct smb2_file_standard_info *fs, smb2_iovec *vec);
int smb2_decode_file_all_info(struct smb2_file_all_info *fs, smb2_iovec *vec);

int smb2_encode_file_extended_info(Smb2ContextPtr smb2,
                                   struct smb2_file_extended_info *info,
                                   const int count,
                                   uint8_t *buffer,
                                   uint32_t *buffer_len);

int smb2_decode_file_extended_info(Smb2ContextPtr smb2,
                                   struct smb2_file_extended_info *info,
                                   smb2_iovec *vec);

int smb2_decode_file_full_ea_info(Smb2ContextPtr smb2,
                                  struct smb2_file_full_ea_info *info,
                                  smb2_iovec *vec);

int smb2_decode_file_stream_info(Smb2ContextPtr smb2,
                                 struct smb2_file_stream_info *info,
                                 smb2_iovec *vec);

int smb2_decode_file_full_stream_info(Smb2ContextPtr smb2,
                                      struct smb2_file_full_stream_info *info,
                                      smb2_iovec *vec);

int smb2_decode_file_fs_size_info(struct smb2_file_fs_size_info *fs, smb2_iovec *vec);
int smb2_decode_file_fs_device_info(struct smb2_file_fs_device_info *fs, smb2_iovec *vec);
int smb2_decode_file_fs_control_info(struct smb2_file_fs_control_info *fs, smb2_iovec *vec);
int smb2_decode_file_fs_full_size_info(struct smb2_file_fs_full_size_info *fs, smb2_iovec *vec);
int smb2_decode_file_fs_sector_size_info(struct smb2_file_fs_sector_size_info *fs, smb2_iovec *vec);

int smb2DecodeSecDescInternal(struct smb2_security_descriptor *sd,
                              smb2_iovec                      *vec,
                              std::string&                    error);

#endif /* _SMB2_DATA_FILE_H */
