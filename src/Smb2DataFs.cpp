#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include "Smb2FileData.h"

int
smb2_decode_file_fs_size_info(struct smb2_file_fs_size_info *fs, smb2_iovec *vec)
{
  if (vec->len < 24)
    return -1;

  vec->smb2_get_uint64(0, &fs->total_allocation_units);
  vec->smb2_get_uint64(8, &fs->available_allocation_units);
  vec->smb2_get_uint32(16, &fs->sectors_per_allocation_unit);
  vec->smb2_get_uint32(20, &fs->bytes_per_sector);

  return 0;
}

int
smb2_decode_file_fs_device_info(struct smb2_file_fs_device_info *fs, smb2_iovec *vec)
{
  if (vec->len < 8)
    return -1;

  vec->smb2_get_uint32(0, &fs->device_type);
  vec->smb2_get_uint32(4, &fs->characteristics);

  return 0;
}

int
smb2_decode_file_fs_control_info(struct smb2_file_fs_control_info *fs, smb2_iovec *vec)
{
  if (vec->len < 48)
    return -1;

  vec->smb2_get_uint64(0, &fs->free_space_start_filtering);
  vec->smb2_get_uint64(8, &fs->free_space_threshold);
  vec->smb2_get_uint64(16, &fs->free_space_stop_filtering);
  vec->smb2_get_uint64(24, &fs->default_quota_threshold);
  vec->smb2_get_uint64(32, &fs->default_quota_limit);
  vec->smb2_get_uint32(40, &fs->file_system_control_flags);

  return 0;
}

int
smb2_decode_file_fs_full_size_info(struct smb2_file_fs_full_size_info *fs, smb2_iovec *vec)
{
  if (vec->len < 32)
    return -1;

  vec->smb2_get_uint64(0, &fs->total_allocation_units);
  vec->smb2_get_uint64(8, &fs->caller_available_allocation_units);
  vec->smb2_get_uint64(16, &fs->actual_available_allocation_units);
  vec->smb2_get_uint32(24, &fs->sectors_per_allocation_unit);
  vec->smb2_get_uint32(28, &fs->bytes_per_sector);

  return 0;
}

int
smb2_decode_file_fs_sector_size_info(struct smb2_file_fs_sector_size_info *fs, smb2_iovec *vec)
{
  if (vec->len < 28)
    return -1;

  vec->smb2_get_uint32(0, &fs->logical_bytes_per_sector);
  vec->smb2_get_uint32(4, &fs->physical_bytes_per_sector_for_atomicity);
  vec->smb2_get_uint32(8, &fs->physical_bytes_per_sector_for_performance);
  vec->smb2_get_uint32(12, &fs->file_system_effective_physical_bytes_per_sector_for_atomicity);
  vec->smb2_get_uint32(16, &fs->flags);
  vec->smb2_get_uint32(20, &fs->byte_offset_for_sector_alignment);
  vec->smb2_get_uint32(24, &fs->byte_offset_for_partition_alignment);

  return 0;
}
