#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <string.h>
#include "Smb2FileData.h"

int
smb2_decode_file_basic_info(struct smb2_file_basic_info *fs, smb2_iovec *vec)
{
  vec->smb2_get_uint64(0, &fs->creation_time);
  vec->smb2_get_uint64(8, &fs->last_access_time);
  vec->smb2_get_uint64(16, &fs->last_write_time);
  vec->smb2_get_uint64(24, &fs->change_time);
  vec->smb2_get_uint32(32, &fs->file_attributes);

  return 0;
}

int
smb2_decode_file_standard_info(struct smb2_file_standard_info *fs, smb2_iovec *vec)
{
  vec->smb2_get_uint64(0, &fs->allocation_size);
  vec->smb2_get_uint64(8, &fs->end_of_file);
  vec->smb2_get_uint32(16, &fs->number_of_links);
  vec->smb2_get_uint8(20, &fs->delete_pending);
  vec->smb2_get_uint8(21, &fs->directory);

  return 0;
}

int
smb2_decode_file_extended_info(Smb2ContextPtr smb2,
                               struct smb2_file_extended_info *info,
                               smb2_iovec *vec)
{
        uint32_t offset = 0;
        struct smb2_file_extended_info *node = info;
        struct smb2_file_extended_info *next_node = NULL;
        struct smb2_file_full_ea_info full_ea_info;

        do {
                smb2_iovec tmp_vec;

                /* Make sure we do not go beyond end of vector */
                if (offset >= vec->len) {
                        smb2->smb2_set_error("Malformed query reply.");
                        return -1;
                }

                tmp_vec.buf = &vec->buf[offset];
                tmp_vec.len = vec->len - offset;

                smb2_decode_file_full_ea_info(smb2, &full_ea_info, &tmp_vec);
                node->name = full_ea_info.ea_name;
                node->name_len = full_ea_info.ea_name_length;
                node->value = full_ea_info.ea_value;
                node->value_len = full_ea_info.ea_value_length;
                node->next = NULL;

                offset += full_ea_info.next_entry_offset;
                if ( full_ea_info.next_entry_offset != 0 )
                {
                        next_node = (struct smb2_file_extended_info*)malloc(sizeof(struct smb2_file_extended_info));
                        if (next_node == NULL) {
                                smb2FreeFileExtendedInfo(info);
                                smb2->smb2_set_error("Failed to allocate smb2_file_extended_info");
                                return -1;
                        }
                        memset(next_node, 0, sizeof(struct smb2_file_extended_info));

                        node->next = next_node;
                        node = next_node;
                }

        } while (full_ea_info.next_entry_offset);

        return 0;
}

int
smb2_decode_file_full_ea_info(Smb2ContextPtr smb2,
                              struct smb2_file_full_ea_info *info,
                              smb2_iovec *vec)
{
        vec->smb2_get_uint32(0, &info->next_entry_offset);
        vec->smb2_get_uint8(4, &info->flags);
        vec->smb2_get_uint8(5, &info->ea_name_length);
        vec->smb2_get_uint16(6, &info->ea_value_length);

        info->ea_name = (uint8_t*)malloc(info->ea_name_length+1);
        if (info->ea_name == NULL) {
                smb2->smb2_set_error("Failed to allocate ea name");
                return -1;
        }
        memset(info->ea_name, 0, info->ea_name_length+1);

        // For printing purpose, extra null character is added to value
        // The actual size of ea value is info->ea_value_length
        info->ea_value = (uint8_t*)malloc(info->ea_value_length+1);
        if (info->ea_value == NULL) {
                smb2->smb2_set_error("Failed to allocate ea value");
                free(info->ea_name);
                return -1;
        }
        memset(info->ea_value, 0, info->ea_value_length+1);

        memcpy(info->ea_name, vec->buf + 8, info->ea_name_length);
        memcpy(info->ea_value, vec->buf + (8 + info->ea_name_length),
               info->ea_value_length);

        return 0;
}

int smb2_encode_file_extended_info(Smb2ContextPtr smb2,
                                   struct smb2_file_extended_info *info,
                                   const int count,
                                   uint8_t *buffer,
                                   uint32_t *buffer_len)
{
        uint32_t offset = 0;

        if (buffer == NULL || buffer_len == NULL) {
                smb2->smb2_set_error("Buffer not allocated for file ea info");
                return -1;
        }

        struct smb2_file_extended_info* tmp_info = info;

        uint32_t *pOffset = NULL;
        int entries = 0;
        while(entries < count) {
                struct smb2_file_full_ea_info *full_ea_info =
                        (struct smb2_file_full_ea_info *)(buffer+offset);
                full_ea_info->ea_name_length = tmp_info->name_len;
                full_ea_info->ea_value_length = htole16(tmp_info->value_len);
                full_ea_info->flags = 0;

                pOffset = &full_ea_info->next_entry_offset;

                // copy to buffer
                offset += sizeof(struct smb2_file_full_ea_info) -
                          (2*sizeof(uint8_t*));
                memcpy(buffer+offset, tmp_info->name,
                       full_ea_info->ea_name_length+1);
                offset += full_ea_info->ea_name_length+1;
                memcpy(buffer+offset, tmp_info->value,
                       full_ea_info->ea_value_length);
                offset += full_ea_info->ea_value_length;

                /*
                 * When multiple FILE_FULL_EA_INFORMATION data elements are
                 * present in the buffer, each MUST be aligned on a 4-byte
                 * boundary. Any bytes inserted for alignment SHOULD be set
                 * to zero, and the receiver MUST ignore them. No padding is
                 * required following the last data element.
                 */
                uint32_t len = sizeof(struct smb2_file_full_ea_info) -
                               (2*sizeof(uint8_t*)) +
                               full_ea_info->ea_name_length + 1 +
                               full_ea_info->ea_value_length;

                if ((len & 0x03) != 0) {
                        uint32_t padlen = 0;
                        padlen = 4 - (len & 0x03);
                        offset += padlen;
                }

                if (entries < (count-1))
                  *pOffset = htole32(offset);

                entries++;
                tmp_info++;
        }

        *buffer_len = offset;
        return 0;
}

int
smb2_decode_file_stream_info(Smb2ContextPtr smb2,
                             struct smb2_file_stream_info *info,
                             smb2_iovec *vec)
{
        uint32_t offset = 0;
        struct smb2_file_stream_info *node = info;
        struct smb2_file_full_stream_info full_stream_info;

        info->next = NULL;

        do {
                smb2_iovec tmp_vec;

                /* Make sure we do not go beyond end of vector */
                if (offset >= vec->len) {
                        smb2FreeFileStreamInfo(info);
                        smb2->smb2_set_error("Malformed query reply.");
                        return -1;
                }

                tmp_vec.buf = &vec->buf[offset];
                tmp_vec.len = vec->len - offset;

                memset(&full_stream_info, 0, sizeof(struct smb2_file_full_stream_info));
                if (smb2_decode_file_full_stream_info(smb2,
                                                      &full_stream_info,
                                                      &tmp_vec) < 0) {
                        smb2FreeFileStreamInfo(info);
                        smb2->smb2_set_error("Failed to decode full_stream_info");
                        return -1;
                }

                memset(node->name, 0, 4096);
                memcpy(&(node->name[0]),
                       full_stream_info.stream_name,
                       ((full_stream_info.stream_name_length)/2));

                free(full_stream_info.stream_name);
                full_stream_info.stream_name = NULL;

                node->size = full_stream_info.stream_size;
                node->allocation_size = full_stream_info.stream_allocation_size;
                node->next = NULL;

                offset += full_stream_info.next_entry_offset;
                if ( full_stream_info.next_entry_offset != 0 )
                {
                        struct smb2_file_stream_info *next_node = NULL;
                        size_t len = sizeof(struct smb2_file_stream_info);
                        next_node = (struct smb2_file_stream_info *)malloc(len);
                        if (next_node == NULL) {
                                smb2FreeFileStreamInfo(info);
                                smb2->smb2_set_error("Failed to allocate smb2_file_stream_info");
                                return -1;
                        }
                        memset(next_node, 0, len);

                        node->next = next_node;
                        node = next_node;
                }
        } while (full_stream_info.next_entry_offset);

        return 0;
}

int
smb2_decode_file_full_stream_info(Smb2ContextPtr smb2,
                                  struct smb2_file_full_stream_info *info,
                                  smb2_iovec *vec)
{
        vec->smb2_get_uint32(0, &info->next_entry_offset);
        vec->smb2_get_uint32(4, &info->stream_name_length);
        vec->smb2_get_uint64(8, &info->stream_size);
        vec->smb2_get_uint64(16, &info->stream_allocation_size);

        info->stream_name = NULL;
        info->stream_name = (uint8_t*)ucs2_to_utf8((uint16_t *)(vec->buf + 24),
                                                   (info->stream_name_length/2));
        if (info->stream_name == NULL) {
                smb2->smb2_set_error("Failed to allocate memory for stream name");
                return -1;
        }

        return 0;
}

int
smb2_decode_file_all_info(struct smb2_file_all_info *fs, smb2_iovec *vec)
{
  smb2_iovec v;

  if (vec->len < 40)
    return -1;

  v.buf = &vec->buf[0];
  v.len = 40;
  smb2_decode_file_basic_info(&fs->basic, &v);

  if (vec->len < 64)
    return -1;

  v.buf = &vec->buf[40];
  v.len = 24;
  smb2_decode_file_standard_info(&fs->standard, &v);

  vec->smb2_get_uint64(64, &fs->index_number);
  vec->smb2_get_uint32(72, &fs->ea_size);
  vec->smb2_get_uint32(76, &fs->access_flags);
  vec->smb2_get_uint64(80, &fs->current_byte_offset);
  vec->smb2_get_uint32(88, &fs->mode);
  vec->smb2_get_uint32(92, &fs->alignment_requirement);

  //fs->name = ucs2_to_utf8((uint16_t *)&vec->buf[80], name_len / 2);

  return 0;
}
