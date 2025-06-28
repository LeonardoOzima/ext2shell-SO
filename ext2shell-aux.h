#ifndef EXT2SHELL_AUX_H
#define EXT2SHELL_AUX_H

#include "ext2shell-consts.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#pragma pack(push, 1)
struct ext2_super_block
{
    uint32_t s_inodes_count;
    uint32_t s_blocks_count;
    uint32_t s_r_blocks_count;
    uint32_t s_free_blocks_count;
    uint32_t s_free_inodes_count;
    uint32_t s_first_data_block;
    uint32_t s_log_block_size;
    uint32_t s_log_frag_size;
    uint32_t s_blocks_per_group;
    uint32_t s_frags_per_group;
    uint32_t s_inodes_per_group;
    uint32_t s_mtime;
    uint32_t s_wtime;
    uint16_t s_mnt_count;
    uint16_t s_max_mnt_count;
    uint16_t s_magic;
    uint16_t s_state;
    uint16_t s_errors;
    uint16_t s_minor_rev_level;
    uint32_t s_lastcheck;
    uint32_t s_checkinterval;
    uint32_t s_creator_os;
    uint32_t s_rev_level;
    uint16_t s_def_resuid;
    uint16_t s_def_resgid;

    uint32_t s_first_ino;
    uint16_t s_inode_size;
    uint16_t s_block_group_nr;
    uint32_t s_feature_compat;
    uint32_t s_feature_incompat;
    uint32_t s_feature_ro_compat;
    uint8_t s_uuid[16];
    char s_volume_name[16];
    char s_last_mounted[64];
    uint32_t s_algorithm_usage_bitmap;

    uint8_t s_prealloc_blocks;
    uint8_t s_prealloc_dir_blocks;
    uint16_t s_padding1;

    uint8_t s_journal_uuid[16];
    uint32_t s_journal_inum;
    uint32_t s_journal_dev;
    uint32_t s_last_orphan;

    uint32_t s_hash_seed[4];
    uint8_t s_def_hash_version;
    uint8_t s_reserved_char_pad;
    uint16_t s_reserved_word_pad;
    uint32_t s_default_mount_opts;
    uint32_t s_first_meta_bg;

    uint32_t s_reserved[190];
};
#pragma pack(pop)

#pragma pack(push, 1)
struct ext2_inode
{
    uint16_t i_mode;
    uint16_t i_uid;
    uint32_t i_size;
    uint32_t i_atime;
    uint32_t i_ctime;
    uint32_t i_mtime;
    uint32_t i_dtime;
    uint16_t i_gid;
    uint16_t i_links_count;
    uint32_t i_blocks;
    uint32_t i_flags;
    uint32_t i_osd1;
    uint32_t i_block[15];
};
#pragma pack(pop)

#pragma pack(push, 1)
struct ext2_dir_entry
{
    uint32_t inode;
    uint16_t rec_len;
    uint8_t name_len;
    uint8_t file_type;
    char name[];
};
#pragma pack(pop)

#pragma pack(push, 1)
struct ext2_group_desc
{
    uint32_t bg_block_bitmap;
    uint32_t bg_inode_bitmap;
    uint32_t bg_inode_table;
    uint16_t bg_free_blocks_count;
    uint16_t bg_free_inodes_count;
    uint16_t bg_used_dirs_count;
    uint16_t bg_pad;
    uint8_t bg_reserved[12];
};
#pragma pack(pop)

extern FILE *img;
extern struct ext2_super_block superblock;
extern struct ext2_group_desc group_desc;
extern struct ext2_inode current_inode;

// Protótipos das funções
void read_superblock();
void read_group_desc();
void read_inode(uint32_t inode_num, struct ext2_inode *inode_out);
void write_inode(uint32_t inode_num, const struct ext2_inode *inode_in);
uint16_t dir_entry_size(uint8_t name_len);

void get_permission_string(uint16_t mode, uint8_t file_type, char *out);
void scan_possible_directories();

int find_free_block();
int find_free_inode();
int file_exists_in_current_dir(const char *filename);
void print_inode_bitmap(int n_bytes);

void set_bitmap_bit(uint32_t block_num, int bit_index, int value);
int get_all_data_blocks(struct ext2_inode *inode, uint32_t *blocks, int max_blocks);

void add_dir_entry(uint32_t dir_inode_num, uint32_t new_inode_num, const char *name, uint8_t file_type);

uint32_t get_block_size();

#endif
