// ext2shell.c

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define SUPERBLOCK_OFFSET 1024
#define EXT2_SUPER_MAGIC 0xEF53

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

struct ext2_inode current_inode;
uint32_t current_inode_num = 2; // root inode

struct ext2_super_block superblock;
struct ext2_group_desc group_desc;
FILE *img = NULL;

uint32_t get_block_size()
{
    return 1024; // fixo conforme especificação
}

void read_superblock()
{
    fseek(img, SUPERBLOCK_OFFSET, SEEK_SET);
    fread(&superblock, sizeof(struct ext2_super_block), 1, img);

    if (superblock.s_magic != EXT2_SUPER_MAGIC)
    {
        fprintf(stderr, "[ERRO] Imagem fornecida não é EXT2\n");
        exit(1);
    }
}

void read_group_desc()
{
    uint32_t block_size = get_block_size();
    uint32_t gdt_offset = (superblock.s_first_data_block + 1) * block_size;
    fseek(img, gdt_offset, SEEK_SET);
    fread(&group_desc, sizeof(struct ext2_group_desc), 1, img);
}

void read_inode(uint32_t inode_num, struct ext2_inode *inode_out)
{
    uint32_t block_size = get_block_size();
    uint32_t inodes_per_group = superblock.s_inodes_per_group;
    uint32_t inode_size = superblock.s_inode_size;

    uint32_t group = (inode_num - 1) / inodes_per_group;
    uint32_t index = (inode_num - 1) % inodes_per_group;

    // ⚠️ Precisamos ler o group descriptor correto
    struct ext2_group_desc gd;
    uint32_t gdt_offset = (superblock.s_first_data_block + 1) * block_size;
    fseek(img, gdt_offset + group * sizeof(struct ext2_group_desc), SEEK_SET);
    fread(&gd, sizeof(struct ext2_group_desc), 1, img);

    uint32_t inode_table_block = gd.bg_inode_table;

    uint32_t inode_offset = inode_table_block * block_size + index * inode_size;

    fseek(img, inode_offset, SEEK_SET);
    fread(inode_out, inode_size, 1, img);
}

void cmd_info()
{
    uint32_t block_size = get_block_size();
    uint64_t image_size_bytes = (uint64_t)superblock.s_blocks_count * block_size;
    uint64_t free_space_kib = (uint64_t)superblock.s_free_blocks_count * block_size / 1024;
    uint32_t group_count = (superblock.s_blocks_count + superblock.s_blocks_per_group - 1) / superblock.s_blocks_per_group;
    uint32_t inodetable_blocks = (superblock.s_inodes_per_group * superblock.s_inode_size) / block_size;

    printf("Volume name.....: %s\n", superblock.s_volume_name);
    printf("Image size......: %llu bytes\n", (unsigned long long)image_size_bytes);
    printf("Free space......: %llu KiB\n", (unsigned long long)free_space_kib);
    printf("Free inodes.....: %u\n", superblock.s_free_inodes_count);
    printf("Free blocks.....: %u\n", superblock.s_free_blocks_count);
    printf("Block size......: %u bytes\n", block_size);
    printf("Inode size......: %u bytes\n", superblock.s_inode_size);
    printf("Groups count....: %u\n", group_count);
    printf("Groups size.....: %u blocks\n", superblock.s_blocks_per_group);
    printf("Groups inodes...: %u inodes\n", superblock.s_inodes_per_group);
    printf("Inodetable size.: %u blocks\n", inodetable_blocks);
}

void cmd_ls()
{
    uint32_t block_size = get_block_size();
    char block[1024];

    printf("[/]$> ls\n\n");

    for (int b = 0; b < 12 && current_inode.i_block[b] != 0; b++)
    {
        uint32_t block_num = current_inode.i_block[b];
        uint32_t offset_in_img = block_num * block_size;

        fseek(img, offset_in_img, SEEK_SET);
        fread(block, block_size, 1, img);

        uint32_t offset = 0;
        while (offset < block_size)
        {
            struct ext2_dir_entry *entry = (struct ext2_dir_entry *)(block + offset);

            if (entry->inode == 0 || entry->rec_len < 8 || offset + entry->rec_len > block_size)
                break;

            char name[256] = {0};
            memcpy(name, entry->name, entry->name_len);
            name[entry->name_len] = '\0';

            // Tradução de tipo
            const char *file_types[] = {
                "Unknown", "Regular", "Directory", "CharDev", "BlockDev", "FIFO", "Socket", "Symlink"};
            const char *ftype = "Unknown";
            if (entry->file_type < 8)
                ftype = file_types[entry->file_type];

            // Exibir formatado
            printf("%s (%s)\n", name, ftype);
            printf("  inode...........: %u\n", entry->inode);
            printf("  record length...: %u\n", entry->rec_len);
            printf("  name length.....: %u\n", entry->name_len);
            printf("  file type.......: %u\n", entry->file_type);
            printf("\n");

            offset += entry->rec_len;
        }
    }
}

void scan_possible_directories()
{
    printf("== Verificando inodes 2 a 50 ==\n");

    for (uint32_t i = 2; i <= 50; i++)
    {
        struct ext2_inode inode;
        read_inode(i, &inode);

        if ((inode.i_mode & 0xF000) == 0x4000)
        {
            printf("[Inode %2u] Diretório encontrado!\n", i);
            printf("  i_mode: 0x%04x\n", inode.i_mode);
            printf("  i_size: %u bytes\n", inode.i_size);
            printf("  Blocos diretos:\n");
            for (int j = 0; j < 12; j++)
            {
                if (inode.i_block[j] != 0)
                {
                    printf("    - i_block[%d] = %u\n", j, inode.i_block[j]);
                }
            }
        }
    }
}

void shell_loop()
{
    char command[128];

    while (1)
    {
        printf("ext2shell:[/] $ ");
        fflush(stdout);

        if (!fgets(command, sizeof(command), stdin))
            break;

        command[strcspn(command, "\n")] = 0;

        if (strcmp(command, "info") == 0)
        {
            cmd_info();
        }
        else if (strcmp(command, "ls") == 0)
        {
            cmd_ls();
        }
        else if (strcmp(command, "exit") == 0 || strcmp(command, "quit") == 0)
        {
            break;
        }
        else if (strcmp(command, "scan") == 0)
        {
            scan_possible_directories();
        }
        else
        {
            printf("Comando desconhecido: %s\n", command);
        }
    }
}

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        fprintf(stderr, "Uso: %s <imagem_ext2>\n", argv[0]);
        return 1;
    }

    img = fopen(argv[1], "rb");
    if (!img)
    {
        perror("Erro ao abrir imagem");
        return 1;
    }

    read_superblock();
    read_group_desc();
    read_inode(2, &current_inode);
    printf("[DEBUG] Inode 2 - i_mode: 0x%04x\n", current_inode.i_mode);
    printf("[DEBUG] Inode 2 - i_block[0]: %u\n", current_inode.i_block[0]);

    shell_loop();

    fclose(img);
    return 0;
}
