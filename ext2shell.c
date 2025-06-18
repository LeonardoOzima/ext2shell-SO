// ext2shell.c

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define SUPERBLOCK_OFFSET 1024
#define EXT2_SUPER_MAGIC 0xEF53

#define EXT2_FT_UNKNOWN  0
#define EXT2_FT_REG_FILE 1
#define EXT2_FT_DIR      2
#define EXT2_FT_CHRDEV   3
#define EXT2_FT_BLKDEV   4
#define EXT2_FT_FIFO     5
#define EXT2_FT_SOCK     6
#define EXT2_FT_SYMLINK  7

#pragma pack(push, 1)
struct ext2_super_block {
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
    uint8_t  s_uuid[16];
    char     s_volume_name[16];
    char     s_last_mounted[64];
    uint32_t s_algorithm_usage_bitmap;

    uint8_t  s_prealloc_blocks;
    uint8_t  s_prealloc_dir_blocks;
    uint16_t s_padding1;

    uint8_t  s_journal_uuid[16];
    uint32_t s_journal_inum;
    uint32_t s_journal_dev;
    uint32_t s_last_orphan;

    uint32_t s_hash_seed[4];
    uint8_t  s_def_hash_version;
    uint8_t  s_reserved_char_pad;
    uint16_t s_reserved_word_pad;
    uint32_t s_default_mount_opts;
    uint32_t s_first_meta_bg;

    uint32_t s_reserved[190];
};
#pragma pack(pop)

#pragma pack(push, 1)
struct ext2_inode {
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
struct ext2_dir_entry {
    uint32_t inode;
    uint16_t rec_len;
    uint8_t  name_len;
    uint8_t  file_type;
    char     name[];
};
#pragma pack(pop)

#pragma pack(push, 1)
struct ext2_group_desc {
    uint32_t bg_block_bitmap;
    uint32_t bg_inode_bitmap;
    uint32_t bg_inode_table;
    uint16_t bg_free_blocks_count;
    uint16_t bg_free_inodes_count;
    uint16_t bg_used_dirs_count;
    uint16_t bg_pad;
    uint8_t  bg_reserved[12];
};
#pragma pack(pop)

struct ext2_inode current_inode;
uint32_t current_inode_num = 2; // root inode

struct ext2_super_block superblock;
struct ext2_group_desc group_desc;
FILE *img = NULL;

char current_path[1024] = "/";

uint32_t get_block_size() {
    return 1024; // fixo conforme especificação
}

void read_superblock() {
    fseek(img, SUPERBLOCK_OFFSET, SEEK_SET);
    fread(&superblock, sizeof(struct ext2_super_block), 1, img);

    if (superblock.s_magic != EXT2_SUPER_MAGIC) {
        fprintf(stderr, "[ERRO] Imagem fornecida não é EXT2\n");
        exit(1);
    }
}

void read_group_desc() {
    uint32_t block_size = get_block_size();
    uint32_t gdt_offset = (superblock.s_first_data_block + 1) * block_size;
    fseek(img, gdt_offset, SEEK_SET);
    fread(&group_desc, sizeof(struct ext2_group_desc), 1, img);
}

void read_inode(uint32_t inode_num, struct ext2_inode *inode_out) {
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


void cmd_info() {
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

void cmd_ls() {
    uint32_t block_size = get_block_size();
    char block[1024];

    printf("[/]$> ls\n\n");

    for (int b = 0; b < 12 && current_inode.i_block[b] != 0; b++) {
        uint32_t block_num = current_inode.i_block[b];
        uint32_t offset_in_img = block_num * block_size;

        fseek(img, offset_in_img, SEEK_SET);
        fread(block, block_size, 1, img);

        uint32_t offset = 0;
        while (offset < block_size) {
            struct ext2_dir_entry *entry = (struct ext2_dir_entry *)(block + offset);

            if (entry->inode == 0 || entry->rec_len < 8 || offset + entry->rec_len > block_size)
                break;

            char name[256] = {0};
            memcpy(name, entry->name, entry->name_len);
            name[entry->name_len] = '\0';

            // Tradução de tipo
            const char *file_types[] = {
                "Unknown", "Regular", "Directory", "CharDev", "BlockDev", "FIFO", "Socket", "Symlink"
            };
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

void get_permission_string(uint16_t mode, uint8_t file_type, char *out) {
    out[0] = (file_type == EXT2_FT_DIR) ? 'd' : 'f'; // d = diretório, f = arquivo
    out[1] = (mode & 0400) ? 'r' : '-';
    out[2] = (mode & 0200) ? 'w' : '-';
    out[3] = (mode & 0100) ? 'x' : '-';
    out[4] = (mode & 0040) ? 'r' : '-';
    out[5] = (mode & 0020) ? 'w' : '-';
    out[6] = (mode & 0010) ? 'x' : '-';
    out[7] = (mode & 0004) ? 'r' : '-';
    out[8] = (mode & 0002) ? 'w' : '-';
    out[9] = (mode & 0001) ? 'x' : '-';
    out[10] = '\0';
}


void scan_possible_directories() {
    printf("== Verificando inodes 2 a 50 ==\n");

    for (uint32_t i = 2; i <= 50; i++) {
        struct ext2_inode inode;
        read_inode(i, &inode);

        if ((inode.i_mode & 0xF000) == 0x4000) {
            printf("[Inode %2u] Diretório encontrado!\n", i);
            printf("  i_mode: 0x%04x\n", inode.i_mode);
            printf("  i_size: %u bytes\n", inode.i_size);
            printf("  Blocos diretos:\n");
            for (int j = 0; j < 12; j++) {
                if (inode.i_block[j] != 0) {
                    printf("    - i_block[%d] = %u\n", j, inode.i_block[j]);
                }
            }
        }
    }
}

void cmd_pwd() {
    printf("%s\n", current_path);
}

void cmd_attr(const char *filename) {
    uint32_t block_size = get_block_size();
    char block[1024];

    for (int b = 0; b < 12 && current_inode.i_block[b] != 0; b++) {
        uint32_t block_num = current_inode.i_block[b];
        uint32_t offset_in_img = block_num * block_size;

        fseek(img, offset_in_img, SEEK_SET);
        fread(block, block_size, 1, img);

        uint32_t offset = 0;
        while (offset < block_size) {
            struct ext2_dir_entry *entry = (struct ext2_dir_entry *)(block + offset);

            if (entry->inode == 0 || entry->rec_len < 8) break;

            char name[256] = {0};
            memcpy(name, entry->name, entry->name_len);
            name[entry->name_len] = '\0';

            if (strcmp(name, filename) == 0) {
                struct ext2_inode inode;
                read_inode(entry->inode, &inode);

                // Cabeçalho formatado
                printf("%-12s %-4s %-4s %-12s %s\n", "permissões", "uid", "gid", "tamanho", "modificado em");

                // Permissões
                char perms[11] = {0};
                get_permission_string(inode.i_mode, entry->file_type, perms); // você pode usar sua print_permissions adaptada

                // Tamanho formatado
                char size_str[16];
                if (inode.i_size < 1024)
                    snprintf(size_str, sizeof(size_str), "%u B", inode.i_size);
                else
                    snprintf(size_str, sizeof(size_str), "%.1f KiB", inode.i_size / 1024.0);

                // Data formatada
                time_t mtime = inode.i_mtime;
                struct tm *tm_info = localtime(&mtime);
                char datebuf[20];
                strftime(datebuf, sizeof(datebuf), "%d/%m/%Y %H:%M", tm_info);

                // Linha de dados formatada
                printf("%-12s %-4u %-4u %-12s %s\n",
                    perms, inode.i_uid, inode.i_gid, size_str, datebuf);

                return;
            }

            offset += entry->rec_len;
        }
    }

    printf("Arquivo '%s' não encontrado.\n", filename);
}

void cmd_cd(const char *dirname) {
    uint32_t block_size = get_block_size();
    char block[1024];

     // Tratamento especial para cd ..
    if (strcmp(dirname, "..") == 0) {
        if (strcmp(current_path, "/") == 0) {
            // Já estamos na raiz, nada a fazer
            return;
        }

        // Remove o último diretório do caminho
        char *last_slash = strrchr(current_path, '/');
        if (last_slash != NULL && last_slash != current_path) {
            *last_slash = '\0';  // Ex: "/imagens" vira "/"
        } else {
            strcpy(current_path, "/"); // Se chegar aqui, volta para raiz
        }

        // Agora ler a entrada ".." do diretório atual (antes de mudar o inode)
        // Para isso precisamos do inode atual, que corresponde ao diretório filho (antes do ..)
        // Portanto vamos procurar ".." no bloco do inode atual.

        // Ler os blocos do diretório atual (antes de mudar o inode)
        for (int b = 0; b < 12 && current_inode.i_block[b] != 0; b++) {
            uint32_t block_num = current_inode.i_block[b];
            fseek(img, block_num * block_size, SEEK_SET);
            fread(block, block_size, 1, img);

            uint32_t offset = 0;
            while (offset < block_size) {
                struct ext2_dir_entry *entry = (struct ext2_dir_entry *)(block + offset);

                // Só comparar se entry->name_len == 2 e nome == ".."
                if (entry->inode != 0 &&
                    entry->name_len == 2 &&
                    strncmp(entry->name, "..", 2) == 0) {
                    
                    // Atualiza o inode atual para o pai
                    current_inode_num = entry->inode;
                    read_inode(current_inode_num, &current_inode);
                    return;
                }

                offset += entry->rec_len;
            }
        }

        // Se não achou a entrada ".." (problema grave), mantém inode atual
        return;
    }

    // Procurar o diretório informado
    for (int b = 0; b < 12 && current_inode.i_block[b] != 0; b++) {
        uint32_t block_num = current_inode.i_block[b];
        fseek(img, block_num * block_size, SEEK_SET);
        fread(block, block_size, 1, img);

        uint32_t offset = 0;
        while (offset < block_size) {
            struct ext2_dir_entry *entry = (struct ext2_dir_entry *)(block + offset);
            if (entry->inode == 0) break;

            char name[256] = {0};
            memcpy(name, entry->name, entry->name_len);
            name[entry->name_len] = '\0';

            if (strcmp(name, dirname) == 0) {
                if (entry->file_type != EXT2_FT_DIR) {
                    printf("'%s' não é um diretório.\n", dirname);
                    return;
                }

                // Atualizar inode atual
                current_inode_num = entry->inode;
                read_inode(current_inode_num, &current_inode);

                // Atualizar caminho
                if (strcmp(current_path, "/") != 0)
                    strcat(current_path, "/");
                strcat(current_path, dirname);

                return;
            }

            offset += entry->rec_len;
        }
    }

    printf("Diretório '%s' não encontrado.\n", dirname);
}


void cmd_cat(const char *filename) {
    uint32_t block_size = get_block_size();
    char block[1024];

    for (int b = 0; b < 12 && current_inode.i_block[b] != 0; b++) {
        uint32_t block_num = current_inode.i_block[b];
        uint32_t offset_in_img = block_num * block_size;

        fseek(img, offset_in_img, SEEK_SET);
        fread(block, block_size, 1, img);

        uint32_t offset = 0;
        while (offset < block_size) {
            struct ext2_dir_entry *entry = (struct ext2_dir_entry *)(block + offset);

            if (entry->inode == 0 || entry->rec_len < 8) break;

            char name[256] = {0};
            memcpy(name, entry->name, entry->name_len);
            name[entry->name_len] = '\0';

            if (strcmp(name, filename) == 0) {
                struct ext2_inode file_inode;
                read_inode(entry->inode, &file_inode);

                uint32_t bytes_remaining = file_inode.i_size;

                // Diretos
                for (int i = 0; i < 12 && bytes_remaining > 0; i++) {
                    if (file_inode.i_block[i] == 0) continue;

                    uint32_t data_block = file_inode.i_block[i];
                    fseek(img, data_block * block_size, SEEK_SET);
                    uint32_t to_read = bytes_remaining < block_size ? bytes_remaining : block_size;

                    fread(block, 1, to_read, img);
                    fwrite(block, 1, to_read, stdout);
                    bytes_remaining -= to_read;
                }

                // Indireto simples
                if (bytes_remaining > 0 && file_inode.i_block[12] != 0) {
                    uint32_t *indirect_block = malloc(block_size);
                    fseek(img, file_inode.i_block[12] * block_size, SEEK_SET);
                    fread(indirect_block, 4, block_size / 4, img);

                    for (int i = 0; i < 256 && bytes_remaining > 0; i++) {
                        if (indirect_block[i] == 0) continue;

                        fseek(img, indirect_block[i] * block_size, SEEK_SET);
                        uint32_t to_read = bytes_remaining < block_size ? bytes_remaining : block_size;

                        fread(block, 1, to_read, img);
                        fwrite(block, 1, to_read, stdout);
                        bytes_remaining -= to_read;
                    }
                    free(indirect_block);
                }

                // Indireto duplo
                if (bytes_remaining > 0 && file_inode.i_block[13] != 0) {
                    uint32_t *doubly_indirect_block = malloc(block_size);
                    fseek(img, file_inode.i_block[13] * block_size, SEEK_SET);
                    fread(doubly_indirect_block, 4, block_size / 4, img);

                    for (int i = 0; i < 256 && bytes_remaining > 0; i++) {
                        if (doubly_indirect_block[i] == 0) continue;

                        uint32_t *indirect_block = malloc(block_size);
                        fseek(img, doubly_indirect_block[i] * block_size, SEEK_SET);
                        fread(indirect_block, 4, block_size / 4, img);

                        for (int j = 0; j < 256 && bytes_remaining > 0; j++) {
                            if (indirect_block[j] == 0) continue;

                            fseek(img, indirect_block[j] * block_size, SEEK_SET);
                            uint32_t to_read = bytes_remaining < block_size ? bytes_remaining : block_size;

                            fread(block, 1, to_read, img);
                            fwrite(block, 1, to_read, stdout);
                            bytes_remaining -= to_read;
                        }

                        free(indirect_block);
                    }

                    free(doubly_indirect_block);
                }

                // Após imprimir o arquivo, saímos da função
                return;
            }

            offset += entry->rec_len;
        }
    }

    // Se chegou aqui, não encontrou o arquivo
    printf("Arquivo '%s' não encontrado.\n", filename);
}



void shell_loop() {
    char command[128];

    while (1) {
        printf("ext2shell:[%s] $ ", current_path);

        fflush(stdout);

        if (!fgets(command, sizeof(command), stdin)) break;

        command[strcspn(command, "\n")] = 0;

        if (strcmp(command, "info") == 0) {
            cmd_info();
        } else if (strcmp(command, "ls") == 0) {
            cmd_ls();
        } else if (strcmp(command, "exit") == 0 || strcmp(command, "quit") == 0) {
            break;
        } else if (strcmp(command, "scan") == 0) {
            scan_possible_directories();
        } else if (strncmp(command, "attr ", 5) == 0) {
            cmd_attr(command + 5);
        } else if (strcmp(command, "pwd") == 0) {
            cmd_pwd();
        } else if (strncmp(command, "cd ", 3) == 0) {
            cmd_cd(command + 3);
        } else if (strncmp(command, "cat ", 4) == 0) {
            cmd_cat(command + 4);
        } 
        else {
            printf("Comando desconhecido: %s\n", command);
        }
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Uso: %s <imagem_ext2>\n", argv[0]);
        return 1;
    }

    img = fopen(argv[1], "rb");
    if (!img) {
        perror("Erro ao abrir imagem");
        return 1;
    }

    read_superblock();
    read_group_desc();
    read_inode(2, &current_inode);
    printf("[DEBUG] Inode 2 - i_mode: 0x%04x\n", current_inode.i_mode);
    printf("[DEBUG] Inode 2 - i_block[0]: %u\n", current_inode.i_block[0]);

    strcpy(current_path, "/");
    shell_loop();

    fclose(img);
    return 0;
}
