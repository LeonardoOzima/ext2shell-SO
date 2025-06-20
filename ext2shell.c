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

//Função para calcular o tamanho da entrada no diretório (deve ser múltiplo de 4 bytes)
uint16_t dir_entry_size(uint8_t name_len) {
    return (8 /* tamanho fixo até o name */ + name_len + 3) & ~3; // arredonda para múltiplo de 4
}


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

int find_free_block() {
    int BLOCK_SIZE = get_block_size();
    uint32_t block_bitmap_block = group_desc.bg_block_bitmap;
    uint8_t bitmap[BLOCK_SIZE];

    // Lê o bloco do bitmap de blocos
    fseek(img, block_bitmap_block * BLOCK_SIZE, SEEK_SET);
    fread(bitmap, 1, BLOCK_SIZE, img);

    for (int byte = 0; byte < BLOCK_SIZE; byte++) {
        for (int bit = 0; bit < 8; bit++) {
            if (!(bitmap[byte] & (1 << bit))) {
                int bloco_livre = byte * 8 + bit + 1; // +1 pois EXT2 começa em bloco 1
                printf("[DEBUG] Bloco livre encontrado: %d\n", bloco_livre);
                return bloco_livre;
            }
        }
    }

    printf("Erro: Nenhum bloco livre disponível!\n");
    return -1;
}


int find_free_inode() {
    int BLOCK_SIZE = get_block_size();
    uint8_t bitmap[BLOCK_SIZE];

    // Le o bloco do bitmap de inodes
    fseek(img, BLOCK_SIZE * group_desc.bg_inode_bitmap, SEEK_SET);
    fread(bitmap, 1, BLOCK_SIZE, img);

    // Total de inodes por grupo
    int inodes_per_group = superblock.s_inodes_per_group;

    for (int i = 0; i < inodes_per_group; i++) {
        int byte_index = i / 8;
        int bit_offset = i % 8;

        // Verifica se o bit está 0 (livre)
        if (!(bitmap[byte_index] & (1 << bit_offset))) {
            printf("[DEBUG] Inode livre encontrado: %d\n", i + 1); // +1 para inode real
            return i + 1; // Inodes começam em 1
        }
    }

    printf("Erro: nenhum inode livre disponível.\n");
    return -1;
}


int file_exists_in_current_dir(const char *filename) {
    uint32_t block_size = get_block_size();
    char block[1024];

    for (int b = 0; b < 12 && current_inode.i_block[b] != 0; b++) {
        uint32_t block_num = current_inode.i_block[b];
        fseek(img, block_num * block_size, SEEK_SET);
        fread(block, block_size, 1, img);

        uint32_t offset = 0;
        while (offset < block_size) {
            struct ext2_dir_entry *entry = (struct ext2_dir_entry *)(block + offset);

            if (entry->inode == 0 || entry->rec_len < 8) break;

            char name[256] = {0};
            memcpy(name, entry->name, entry->name_len);
            name[entry->name_len] = '\0';

            if (strcmp(name, filename) == 0) {
                return 1; // já existe
            }

            offset += entry->rec_len;
        }
    }

    return 0; // não existe
}

void print_inode_bitmap(int n_bytes) {
    // Supondo que 'inode_bitmap_block' seja o bloco onde está o bitmap de inodes (já lido)
    // Você pode ajustar para ler diretamente do arquivo, se quiser.
    unsigned char buffer[n_bytes];
    int block_size = get_block_size();
    // Seek para o bitmap de inodes no arquivo (ajuste conforme seu superbloco e grupo)
    fseek(img, group_desc.bg_inode_bitmap * block_size, SEEK_SET);
    fread(buffer, 1, n_bytes, img);

    printf("Bitmap de inodes (primeiros %d bytes):\n", n_bytes);
    for (int i = 0; i < n_bytes; i++) {
        printf("Byte %2d: ", i);
        for (int bit = 7; bit >= 0; bit--) {
            printf("%d", (buffer[i] >> bit) & 1);
        }
        printf("\n");
    }
}

void set_bitmap_bit(uint32_t block_num, int bit_index, int value) {
    int BLOCK_SIZE = get_block_size();
    uint8_t buffer[BLOCK_SIZE];
    fseek(img, block_num * BLOCK_SIZE, SEEK_SET);
    fread(buffer, 1, BLOCK_SIZE, img);

    int byte_index = bit_index / 8;
    int bit_offset = bit_index % 8;

    if (value)
        buffer[byte_index] |= (1 << bit_offset);   // seta bit
    else
        buffer[byte_index] &= ~(1 << bit_offset);  // limpa bit

    fseek(img, block_num * BLOCK_SIZE, SEEK_SET);
    fwrite(buffer, 1, BLOCK_SIZE, img);
}

void write_inode(uint32_t inode_num, const struct ext2_inode *inode_in) {
    uint32_t block_size = get_block_size();
    uint32_t inodes_per_group = superblock.s_inodes_per_group;
    uint32_t inode_size = superblock.s_inode_size;

    uint32_t group = (inode_num - 1) / inodes_per_group;
    uint32_t index = (inode_num - 1) % inodes_per_group;

    // Lê o group descriptor correto
    struct ext2_group_desc gd;
    uint32_t gdt_offset = (superblock.s_first_data_block + 1) * block_size;
    fseek(img, gdt_offset + group * sizeof(struct ext2_group_desc), SEEK_SET);
    fread(&gd, sizeof(struct ext2_group_desc), 1, img);

    uint32_t inode_table_block = gd.bg_inode_table;
    uint32_t inode_offset = inode_table_block * block_size + index * inode_size;

    // Grava o inode
    fseek(img, inode_offset, SEEK_SET);
    fwrite(inode_in, inode_size, 1, img);
    fflush(img); // garante que os dados sejam realmente gravados
}

void add_dir_entry(uint32_t dir_inode_num, uint32_t new_inode_num, const char* name, uint8_t file_type) {
    uint32_t block_size = get_block_size();
    struct ext2_inode dir_inode;
    read_inode(dir_inode_num, &dir_inode);

    uint32_t block = dir_inode.i_block[0];
    uint8_t buffer[block_size];

    fseek(img, block * block_size, SEEK_SET);
    fread(buffer, 1, block_size, img);

    uint16_t offset = 0;
    uint16_t name_len = strlen(name);
    uint16_t new_entry_size = dir_entry_size(name_len);
    int inserted = 0;

    while (offset < block_size) {
        struct ext2_dir_entry* entry = (struct ext2_dir_entry*)(buffer + offset);
        uint16_t actual_size = dir_entry_size(entry->name_len);
        uint16_t space_left = entry->rec_len - actual_size;

        if (space_left >= new_entry_size) {
            // Atualiza rec_len da entrada atual
            entry->rec_len = actual_size;

            // Nova entrada começa logo depois
            struct ext2_dir_entry* new_entry = (struct ext2_dir_entry*)(buffer + offset + actual_size);
            new_entry->inode = new_inode_num;
            new_entry->name_len = name_len;
            new_entry->file_type = file_type;
            new_entry->rec_len = space_left;
            memcpy(new_entry->name, name, name_len);

            inserted = 1;
            break;
        }

        offset += entry->rec_len;
    }

    // Caso nenhuma entrada tivesse espaço, colocamos no final do bloco
    if (!inserted && (offset + new_entry_size <= block_size)) {
        struct ext2_dir_entry* new_entry = (struct ext2_dir_entry*)(buffer + offset);
        new_entry->inode = new_inode_num;
        new_entry->name_len = name_len;
        new_entry->file_type = file_type;
        new_entry->rec_len = block_size - offset;
        memcpy(new_entry->name, name, name_len);
        inserted = 1;
    }

    if (inserted) {
        // Escreve o bloco atualizado
        fseek(img, block * block_size, SEEK_SET);
        fwrite(buffer, 1, block_size, img);

        // Atualiza inode do diretório
        printf("[DEBUG] Diretório pai (inode %u) antigo tamanho: %u bytes\n", dir_inode_num, dir_inode.i_size);
        dir_inode.i_size += new_entry_size;
        dir_inode.i_mtime = dir_inode.i_ctime = time(NULL);
        write_inode(dir_inode_num, &dir_inode);
        printf("[DEBUG] Diretório pai (inode %u) atualizado com novo tamanho: %u bytes\n", dir_inode_num, dir_inode.i_size);

        printf("Entrada '%s' adicionada ao diretório inode %u\n", name, dir_inode_num);
    } else {
        printf("Erro: espaço insuficiente no bloco do diretório para adicionar '%s'\n", name);
    }
}



void cmd_touch(const char *filename) {
    if (file_exists_in_current_dir(filename)) {
        printf("Erro: o arquivo '%s' já existe.\n", filename);
        return;
    }

    printf("Arquivo '%s' não existe. (Simulação de criação aqui!)\n", filename);
    int free_inode = find_free_inode();
if (free_inode == -1) {
    printf("Erro: nenhum inode livre.\n");
    return;
}
printf("Pronto para usar inode %d!\n", free_inode);

int free_block = find_free_block();
if (free_block == -1) {
    printf("Erro: nenhum bloco livre disponível.\n");
    return;
}
printf("Pronto para usar bloco %d!\n", free_block);

printf("[DEBUG] inode_bitmap_block: %u\n", group_desc.bg_inode_bitmap);
printf("[DEBUG] block_bitmap_block: %u\n", group_desc.bg_block_bitmap);

set_bitmap_bit(group_desc.bg_inode_bitmap, free_inode - 1, 1); // Marca inode como usado

set_bitmap_bit(group_desc.bg_block_bitmap, free_block - 1, 1); // Marca bloco como usado

// Mostrar valores antes
printf("[DEBUG] Inodes livres (antes): Superbloco = %u, GroupDesc = %u\n",
       superblock.s_free_inodes_count, group_desc.bg_free_inodes_count);

// Atualizar contadores de inodes
superblock.s_free_inodes_count--;
group_desc.bg_free_inodes_count--;

printf("[DEBUG] Inodes livres (depois): Superbloco = %u, GroupDesc = %u\n",
       superblock.s_free_inodes_count, group_desc.bg_free_inodes_count);

// Reescrever superbloco
fseek(img, 1024, SEEK_SET);
fwrite(&superblock, sizeof(superblock), 1, img);

// Reescrever group descriptor (já está feito mais abaixo, então você pode remover o duplicado)

// Mostrar valores antes
printf("[DEBUG] Blocos livres (antes): Superbloco = %u, GroupDesc = %u\n",
       superblock.s_free_blocks_count, group_desc.bg_free_blocks_count);

// Atualizar contadores
superblock.s_free_blocks_count--;
group_desc.bg_free_blocks_count--;

// Reescrever superbloco
fseek(img, 1024, SEEK_SET); // Superbloco sempre começa no offset 1024
fwrite(&superblock, sizeof(superblock), 1, img);

// Reescrever group descriptor (primeiro grupo)
uint32_t block_size = get_block_size();
uint32_t gdt_offset = (superblock.s_first_data_block + 1) * block_size;
fseek(img, gdt_offset, SEEK_SET);
fwrite(&group_desc, sizeof(group_desc), 1, img);

// Mostrar valores depois
printf("[DEBUG] Blocos livres (depois): Superbloco = %u, GroupDesc = %u\n",
       superblock.s_free_blocks_count, group_desc.bg_free_blocks_count);


struct ext2_inode new_inode;
memset(&new_inode, 0, sizeof(new_inode));  // zera tudo

new_inode.i_mode = 0x81A4;  // regular file com permissão 644
new_inode.i_size = 0;
new_inode.i_blocks = 0;     // número de blocos de disco (não é i_block[])
new_inode.i_block[0] = free_block;  // o bloco que você encontrou
new_inode.i_links_count = 1;
new_inode.i_ctime = new_inode.i_mtime = new_inode.i_atime = time(NULL);

// Grava no disco
write_inode(free_inode, &new_inode);

printf("Inode %d escrito no disco!\n", free_inode);

// Ler o inode de volta do disco para checar
struct ext2_inode check_inode;
read_inode(free_inode, &check_inode);

// Mostrar informações para confirmar
printf("[DEBUG] Confirmação do inode %d:\n", free_inode);
printf("  i_mode: 0x%04x\n", check_inode.i_mode);
printf("  i_size: %u\n", check_inode.i_size);
printf("  i_block[0]: %u\n", check_inode.i_block[0]);

printf("Inode %d escrito no disco!\n", free_inode);

add_dir_entry(current_inode_num, free_inode, filename, 1);  // 2 = inode do diretório root, 1 = arquivo regular

    // Em breve: alocar inode, marcar bitmap, escrever inode, atualizar diretório
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

        }else if (strncmp(command, "attr ", 5) == 0) {
    cmd_attr(command + 5);
}else if (strcmp(command, "pwd") == 0) {
    cmd_pwd();}
    else if (strncmp(command, "cd ", 3) == 0) {
    cmd_cd(command + 3);
}
else if (strncmp(command, "touch ", 6) == 0) {
    cmd_touch(command + 6);
}
    else if (strncmp(command, "cat ", 4) == 0) {
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

    img = fopen(argv[1], "r+b");
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
    print_inode_bitmap(8);  // imprime os primeiros 8 bytes (64 inodes)

    shell_loop();

    fclose(img);
    return 0;
}
