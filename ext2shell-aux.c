/**
 * Arquivo auxiliar contendo as funções auxiliares utilizadas no projeto.
 *
 * Data de criação: 17/06/2025
 * Data de modificação: 28/06/2025
 *
 * Autores: Gabriel Craco e Leonardo Jun-Ity
 * Professor: Rodrigo Campiolo
 * Sistemas Operacionais - Universidade Tecnológica Federal do Paraná
 */

#include "ext2shell-consts.h"
#include "ext2shell-aux.h"

uint16_t dir_entry_size(uint8_t name_len)
{
    return (8 /* tamanho fixo até o name */ + name_len + 3) & ~3; // arredonda para múltiplo de 4
}

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

void get_permission_string(uint16_t mode, uint8_t file_type, char *out)
{
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

int find_free_block()
{
    int BLOCK_SIZE = get_block_size();
    uint32_t block_bitmap_block = group_desc.bg_block_bitmap;
    uint8_t bitmap[BLOCK_SIZE];

    // Lê o bloco do bitmap de blocos
    fseek(img, block_bitmap_block * BLOCK_SIZE, SEEK_SET);
    fread(bitmap, 1, BLOCK_SIZE, img);

    for (int byte = 0; byte < BLOCK_SIZE; byte++)
    {
        for (int bit = 0; bit < 8; bit++)
        {
            if (!(bitmap[byte] & (1 << bit)))
            {
                int bloco_livre = byte * 8 + bit + 1; // +1 pois EXT2 começa em bloco 1
                printf("[DEBUG] Bloco livre encontrado: %d\n", bloco_livre);
                return bloco_livre;
            }
        }
    }

    printf("Erro: Nenhum bloco livre disponível!\n");
    return -1;
}

int find_free_inode()
{
    int BLOCK_SIZE = get_block_size();
    uint8_t bitmap[BLOCK_SIZE];

    // Le o bloco do bitmap de inodes
    fseek(img, BLOCK_SIZE * group_desc.bg_inode_bitmap, SEEK_SET);
    fread(bitmap, 1, BLOCK_SIZE, img);

    // Total de inodes por grupo
    int inodes_per_group = superblock.s_inodes_per_group;

    for (int i = 0; i < inodes_per_group; i++)
    {
        int byte_index = i / 8;
        int bit_offset = i % 8;

        // Verifica se o bit está 0 (livre)
        if (!(bitmap[byte_index] & (1 << bit_offset)))
        {
            printf("[DEBUG] Inode livre encontrado: %d\n", i + 1); // +1 para inode real
            return i + 1;                                          // Inodes começam em 1
        }
    }

    printf("Erro: nenhum inode livre disponível.\n");
    return -1;
}

int file_exists_in_current_dir(const char *filename)
{
    uint32_t block_size = get_block_size();
    char block[1024];

    for (int b = 0; b < 12 && current_inode.i_block[b] != 0; b++)
    {
        uint32_t block_num = current_inode.i_block[b];
        fseek(img, block_num * block_size, SEEK_SET);
        fread(block, block_size, 1, img);

        uint32_t offset = 0;
        while (offset < block_size)
        {
            struct ext2_dir_entry *entry = (struct ext2_dir_entry *)(block + offset);

            if (entry->inode == 0 || entry->rec_len < 8)
                break;

            char name[256] = {0};
            memcpy(name, entry->name, entry->name_len);
            name[entry->name_len] = '\0';

            if (strcmp(name, filename) == 0)
            {
                return 1; // já existe
            }

            offset += entry->rec_len;
        }
    }

    return 0; // não existe
}

void print_inode_bitmap(int n_bytes)
{
    unsigned char buffer[n_bytes];
    int block_size = get_block_size();
    fseek(img, group_desc.bg_inode_bitmap * block_size, SEEK_SET);
    fread(buffer, 1, n_bytes, img);

    printf("Bitmap de inodes (primeiros %d bytes):\n", n_bytes);
    for (int i = 0; i < n_bytes; i++)
    {
        printf("Byte %2d: ", i);
        for (int bit = 7; bit >= 0; bit--)
        {
            printf("%d", (buffer[i] >> bit) & 1);
        }
        printf("\n");
    }
}

void set_bitmap_bit(uint32_t block_num, int bit_index, int value)
{
    int BLOCK_SIZE = get_block_size();
    uint8_t buffer[BLOCK_SIZE];
    fseek(img, block_num * BLOCK_SIZE, SEEK_SET);
    fread(buffer, 1, BLOCK_SIZE, img);

    int byte_index = bit_index / 8;
    int bit_offset = bit_index % 8;

    if (value)
        buffer[byte_index] |= (1 << bit_offset); // seta bit
    else
        buffer[byte_index] &= ~(1 << bit_offset); // limpa bit

    fseek(img, block_num * BLOCK_SIZE, SEEK_SET);
    fwrite(buffer, 1, BLOCK_SIZE, img);
}

int get_all_data_blocks(struct ext2_inode *inode, uint32_t *blocks, int max_blocks)
{
    uint32_t bs = get_block_size();
    int count = 0;

    // Diretos (i_block[0] a i_block[11])
    for (int i = 0; i < 12 && count < max_blocks; i++)
    {
        if (inode->i_block[i] != 0)
        {
            blocks[count++] = inode->i_block[i];
        }
    }

    // Indireto simples (i_block[12])
    if (inode->i_block[12] != 0 && count < max_blocks)
    {
        uint32_t indirect[bs / sizeof(uint32_t)];
        fseek(img, inode->i_block[12] * bs, SEEK_SET);
        fread(indirect, sizeof(uint32_t), bs / sizeof(uint32_t), img);

        for (int i = 0; i < bs / sizeof(uint32_t) && indirect[i] != 0 && count < max_blocks; i++)
        {
            blocks[count++] = indirect[i];
        }
    }

    return count;
}

void write_inode(uint32_t inode_num, const struct ext2_inode *inode_in)
{
    uint32_t block_size = get_block_size();
    uint32_t inodes_per_group = superblock.s_inodes_per_group;
    uint32_t inode_size = superblock.s_inode_size;

    uint32_t group = (inode_num - 1) / inodes_per_group;
    uint32_t index = (inode_num - 1) % inodes_per_group;

    struct ext2_group_desc gd;
    uint32_t gdt_offset = (superblock.s_first_data_block + 1) * block_size;
    fseek(img, gdt_offset + group * sizeof(struct ext2_group_desc), SEEK_SET);
    fread(&gd, sizeof(struct ext2_group_desc), 1, img);

    uint32_t inode_table_block = gd.bg_inode_table;
    uint32_t inode_offset = inode_table_block * block_size + index * inode_size;

    fseek(img, inode_offset, SEEK_SET);
    fwrite(inode_in, inode_size, 1, img);
    fflush(img);
}

void add_dir_entry(uint32_t dir_inode_num, uint32_t new_inode_num, const char *name, uint8_t file_type)
{
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

    while (offset < block_size)
    {
        struct ext2_dir_entry *entry = (struct ext2_dir_entry *)(buffer + offset);
        uint16_t actual_size = dir_entry_size(entry->name_len);
        uint16_t space_left = entry->rec_len - actual_size;

        if (space_left >= new_entry_size)
        {
            entry->rec_len = actual_size;

            struct ext2_dir_entry *new_entry = (struct ext2_dir_entry *)(buffer + offset + actual_size);
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

    if (!inserted && (offset + new_entry_size <= block_size))
    {
        struct ext2_dir_entry *new_entry = (struct ext2_dir_entry *)(buffer + offset);
        new_entry->inode = new_inode_num;
        new_entry->name_len = name_len;
        new_entry->file_type = file_type;
        new_entry->rec_len = block_size - offset;
        memcpy(new_entry->name, name, name_len);
        inserted = 1;
    }

    if (inserted)
    {
        fseek(img, block * block_size, SEEK_SET);
        fwrite(buffer, 1, block_size, img);

        printf("[DEBUG] Diretório pai (inode %u) antigo tamanho: %u bytes\n", dir_inode_num, dir_inode.i_size);
        dir_inode.i_size += new_entry_size;
        dir_inode.i_mtime = dir_inode.i_ctime = time(NULL);
        write_inode(dir_inode_num, &dir_inode);
        printf("[DEBUG] Diretório pai (inode %u) atualizado com novo tamanho: %u bytes\n", dir_inode_num, dir_inode.i_size);

        printf("Entrada '%s' adicionada ao diretório inode %u\n", name, dir_inode_num);
    }
    else
    {
        printf("Erro: espaço insuficiente no bloco do diretório para adicionar '%s'\n", name);
    }
}
