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

    uint32_t first_data_block = superblock.s_first_data_block;

    fseek(img, block_bitmap_block * BLOCK_SIZE, SEEK_SET);
    fread(bitmap, 1, BLOCK_SIZE, img);

    for (int byte = 0; byte < BLOCK_SIZE; byte++)
    {
        for (int bit = 0; bit < 8; bit++)
        {
            if (!(bitmap[byte] & (1 << bit)))
            {
                int bloco_livre = byte * 8 + bit + 1;
                if (bloco_livre >= first_data_block)
                {
                    printf("[DEBUG] Bloco livre encontrado: %d\n", bloco_livre);
                    return bloco_livre;
                }
            }
        }
    }

    printf("Erro: Nenhum bloco livre disponível válido!\n");
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

    printf("first_data_block: %u\n", superblock.s_first_data_block);
    printf("bg_inode_table: %u\n", group_desc.bg_inode_table);
    printf("bg_block_bitmap: %u\n", group_desc.bg_block_bitmap);
    printf("bg_inode_bitmap: %u\n", group_desc.bg_inode_bitmap);
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

        if (entry->inode == 0)
        {
            // Entrada vazia, pode ser usada diretamente
            if (new_entry_size <= entry->rec_len)
            {
                entry->inode = new_inode_num;
                entry->name_len = name_len;
                entry->file_type = file_type;
                entry->rec_len = entry->rec_len; // mantém o tamanho original
                memcpy(entry->name, name, name_len);
                inserted = 1;
                break;
            }
        }
        else
        {
            uint16_t actual_size = dir_entry_size(entry->name_len);
            uint16_t space_left = entry->rec_len - actual_size;

            if (space_left >= new_entry_size)
            {
                // Ajusta a entrada atual para seu tamanho real
                entry->rec_len = actual_size;

                // Cria nova entrada logo depois
                struct ext2_dir_entry *new_entry = (struct ext2_dir_entry *)(buffer + offset + actual_size);
                new_entry->inode = new_inode_num;
                new_entry->name_len = name_len;
                new_entry->file_type = file_type;
                new_entry->rec_len = space_left;
                memcpy(new_entry->name, name, name_len);

                inserted = 1;
                break;
            }
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

/**
 * @brief Libera um único bloco de dados. (VERSÃO CORRIGIDA)
 * Aloca memória para zerar o bloco na HEAP para evitar stack overflow.
 */
void free_block(uint32_t block_num)
{
    if (block_num == 0)
        return;

    uint32_t block_size = get_block_size();
    printf("[DEBUG] Liberando bloco de dados %u...\n", block_num);

    set_bitmap_bit(group_desc.bg_block_bitmap, block_num - 1, 0);

    superblock.s_free_blocks_count++;
    group_desc.bg_free_blocks_count++;

    // Aloca buffer na HEAP para evitar stack overflow
    char *zeros = (char *)malloc(block_size);
    if (zeros == NULL)
    {
        perror("[ERRO] Falha ao alocar memória para zerar bloco");
        return; // Não consegue zerar, mas o bloco foi liberado no bitmap
    }

    memset(zeros, 0, block_size);
    if (fseek(img, block_num * block_size, SEEK_SET) == 0)
    {
        fwrite(zeros, block_size, 1, img);
    }

    // Libera a memória alocada na heap
    free(zeros);
}

void free_inode_blocks(struct ext2_inode *inode_to_free)
{
    uint32_t block_size = get_block_size();
    uint32_t pointers_per_block = block_size / sizeof(uint32_t);

    // Aloca buffers na HEAP
    uint32_t *l1_block = (uint32_t *)malloc(block_size);
    uint32_t *l2_block = (uint32_t *)malloc(block_size);

    if (l1_block == NULL || l2_block == NULL)
    {
        perror("[ERRO] Falha ao alocar memória para ler blocos indiretos");
        if (l1_block)
            free(l1_block);
        if (l2_block)
            free(l2_block);
        return;
    }

    // 1. Liberar blocos duplamente indiretos (nível 2)
    if (inode_to_free->i_block[13] != 0)
    {
        printf("[DEBUG] Liberando blocos duplamente indiretos (a partir do bloco %u)\n", inode_to_free->i_block[13]);
        fseek(img, inode_to_free->i_block[13] * block_size, SEEK_SET);
        fread(l2_block, block_size, 1, img);

        for (int i = 0; i < pointers_per_block; i++)
        {
            if (l2_block[i] != 0)
            {
                fseek(img, l2_block[i] * block_size, SEEK_SET);
                fread(l1_block, block_size, 1, img);
                for (int j = 0; j < pointers_per_block; j++)
                {
                    if (l1_block[j] != 0)
                        free_block(l1_block[j]);
                }
                free_block(l2_block[i]);
            }
        }
        free_block(inode_to_free->i_block[13]);
    }

    // 2. Liberar blocos indiretos (nível 1)
    if (inode_to_free->i_block[12] != 0)
    {
        printf("[DEBUG] Liberando blocos indiretos (a partir do bloco %u)\n", inode_to_free->i_block[12]);
        fseek(img, inode_to_free->i_block[12] * block_size, SEEK_SET);
        fread(l1_block, block_size, 1, img);

        for (int i = 0; i < pointers_per_block; i++)
        {
            if (l1_block[i] != 0)
                free_block(l1_block[i]);
        }
        free_block(inode_to_free->i_block[12]);
    }

    // 3. Liberar blocos diretos
    printf("[DEBUG] Liberando blocos diretos...\n");
    for (int i = 0; i < 12; i++)
    {
        if (inode_to_free->i_block[i] != 0)
            free_block(inode_to_free->i_block[i]);
    }
    printf("[DEBUG] Blocos diretos liberados.\n");

    printf("[DEBUG] Conteúdo de l1_block (primeiros 16 ponteiros):\n");
    for (int i = 0; i < 16 && i < (int)(block_size / sizeof(uint32_t)); i++)
    {
        printf("  l1_block[%d] = %u\n", i, l1_block[i]);
    }

    printf("[DEBUG] Conteúdo de l2_block (primeiros 16 ponteiros):\n");
    for (int i = 0; i < 16 && i < (int)(block_size / sizeof(uint32_t)); i++)
    {
        printf("  l2_block[%d] = %u\n", i, l2_block[i]);
    }
    printf("[DEBUG] Blocos indiretos e duplamente indiretos liberados.\n");

    // Libera a memória alocada no início da função
    free(l1_block);
    free(l2_block);
    printf("[DEBUG] Memória de buffers liberada.\n");
}