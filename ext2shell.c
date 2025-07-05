/**
 * Aplicação em C que simula um terminal de comandos para acessar,
 * ler e modificar arquivos dentro de um sistema de arquivos EXT2.
 *
 * Arquivo contém as principais funções que controlam o terminal.
 *
 * Data de criação: 17/06/2025
 * Data de modificação: 04/07/2025
 *
 * Autores: Gabriel Craco e Leonardo Jun-Ity
 * Professor: Rodrigo Campiolo
 * Sistemas Operacionais - Universidade Tecnológica Federal do Paraná
 */

#include <sys/stat.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "ext2shell-consts.h"
#include "ext2shell-aux.h"
#include "ext2shell.h"

struct ext2_inode current_inode;
uint32_t current_inode_num = 2;

struct ext2_super_block superblock;
struct ext2_group_desc group_desc;
FILE *img = NULL;

char current_path[1024] = "/";

void cmd_info()
{
    read_superblock();
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

void cmd_pwd()
{
    printf("%s\n", current_path);
}

void cmd_attr(const char *filename)
{
    uint32_t block_size = get_block_size();
    char block[1024];

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

            if (entry->inode == 0 || entry->rec_len < 8)
                break;

            char name[256] = {0};
            memcpy(name, entry->name, entry->name_len);
            name[entry->name_len] = '\0';

            if (strcmp(name, filename) == 0)
            {
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

void cmd_cd(const char *dirname)
{
    uint32_t block_size = get_block_size();
    char block[1024];

    if (strcmp(dirname, ".") == 0)
    {
        // cd . não altera o diretório atual
        return;
    }

    // Tratamento especial para cd ..
    if (strcmp(dirname, "..") == 0)
    {
        if (strcmp(current_path, "/") == 0)
        {
            // Já estamos na raiz, nada a fazer
            return;
        }

        // Remove o último diretório do caminho
        char *last_slash = strrchr(current_path, '/');
        if (last_slash != NULL && last_slash != current_path)
        {
            *last_slash = '\0'; // Ex: "/imagens" vira "/"
        }
        else
        {
            strcpy(current_path, "/"); // Se chegar aqui, volta para raiz
        }

        // Agora ler a entrada ".." do diretório atual (antes de mudar o inode)
        // Para isso precisamos do inode atual, que corresponde ao diretório filho (antes do ..)
        // Portanto vamos procurar ".." no bloco do inode atual.

        // Ler os blocos do diretório atual (antes de mudar o inode)
        for (int b = 0; b < 12 && current_inode.i_block[b] != 0; b++)
        {
            uint32_t block_num = current_inode.i_block[b];
            fseek(img, block_num * block_size, SEEK_SET);
            fread(block, block_size, 1, img);

            uint32_t offset = 0;
            while (offset < block_size)
            {
                struct ext2_dir_entry *entry = (struct ext2_dir_entry *)(block + offset);

                // Só comparar se entry->name_len == 2 e nome == ".."
                if (entry->inode != 0 &&
                    entry->name_len == 2 &&
                    strncmp(entry->name, "..", 2) == 0)
                {

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
    for (int b = 0; b < 12 && current_inode.i_block[b] != 0; b++)
    {
        uint32_t block_num = current_inode.i_block[b];
        fseek(img, block_num * block_size, SEEK_SET);
        fread(block, block_size, 1, img);

        uint32_t offset = 0;
        while (offset < block_size)
        {
            struct ext2_dir_entry *entry = (struct ext2_dir_entry *)(block + offset);
            if (entry->inode == 0)
                break;

            char name[256] = {0};
            memcpy(name, entry->name, entry->name_len);
            name[entry->name_len] = '\0';

            if (strcmp(name, dirname) == 0)
            {
                if (entry->file_type != EXT2_FT_DIR)
                {
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
                // Normaliza o caminho removendo "/." no final, se existir
                int len = strlen(current_path);
                if (len >= 2 && strcmp(current_path + len - 2, "/.") == 0)
                {
                    current_path[len - 2] = '\0'; // Remove os dois últimos caracteres
                }

                return;
            }

            offset += entry->rec_len;
        }
    }

    printf("diretório '%s' não encontrado.\n", dirname);
}

void cmd_cat(const char *filename)
{
    uint32_t block_size = get_block_size();
    char block[1024];

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

            if (entry->inode == 0 || entry->rec_len < 8)
                break;

            char name[256] = {0};
            memcpy(name, entry->name, entry->name_len);
            name[entry->name_len] = '\0';

            if (strcmp(name, filename) == 0)
            {
                struct ext2_inode file_inode;
                read_inode(entry->inode, &file_inode);

                uint32_t bytes_remaining = file_inode.i_size;

                // Diretos
                for (int i = 0; i < 12 && bytes_remaining > 0; i++)
                {
                    if (file_inode.i_block[i] == 0)
                        continue;

                    uint32_t data_block = file_inode.i_block[i];
                    fseek(img, data_block * block_size, SEEK_SET);
                    uint32_t to_read = bytes_remaining < block_size ? bytes_remaining : block_size;

                    fread(block, 1, to_read, img);
                    fwrite(block, 1, to_read, stdout);
                    bytes_remaining -= to_read;
                }

                // Indireto simples
                if (bytes_remaining > 0 && file_inode.i_block[12] != 0)
                {
                    uint32_t *indirect_block = malloc(block_size);
                    fseek(img, file_inode.i_block[12] * block_size, SEEK_SET);
                    fread(indirect_block, 4, block_size / 4, img);

                    for (int i = 0; i < 256 && bytes_remaining > 0; i++)
                    {
                        if (indirect_block[i] == 0)
                            continue;

                        fseek(img, indirect_block[i] * block_size, SEEK_SET);
                        uint32_t to_read = bytes_remaining < block_size ? bytes_remaining : block_size;

                        fread(block, 1, to_read, img);
                        fwrite(block, 1, to_read, stdout);
                        bytes_remaining -= to_read;
                    }
                    free(indirect_block);
                }

                // Indireto duplo
                if (bytes_remaining > 0 && file_inode.i_block[13] != 0)
                {
                    uint32_t *doubly_indirect_block = malloc(block_size);
                    fseek(img, file_inode.i_block[13] * block_size, SEEK_SET);
                    fread(doubly_indirect_block, 4, block_size / 4, img);

                    for (int i = 0; i < 256 && bytes_remaining > 0; i++)
                    {
                        if (doubly_indirect_block[i] == 0)
                            continue;

                        uint32_t *indirect_block = malloc(block_size);
                        fseek(img, doubly_indirect_block[i] * block_size, SEEK_SET);
                        fread(indirect_block, 4, block_size / 4, img);

                        for (int j = 0; j < 256 && bytes_remaining > 0; j++)
                        {
                            if (indirect_block[j] == 0)
                                continue;

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

void cmd_touch(const char *filename)
{
    if (file_exists_in_current_dir(filename))
    {
        printf("erro: o arquivo '%s' já existe.\n", filename);
        return;
    }

    printf("Arquivo '%s' não existe. Criando...\n", filename);

    int free_inode = find_free_inode();
    if (free_inode == -1)
    {
        printf("erro: nenhum inode livre.\n");
        return;
    }

    set_bitmap_bit(group_desc.bg_inode_bitmap, free_inode - 1, 1);

    superblock.s_free_inodes_count--;
    group_desc.bg_free_inodes_count--;

    fseek(img, 1024, SEEK_SET);
    fwrite(&superblock, sizeof(superblock), 1, img);

    uint32_t block_size = get_block_size();
    uint32_t gdt_offset = (superblock.s_first_data_block + 1) * block_size;
    fseek(img, gdt_offset, SEEK_SET);
    fwrite(&group_desc, sizeof(group_desc), 1, img);

    struct ext2_inode new_inode;
    memset(&new_inode, 0, sizeof(new_inode));

    new_inode.i_mode = 0x81A4; // Arquivo regular 0644
    new_inode.i_size = 0;      // Arquivo vazio
    new_inode.i_blocks = 0;    // Nenhum bloco alocado
    // i_block[] zerado
    new_inode.i_links_count = 1;
    new_inode.i_ctime = new_inode.i_mtime = new_inode.i_atime = time(NULL);

    write_inode(free_inode, &new_inode);

    printf("Inode %d criado para arquivo '%s'\n", free_inode, filename);

    // Adiciona entrada no diretório atual
    add_dir_entry(current_inode_num, free_inode, filename, EXT2_FT_REG_FILE);

    // Atualiza links_count do diretório pai não é necessário para arquivo,
    // mas pode atualizar timestamps se quiser:
    struct ext2_inode parent_inode;
    read_inode(current_inode_num, &parent_inode);
    parent_inode.i_mtime = parent_inode.i_ctime = time(NULL);
    write_inode(current_inode_num, &parent_inode);

    printf("Arquivo '%s' criado com inode %d\n", filename, free_inode);
}

void cmd_mkdir(const char *dirname)
{
    if (file_exists_in_current_dir(dirname))
    {
        printf("erro: o diretório '%s' já existe.\n", dirname);
        return;
    }

    printf("diretório '%s' não existe. Criando...\n", dirname);

    int free_inode = find_free_inode();
    if (free_inode == -1)
    {
        printf("erro: nenhum inode livre.\n");
        return;
    }
    int free_block = find_free_block();
    if (free_block == -1)
    {
        printf("erro: nenhum bloco livre.\n");
        return;
    }

    set_bitmap_bit(group_desc.bg_inode_bitmap, free_inode - 1, 1);
    set_bitmap_bit(group_desc.bg_block_bitmap, free_block - 1, 1);

    superblock.s_free_inodes_count--;
    group_desc.bg_free_inodes_count--;
    superblock.s_free_blocks_count--;
    group_desc.bg_free_blocks_count--;

    fseek(img, 1024, SEEK_SET);
    fwrite(&superblock, sizeof(superblock), 1, img);

    uint32_t block_size = get_block_size();
    uint32_t gdt_offset = (superblock.s_first_data_block + 1) * block_size;
    fseek(img, gdt_offset, SEEK_SET);
    fwrite(&group_desc, sizeof(group_desc), 1, img);

    struct ext2_inode new_inode;
    memset(&new_inode, 0, sizeof(new_inode));
    new_inode.i_mode = 0x41ED; // diretório 0755
    new_inode.i_size = block_size;
    new_inode.i_blocks = block_size / 512;
    new_inode.i_block[0] = free_block;
    new_inode.i_links_count = 2; // "." + referencia do pai
    new_inode.i_ctime = new_inode.i_mtime = new_inode.i_atime = time(NULL);

    // Criar entradas . e ..
    uint8_t dir_block[block_size];
    memset(dir_block, 0, block_size);

    struct ext2_dir_entry *dot = (struct ext2_dir_entry *)dir_block;
    dot->inode = free_inode;
    dot->name_len = 1;
    dot->rec_len = dir_entry_size(1);
    dot->file_type = EXT2_FT_DIR;
    memcpy(dot->name, ".", 1);

    struct ext2_dir_entry *dotdot = (struct ext2_dir_entry *)(dir_block + dot->rec_len);
    dotdot->inode = current_inode_num;
    dotdot->name_len = 2;
    dotdot->rec_len = block_size - dot->rec_len;
    dotdot->file_type = EXT2_FT_DIR;
    memcpy(dotdot->name, "..", 2);

    fseek(img, free_block * block_size, SEEK_SET);
    fwrite(dir_block, 1, block_size, img);

    write_inode(free_inode, &new_inode);

    add_dir_entry(current_inode_num, free_inode, dirname, EXT2_FT_DIR);

    // Atualizar i_links_count do diretório pai
    struct ext2_inode parent_inode;
    read_inode(current_inode_num, &parent_inode);
    parent_inode.i_links_count++;
    write_inode(current_inode_num, &parent_inode);

    printf("diretório '%s' criado com inode %d e bloco %d.\n", dirname, free_inode, free_block);
}

void cmd_rm_rmdir(const char *name, int is_dir)
{
    uint32_t block_size = get_block_size();
    uint8_t block[block_size];
    uint32_t found_inode = 0;
    struct ext2_inode target_inode;

    printf("[DEBUG] Procurando por '%s' no diretório atual (inode %u)...\n", name, current_inode_num);

    for (int b = 0; b < 12 && current_inode.i_block[b] != 0; b++)
    {
        uint32_t block_num = current_inode.i_block[b];
        if (fseek(img, block_num * block_size, SEEK_SET) != 0)
        {
            perror("[ERRO] fseek no bloco do diretório");
            return;
        }
        if (fread(block, block_size, 1, img) != 1)
        {
            perror("[ERRO] fread no bloco do diretório");
            return;
        }

        uint32_t offset = 0;
        struct ext2_dir_entry *prev_entry = NULL;

        while (offset < block_size)
        {
            struct ext2_dir_entry *entry = (struct ext2_dir_entry *)(block + offset);

            if (entry->inode == 0 || entry->rec_len < 8)
                break;

            char entry_name[256] = {0};
            memcpy(entry_name, entry->name, entry->name_len);
            entry_name[entry->name_len] = '\0';

            if (strcmp(entry_name, name) == 0)
            {
                found_inode = entry->inode;
                printf("[DEBUG] Entrada '%s' encontrada! inode = %u, file_type = %u\n", name, found_inode, entry->file_type);

                read_inode(found_inode, &target_inode);

                // Verificação do tipo
                if (is_dir && entry->file_type != EXT2_FT_DIR)
                {
                    printf("erro: '%s' não é um diretório.\n", name);
                    return;
                }
                if (!is_dir && entry->file_type != EXT2_FT_REG_FILE)
                {
                    printf("erro: '%s' não é um arquivo.\n", name);
                    return;
                }

                // Se diretório, verificar vazio (apenas . e ..)
                if (is_dir)
                {
                    int is_empty = 1;
                    uint8_t dir_block[block_size];
                    for (int db = 0; db < 12 && target_inode.i_block[db] != 0; db++)
                    {
                        if (fseek(img, target_inode.i_block[db] * block_size, SEEK_SET) != 0)
                        {
                            perror("[ERRO] fseek bloco do diretório alvo");
                            return;
                        }
                        if (fread(dir_block, block_size, 1, img) != 1)
                        {
                            perror("[ERRO] fread bloco do diretório alvo");
                            return;
                        }

                        uint32_t doffset = 0;
                        while (doffset < block_size)
                        {
                            struct ext2_dir_entry *dent = (struct ext2_dir_entry *)(dir_block + doffset);
                            if (dent->inode != 0 && dent->name_len > 0)
                            {
                                char dname[256] = {0};
                                memcpy(dname, dent->name, dent->name_len);
                                dname[dent->name_len] = '\0';

                                if (strcmp(dname, ".") != 0 && strcmp(dname, "..") != 0)
                                {
                                    is_empty = 0;
                                    break;
                                }
                            }
                            doffset += dent->rec_len;
                        }
                        if (!is_empty)
                            break;
                    }
                    if (!is_empty)
                    {
                        printf("erro: diretório '%s' não está vazio.\n", name);
                        return;
                    }
                }

                // Remover entrada do diretório atual
                printf("[DEBUG] Removendo entrada '%s' do bloco %u\n", name, block_num);
                if (prev_entry != NULL)
                {
                    prev_entry->rec_len += entry->rec_len;
                    printf("[DEBUG] Ajustado rec_len da entrada anterior para %u\n", prev_entry->rec_len);
                }
                else
                {
                    // Se for a primeira entrada, marcar inode=0 e limpar nome e tipo
                    entry->inode = 0;
                    entry->name_len = 0;
                    entry->file_type = 0;
                    memset(entry->name, 0, 255);
                    printf("[DEBUG] Entrada removida marcando inode=0 e limpando nome\n");
                }

                if (fseek(img, block_num * block_size, SEEK_SET) != 0)
                {
                    perror("[ERRO] fseek para escrever bloco do diretório");
                    return;
                }
                if (fwrite(block, block_size, 1, img) != 1)
                {
                    perror("[ERRO] fwrite bloco do diretório");
                    return;
                }

                // Atualizar i_links_count
                if (target_inode.i_links_count == 0)
                {
                    printf("[WARN] inode %u já tem i_links_count = 0\n", found_inode);
                }
                if (target_inode.i_links_count > 0)
                {
                    target_inode.i_links_count--;
                }
                printf("[DEBUG] inode %u: i_links_count agora = %u\n", found_inode, target_inode.i_links_count);

                write_inode(found_inode, &target_inode);

                // Liberar recursos se não houver mais links
                if (target_inode.i_links_count == 0)
                {
                    if (found_inode == 0)
                    {
                        printf("[ERRO] Tentativa de liberar inode 0! Isso é inválido.\n");
                        return;
                    }
                    free_inode_blocks(&target_inode);
                    printf("[DEBUG] Blocos do inode %u liberados\n", found_inode);

                    set_bitmap_bit(group_desc.bg_inode_bitmap, found_inode - 1, 0);
                    superblock.s_free_inodes_count++;
                    group_desc.bg_free_inodes_count++;
                    printf("[DEBUG] Inode %u liberado\n", found_inode);
                }

                // Atualizar timestamps e tamanho do diretório atual
                time_t now = time(NULL);
                current_inode.i_mtime = now;
                current_inode.i_ctime = now;
                // Ajuste simples do tamanho do diretório (subtrai tamanho da entrada)
                current_inode.i_size -= entry->rec_len;
                printf("[DEBUG] diretório atual inode %u i_size atualizado para %u bytes\n", current_inode_num, current_inode.i_size);

                write_inode(current_inode_num, &current_inode);
                printf("[DEBUG] Inode do diretório atual %u atualizado no disco\n", current_inode_num);

                // Gravar superbloco e group descriptor atualizados
                if (fseek(img, 1024, SEEK_SET) != 0)
                {
                    perror("[ERRO] fseek superbloco");
                    return;
                }
                if (fwrite(&superblock, sizeof(superblock), 1, img) != 1)
                {
                    perror("[ERRO] fwrite superbloco");
                    return;
                }

                uint32_t gdt_offset = (superblock.s_first_data_block + 1) * block_size;
                if (fseek(img, gdt_offset, SEEK_SET) != 0)
                {
                    perror("[ERRO] fseek group descriptor");
                    return;
                }
                if (fwrite(&group_desc, sizeof(group_desc), 1, img) != 1)
                {
                    perror("[ERRO] fwrite group descriptor");
                    return;
                }

                printf("Remoção de '%s' concluída com sucesso.\n", name);
                return;
            }

            prev_entry = entry;
            offset += entry->rec_len;
        }
    }

    printf("erro: entrada '%s' não encontrada no diretório atual.\n", name);
}

void cmd_rename(uint32_t dir_inode_num, const char *old_name, const char *new_name)
{
    uint32_t bs = get_block_size();
    struct ext2_inode dir_inode;
    read_inode(dir_inode_num, &dir_inode);

    uint32_t blocks[256];
    int num_blocks = get_all_data_blocks(&dir_inode, blocks, 256);

    uint32_t target_inode = 0;
    uint8_t file_type = 0;
    uint16_t needed = dir_entry_size(strlen(new_name));

    // Primeira passada: procurar e remover se necessário
    for (int b = 0; b < num_blocks; b++)
    {
        uint8_t buffer[bs];
        fseek(img, blocks[b] * bs, SEEK_SET);
        fread(buffer, 1, bs, img);

        uint16_t offset = 0;
        struct ext2_dir_entry *prev = NULL;

        while (offset < bs)
        {
            struct ext2_dir_entry *entry = (struct ext2_dir_entry *)(buffer + offset);

            if (entry->inode != 0 &&
                strncmp(entry->name, old_name, entry->name_len) == 0 &&
                strlen(old_name) == entry->name_len)
            {

                if (needed <= entry->rec_len)
                {
                    // Renomeia direto
                    memset(entry->name, 0, entry->name_len);
                    memcpy(entry->name, new_name, strlen(new_name));
                    entry->name_len = strlen(new_name);

                    fseek(img, blocks[b] * bs, SEEK_SET);
                    fwrite(buffer, 1, bs, img);
                    printf("[DEBUG] Renomeado '%s' para '%s' diretamente.\n", old_name, new_name);
                    return;
                }
                else
                {
                    // Salvar infos para reinserção
                    target_inode = entry->inode;
                    file_type = entry->file_type;

                    if (prev)
                        prev->rec_len += entry->rec_len;
                    else
                        entry->inode = 0; // marca como removido

                    fseek(img, blocks[b] * bs, SEEK_SET);
                    fwrite(buffer, 1, bs, img);
                    break; // vamos reinserir depois
                }
            }

            prev = entry;
            offset += entry->rec_len;
        }

        if (target_inode)
            break;
    }

    if (!target_inode)
    {
        printf("erro: entrada '%s' não encontrada.\n", old_name);
        return;
    }

    // Segunda passada: tentar reutilizar entrada com inode == 0
    for (int b = 0; b < num_blocks; b++)
    {
        uint8_t buffer[bs];
        fseek(img, blocks[b] * bs, SEEK_SET);
        fread(buffer, 1, bs, img);

        uint16_t offset = 0;
        while (offset < bs)
        {
            struct ext2_dir_entry *entry = (struct ext2_dir_entry *)(buffer + offset);

            if (entry->inode == 0 && entry->rec_len >= needed)
            {
                entry->inode = target_inode;
                entry->file_type = file_type;
                entry->name_len = strlen(new_name);
                memcpy(entry->name, new_name, strlen(new_name));

                fseek(img, blocks[b] * bs, SEEK_SET);
                fwrite(buffer, 1, bs, img);
                printf("[DEBUG] Renomeado '%s' para '%s' reutilizando entrada vazia.\n", old_name, new_name);
                return;
            }

            offset += entry->rec_len;
        }
    }

    // Se não achou espaço, insere no final
    add_dir_entry(dir_inode_num, target_inode, new_name, file_type);
    printf("[DEBUG] Renomeado '%s' para '%s' via reinserção.\n", old_name, new_name);
}

void cmd_cp(const char *source_path, const char *target_path)
{
    uint32_t block_size = get_block_size();
    char block[1024];

    char full_target[512];
    int tried_as_file = 0;

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

            if (strcmp(name, source_path) == 0)
            {
                // inode
                struct ext2_inode file_inode;
                read_inode(entry->inode, &file_inode);

                if ((file_inode.i_mode & 0xF000) != 0x8000)
                {
                    printf("cp: '%s' não é um arquivo regular.\n", source_path);
                    return;
                }

                // 1 tentativa: usar target_path como nome de arquivo
                FILE *fp = fopen(target_path, "wb");
                if (fp)
                {
                    strncpy(full_target, target_path, sizeof(full_target));
                    full_target[sizeof(full_target) - 1] = '\0';
                    tried_as_file = 1;
                    fclose(fp); // só testamos — vamos abrir de novo depois
                }

                if (!tried_as_file)
                {
                    // Considerar como diretório: montar full_target com nome do arquivo
                    // Previne "//" no caminho final
                    size_t tlen = strlen(target_path);
                    if (tlen > 0 && target_path[tlen - 1] == '/')
                        snprintf(full_target, sizeof(full_target), "%s%s", target_path, source_path);
                    else
                        snprintf(full_target, sizeof(full_target), "%s/%s", target_path, source_path);
                }

                struct stat st;
                if (stat(target_path, &st) == -1)
                {
                    printf("diretório '%s' não existe.\n", target_path);
                    return;
                }

                // Agora sim, abrir arquivo para escrita
                FILE *out = fopen(full_target, "wb");
                if (!out)
                {
                    printf("cp: não foi possível criar '%s'\n", full_target);
                    return;
                }

                uint32_t bytes_remaining = file_inode.i_size;

                // Blocos diretos
                for (int i = 0; i < 12 && bytes_remaining > 0; i++)
                {
                    if (file_inode.i_block[i] == 0)
                        continue;

                    fseek(img, file_inode.i_block[i] * block_size, SEEK_SET);
                    uint32_t to_read = bytes_remaining < block_size ? bytes_remaining : block_size;
                    fread(block, 1, to_read, img);
                    fwrite(block, 1, to_read, out);
                    bytes_remaining -= to_read;
                }

                // Indireto simples
                if (bytes_remaining > 0 && file_inode.i_block[12] != 0)
                {
                    uint32_t indirect[256];
                    fseek(img, file_inode.i_block[12] * block_size, SEEK_SET);
                    fread(indirect, 4, 256, img);

                    for (int i = 0; i < 256 && bytes_remaining > 0; i++)
                    {
                        if (indirect[i] == 0)
                            continue;

                        fseek(img, indirect[i] * block_size, SEEK_SET);
                        uint32_t to_read = bytes_remaining < block_size ? bytes_remaining : block_size;
                        fread(block, 1, to_read, img);
                        fwrite(block, 1, to_read, out);
                        bytes_remaining -= to_read;
                    }
                }

                fclose(out);
                printf("Arquivo '%s' copiado com sucesso para '%s'\n", source_path, full_target);
                return;
            }

            offset += entry->rec_len;
        }
    }

    printf("cp: Arquivo '%s' não encontrado.\n", source_path);
}

void cmd_mv(const char *source_path, const char *target_path)
{
    cmd_cp(source_path, target_path);
    cmd_rm_rmdir(source_path, 0);
}

void shell_loop()
{
    char command[128];

    while (1)
    {
        printf(GREEN "ext2shell:" YELLOW "[%s] " MAGENTA "$ " RESET, current_path);

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
        else if (strncmp(command, "attr ", 5) == 0)
        {
            cmd_attr(command + 5);
        }
        else if (strcmp(command, "pwd") == 0)
        {
            cmd_pwd();
        }
        else if (strncmp(command, "cd ", 3) == 0)
        {
            cmd_cd(command + 3);
        }
        else if (strncmp(command, "mkdir ", 6) == 0)
        {
            if (strlen(command + 6) == 0)
            {
                printf("sintaxe inválida.\n");
            }
            else
            {
                cmd_mkdir(command + 6);
            }
        }
        else if (strncmp(command, "rename ", 7) == 0)
        {
            char old_name[256], new_name[256];
            if (sscanf(command + 7, "%255s %255s", old_name, new_name) == 2)
            {
                cmd_rename(current_inode_num, old_name, new_name);
            }
            else
            {
                printf("sintaxe inválida.\n");
            }
        }
        else if (strncmp(command, "touch ", 6) == 0)
        {
            if (strlen(command + 6) == 0)
            {
                printf("sintaxe inválida.\n");
            }
            else
            {
                cmd_touch(command + 6);
            }
        }
        else if (strncmp(command, "cat ", 4) == 0)
        {
            if (strlen(command + 4) == 0)
            {
                printf("sintaxe inválida.\n");
            }
            else
            {
                cmd_cat(command + 4);
            }
        }
        else if (strncmp(command, "rm ", 3) == 0)
        {
            const char *filename = command + 3;
            if (strlen(filename) == 0)
            {
                printf("sintaxe inválida.\n");
            }
            else
            {
                cmd_rm_rmdir(filename, 0); // 0 = arquivo
            }
        }
        else if (strncmp(command, "rmdir ", 6) == 0)
        {
            const char *dirname = command + 6;
            if (strlen(dirname) == 0)
            {
                printf("sintaxe inválida.\n");
            }
            else
            {
                cmd_rm_rmdir(dirname, 1); // 1 = diretório
            }
        }
        else if (strncmp(command, "cp ", 3) == 0)
        {
            char source[256], target[256];
            if (sscanf(command + 3, "%255s %255s", source, target) != 2)
            {
                printf("sintaxe inválida.\n");
            }
            else
            {
                cmd_cp(source, target);
            }
        }
        else if (strncmp(command, "mv ", 3) == 0)
        {
            char source[256], target[256];
            if (sscanf(command + 3, "%255s %255s", source, target) != 2)
            {
                printf("sintaxe inválida.\n");
            }
            else
            {
                cmd_mv(source, target);
            }
        }
        else
        {
            const char *known_commands[] = {
                "info", "ls", "exit", "quit", "scan", "attr", "pwd", "cd", "mkdir", "rename", "touch", "cat", "rm", "rmdir", "cp", "mv"};
            int is_known = 0;
            for (size_t i = 0; i < sizeof(known_commands) / sizeof(known_commands[0]); i++)
            {
                size_t len = strlen(known_commands[i]);
                if (strncmp(command, known_commands[i], len) == 0 &&
                    (command[len] == ' ' || command[len] == '\0'))
                {
                    is_known = 1;
                    break;
                }
            }

            if (is_known)
            {
                printf("sintaxe inválida.\n");
            }
            else if (strlen(command) == 0)
            {
                continue;
            }
            else
            {
                printf("Comando desconhecido: %s\n", command);
            }
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

    img = fopen(argv[1], "r+b");
    if (!img)
    {
        perror("erro ao abrir imagem");
        return 1;
    }

    read_superblock();
    read_group_desc();
    read_inode(2, &current_inode);
    printf("[DEBUG] Inode 2 - i_mode: 0x%04x\n", current_inode.i_mode);
    printf("[DEBUG] Inode 2 - i_block[0]: %u\n", current_inode.i_block[0]);

    strcpy(current_path, "/");
    print_inode_bitmap(8); // imprime os primeiros 8 bytes (64 inodes)

    shell_loop();

    fclose(img);
    return 0;
}
