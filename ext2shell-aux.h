/**
 * Arquivo auxiliar contendo as interfaces das funções e estruturas utilizadas no projeto.
 *
 * Data de criação: 17/06/2025
 * Data de modificação: 28/06/2025
 *
 * Autores: Gabriel Craco e Leonardo Jun-Ity
 * Professor: Rodrigo Campiolo
 * Sistemas Operacionais - Universidade Tecnológica Federal do Paraná
 */

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

/**
 * Lê e carrega o superbloco da imagem do sistema de arquivos.
 */
void read_superblock();

/**
 * Lê e carrega o descritor de grupo da imagem do sistema de arquivos.
 */
void read_group_desc();

/**
 * Lê o inode especificado pelo número 'inode_num' e armazena em 'inode_out'.
 *
 * @param inode_num Número do inode a ser lido.
 * @param inode_out Ponteiro para a estrutura onde será armazenado o inode lido.
 */
void read_inode(uint32_t inode_num, struct ext2_inode *inode_out);

/**
 * Escreve o inode fornecido em 'inode_in' na posição especificada por 'inode_num'.
 *
 * @param inode_num Número do inode a ser escrito.
 * @param inode_in Ponteiro para a estrutura contendo os dados do inode a serem escritos.
 */
void write_inode(uint32_t inode_num, const struct ext2_inode *inode_in);

/**
 * Calcula o tamanho necessário para armazenar uma entrada de diretório
 * baseado no comprimento do nome do arquivo.
 *
 * @param name_len Comprimento do nome do arquivo.
 * @return Tamanho em bytes da entrada de diretório.
 */
uint16_t dir_entry_size(uint8_t name_len);

/**
 * Converte os bits de permissão do modo do inode em uma string legível para humanos.
 *
 * @param mode Campo de modo do inode.
 * @param file_type Tipo do arquivo.
 * @param out String de saída onde a permissão será escrita (deve ter espaço suficiente).
 */
void get_permission_string(uint16_t mode, uint8_t file_type, char *out);

/**
 * Escaneia os possíveis diretórios para alguma funcionalidade interna (ex: validação ou listagem).
 */
void scan_possible_directories();

/**
 * Busca por um bloco livre na tabela de blocos.
 *
 * @return Número do bloco livre encontrado ou -1 se não houver blocos livres.
 */
int find_free_block();

/**
 * Busca por um inode livre na tabela de inodes.
 *
 * @return Número do inode livre encontrado ou -1 se não houver inodes livres.
 */
int find_free_inode();

/**
 * Verifica se um arquivo com o nome especificado existe no diretório atual.
 *
 * @param filename Nome do arquivo a verificar.
 * @return 1 se o arquivo existir, 0 caso contrário.
 */
int file_exists_in_current_dir(const char *filename);

/**
 * Imprime o bitmap de inodes para debug.
 *
 * @param n_bytes Número de bytes do bitmap a imprimir.
 */
void print_inode_bitmap(int n_bytes);

/**
 * Define o valor (0 ou 1) de um bit específico no bitmap de blocos.
 *
 * @param block_num Número do bloco referente ao bitmap.
 * @param bit_index Índice do bit a ser alterado.
 * @param value Valor a ser setado (0 ou 1).
 */
void set_bitmap_bit(uint32_t block_num, int bit_index, int value);

/**
 * Obtém todos os blocos de dados associados a um inode, preenchendo o array 'blocks'.
 *
 * @param inode Ponteiro para o inode.
 * @param blocks Array para armazenar os números dos blocos encontrados.
 * @param max_blocks Tamanho máximo do array blocks.
 * @return Número de blocos encontrados e preenchidos no array.
 */
int get_all_data_blocks(struct ext2_inode *inode, uint32_t *blocks, int max_blocks);

/**
 * Adiciona uma entrada de diretório no diretório especificado pelo inode.
 *
 * @param dir_inode_num Número do inode do diretório onde será adicionada a entrada.
 * @param new_inode_num Número do inode do novo arquivo/diretório a adicionar.
 * @param name Nome do arquivo/diretório a adicionar.
 * @param file_type Tipo do arquivo (arquivo, diretório, etc).
 */
void add_dir_entry(uint32_t dir_inode_num, uint32_t new_inode_num, const char *name, uint8_t file_type);

/**
 * Libera todos os blocos associados a um inode, incluindo blocos diretos, indiretos e duplamente indiretos.
 *
 * @param inode Ponteiro para o inode cujos blocos serão liberados.
 */
void free_inode_blocks(struct ext2_inode *inode);

/**
 * Retorna o tamanho do bloco usado no sistema de arquivos EXT2 da imagem.
 *
 * @return Tamanho do bloco em bytes.
 */
uint32_t get_block_size();

/**
 * Libera um bloco no sistema de arquivos.
 *
 * @param block_num Número do bloco a ser liberado.
 */
void free_block(uint32_t block_num);

#endif
