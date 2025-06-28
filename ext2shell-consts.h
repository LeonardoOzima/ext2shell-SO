/**
 * Arquivo auxiliar contendo as constantes utilizadas no projeto.
 *
 * Data de criação: 17/06/2025
 * Data de modificação: 28/06/2025
 *
 * Autores: Gabriel Craco e Leonardo Jun-Ity
 * Professor: Rodrigo Campiolo
 * Sistemas Operacionais - Universidade Tecnológica Federal do Paraná
 */

#ifndef EXT2SHELL_CONSTS_H
#define EXT2SHELL_CONSTS_H

#define SUPERBLOCK_OFFSET 1024
#define EXT2_SUPER_MAGIC 0xEF53
#define EXT2_S_IFREG 0x8000

#define EXT2_FT_UNKNOWN 0
#define EXT2_FT_REG_FILE 1
#define EXT2_FT_DIR 2
#define EXT2_FT_CHRDEV 3
#define EXT2_FT_BLKDEV 4
#define EXT2_FT_FIFO 5
#define EXT2_FT_SOCK 6
#define EXT2_FT_SYMLINK 7

#define GREEN "\x1b[32m"
#define MAGENTA "\x1b[35m"
#define RESET "\x1b[0m"
#define YELLOW "\x1b[33m"

#endif
