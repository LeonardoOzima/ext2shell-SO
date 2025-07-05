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

/*
 * Offset in bytes where the EXT2 superblock starts within the filesystem image.
 */
#define SUPERBLOCK_OFFSET 1024

/*
 * Magic number used to identify an EXT2 filesystem (should be 0xEF53).
 */
#define EXT2_SUPER_MAGIC 0xEF53

/*
 * Bitmask representing a regular file in EXT2 inode mode field.
 */
#define EXT2_S_IFREG 0x8000

/*
 * Directory entry file type for unknown file type.
 */
#define EXT2_FT_UNKNOWN 0

/*
 * Directory entry file type for a regular file.
 */
#define EXT2_FT_REG_FILE 1

/*
 * Directory entry file type for a directory.
 */
#define EXT2_FT_DIR 2

/*
 * Directory entry file type for a character device.
 */
#define EXT2_FT_CHRDEV 3

/*
 * Directory entry file type for a block device.
 */
#define EXT2_FT_BLKDEV 4

/*
 * Directory entry file type for a FIFO (named pipe).
 */
#define EXT2_FT_FIFO 5

/*
 * Directory entry file type for a socket.
 */
#define EXT2_FT_SOCK 6

/*
 * Directory entry file type for a symbolic link.
 */
#define EXT2_FT_SYMLINK 7

/*
 * ANSI escape code for green text color.
 */
#define GREEN "\x1b[32m"

/*
 * ANSI escape code for magenta text color.
 */
#define MAGENTA "\x1b[35m"

/*
 * ANSI escape code to reset text formatting.
 */
#define RESET "\x1b[0m"

/*
 * ANSI escape code for yellow text color.
 */
#define YELLOW "\x1b[33m"