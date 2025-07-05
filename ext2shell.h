/**
 * Arquivo que documenta as funções principais do shell interativo
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

#ifndef EXT2SHELL_H
#define EXT2SHELL_H

#include <stdint.h>

/**
 * Exibe informações gerais do volume e sistema de arquivos EXT2 carregado.
 */
void cmd_info();

/**
 * Lista os arquivos e diretórios presentes no diretório atual.
 */
void cmd_ls();

/**
 * Exibe o caminho completo do diretório atual.
 */
void cmd_pwd();

/**
 * Exibe atributos detalhados (permissões, dono, tamanho, modificação) do arquivo ou diretório especificado.
 *
 * @param filename Nome do arquivo ou diretório a consultar.
 */
void cmd_attr(const char *filename);

/**
 * Altera o diretório atual para o especificado.
 *
 * Suporta os comandos especiais "." e "..".
 *
 * @param dirname Nome do diretório para onde deseja navegar.
 */
void cmd_cd(const char *dirname);

/**
 * Renomeia um arquivo ou diretório dentro de um diretório especificado.
 *
 * @param dir_inode_num Número do inode do diretório que contém o arquivo/diretório.
 * @param old_name Nome atual do arquivo/diretório.
 * @param new_name Novo nome para o arquivo/diretório.
 */
void cmd_rename(uint32_t dir_inode_num, const char *old_name, const char *new_name);

/**
 * Copia um arquivo da imagem EXT2 para o sistema de arquivos real.
 *
 * @param source_path Caminho do arquivo na imagem EXT2.
 * @param target_path Caminho destino no sistema real.
 */
void cmd_cp(const char *source_path, const char *target_path);

/**
 * Move um arquivo da imagem EXT2 para o sistema de arquivos real.
 *
 * Implementado como cópia seguida de remoção do arquivo original.
 *
 * @param source_path Caminho do arquivo na imagem EXT2.
 * @param target_path Caminho destino no sistema real.
 */
void cmd_mv(const char *source_path, const char *target_path);

/**
 * Loop principal do shell interativo.
 *
 * Processa comandos do usuário até o comando de saída.
 */
void shell_loop();

#endif // EXT2SHELL_H
