# EXT2Shell

Este projeto implementa um shell interativo para manipular uma imagem `.img` de um sistema de arquivos EXT2, permitindo realizar operações básicas diretamente na imagem como se fosse um terminal Linux.

## Descrição

O `ext2shell` é uma aplicação em C que simula um terminal de comandos para acessar, ler e modificar arquivos dentro de um sistema de arquivos EXT2. A execução começa no diretório raiz (`/`) da imagem e permite navegar e interagir com o conteúdo como se fosse um sistema de arquivos real.

## ⚙Comandos suportados

| Comando                 | Descrição                                                                 |
|------------------------|---------------------------------------------------------------------------|
| `info`                 | Exibe informações gerais do disco e do sistema de arquivos EXT2.          |
| `cat <file>`           | Mostra o conteúdo de um arquivo de texto.                                |
| `attr <file \| dir>`    | Exibe atributos de arquivos ou diretórios.                               |
| `cd <path>`            | Altera o diretório atual.                                                 |
| `ls`                   | Lista os arquivos/diretórios do diretório atual.                          |
| `pwd`                  | Exibe o caminho completo do diretório atual.                              |
| `touch <file>`         | Cria um arquivo vazio.                                                    |
| `mkdir <dir>`          | Cria um diretório vazio.                                                  |
| `rm <file>`            | Remove um arquivo.                                                        |
| `rmdir <dir>`          | Remove um diretório vazio.                                                |
| `rename <file> <novo>` | Renomeia um arquivo.                                                      |
| `cp <origem> <destino>`| Copia um arquivo da imagem para o sistema de arquivos real.               |
| `mv <origem> <destino>`| (Opcional) Move arquivo da imagem para fora.                              |

## 🧪 Restrições e simplificações

- Não utiliza `system()` ou bibliotecas prontas EXT2.
- Apenas 1 bloco por diretório (sem subdiretórios profundos).
- Tamanho fixo de bloco: 1024 bytes.
- Arquivos limitados a 64 MiB.
- Caminhos relativos simples (ex: `dir/arquivo.txt` não é necessário).

## Execução

Para rodar o shell:

```bash
./ext2shell imagem.img
```

Você verá um prompt semelhante a:

```
ext2shell:[/] $
```

## Créditos e Copyright

© 2025 Gabriel Craco e Leonardo Jun-Ity  
Orientador: Professor Rodrigo Campiolo  
Curso de Sistemas Operacionais – Universidade Tecnológica Federal do Paraná (UTFPR)  

Data de criação: 17/06/2025  
Data de modificação: 28/06/2025  

Este projeto foi desenvolvido como parte das atividades acadêmicas do curso de Sistemas Operacionais da UTFPR.  
Todos os direitos reservados aos autores acima mencionados.
