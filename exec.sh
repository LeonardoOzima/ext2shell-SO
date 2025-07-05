#!/bin/bash

# Remove a imagem antiga
rm -rf myext2image.img

# Extrai a imagem a partir do tar.gz
tar -zvxf myext2image.tar.gz

# Compila o projeto
make
