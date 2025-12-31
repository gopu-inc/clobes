#!/usr/bin/env python3
# create_clobes_fixed.py - Version corrigée

import os
import sys
import stat

def create_file(filepath, content, executable=False):
    """Crée un fichier avec le contenu donné"""
    # Créer le répertoire parent si nécessaire
    dirname = os.path.dirname(filepath)
    if dirname:
        os.makedirs(dirname, exist_ok=True)
    
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)
    
    if executable:
        os.chmod(filepath, os.stat(filepath).st_mode | stat.S_IEXEC)
    
    print(f"📄 Créé: {filepath}")
    if executable:
        print(f"   ✅ Rendu exécutable")

def main():
    print("🚀 Création du projet CLOBES final...")
    print("========================================")
    
    # Créer la structure
    directories = ["src", "bin", "tests"]
    for dir_name in directories:
        os.makedirs(dir_name, exist_ok=True)
        print(f"📁 Créé: {dir_name}/")
    
    # 1. @za.json
    create_file("@za.json", """{
    "name": "clobes",
    "version": "2.0.0",
    "author": "Zenv Team",
    "license": "MIT",
    "description": "Command Line Operations Bundle & Execution System",
    "build_dir": ".",
    "output": "clobes-2.0.0.zv",
    "include": [
        "src/",
        "bin/",
        "Makefile",
        "@za.json",
        "install.sh"
    ],
    "exclude": [
        "*.tmp",
        "*.log",
        "*.o",
        "__pycache__"
    ]
}""")
    
    # 2. install.sh
    create_file("install.sh", """#!/bin/bash
# install.sh - Installation de CLOBES

set -e

RED='\\033[0;31m'
GREEN='\\033[0;32m'
YELLOW='\\033[1;33m'
BLUE='\\033[0;34m'
CYAN='\\033[0;36m'
NC='\\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

show_banner() {
    echo -e "${CYAN}"
    echo "╔════════════════════════════════════════════════════╗"
    echo "║             🚀 INSTALLATION CLOBES                 ║"
    echo "╚════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "Exécutez avec: sudo $0"
        exit 1
    fi
}

install_deps() {
    log_info "Installation des dépendances..."
    
    if command -v apk >/dev/null 2>&1; then
        apk add --no-cache curl gcc make libc-dev curl-dev
    elif command -v apt-get >/dev/null 2>&1; then
        apt-get update
        apt-get install -y curl gcc make libc6-dev libcurl4-openssl-dev
    elif command -v yum >/dev/null 2>&1; then
        yum install -y curl gcc make glibc-devel libcurl-devel
    fi
    
    log_success "Dépendances installées"
}

compile_clobes() {
    log_info "Compilation de CLOBES..."
    
    if [ -f "Makefile" ]; then
        if make; then
            log_success "Compilation réussie"
        else
            gcc -Wall -Wextra -O2 -std=c99 -o clobes src/clobes.c -lcurl -lm
        fi
    else
        gcc -Wall -Wextra -O2 -std=c99 -o clobes src/clobes.c -lcurl -lm
    fi
    
    if [ ! -f "clobes" ]; then
        log_error "Échec de la compilation"
        exit 1
    fi
}

install_files() {
    log_info "Installation des fichiers..."
    
    mkdir -p /usr/local/bin
    mkdir -p /etc/clobes
    
    cp clobes /usr/local/bin/
    chmod 755 /usr/local/bin/clobes
    
    if [ -d "bin" ]; then
        for script in bin/*; do
            if [ -f "$script" ]; then
                cp "$script" /usr/local/bin/
                chmod 755 "/usr/local/bin/$(basename "$script")"
            fi
        done
    fi
    
    echo '{"version":"2.0.0","debug":false}' > /etc/clobes/config.json
    
    log_success "Fichiers installés"
}

verify_install() {
    log_info "Vérification..."
    
    if command -v clobes >/dev/null 2>&1; then
        log_success "CLOBES installé!"
        echo ""
        echo "Commandes:"
        echo "  clobes help           - Aide"
        echo "  clobes version        - Version"
        echo "  clobes sysinfo        - Infos système"
        echo "  curl-wrapper          - Client HTTP"
        echo "  ccompile              - Compilateur C"
        echo "  sysmon                - Monitoring"
    fi
}

main() {
    show_banner
    check_root
    install_deps
    compile_clobes
    install_files
    verify_install
}

trap 'log_error "Installation interrompue"; exit 1' INT TERM
main "$@"

exit 0
""", executable=True)
    
    # 3. Makefile
    create_file("Makefile", """# Makefile for CLOBES
CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c99
LIBS = -lcurl -lm
TARGET = clobes
SRC = src/clobes.c
OBJ = src/clobes.o

all: $(TARGET)

$(TARGET): $(OBJ)
	@echo "🔨 Compilation de $(TARGET)..."
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJ) $(LIBS)
	@echo "✅ $(TARGET) compilé"

$(OBJ): $(SRC) src/clobes.h
	$(CC) $(CFLAGS) -c $(SRC) -o $(OBJ)

install: $(TARGET)
	@echo "📦 Installation..."
	@sudo ./install.sh || echo "⚠️  Utilisez: sudo make install"

clean:
	@echo "🧹 Nettoyage..."
	rm -f $(TARGET) $(OBJ)
	@echo "✅ Nettoyé"

test: $(TARGET)
	@echo "🧪 Tests..."
	./$(TARGET) version
	@echo "✅ Test OK"

help:
	@echo "Commandes:"
	@echo "  make           - Compiler"
	@echo "  make install   - Installer (sudo)"
	@echo "  make clean     - Nettoyer"
	@echo "  make test      - Tester"
	@echo "  make help      - Aide"
""")
    
    # 4. src/clobes.h
    create_file("src/clobes.h", """#ifndef CLOBES_H
#define CLOBES_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CLOBES_VERSION "2.0.0"
#define MAX_CMD_LENGTH 1024

void print_info(const char *message);
void print_success(const char *message);
void print_warning(const char *message);
void print_error(const char *message);

void show_help();
void show_version();

#endif""")
    
    # 5. src/clobes.c - Version simplifiée mais fonctionnelle
    create_file("src/clobes.c", """#include "clobes.h"

#define COLOR_RESET   "\\033[0m"
#define COLOR_RED     "\\033[31m"
#define COLOR_GREEN   "\\033[32m"
#define COLOR_YELLOW  "\\033[33m"
#define COLOR_BLUE    "\\033[34m"

void print_info(const char *message) {
    printf(COLOR_BLUE "[INFO] " COLOR_RESET "%s\\n", message);
}

void print_success(const char *message) {
    printf(COLOR_GREEN "[SUCCESS] " COLOR_RESET "%s\\n", message);
}

void print_warning(const char *message) {
    printf(COLOR_YELLOW "[WARNING] " COLOR_RESET "%s\\n", message);
}

void print_error(const char *message) {
    fprintf(stderr, COLOR_RED "[ERROR] " COLOR_RESET "%s\\n", message);
}

void show_help() {
    printf("🚀 CLOBES v%s - Command Line Operations Bundle\\n", CLOBES_VERSION);
    printf("══════════════════════════════════════════\\n\\n");
    
    printf("Commandes disponibles:\\n");
    printf("  help           - Afficher cette aide\\n");
    printf("  version        - Afficher la version\\n");
    printf("  sysinfo        - Informations système\\n");
    printf("  network ping   - Tester la connectivité\\n");
    printf("  compile        - Compiler programme C\\n");
    printf("\\n");
    printf("Exemples:\\n");
    printf("  clobes sysinfo\\n");
    printf("  clobes network ping google.com\\n");
    printf("  clobes compile program.c\\n");
}

void show_version() {
    printf("CLOBES Version: %s\\n", CLOBES_VERSION);
    printf("Compilé le: %s %s\\n", __DATE__, __TIME__);
}

void show_sysinfo() {
    printf("🖥️  INFORMATIONS SYSTÈME\\n");
    printf("══════════════════════════════════════════\\n\\n");
    
    // OS
    print_info("Système d'exploitation:");
    system("cat /etc/os-release 2>/dev/null | grep PRETTY_NAME || uname -a");
    
    // CPU
    printf("\\n");
    print_info("Processeur:");
    system("grep 'model name' /proc/cpuinfo | head -1 | cut -d':' -f2");
    
    // Mémoire
    printf("\\n");
    print_info("Mémoire RAM:");
    system("free -h | grep Mem");
    
    // Uptime
    printf("\\n");
    print_info("Uptime:");
    system("uptime -p");
    
    printf("\\n");
}

void handle_network(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Usage: clobes network ping <host>\\n");
        return;
    }
    
    if (strcmp(argv[2], "ping") == 0 && argc >= 4) {
        char cmd[MAX_CMD_LENGTH];
        snprintf(cmd, sizeof(cmd), "ping -c 4 %s", argv[3]);
        print_info("Pinging...");
        system(cmd);
    }
}

void handle_compile(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Usage: clobes compile <file.c>\\n");
        return;
    }
    
    char output[256] = "a.out";
    char source[256] = "";
    
    strncpy(source, argv[2], sizeof(source) - 1);
    
    char cmd[MAX_CMD_LENGTH];
    snprintf(cmd, sizeof(cmd), "gcc -Wall -Wextra -O2 -std=c99 -o %s %s -lm", output, source);
    
    print_info("Compilation en cours...");
    printf("Commande: %s\\n", cmd);
    
    int result = system(cmd);
    if (result == 0) {
        print_success("Compilation réussie!");
        printf("Exécutable: %s\\n", output);
    } else {
        print_error("Échec de la compilation");
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        show_help();
        return 0;
    }
    
    if (strcmp(argv[1], "help") == 0) {
        show_help();
    } else if (strcmp(argv[1], "version") == 0) {
        show_version();
    } else if (strcmp(argv[1], "sysinfo") == 0) {
        show_sysinfo();
    } else if (strcmp(argv[1], "network") == 0) {
        handle_network(argc, argv);
    } else if (strcmp(argv[1], "compile") == 0) {
        handle_compile(argc, argv);
    } else {
        print_error("Commande inconnue");
        printf("Utilisez 'clobes help' pour voir les commandes\\n");
        return 1;
    }
    
    return 0;
}
""")
    
    # 6. Scripts binaires
    # curl-wrapper
    create_file("bin/curl-wrapper", """#!/bin/bash
# curl-wrapper - Client HTTP

VERSION="1.0.0"

show_help() {
    echo "curl-wrapper v$VERSION"
    echo "Usage: curl-wrapper [get|post|download] <url>"
}

if [ $# -eq 0 ]; then
    show_help
    exit 0
fi

case "$1" in
    get)
        if [ -z "$2" ]; then
            echo "URL required"
            exit 1
        fi
        curl -s "$2"
        ;;
        
    post)
        if [ -z "$3" ]; then
            echo "URL and data required"
            exit 1
        fi
        curl -s -X POST "$2" -d "$3"
        ;;
        
    download)
        if [ -z "$3" ]; then
            echo "URL and output file required"
            exit 1
        fi
        curl -L -o "$3" "$2"
        ;;
        
    *)
        curl "$@"
        ;;
esac
""", executable=True)
    
    # ccompile
    create_file("bin/ccompile", """#!/bin/bash
# ccompile - Compilateur C

if [ $# -eq 0 ]; then
    echo "Usage: ccompile <file.c> [-o output]"
    exit 0
fi

OUTPUT="a.out"
SOURCE=""

while [[ $# -gt 0 ]]; do
    case $1 in
        -o)
            OUTPUT="$2"
            shift 2
            ;;
        *)
            SOURCE="$1"
            shift
            ;;
    esac
done

if [ -z "$SOURCE" ]; then
    echo "Source file required"
    exit 1
fi

echo "Compiling $SOURCE..."
gcc -Wall -Wextra -O2 -std=c99 -o "$OUTPUT" "$SOURCE" -lm

if [ $? -eq 0 ]; then
    echo "Compilation successful: $OUTPUT"
else
    echo "Compilation failed"
    exit 1
fi
""", executable=True)
    
    # sysmon
    create_file("bin/sysmon", """#!/bin/bash
# sysmon - Monitoring

echo "System Monitor"
echo "════════════════════════════"
echo ""

echo "CPU Usage:"
top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1
echo "%"
echo ""

echo "Memory:"
free -h | grep Mem
echo ""

echo "Disk:"
df -h / | tail -1
echo ""

echo "Uptime:"
uptime -p
""", executable=True)
    
    print("")
    print("✨ PROJET CLOBES CRÉÉ AVEC SUCCÈS ✨")
    print("========================================")
    print("")
    print("Pour installer: sudo ./install.sh")
    print("Pour compiler: make")
    print("Pour tester: ./clobes version")

if __name__ == "__main__":
    main()
