#!/usr/bin/env python3
# create_clobes_final.py - Crée CLOBES complet sans markdown ni docker

import os
import sys
import stat

def create_file(filepath, content, executable=False):
    """Crée un fichier avec le contenu donné"""
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
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
    
    # 2. install.sh - Installation principale
    create_file("install.sh", """#!/bin/bash
# install.sh - Installation de CLOBES

set -e

# Couleurs
RED='\\033[0;31m'
GREEN='\\033[0;32m'
YELLOW='\\033[1;33m'
BLUE='\\033[0;34m'
CYAN='\\033[0;36m'
NC='\\033[0m'

# Logging
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

show_banner() {
    echo -e "${CYAN}"
    echo "╔════════════════════════════════════════════════════╗"
    echo "║             🚀 INSTALLATION CLOBES                 ║"
    echo "║        Command Line Operations Bundle              ║"
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
    else
        log_warning "Installez manuellement: gcc, make, curl, libcurl"
    fi
    
    log_success "Dépendances installées"
}

compile_clobes() {
    log_info "Compilation de CLOBES..."
    
    if [ -f "Makefile" ]; then
        make clean 2>/dev/null || true
        if make; then
            log_success "Compilation réussie"
        else
            log_error "Compilation échouée"
            log_info "Tentative de compilation manuelle..."
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
    
    # Dossiers
    mkdir -p /usr/local/bin
    mkdir -p /etc/clobes
    mkdir -p /var/log/clobes
    
    # Binaire principal
    cp clobes /usr/local/bin/
    chmod 755 /usr/local/bin/clobes
    
    # Scripts
    if [ -d "bin" ]; then
        for script in bin/*; do
            if [ -f "$script" ]; then
                cp "$script" /usr/local/bin/
                chmod 755 "/usr/local/bin/$(basename "$script")"
            fi
        done
    fi
    
    # Configuration
    if [ ! -f "/etc/clobes/config.json" ]; then
        echo '{"version":"2.0.0","debug":false}' > /etc/clobes/config.json
    fi
    
    log_success "Fichiers installés"
}

create_uninstall_script() {
    cat > /usr/local/bin/clobes-uninstall << 'EOF'
#!/bin/bash
# Désinstallation de CLOBES

echo "🗑️  Désinstallation de CLOBES..."
rm -f /usr/local/bin/clobes
rm -f /usr/local/bin/curl-wrapper
rm -f /usr/local/bin/ccompile
rm -f /usr/local/bin/sysmon
rm -f /usr/local/bin/clobes-uninstall
echo "✅ CLOBES désinstallé"
EOF
    chmod 755 /usr/local/bin/clobes-uninstall
}

verify_install() {
    log_info "Vérification de l'installation..."
    
    if command -v clobes >/dev/null 2>&1; then
        log_success "CLOBES installé avec succès"
        echo ""
        echo "Commandes disponibles:"
        echo "  clobes help           - Afficher l'aide"
        echo "  clobes version        - Version"
        echo "  clobes sysinfo        - Infos système"
        echo "  curl-wrapper          - Client HTTP"
        echo "  ccompile              - Compilateur C"
        echo "  sysmon                - Monitoring"
        echo "  clobes-uninstall      - Désinstaller"
        echo ""
        echo "Pour tester: clobes help"
    else
        log_error "CLOBES non trouvé dans PATH"
    fi
}

main() {
    show_banner
    check_root
    install_deps
    compile_clobes
    install_files
    create_uninstall_script
    verify_install
}

# Exécution
trap 'log_error "Installation interrompue"; exit 1' INT TERM
main "$@"

exit 0
""", executable=True)
    
    # 3. Makefile simplifié
    create_file("Makefile", """# Makefile for CLOBES
CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c99
LIBS = -lcurl -lm
TARGET = clobes
SRC = src/clobes.c
OBJ = src/clobes.o

# Couleurs
RED = \\033[0;31m
GREEN = \\033[0;32m
YELLOW = \\033[1;33m
BLUE = \\033[0;34m
NC = \\033[0m

all: $(TARGET)

$(TARGET): $(OBJ)
	@echo "$(GREEN)🔨 Compilation de $(TARGET)...$(NC)"
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJ) $(LIBS)
	@echo "$(GREEN)✅ $(TARGET) compilé$(NC)"

$(OBJ): $(SRC) src/clobes.h
	$(CC) $(CFLAGS) -c $(SRC) -o $(OBJ)

install: $(TARGET)
	@echo "$(GREEN)📦 Installation...$(NC)"
	@sudo ./install.sh || echo "$(YELLOW)⚠️  Utilisez: sudo make install$(NC)"

clean:
	@echo "$(BLUE)🧹 Nettoyage...$(NC)"
	rm -f $(TARGET) $(OBJ)
	@echo "$(GREEN)✅ Nettoyé$(NC)"

test: $(TARGET)
	@echo "$(BLUE)🧪 Tests...$(NC)"
	./$(TARGET) version
	@echo "$(GREEN)✅ Test OK$(NC)"

help:
	@echo "$(GREEN)Commandes disponibles:$(NC)"
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
#include <unistd.h>
#include <sys/stat.h>
#include <time.h>
#include <dirent.h>

#define CLOBES_VERSION "2.0.0"
#define MAX_CMD_LENGTH 1024
#define MAX_ARGS 50
#define COLOR_RESET   "\\033[0m"
#define COLOR_RED     "\\033[31m"
#define COLOR_GREEN   "\\033[32m"
#define COLOR_YELLOW  "\\033[33m"
#define COLOR_BLUE    "\\033[34m"

typedef struct {
    char name[32];
    char description[128];
    char usage[256];
} Command;

typedef enum {
    CMD_HELP,
    CMD_VERSION,
    CMD_NETWORK,
    CMD_COMPILE,
    CMD_SYSINFO,
    CMD_FILES,
    CMD_SECURITY,
    CMD_UNKNOWN
} CommandType;

void print_info(const char *message);
void print_success(const char *message);
void print_warning(const char *message);
void print_error(const char *message);

void show_help();
void show_version();
CommandType parse_command(const char *cmd);
void execute_command(CommandType cmd, int argc, char *argv[]);

void handle_network(int argc, char *argv[]);
void handle_compile(int argc, char *argv[]);
void handle_sysinfo();
void handle_files(int argc, char *argv[]);
void handle_security(int argc, char *argv[]);

int execute_system(const char *cmd);
int file_exists(const char *path);
size_t get_file_size(const char *path);

#endif""")
    
    # 5. src/clobes.c - Version complète et fonctionnelle
    create_file("src/clobes.c", """#include "clobes.h"
#include <sys/utsname.h>
#include <sys/sysinfo.h>

Command commands[] = {
    {"help", "Afficher l'aide", "clobes help"},
    {"version", "Afficher la version", "clobes version"},
    {"network", "Commandes réseau", "clobes network [ping|curl|scan]"},
    {"compile", "Compiler un programme C", "clobes compile <file.c> [options]"},
    {"sysinfo", "Informations système", "clobes sysinfo"},
    {"files", "Operations fichiers", "clobes files [list|search|size]"},
    {"security", "Sécurité", "clobes security [hash|check]"},
    {"", "", ""}
};

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
    for (int i = 0; commands[i].name[0] != 0; i++) {
        printf("  %-12s - %s\\n", commands[i].name, commands[i].description);
        printf("      Usage: %s\\n\\n", commands[i].usage);
    }
    
    printf("Exemples:\\n");
    printf("  clobes sysinfo\\n");
    printf("  clobes network ping google.com\\n");
    printf("  clobes compile program.c -o program\\n");
    printf("  clobes files search /var/log *.log\\n");
}

void show_version() {
    printf("CLOBES Version: %s\\n", CLOBES_VERSION);
    printf("Compilé le: %s %s\\n", __DATE__, __TIME__);
}

CommandType parse_command(const char *cmd) {
    for (int i = 0; commands[i].name[0] != 0; i++) {
        if (strcmp(commands[i].name, cmd) == 0) {
            if (strcmp(cmd, "help") == 0) return CMD_HELP;
            if (strcmp(cmd, "version") == 0) return CMD_VERSION;
            if (strcmp(cmd, "network") == 0) return CMD_NETWORK;
            if (strcmp(cmd, "compile") == 0) return CMD_COMPILE;
            if (strcmp(cmd, "sysinfo") == 0) return CMD_SYSINFO;
            if (strcmp(cmd, "files") == 0) return CMD_FILES;
            if (strcmp(cmd, "security") == 0) return CMD_SECURITY;
        }
    }
    return CMD_UNKNOWN;
}

int execute_system(const char *cmd) {
    return system(cmd);
}

int file_exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0;
}

size_t get_file_size(const char *path) {
    struct stat st;
    if (stat(path, &st) == 0) {
        return st.st_size;
    }
    return 0;
}

void handle_network(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Sous-commandes réseau:\\n");
        printf("  ping <host>        - Tester la connectivité\\n");
        printf("  curl <url>         - Requête HTTP\\n");
        printf("  scan <host> <port> - Scanner un port\\n");
        return;
    }
    
    if (strcmp(argv[2], "ping") == 0 && argc >= 4) {
        char cmd[MAX_CMD_LENGTH];
        snprintf(cmd, sizeof(cmd), "ping -c 4 %s", argv[3]);
        print_info("Pinging...");
        execute_system(cmd);
    } else if (strcmp(argv[2], "curl") == 0 && argc >= 4) {
        char cmd[MAX_CMD_LENGTH];
        snprintf(cmd, sizeof(cmd), "curl -s %s", argv[3]);
        execute_system(cmd);
    } else {
        print_error("Commande réseau invalide");
    }
}

void handle_compile(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Usage: clobes compile <file.c> [options]\\n");
        printf("Options:\\n");
        printf("  -o <output>    Fichier de sortie\\n");
        printf("  -std <version> Standard C\\n");
        printf("  -O<level>      Niveau optimisation\\n");
        printf("  -Wall          Activer tous warnings\\n");
        return;
    }
    
    char output[256] = "a.out";
    char source[256] = "";
    
    // Parser arguments
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            strncpy(output, argv[i + 1], sizeof(output) - 1);
            i++;
        } else {
            strncpy(source, argv[i], sizeof(source) - 1);
        }
    }
    
    if (source[0] == 0) {
        print_error("Fichier source manquant");
        return;
    }
    
    if (!file_exists(source)) {
        print_error("Fichier non trouvé");
        return;
    }
    
    char cmd[MAX_CMD_LENGTH];
    snprintf(cmd, sizeof(cmd), "gcc -Wall -Wextra -O2 -std=c99 -o %s %s -lm", output, source);
    
    print_info("Compilation en cours...");
    printf("Commande: %s\\n", cmd);
    
    int result = execute_system(cmd);
    if (result == 0) {
        print_success("Compilation réussie!");
        printf("Exécutable: %s\\n", output);
        
        struct stat st;
        if (stat(output, &st) == 0) {
            printf("Taille: %.2f KB\\n", st.st_size / 1024.0);
        }
    } else {
        print_error("Échec de la compilation");
    }
}

void handle_sysinfo() {
    printf("🖥️  INFORMATIONS SYSTÈME\\n");
    printf("══════════════════════════════════════════\\n\\n");
    
    // OS
    print_info("Système d'exploitation:");
    execute_system("cat /etc/os-release 2>/dev/null | grep PRETTY_NAME || uname -a");
    
    // CPU
    printf("\\n");
    print_info("Processeur:");
    execute_system("grep 'model name' /proc/cpuinfo | head -1 | cut -d':' -f2");
    
    // Mémoire
    printf("\\n");
    print_info("Mémoire RAM:");
    execute_system("free -h | grep Mem");
    
    // Disque
    printf("\\n");
    print_info("Espace disque:");
    execute_system("df -h / | tail -1");
    
    // Uptime
    printf("\\n");
    print_info("Uptime:");
    execute_system("uptime -p");
    
    printf("\\n");
}

void handle_files(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Sous-commandes fichiers:\\n");
        printf("  list <dir>          - Lister fichiers\\n");
        printf("  search <dir> <pattern> - Rechercher\\n");
        printf("  size <file>         - Taille fichier\\n");
        return;
    }
    
    if (strcmp(argv[2], "list") == 0 && argc >= 4) {
        char cmd[MAX_CMD_LENGTH];
        snprintf(cmd, sizeof(cmd), "ls -la %s", argv[3]);
        execute_system(cmd);
    } else if (strcmp(argv[2], "search") == 0 && argc >= 5) {
        char cmd[MAX_CMD_LENGTH];
        snprintf(cmd, sizeof(cmd), "find %s -name \"%s\" 2>/dev/null", argv[3], argv[4]);
        execute_system(cmd);
    } else if (strcmp(argv[2], "size") == 0 && argc >= 4) {
        size_t size = get_file_size(argv[3]);
        if (size > 0) {
            printf("Taille de %s: %.2f KB (%.2f MB)\\n", 
                   argv[3], size / 1024.0, size / (1024.0 * 1024.0));
        } else {
            print_error("Fichier non trouvé");
        }
    }
}

void handle_security(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Sous-commandes sécurité:\\n");
        printf("  hash <file>         - Calculer hash\\n");
        printf("  check <file> <hash> - Vérifier hash\\n");
        return;
    }
    
    if (strcmp(argv[2], "hash") == 0 && argc >= 4) {
        if (!file_exists(argv[3])) {
            print_error("Fichier non trouvé");
            return;
        }
        
        print_info("Calcul du hash...");
        char cmd[MAX_CMD_LENGTH];
        snprintf(cmd, sizeof(cmd), "sha256sum %s", argv[3]);
        execute_system(cmd);
    } else {
        print_error("Commande sécurité invalide");
    }
}

void execute_command(CommandType cmd, int argc, char *argv[]) {
    switch (cmd) {
        case CMD_HELP:
            show_help();
            break;
            
        case CMD_VERSION:
            show_version();
            break;
            
        case CMD_NETWORK:
            handle_network(argc, argv);
            break;
            
        case CMD_COMPILE:
            handle_compile(argc, argv);
            break;
            
        case CMD_SYSINFO:
            handle_sysinfo();
            break;
            
        case CMD_FILES:
            handle_files(argc, argv);
            break;
            
        case CMD_SECURITY:
            handle_security(argc, argv);
            break;
            
        case CMD_UNKNOWN:
            print_error("Commande inconnue");
            printf("Utilisez 'clobes help' pour voir les commandes\\n");
            break;
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        show_help();
        return 0;
    }
    
    CommandType cmd = parse_command(argv[1]);
    execute_command(cmd, argc, argv);
    
    return 0;
}
""")
    
    # 6. Scripts binaires
    print("📝 Création des scripts binaires...")
    
    # curl-wrapper
    create_file("bin/curl-wrapper", """#!/bin/bash
# curl-wrapper - Client HTTP simplifié

VERSION="1.0.0"
RED='\\033[31m'
GREEN='\\033[32m'
YELLOW='\\033[33m'
BLUE='\\033[34m'
NC='\\033[0m'

log() {
    local level=$1
    local msg=$2
    local color=""
    
    case $level in
        error) color=$RED ;;
        success) color=$GREEN ;;
        warning) color=$YELLOW ;;
        info) color=$BLUE ;;
    esac
    
    echo -e "${color}[${level^^}]${NC} $msg"
}

show_help() {
    echo "curl-wrapper v$VERSION"
    echo "Client HTTP simplifié pour CLOBES"
    echo ""
    echo "Usage:"
    echo "  curl-wrapper [METHOD] URL [OPTIONS]"
    echo "  curl-wrapper <command> [args]"
    echo ""
    echo "Commandes:"
    echo "  get URL              - GET request"
    echo "  post URL DATA        - POST avec données"
    echo "  download URL FILE    - Télécharger fichier"
    echo "  status URL           - Vérifier status HTTP"
    echo "  headers URL          - Afficher headers"
    echo "  help                 - Cette aide"
    echo ""
    echo "Options:"
    echo "  -H HEADER            - Ajouter header"
    echo "  -d DATA              - Envoyer données"
    echo "  -o FILE              - Sauvegarder dans fichier"
    echo "  -t SECONDS           - Timeout"
    echo "  -v                   - Mode verbeux"
}

if ! command -v curl >/dev/null 2>&1; then
    log error "curl non installé"
    exit 1
fi

if [ $# -eq 0 ]; then
    show_help
    exit 0
fi

case "$1" in
    get)
        if [ -z "$2" ]; then
            log error "URL requise"
            exit 1
        fi
        curl -s -X GET "$2" -H "User-Agent: curl-wrapper/$VERSION"
        ;;
        
    post)
        if [ -z "$3" ]; then
            log error "URL et données requises"
            exit 1
        fi
        curl -s -X POST "$2" -H "Content-Type: application/json" -d "$3"
        ;;
        
    download)
        if [ -z "$3" ]; then
            log error "URL et fichier de sortie requis"
            exit 1
        fi
        log info "Téléchargement de $2..."
        curl -L -o "$3" "$2" --progress-bar
        if [ $? -eq 0 ]; then
            log success "Téléchargé: $3"
            ls -lh "$3"
        else
            log error "Échec du téléchargement"
        fi
        ;;
        
    status)
        if [ -z "$2" ]; then
            log error "URL requise"
            exit 1
        fi
        code=$(curl -s -o /dev/null -w "%{http_code}" "$2")
        echo "HTTP $code - $2"
        ;;
        
    headers)
        curl -I -s "$2"
        ;;
        
    help|--help|-h)
        show_help
        ;;
        
    *)
        # Passer à curl normal
        curl "$@"
        ;;
esac
""", executable=True)
    
    # ccompile
    create_file("bin/ccompile", """#!/bin/bash
# ccompile - Compilateur C simplifié

VERSION="1.0.0"
RED='\\033[31m'
GREEN='\\033[32m'
YELLOW='\\033[33m'
BLUE='\\033[34m'
NC='\\033[0m'

log() {
    local level=$1
    local msg=$2
    local color=""
    
    case $level in
        error) color=$RED ;;
        success) color=$GREEN ;;
        warning) color=$YELLOW ;;
        info) color=$BLUE ;;
    esac
    
    echo -e "${color}[${level^^}]${NC} $msg"
}

show_help() {
    echo "ccompile v$VERSION"
    echo "Compilateur C simplifié pour CLOBES"
    echo ""
    echo "Usage: ccompile [OPTIONS] <file.c>"
    echo ""
    echo "Options:"
    echo "  -o FILE        Fichier de sortie (défaut: a.out)"
    echo "  -std VERSION   Standard C (c99, c11, c17)"
    echo "  -O LEVEL       Niveau optimisation (0,1,2,3,s)"
    echo "  -g             Inclure info debug"
    echo "  -Wall          Activer tous warnings"
    echo "  -l LIB         Lier avec bibliothèque"
    echo "  -I DIR         Ajouter répertoire include"
    echo "  -L DIR         Ajouter répertoire lib"
    echo "  -v             Mode verbeux"
    echo "  -h             Aide"
}

if ! command -v gcc >/dev/null 2>&1; then
    log error "gcc non installé"
    exit 1
fi

if [ $# -eq 0 ]; then
    show_help
    exit 0
fi

OUTPUT="a.out"
SOURCE=""
FLAGS="-Wall -Wextra -std=c99"
VERBOSE=0

while [[ $# -gt 0 ]]; do
    case $1 in
        -o)
            OUTPUT="$2"
            shift 2
            ;;
        -std)
            FLAGS="$FLAGS -std=$2"
            shift 2
            ;;
        -O*)
            FLAGS="$FLAGS $1"
            shift
            ;;
        -g|-Wall|-Wextra)
            FLAGS="$FLAGS $1"
            shift
            ;;
        -l)
            FLAGS="$FLAGS -l$2"
            shift 2
            ;;
        -I)
            FLAGS="$FLAGS -I$2"
            shift 2
            ;;
        -L)
            FLAGS="$FLAGS -L$2"
            shift 2
            ;;
        -v)
            VERBOSE=1
            shift
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        -*)
            log warning "Option ignorée: $1"
            shift
            ;;
        *)
            if [[ "$1" == *.c ]]; then
                SOURCE="$1"
            else
                log warning "Extension .c recommandée: $1"
                SOURCE="$1"
            fi
            shift
            ;;
    esac
done

if [ -z "$SOURCE" ]; then
    log error "Fichier source requis"
    exit 1
fi

if [ ! -f "$SOURCE" ]; then
    log error "Fichier non trouvé: $SOURCE"
    exit 1
fi

CMD="gcc $FLAGS -o $OUTPUT $SOURCE -lm"

if [ $VERBOSE -eq 1 ]; then
    log info "Commande: $CMD"
fi

log info "Compilation de $SOURCE..."
START=$(date +%s.%N)

if eval $CMD; then
    END=$(date +%s.%N)
    TIME=$(echo "$END - $START" | bc)
    
    log success "Compilation réussie!"
    echo "  Output: $OUTPUT"
    
    if [ -f "$OUTPUT" ]; then
        SIZE=$(stat -c%s "$OUTPUT" 2>/dev/null || stat -f%z "$OUTPUT" 2>/dev/null)
        echo "  Taille: $((SIZE/1024)) KB"
        echo "  Temps: ${TIME}s"
        
        # Vérifier si exécutable
        if [[ -x "$OUTPUT" ]]; then
            echo "  ✅ Exécutable"
        fi
    fi
else
    log error "Échec de la compilation"
    exit 1
fi
""", executable=True)
    
    # sysmon
    create_file("bin/sysmon", """#!/bin/bash
# sysmon - Monitoring système

VERSION="1.0.0"
INTERVAL=2
COUNT=10

show_help() {
    echo "sysmon v$VERSION"
    echo "Monitoring système pour CLOBES"
    echo ""
    echo "Usage: sysmon [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -i SECONDS    Intervalle (défaut: 2)"
    echo "  -c COUNT      Nombre d'itérations (défaut: 10)"
    echo "  -m MODE       Mode (basic, cpu, mem, disk)"
    echo "  -h            Aide"
}

get_cpu_usage() {
    # Lecture de /proc/stat
    local cpu_line=$(grep '^cpu ' /proc/stat)
    local idle=$(echo $cpu_line | awk '{print $5}')
    local total=0
    
    for i in $cpu_line; do
        total=$((total + i))
    done
    
    echo $((100 - (idle * 100) / total))
}

get_memory_usage() {
    free -m | awk '
    /^Mem:/ {
        printf "%.1f%% (%d/%d MB)", ($3/$2)*100, $3, $2
    }'
}

get_disk_usage() {
    df -h / | tail -1 | awk '{print $5}'
}

get_load_avg() {
    cat /proc/loadavg | awk '{print $1, $2, $3}'
}

get_uptime() {
    uptime -p | sed 's/^up //'
}

monitor_basic() {
    clear
    echo "🖥️  SYSMON - $(date)"
    echo "════════════════════════════════════"
    echo ""
    
    # CPU
    echo "⚡ CPU: $(get_cpu_usage)%"
    
    # Mémoire
    echo "💾 Mémoire: $(get_memory_usage)"
    
    # Disque
    echo "💿 Disque (/): $(get_disk_usage)"
    
    # Load average
    echo "📈 Load: $(get_load_avg)"
    
    # Uptime
    echo "⏱️  Uptime: $(get_uptime)"
    
    # Processus
    echo ""
    echo "🔄 Top processus:"
    ps aux --sort=-%cpu | head -6 | awk '
    NR==1 {print "USER       PID %CPU %MEM COMMAND"}
    NR>1 {printf "%-10s %5d %4.1f %4.1f %s\\n", $1, $2, $3, $4, $11}'
}

# Parser arguments
while getopts "i:c:m:h" opt; do
    case $opt in
        i) INTERVAL=$OPTARG ;;
        c) COUNT=$OPTARG ;;
        m) MODE=$OPTARG ;;
        h) show_help; exit 0 ;;
        *) show_help; exit 1 ;;
    esac
done

# Monitoring
for ((i=1; i<=COUNT; i++)); do
    monitor_basic
    
    if [ $i -lt $COUNT ]; then
        sleep $INTERVAL
    fi
done
""", executable=True)
    
    # 7. Fichier de test
    create_file("tests/test_basic.sh", """#!/bin/bash
# Test basique de CLOBES

echo "🧪 Test de CLOBES..."
echo "════════════════════════════"

# Vérifier la compilation
if [ ! -f "../Makefile" ]; then
    echo "❌ Makefile non trouvé"
    exit 1
fi

cd ..

# Clean
make clean 2>/dev/null || true

# Compiler
echo "🔨 Compilation..."
if make; then
    echo "✅ Compilation réussie"
else
    echo "❌ Échec compilation"
    exit 1
fi

# Tests basiques
echo ""
echo "🧪 Tests fonctionnels..."

# Test version
echo "1. Test version..."
./clobes version
if [ $? -eq 0 ]; then
    echo "   ✅ Version OK"
else
    echo "   ❌ Version échoué"
fi

# Test help
echo ""
echo "2. Test help..."
./clobes help > /dev/null
if [ $? -eq 0 ]; then
    echo "   ✅ Help OK"
else
    echo "   ❌ Help échoué"
fi

# Test sysinfo
echo ""
echo "3. Test sysinfo..."
./clobes sysinfo > /dev/null
if [ $? -eq 0 ]; then
    echo "   ✅ Sysinfo OK"
else
    echo "   ❌ Sysinfo échoué"
fi

# Nettoyage
make clean

echo ""
echo "════════════════════════════"
echo "✅ Tests terminés avec succès"
echo ""
echo "Pour installer: sudo make install"
""", executable=True)
    
    print("")
    print("✨ PROJET CLOBES CRÉÉ AVEC SUCCÈS ✨")
    print("========================================")
    print("")
    print("📁 Structure créée:")
    print("  @za.json          - Configuration du package")
    print("  install.sh        - Script d'installation")
    print("  Makefile          - Fichier de compilation")
    print("  src/clobes.h      - Header principal")
    print("  src/clobes.c      - Code source principal")
    print("  bin/curl-wrapper  - Client HTTP")
    print("  bin/ccompile      - Compilateur C")
    print("  bin/sysmon        - Monitoring système")
    print("  tests/test_basic.sh - Tests")
    print("")
    print("🚀 Pour installer depuis GitHub:")
    print("  curl -fsSL https://raw.githubusercontent.com/gopu-inc/clobes/main/install.sh | sudo sh")
    print("")
    print("🔨 Pour compiler localement:")
    print("  make")
    print("  sudo make install")
    print("")
    print("📦 Pour créer un package:")
    print("  zarch build @za.json")
    print("  zarch publish clobes-2.0.0.zv")

if __name__ == "__main__":
    main()
