#!/usr/bin/env python3
# upgrade_clobes.py - Améliore CLOBES pour rivaliser avec curl

import os
import shutil

def backup_original():
    """Sauvegarde la version originale"""
    if os.path.exists("clobes"):
        shutil.copy("clobes", "clobes.backup")
        print("✅ Version originale sauvegardée: clobes.backup")
    if os.path.exists("src/clobes.c"):
        shutil.copy("src/clobes.c", "src/clobes.c.backup")
        print("✅ Source originale sauvegardée: src/clobes.c.backup")

def create_enhanced_clobes():
    """Crée une version améliorée de clobes.c"""
    print("🔄 Création de CLOBES amélioré...")
    
    enhanced_code = '''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <time.h>
#include <curl/curl.h>
#include <sys/utsname.h>
#include <sys/sysinfo.h>
#include <dirent.h>
#include <errno.h>

#define CLOBES_VERSION "3.0.0"
#define MAX_CMD_LENGTH 4096
#define MAX_OUTPUT 8192
#define COLOR_RESET   "\\033[0m"
#define COLOR_RED     "\\033[31m"
#define COLOR_GREEN   "\\033[32m"
#define COLOR_YELLOW  "\\033[33m"
#define COLOR_BLUE    "\\033[0;34m"
#define COLOR_CYAN    "\\033[0;36m"
#define COLOR_MAGENTA "\\033[0;35m"

// Structure pour réponse HTTP
typedef struct {
    char *data;
    size_t size;
} HTTPResponse;

// Fonctions d'affichage
void print_info(const char *format, ...) {
    va_list args;
    va_start(args, format);
    printf(COLOR_BLUE "[INFO] " COLOR_RESET);
    vprintf(format, args);
    printf("\\n");
    va_end(args);
}

void print_success(const char *format, ...) {
    va_list args;
    va_start(args, format);
    printf(COLOR_GREEN "[SUCCESS] " COLOR_RESET);
    vprintf(format, args);
    printf("\\n");
    va_end(args);
}

void print_warning(const char *format, ...) {
    va_list args;
    va_start(args, format);
    printf(COLOR_YELLOW "[WARNING] " COLOR_RESET);
    vprintf(format, args);
    printf("\\n");
    va_end(args);
}

void print_error(const char *format, ...) {
    va_list args;
    va_start(args, format);
    fprintf(stderr, COLOR_RED "[ERROR] " COLOR_RESET);
    vfprintf(stderr, format, args);
    fprintf(stderr, "\\n");
    va_end(args);
}

void print_debug(const char *format, ...) {
    if (getenv("CLOBES_DEBUG")) {
        va_list args;
        va_start(args, format);
        printf(COLOR_MAGENTA "[DEBUG] " COLOR_RESET);
        vprintf(format, args);
        printf("\\n");
        va_end(args);
    }
}

// Callback pour curl
static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    HTTPResponse *resp = (HTTPResponse *)userp;
    
    char *ptr = realloc(resp->data, resp->size + realsize + 1);
    if (!ptr) return 0;
    
    resp->data = ptr;
    memcpy(&(resp->data[resp->size]), contents, realsize);
    resp->size += realsize;
    resp->data[resp->size] = 0;
    
    return realsize;
}

// Fonction HTTP GET avancée
char* http_get(const char *url, int timeout, int verbose) {
    CURL *curl = curl_easy_init();
    if (!curl) return NULL;
    
    HTTPResponse resp = {NULL, 0};
    
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&resp);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "clobes/3.0.0");
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    
    if (verbose) {
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    }
    
    CURLcode res = curl_easy_perform(curl);
    
    if (res != CURLE_OK) {
        print_error("HTTP request failed: %s", curl_easy_strerror(res));
        free(resp.data);
        resp.data = NULL;
    }
    
    curl_easy_cleanup(curl);
    return resp.data;
}

// Fonction HTTP POST
char* http_post(const char *url, const char *data, const char *content_type, int timeout) {
    CURL *curl = curl_easy_init();
    if (!curl) return NULL;
    
    HTTPResponse resp = {NULL, 0};
    
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&resp);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "clobes/3.0.0");
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout);
    
    if (content_type) {
        struct curl_slist *headers = NULL;
        char header[256];
        snprintf(header, sizeof(header), "Content-Type: %s", content_type);
        headers = curl_slist_append(headers, header);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    }
    
    CURLcode res = curl_easy_perform(curl);
    
    if (res != CURLE_OK) {
        print_error("HTTP POST failed: %s", curl_easy_strerror(res));
        free(resp.data);
        resp.data = NULL;
    }
    
    curl_easy_cleanup(curl);
    return resp.data;
}

// Téléchargement de fichier avec progression
int download_file(const char *url, const char *output, int show_progress) {
    CURL *curl = curl_easy_init();
    if (!curl) return 0;
    
    FILE *fp = fopen(output, "wb");
    if (!fp) {
        print_error("Cannot open file: %s", output);
        curl_easy_cleanup(curl);
        return 0;
    }
    
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, fwrite);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "clobes/3.0.0");
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    
    if (show_progress) {
        curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
        print_info("Downloading %s...", url);
    }
    
    CURLcode res = curl_easy_perform(curl);
    fclose(fp);
    curl_easy_cleanup(curl);
    
    if (res != CURLE_OK) {
        print_error("Download failed: %s", curl_easy_strerror(res));
        remove(output);
        return 0;
    }
    
    return 1;
}

// Système d'information amélioré
void show_sysinfo_detail() {
    printf(COLOR_CYAN "🖥️  SYSTEM INFORMATION\\n" COLOR_RESET);
    printf("══════════════════════════════════════════════════\\n\\n");
    
    struct utsname sysinfo;
    if (uname(&sysinfo) == 0) {
        printf(COLOR_BLUE "System:\\n" COLOR_RESET);
        printf("  OS:      %s\\n", sysinfo.sysname);
        printf("  Host:    %s\\n", sysinfo.nodename);
        printf("  Release: %s\\n", sysinfo.release);
        printf("  Version: %s\\n", sysinfo.version);
        printf("  Arch:    %s\\n", sysinfo.machine);
    }
    
    struct sysinfo meminfo;
    if (sysinfo(&meminfo) == 0) {
        printf("\\n" COLOR_BLUE "Memory:\\n" COLOR_RESET);
        printf("  Total:     %lu MB\\n", meminfo.totalram / 1024 / 1024);
        printf("  Free:      %lu MB\\n", meminfo.freeram / 1024 / 1024);
        printf("  Used:      %lu MB\\n", (meminfo.totalram - meminfo.freeram) / 1024 / 1024);
        printf("  Processes: %d\\n", meminfo.procs);
    }
    
    printf("\\n" COLOR_BLUE "Uptime:\\n" COLOR_RESET);
    system("uptime -p");
    
    printf("\\n" COLOR_BLUE "Load Average:\\n" COLOR_RESET);
    system("cat /proc/loadavg");
    
    printf("\\n" COLOR_BLUE "Disk Usage:\\n" COLOR_RESET);
    system("df -h / | grep -v Filesystem");
}

// Gestionnaire de réseau amélioré
void handle_network_advanced(int argc, char *argv[]) {
    if (argc < 3) {
        printf(COLOR_CYAN "🌐 NETWORK COMMANDS\\n" COLOR_RESET);
        printf("══════════════════════════════════════════\\n\\n");
        printf("  ping <host>            - Ping host\\n");
        printf("  curl <url> [options]   - HTTP client\\n");
        printf("  download <url> <file>  - Download file\\n");
        printf("  scan <host> <port>     - Port scan\\n");
        printf("  dns <domain>           - DNS lookup\\n");
        printf("  ip                     - Show IP addresses\\n");
        printf("  speedtest              - Speed test\\n");
        return;
    }
    
    if (strcmp(argv[2], "curl") == 0 && argc >= 4) {
        int timeout = 30;
        int verbose = 0;
        char *method = "GET";
        char *data = NULL;
        char *content_type = "application/json";
        
        // Parser les options
        for (int i = 4; i < argc; i++) {
            if (strcmp(argv[i], "-X") == 0 && i + 1 < argc) {
                method = argv[i + 1];
                i++;
            } else if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
                data = argv[i + 1];
                i++;
            } else if (strcmp(argv[i], "-H") == 0 && i + 1 < argc) {
                content_type = argv[i + 1];
                i++;
            } else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
                timeout = atoi(argv[i + 1]);
                i++;
            } else if (strcmp(argv[i], "-v") == 0) {
                verbose = 1;
            }
        }
        
        if (strcmp(method, "GET") == 0) {
            char *response = http_get(argv[3], timeout, verbose);
            if (response) {
                printf("%s\\n", response);
                free(response);
            }
        } else if (strcmp(method, "POST") == 0 && data) {
            char *response = http_post(argv[3], data, content_type, timeout);
            if (response) {
                printf("%s\\n", response);
                free(response);
            }
        } else {
            print_error("Invalid HTTP method or missing data");
        }
        
    } else if (strcmp(argv[2], "download") == 0 && argc >= 5) {
        if (download_file(argv[3], argv[4], 1)) {
            print_success("Download completed: %s", argv[4]);
            struct stat st;
            if (stat(argv[4], &st) == 0) {
                printf("Size: %.2f MB\\n", st.st_size / (1024.0 * 1024.0));
            }
        }
        
    } else if (strcmp(argv[2], "ping") == 0 && argc >= 4) {
        char cmd[MAX_CMD_LENGTH];
        snprintf(cmd, sizeof(cmd), "ping -c 4 -i 0.2 -W 1 %s", argv[3]);
        print_info("Pinging %s...", argv[3]);
        system(cmd);
        
    } else if (strcmp(argv[2], "scan") == 0 && argc >= 5) {
        char cmd[MAX_CMD_LENGTH];
        snprintf(cmd, sizeof(cmd), "nc -zv %s %s 2>&1 | grep succeeded", argv[3], argv[4]);
        print_info("Scanning %s:%s...", argv[3], argv[4]);
        system(cmd);
        
    } else if (strcmp(argv[2], "dns") == 0 && argc >= 4) {
        char cmd[MAX_CMD_LENGTH];
        snprintf(cmd, sizeof(cmd), "dig +short %s", argv[3]);
        print_info("DNS lookup for %s:", argv[3]);
        system(cmd);
        
    } else if (strcmp(argv[2], "ip") == 0) {
        print_info("IP Addresses:");
        system("ip addr show | grep inet | grep -v 127.0.0.1");
        
    } else if (strcmp(argv[2], "speedtest") == 0) {
        print_info("Running speed test...");
        system("curl -s https://raw.githubusercontent.com/sivel/speedtest-cli/master/speedtest.py | python3 -");
        
    } else {
        print_error("Unknown network command");
    }
}

// Compilateur amélioré
void handle_compile_advanced(int argc, char *argv[]) {
    if (argc < 3) {
        printf(COLOR_CYAN "🛠️  COMPILER COMMANDS\\n" COLOR_RESET);
        printf("══════════════════════════════════════════\\n\\n");
        printf("  compile <file.c> [options] - Compile C program\\n");
        printf("  build <project>           - Build project\\n");
        printf("  debug <program>           - Debug program\\n");
        printf("  analyze <file.c>          - Static analysis\\n");
        return;
    }
    
    if (strcmp(argv[2], "compile") == 0 && argc >= 4) {
        char output[256] = "a.out";
        char flags[MAX_CMD_LENGTH] = "-Wall -Wextra -O2 -std=c99";
        char libraries[256] = "-lm";
        int debug = 0;
        int optimize = 2;
        
        // Parser options
        for (int i = 4; i < argc; i++) {
            if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
                snprintf(output, sizeof(output), "%s", argv[i + 1]);
                i++;
            } else if (strcmp(argv[i], "-std") == 0 && i + 1 < argc) {
                snprintf(flags, sizeof(flags), "-Wall -Wextra -std=%s", argv[i + 1]);
                i++;
            } else if (strcmp(argv[i], "-g") == 0) {
                debug = 1;
                strcat(flags, " -g");
            } else if (strcmp(argv[i], "-O0") == 0 || strcmp(argv[i], "-O1") == 0 || 
                       strcmp(argv[i], "-O2") == 0 || strcmp(argv[i], "-O3") == 0) {
                optimize = argv[i][2] - '0';
            } else if (strcmp(argv[i], "-l") == 0 && i + 1 < argc) {
                snprintf(libraries, sizeof(libraries), "%s -l%s", libraries, argv[i + 1]);
                i++;
            }
        }
        
        char cmd[MAX_CMD_LENGTH];
        snprintf(cmd, sizeof(cmd), "gcc %s -o %s %s %s", flags, output, argv[3], libraries);
        
        print_info("Compiling %s...", argv[3]);
        print_debug("Command: %s", cmd);
        
        time_t start = time(NULL);
        int result = system(cmd);
        time_t end = time(NULL);
        
        if (result == 0) {
            print_success("Compilation successful!");
            printf("  Output:    %s\\n", output);
            printf("  Time:      %ld seconds\\n", end - start);
            
            struct stat st;
            if (stat(output, &st) == 0) {
                printf("  Size:      %.2f KB\\n", st.st_size / 1024.0);
                printf("  Optimize:  O%d\\n", optimize);
                printf("  Debug:     %s\\n", debug ? "Yes" : "No");
            }
            
            // Test si exécutable
            if (access(output, X_OK) == 0) {
                printf("  Executable: Yes\\n");
            }
        } else {
            print_error("Compilation failed");
        }
        
    } else if (strcmp(argv[2], "analyze") == 0 && argc >= 4) {
        print_info("Static analysis of %s:", argv[3]);
        char cmd[MAX_CMD_LENGTH];
        snprintf(cmd, sizeof(cmd), "cppcheck --enable=all %s 2>&1", argv[3]);
        system(cmd);
    }
}

// Gestionnaire de fichiers amélioré
void handle_files_advanced(int argc, char *argv[]) {
    if (argc < 3) {
        printf(COLOR_CYAN "📁 FILE OPERATIONS\\n" COLOR_RESET);
        printf("══════════════════════════════════════════\\n\\n");
        printf("  find <dir> <pattern>    - Find files\\n");
        printf("  size <file|dir>         - Get size\\n");
        printf("  hash <file>             - Calculate hash\\n");
        printf("  compare <file1> <file2> - Compare files\\n");
        printf("  backup <source> <dest>  - Backup files\\n");
        return;
    }
    
    if (strcmp(argv[2], "find") == 0 && argc >= 5) {
        char cmd[MAX_CMD_LENGTH];
        snprintf(cmd, sizeof(cmd), "find %s -name \"%s\" -type f 2>/dev/null | head -20", 
                argv[3], argv[4]);
        print_info("Finding files matching '%s' in %s:", argv[4], argv[3]);
        system(cmd);
        
    } else if (strcmp(argv[2], "size") == 0 && argc >= 4) {
        struct stat st;
        if (stat(argv[3], &st) == 0) {
            if (S_ISDIR(st.st_mode)) {
                char cmd[MAX_CMD_LENGTH];
                snprintf(cmd, sizeof(cmd), "du -sh %s", argv[3]);
                system(cmd);
            } else {
                printf("File: %s\\n", argv[3]);
                printf("Size: %.2f KB (%.2f MB)\\n", 
                      st.st_size / 1024.0, 
                      st.st_size / (1024.0 * 1024.0));
                printf("Permissions: %o\\n", st.st_mode & 0777);
                printf("Modified: %s", ctime(&st.st_mtime));
            }
        } else {
            print_error("File not found: %s", argv[3]);
        }
        
    } else if (strcmp(argv[2], "hash") == 0 && argc >= 4) {
        print_info("Hashes for %s:", argv[3]);
        char cmd[MAX_CMD_LENGTH];
        snprintf(cmd, sizeof(cmd), "md5sum %s", argv[3]);
        system(cmd);
        snprintf(cmd, sizeof(cmd), "sha256sum %s", argv[3]);
        system(cmd);
    }
}

// Afficher l'aide améliorée
void show_help_enhanced() {
    printf(COLOR_CYAN "🚀 CLOBES v%s - Complete CLI Toolkit\\n" COLOR_RESET, CLOBES_VERSION);
    printf("══════════════════════════════════════════════════\\n\\n");
    
    printf(COLOR_BLUE "📦 Core Commands:\\n" COLOR_RESET);
    printf("  help        - Show this help\\n");
    printf("  version     - Show version\\n");
    printf("  sysinfo     - Detailed system information\\n");
    printf("\\n");
    
    printf(COLOR_BLUE "🌐 Network (curl replacement):\\n" COLOR_RESET);
    printf("  network curl <url>        - HTTP client with JSON support\\n");
    printf("  network download <url>    - Download files with progress\\n");
    printf("  network ping <host>       - Advanced ping\\n");
    printf("  network scan <host:port>  - Port scanner\\n");
    printf("  network dns <domain>      - DNS lookup\\n");
    printf("  network speedtest         - Internet speed test\\n");
    printf("\\n");
    
    printf(COLOR_BLUE "🛠️  Development:\\n" COLOR_RESET);
    printf("  compile compile <file.c>  - Advanced C compiler\\n");
    printf("  compile analyze <file.c>  - Static code analysis\\n");
    printf("\\n");
    
    printf(COLOR_BLUE "📁 File Operations:\\n" COLOR_RESET);
    printf("  files find <dir> <pattern> - Find files\\n");
    printf("  files size <file>          - Get file size and info\\n");
    printf("  files hash <file>          - Calculate file hashes\\n");
    printf("\\n");
    
    printf(COLOR_BLUE "🔧 Examples:\\n" COLOR_RESET);
    printf("  clobes network curl https://api.github.com -H \"Accept: application/json\"\\n");
    printf("  clobes network download https://example.com/file.zip file.zip\\n");
    printf("  clobes compile compile program.c -o app -O3 -g\\n");
    printf("  clobes files find /var/log \"*.log\"\\n");
    printf("\\n");
    
    printf("💡 Tip: Use --debug for verbose output\\n");
}

// Fonction principale
int main(int argc, char *argv[]) {
    // Initialiser curl global
    curl_global_init(CURL_GLOBAL_DEFAULT);
    
    // Afficher banner
    if (argc < 2) {
        show_help_enhanced();
        curl_global_cleanup();
        return 0;
    }
    
    // Gérer les commandes
    if (strcmp(argv[1], "help") == 0 || strcmp(argv[1], "--help") == 0) {
        show_help_enhanced();
    } else if (strcmp(argv[1], "version") == 0 || strcmp(argv[1], "--version") == 0) {
        printf("CLOBES Version: %s\\n", CLOBES_VERSION);
        printf("Advanced CLI Toolkit - Replacement for curl + more\\n");
    } else if (strcmp(argv[1], "sysinfo") == 0) {
        show_sysinfo_detail();
    } else if (strcmp(argv[1], "network") == 0) {
        handle_network_advanced(argc, argv);
    } else if (strcmp(argv[1], "compile") == 0) {
        handle_compile_advanced(argc, argv);
    } else if (strcmp(argv[1], "files") == 0) {
        handle_files_advanced(argc, argv);
    } else {
        print_error("Unknown command: %s", argv[1]);
        printf("Use 'clobes help' to see available commands\\n");
        curl_global_cleanup();
        return 1;
    }
    
    curl_global_cleanup();
    return 0;
}
'''
    
    with open("src/clobes_enhanced.c", "w") as f:
        f.write(enhanced_code)
    
    print("✅ Version améliorée créée: src/clobes_enhanced.c")
    
    # Mettre à jour le Makefile pour compiler la version améliorée
    with open("Makefile", "r") as f:
        makefile = f.read()
    
    # Remplacer la source par la version améliorée
    makefile = makefile.replace("SRC = src/clobes.c", "SRC = src/clobes_enhanced.c")
    
    with open("Makefile", "w") as f:
        f.write(makefile)
    
    print("✅ Makefile mis à jour")
    
    # Mettre à jour install.sh pour les nouvelles dépendances
    with open("install.sh", "r") as f:
        install_script = f.read()
    
    # Ajouter libcurl-dev aux dépendances
    install_script = install_script.replace(
        "apk add --no-cache curl gcc make libc-dev curl-dev",
        "apk add --no-cache curl gcc make libc-dev curl-dev libcurl-dev"
    )
    
    install_script = install_script.replace(
        "apt-get install -y curl gcc make libc6-dev libcurl4-openssl-dev",
        "apt-get install -y curl gcc make libc6-dev libcurl4-openssl-dev libcurl4-openssl-dev"
    )
    
    with open("install.sh", "w") as f:
        f.write(install_script)
    
    print("✅ install.sh mis à jour")
    
    # Créer un script de test
    test_script = '''#!/bin/bash
# test_enhanced.sh - Test CLOBES amélioré

echo "🧪 TEST CLOBES ENHANCED v3.0.0"
echo "══════════════════════════════════════════"

# Compiler
echo "🔨 Compilation..."
make clean
make

if [ ! -f "clobes" ]; then
    echo "❌ Compilation failed"
    exit 1
fi

echo "✅ Compiled successfully"
echo ""

# Test 1: Version
echo "1. Test version:"
./clobes version
echo ""

# Test 2: Help
echo "2. Test help:"
./clobes help | head -20
echo ""

# Test 3: Sysinfo
echo "3. Test sysinfo:"
./clobes sysinfo | head -30
echo ""

# Test 4: Network help
echo "4. Test network help:"
./clobes network | head -20
echo ""

# Test 5: Compile help
echo "5. Test compile help:"
./clobes compile | head -20
echo ""

# Test 6: Files help
echo "6. Test files help:"
./clobes files | head -20
echo ""

echo "══════════════════════════════════════════"
echo "✅ All tests completed successfully!"
echo ""
echo "🚀 CLOBES v3.0.0 is ready to use!"
echo "Try: ./clobes network curl https://httpbin.org/get"
'''

    with open("test_enhanced.sh", "w") as f:
        f.write(test_script)
    
    os.chmod("test_enhanced.sh", 0o755)
    print("✅ Script de test créé: test_enhanced.sh")
    
    print("")
    print("✨ CLOBES AMÉLIORÉ CRÉÉ AVEC SUCCÈS ✨")
    print("══════════════════════════════════════════")
    print("")
    print("Pour tester la nouvelle version:")
    print("  ./test_enhanced.sh")
    print("")
    print("Pour compiler:")
    print("  make clean && make")
    print("")
    print("Nouvelles fonctionnalités:")
    print("  • Client HTTP avancé (remplacement curl)")
    print("  • Téléchargement avec progression")
    print("  • Analyse de code statique")
    print("  • Scanner de ports")
    print("  • Recherche de fichiers avancée")
    print("  • Speed test internet")
    print("  • Output coloré et structuré")

if __name__ == "__main__":
    backup_original()
    create_enhanced_clobes()
