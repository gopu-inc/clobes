// CLOBES PRO Alpine Edition
#include "clobes.h"
#include <stdarg.h>
#include <dirent.h>

// Global state
GlobalState g_state = {
    .config = {
        .timeout = 30,
        .verify_ssl = 1,
        .colors = 1
    },
    .debug_mode = 0
};

// Command registry
static Command g_commands[20];
static int g_command_count = 0;

// Memory structure for curl
typedef struct {
    char *memory;
    size_t size;
} MemoryStruct;

// Write callback for curl
static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    MemoryStruct *mem = (MemoryStruct *)userp;
    
    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if (!ptr) return 0;
    
    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;
    
    return realsize;
}

// Print functions
void print_success(const char *format, ...) {
    va_list args;
    va_start(args, format);
    
    if (g_state.config.colors) {
        printf(COLOR_GREEN "✓ " COLOR_RESET);
    } else {
        printf("[OK] ");
    }
    
    vprintf(format, args);
    printf("\n");
    
    va_end(args);
}

void print_error(const char *format, ...) {
    va_list args;
    va_start(args, format);
    
    if (g_state.config.colors) {
        fprintf(stderr, COLOR_RED "✗ " COLOR_RESET);
    } else {
        fprintf(stderr, "[ERROR] ");
    }
    
    vfprintf(stderr, format, args);
    fprintf(stderr, "\n");
    
    va_end(args);
}

void print_warning(const char *format, ...) {
    va_list args;
    va_start(args, format);
    
    if (g_state.config.colors) {
        printf(COLOR_YELLOW "⚠ " COLOR_RESET);
    } else {
        printf("[WARN] ");
    }
    
    vprintf(format, args);
    printf("\n");
    
    va_end(args);
}

void print_info(const char *format, ...) {
    va_list args;
    va_start(args, format);
    
    if (g_state.config.colors) {
        printf(COLOR_BLUE "ℹ " COLOR_RESET);
    } else {
        printf("[INFO] ");
    }
    
    vprintf(format, args);
    printf("\n");
    
    va_end(args);
}

void print_banner() {
    if (!g_state.config.colors) {
        printf("CLOBES PRO v%s\n", CLOBES_VERSION);
        return;
    }
    
    printf(COLOR_CYAN);
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║                                                              ║\n");
    printf("║   🚀 C L O B E S  P R O  v%s                               ║\n", CLOBES_VERSION);
    printf("║   Ultimate Command Line Toolkit - Alpine Edition            ║\n");
    printf("║                                                              ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n");
    printf(COLOR_RESET);
    printf("\n");
}

// HTTP GET (simple version)
char* http_get_simple(const char *url) {
    CURL *curl = curl_easy_init();
    if (!curl) {
        print_error("Failed to initialize curl");
        return NULL;
    }
    
    MemoryStruct chunk = {NULL, 0};
    
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, g_state.config.timeout);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, g_state.config.verify_ssl);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "CLOBES-PRO/4.1.0");
    
    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    
    if (res != CURLE_OK) {
        print_error("curl_easy_perform() failed: %s", curl_easy_strerror(res));
        free(chunk.memory);
        return NULL;
    }
    
    return chunk.memory;
}

// HTTP download
int http_download(const char *url, const char *output) {
    CURL *curl = curl_easy_init();
    if (!curl) {
        print_error("Failed to initialize download");
        return 1;
    }
    
    FILE *fp = fopen(output, "wb");
    if (!fp) {
        print_error("Cannot open file for writing: %s", output);
        curl_easy_cleanup(curl);
        return 1;
    }
    
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, fwrite);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, g_state.config.verify_ssl);
    
    print_info("Downloading %s to %s...", url, output);
    
    CURLcode res = curl_easy_perform(curl);
    fclose(fp);
    curl_easy_cleanup(curl);
    
    if (res == CURLE_OK) {
        struct stat st;
        if (stat(output, &st) == 0) {
            print_success("Download completed: %s (%.2f KB)", output, st.st_size / 1024.0);
        } else {
            print_success("Download completed: %s", output);
        }
        return 0;
    } else {
        print_error("Download failed: %s", curl_easy_strerror(res));
        remove(output);
        return 1;
    }
}

// Command: version
int cmd_version(int argc, char **argv) {
    (void)argc; (void)argv;
    
    print_banner();
    
    printf("Version:       %s \"%s\"\n", CLOBES_VERSION, CLOBES_CODENAME);
    printf("Build:         %s\n", CLOBES_BUILD);
    printf("Platform:      Alpine Linux iSH\n");
    
    struct utsname uname_info;
    if (uname(&uname_info) == 0) {
        printf("System:        %s %s %s\n", 
               uname_info.sysname, uname_info.release, uname_info.machine);
    }
    
    return 0;
}

// Command: help
int cmd_help(int argc, char **argv) {
    if (argc > 2) {
        for (int i = 0; i < g_command_count; i++) {
            if (strcmp(g_commands[i].name, argv[2]) == 0) {
                printf(COLOR_CYAN "%s\n" COLOR_RESET, g_commands[i].name);
                printf("%s\n", g_commands[i].description);
                printf("\nUsage: %s\n", g_commands[i].usage);
                return 0;
            }
        }
        print_error("Command not found: %s", argv[2]);
        return 1;
    }
    
    print_banner();
    
    printf("Available commands:\n\n");
    
    for (int i = 0; i < g_command_count; i++) {
        printf("  %-15s - %s\n", 
               g_commands[i].name, 
               g_commands[i].description);
    }
    
    printf("\n" COLOR_GREEN "Quick examples:\n" COLOR_RESET);
    printf("  clobes version\n");
    printf("  clobes network get https://api.github.com\n");
    printf("  clobes server start --port 8080\n");
    printf("  clobes system info\n");
    printf("\n");
    
    return 0;
}

// Command: network
int cmd_network(int argc, char **argv) {
    if (argc < 3) {
        printf(COLOR_CYAN "🌐 NETWORK COMMANDS\n" COLOR_RESET);
        printf("══════════════════════════════════════════\n\n");
        
        printf("  get <url>              - HTTP GET request\n");
        printf("  download <url> <file>  - Download file\n");
        printf("  myip                   - Show public IP\n");
        printf("\n");
        return 0;
    }
    
    if (strcmp(argv[2], "get") == 0 && argc >= 4) {
        char *response = http_get_simple(argv[3]);
        if (response) {
            printf("%s\n", response);
            free(response);
            return 0;
        } else {
            print_error("Failed to fetch URL");
            return 1;
        }
    } else if (strcmp(argv[2], "download") == 0 && argc >= 5) {
        return http_download(argv[3], argv[4]);
    } else if (strcmp(argv[2], "myip") == 0) {
        char *response = http_get_simple("https://api.ipify.org");
        if (response) {
            printf("Public IP: %s\n", response);
            free(response);
            return 0;
        } else {
            print_error("Failed to get IP address");
            return 1;
        }
    } else {
        print_error("Unknown network command: %s", argv[2]);
        return 1;
    }
}

// Command: system
int cmd_system(int argc, char **argv) {
    if (argc < 3) {
        printf(COLOR_CYAN "💻 SYSTEM COMMANDS\n" COLOR_RESET);
        printf("══════════════════════════════════════════\n\n");
        
        printf("  info              - System information\n");
        printf("  disks             - Disk usage\n");
        printf("  memory            - Memory usage\n");
        printf("\n");
        return 0;
    }
    
    if (strcmp(argv[2], "info") == 0) {
        struct utsname uname_info;
        if (uname(&uname_info) == 0) {
            printf("System:        %s %s %s\n", 
                   uname_info.sysname, uname_info.release, uname_info.machine);
            printf("Hostname:      %s\n", uname_info.nodename);
        }
        
        struct sysinfo mem_info;
        if (sysinfo(&mem_info) == 0) {
            printf("\nMemory:\n");
            printf("  Total:       %lu MB\n", mem_info.totalram / 1024 / 1024);
            printf("  Free:        %lu MB\n", mem_info.freeram / 1024 / 1024);
            printf("  Used:        %lu MB\n", 
                   (mem_info.totalram - mem_info.freeram) / 1024 / 1024);
        }
        
        return 0;
    } else if (strcmp(argv[2], "disks") == 0) {
        system("df -h");
        return 0;
    } else if (strcmp(argv[2], "memory") == 0) {
        system("free -h");
        return 0;
    }
    
    print_error("Unknown system command: %s", argv[2]);
    return 1;
}

// Command: crypto
int cmd_crypto(int argc, char **argv) {
    if (argc < 3) {
        printf(COLOR_CYAN "🔐 CRYPTO COMMANDS\n" COLOR_RESET);
        printf("══════════════════════════════════════════\n\n");
        
        printf("  encode base64 <text>    - Base64 encode\n");
        printf("  decode base64 <text>    - Base64 decode\n");
        printf("\n");
        return 0;
    }
    
    if (strcmp(argv[2], "encode") == 0 && argc >= 5 && strcmp(argv[3], "base64") == 0) {
        // Simple base64 encode
        const char *input = argv[4];
        size_t len = strlen(input);
        size_t out_len = 4 * ((len + 2) / 3);
        char *encoded = malloc(out_len + 1);
        
        if (!encoded) {
            print_error("Memory allocation failed");
            return 1;
        }
        
        // Simple base64 implementation
        const char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        
        int i, j;
        for (i = 0, j = 0; i < len;) {
            uint32_t octet_a = i < len ? (unsigned char)input[i++] : 0;
            uint32_t octet_b = i < len ? (unsigned char)input[i++] : 0;
            uint32_t octet_c = i < len ? (unsigned char)input[i++] : 0;
            
            uint32_t triple = (octet_a << 16) | (octet_b << 8) | octet_c;
            
            encoded[j++] = base64_table[(triple >> 18) & 0x3F];
            encoded[j++] = base64_table[(triple >> 12) & 0x3F];
            encoded[j++] = base64_table[(triple >> 6) & 0x3F];
            encoded[j++] = base64_table[triple & 0x3F];
        }
        
        // Add padding
        for (int i = 0; i < (3 - len % 3) % 3; i++) {
            encoded[out_len - 1 - i] = '=';
        }
        
        encoded[out_len] = '\0';
        printf("%s\n", encoded);
        free(encoded);
        return 0;
        
    } else if (strcmp(argv[2], "decode") == 0 && argc >= 5 && strcmp(argv[3], "base64") == 0) {
        print_warning("Base64 decode not implemented in Alpine edition");
        return 0;
    }
    
    print_error("Unknown crypto command: %s", argv[2]);
    return 1;
}

// Simple HTTP server function
static void* simple_server_thread(void *arg) {
    int port = *(int*)arg;
    int server_fd, client_fd;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    
    // Create socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        print_error("Socket creation failed");
        return NULL;
    }
    
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);
    
    // Bind socket
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        print_error("Bind failed");
        close(server_fd);
        return NULL;
    }
    
    // Listen
    if (listen(server_fd, 3) < 0) {
        print_error("Listen failed");
        close(server_fd);
        return NULL;
    }
    
    print_success("Server started on port %d", port);
    printf("Visit: http://localhost:%d\n", port);
    
    // Simple request handling
    char buffer[1024];
    while (1) {
        client_fd = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen);
        if (client_fd < 0) {
            continue;
        }
        
        read(client_fd, buffer, sizeof(buffer));
        
        // Simple HTTP response
        char response[] = "HTTP/1.1 200 OK\r\n"
                         "Content-Type: text/html; charset=utf-8\r\n"
                         "Connection: close\r\n\r\n"
                         "<!DOCTYPE html>"
                         "<html><head><title>CLOBES PRO Server</title></head>"
                         "<body><h1>🚀 CLOBES PRO Server v" CLOBES_VERSION "</h1>"
                         "<p>Server is running on Alpine iSH</p></body></html>";
        
        write(client_fd, response, strlen(response));
        close(client_fd);
    }
    
    close(server_fd);
    return NULL;
}

// Command: server
int cmd_server(int argc, char **argv) {
    if (argc < 3) {
        printf(COLOR_CYAN "🌐 SERVER COMMANDS\n" COLOR_RESET);
        printf("══════════════════════════════════════════\n\n");
        
        printf("  start                 - Start HTTP server\n");
        printf("\nOptions:\n");
        printf("  --port <number>       - Port number (default: 8080)\n");
        printf("\n");
        return 0;
    }
    
    if (strcmp(argv[2], "start") == 0) {
        int port = 8080;
        
        // Parse options
        for (int i = 3; i < argc; i++) {
            if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
                port = atoi(argv[++i]);
            }
        }
        
        print_info("Starting CLOBES PRO HTTP Server on port %d...", port);
        
        pthread_t server_thread;
        if (pthread_create(&server_thread, NULL, simple_server_thread, &port) != 0) {
            print_error("Failed to start server thread");
            return 1;
        }
        
        print_success("Server started! Press Ctrl+C to stop");
        
        // Wait forever
        while (1) {
            sleep(1);
        }
        
        return 0;
    }
    
    print_error("Unknown server command: %s", argv[2]);
    return 1;
}

// Register commands
void register_commands() {
    // Core commands
    g_commands[g_command_count++] = (Command){
        .name = "version",
        .description = "Show version information",
        .usage = "clobes version",
        .category = CATEGORY_SYSTEM,
        .handler = cmd_version
    };
    
    g_commands[g_command_count++] = (Command){
        .name = "help",
        .description = "Show help information",
        .usage = "clobes help [command]",
        .category = CATEGORY_SYSTEM,
        .handler = cmd_help
    };
    
    // Network commands
    g_commands[g_command_count++] = (Command){
        .name = "network",
        .description = "Network operations",
        .usage = "clobes network [command] [args]",
        .category = CATEGORY_NETWORK,
        .handler = cmd_network
    };
    
    // System commands
    g_commands[g_command_count++] = (Command){
        .name = "system",
        .description = "System operations",
        .usage = "clobes system [command]",
        .category = CATEGORY_SYSTEM,
        .handler = cmd_system
    };
    
    // Crypto commands
    g_commands[g_command_count++] = (Command){
        .name = "crypto",
        .description = "Cryptography operations",
        .usage = "clobes crypto [command] [args]",
        .category = CATEGORY_CRYPTO,
        .handler = cmd_crypto
    };
    
    // Server commands
    g_commands[g_command_count++] = (Command){
        .name = "server",
        .description = "HTTP server operations",
        .usage = "clobes server start [--port N]",
        .category = CATEGORY_SERVER,
        .handler = cmd_server
    };
}

// Find command
Command* find_command(const char *name) {
    for (int i = 0; i < g_command_count; i++) {
        if (strcmp(g_commands[i].name, name) == 0) {
            return &g_commands[i];
        }
    }
    return NULL;
}

// Interactive mode (simplified)
int interactive_mode() {
    printf(COLOR_CYAN "🚀 CLOBES Interactive Mode\n" COLOR_RESET);
    printf("Type 'exit' to quit\n\n");
    
    char input[1024];
    while (1) {
        printf(COLOR_GREEN "clobes> " COLOR_RESET);
        fflush(stdout);
        
        if (!fgets(input, sizeof(input), stdin)) break;
        input[strcspn(input, "\n")] = 0;
        
        if (strlen(input) == 0) continue;
        
        if (strcmp(input, "exit") == 0 || strcmp(input, "quit") == 0) {
            printf("Goodbye!\n");
            break;
        }
        
        if (strcmp(input, "clear") == 0) {
            system("clear");
            continue;
        }
        
        // Simulate command execution
        char *argv[10] = {"clobes"};
        char *token = strtok(input, " ");
        int argc = 1;
        
        while (token && argc < 10) {
            argv[argc++] = token;
            token = strtok(NULL, " ");
        }
        
        Command *cmd = find_command(argv[1]);
        if (cmd) {
            cmd->handler(argc, argv);
        } else {
            printf("Unknown command: %s\n", argv[1]);
        }
    }
    
    return 0;
}

// Main function
int main(int argc, char **argv) {
    // Check for interactive mode
    if (argc == 2 && (strcmp(argv[1], "-i") == 0 || strcmp(argv[1], "--interactive") == 0)) {
        curl_global_init(CURL_GLOBAL_ALL);
        register_commands();
        int result = interactive_mode();
        curl_global_cleanup();
        return result;
    }
    
    // Initialize curl
    CURLcode res = curl_global_init(CURL_GLOBAL_ALL);
    if (res != CURLE_OK) {
        fprintf(stderr, "Failed to initialize curl: %s\n", curl_easy_strerror(res));
        return 1;
    }
    
    // Register commands
    register_commands();
    
    // Parse command line
    if (argc < 2) {
        cmd_help(1, argv);
        curl_global_cleanup();
        return 0;
    }
    
    // Find and execute command
    Command *cmd = find_command(argv[1]);
    if (cmd) {
        int result = cmd->handler(argc, argv);
        curl_global_cleanup();
        return result;
    }
    
    // Command not found
    print_error("Unknown command: %s", argv[1]);
    printf("Use 'clobes help' to see available commands\n");
    
    curl_global_cleanup();
    return 1;
}
