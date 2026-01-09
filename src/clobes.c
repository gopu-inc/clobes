// CLOBES PRO v4.0.0 - Ultimate CLI Toolkit
#include "clobes.h"
#include <stdarg.h>
#include <dirent.h>
#include <regex.h>

// Global state
static GlobalState g_state = {
    .config = {
        .timeout = 30,
        .cache_enabled = 1,
        .user_agent = "CLOBES-PRO/4.0.0",
        .verify_ssl = 1,
        .colors = 1,
        .progress_bars = 1,
        .verbose = 0,
        .enable_websocket = 0,
        .enable_jwt = 0,
        .enable_cache = 0,
        .enable_gzip = 0,
        .enable_proxy = 0
    },
    .cache_hits = 0,
    .cache_misses = 0,
    .total_requests = 0,
    .total_request_time = 0.0,
    .debug_mode = 0,
    .log_level = LOG_INFO
};

// Command registry
static Command g_commands[50];
static int g_command_count = 0;

// Memory structure for curl
typedef struct {
    char *memory;
    size_t size;
} MemoryStruct;

// Base64 encoding table
static const char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// Base64 encode
char* base64_encode(const char *input, size_t length) {
    size_t output_length = 4 * ((length + 2) / 3);
    char *encoded = malloc(output_length + 1);
    if (!encoded) return NULL;
    
    for (size_t i = 0, j = 0; i < length;) {
        uint32_t octet_a = i < length ? (unsigned char)input[i++] : 0;
        uint32_t octet_b = i < length ? (unsigned char)input[i++] : 0;
        uint32_t octet_c = i < length ? (unsigned char)input[i++] : 0;
        
        uint32_t triple = (octet_a << 16) | (octet_b << 8) | octet_c;
        
        encoded[j++] = base64_table[(triple >> 18) & 0x3F];
        encoded[j++] = base64_table[(triple >> 12) & 0x3F];
        encoded[j++] = base64_table[(triple >> 6) & 0x3F];
        encoded[j++] = base64_table[triple & 0x3F];
    }
    
    // Add padding
    for (size_t i = 0; i < (3 - length % 3) % 3; i++) {
        encoded[output_length - 1 - i] = '=';
    }
    
    encoded[output_length] = '\0';
    return encoded;
}

// Base64 decode
char* base64_decode(const char *input, size_t *output_length) {
    size_t input_length = strlen(input);
    if (input_length % 4 != 0) return NULL;
    
    size_t output_len = input_length / 4 * 3;
    if (input[input_length - 1] == '=') output_len--;
    if (input[input_length - 2] == '=') output_len--;
    
    char *decoded = malloc(output_len + 1);
    if (!decoded) return NULL;
    
    for (size_t i = 0, j = 0; i < input_length;) {
        uint32_t sextet_a = input[i] == '=' ? 0 & i++ : strchr(base64_table, input[i++]) - base64_table;
        uint32_t sextet_b = input[i] == '=' ? 0 & i++ : strchr(base64_table, input[i++]) - base64_table;
        uint32_t sextet_c = input[i] == '=' ? 0 & i++ : strchr(base64_table, input[i++]) - base64_table;
        uint32_t sextet_d = input[i] == '=' ? 0 & i++ : strchr(base64_table, input[i++]) - base64_table;
        
        uint32_t triple = (sextet_a << 18) | (sextet_b << 12) | (sextet_c << 6) | sextet_d;
        
        if (j < output_len) decoded[j++] = (triple >> 16) & 0xFF;
        if (j < output_len) decoded[j++] = (triple >> 8) & 0xFF;
        if (j < output_len) decoded[j++] = triple & 0xFF;
    }
    
    decoded[output_len] = '\0';
    if (output_length) *output_length = output_len;
    return decoded;
}

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

// Progress callback for curl
static int progress_callback(void *clientp, double dltotal, double dlnow, 
                            double ultotal, double ulnow) {
    (void)clientp;
    (void)ultotal;
    (void)ulnow;
    
    if (g_state.config.progress_bars && dltotal > 0) {
        int bar_width = 50;
        double progress = dlnow / dltotal;
        int pos = bar_width * progress;
        
        printf("\r[");
        for (int i = 0; i < bar_width; ++i) {
            if (i < pos) printf("=");
            else if (i == pos) printf(">");
            else printf(" ");
        }
        printf("] %.1f%% (%.2f/%.2f MB)", 
               progress * 100.0,
               dlnow / (1024.0 * 1024.0),
               dltotal / (1024.0 * 1024.0));
        fflush(stdout);
    }
    return 0;
}

// Logging implementation
void log_message(LogLevel level, const char *format, ...) {
    if (level > g_state.log_level) return;
    
    va_list args;
    va_start(args, format);
    
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    
    const char *level_str;
    const char *color;
    
    switch (level) {
        case LOG_FATAL:   level_str = "FATAL";   color = COLOR_BRIGHT_RED; break;
        case LOG_ERROR:   level_str = "ERROR";   color = COLOR_RED; break;
        case LOG_WARNING: level_str = "WARNING"; color = COLOR_YELLOW; break;
        case LOG_INFO:    level_str = "INFO";    color = COLOR_BLUE; break;
        case LOG_DEBUG:   level_str = "DEBUG";   color = COLOR_MAGENTA; break;
        case LOG_TRACE:   level_str = "TRACE";   color = COLOR_BRIGHT_RED; break;
        default:          level_str = "UNKNOWN"; color = COLOR_WHITE; break;
    }
    
    if (g_state.config.colors) {
        fprintf(stderr, "%s[%s]%s [%s] ", color, timestamp, COLOR_RESET, level_str);
    } else {
        fprintf(stderr, "[%s] [%s] ", timestamp, level_str);
    }
    
    vfprintf(stderr, format, args);
    fprintf(stderr, "\n");
    
    va_end(args);
}

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

void print_debug(const char *format, ...) {
    if (!g_state.debug_mode) return;
    
    va_list args;
    va_start(args, format);
    
    if (g_state.config.colors) {
        printf(COLOR_MAGENTA "🔧 " COLOR_RESET);
    } else {
        printf("[DEBUG] ");
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
    
    printf(COLOR_CYAN STYLE_BOLD);
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║                                                              ║\n");
    printf("║   " COLOR_BRIGHT_CYAN "🚀 C L O B E S  P R O  v%s" COLOR_CYAN "                      ║\n", CLOBES_VERSION);
    printf("║   " COLOR_BRIGHT_WHITE "Ultimate Command Line Toolkit" COLOR_CYAN "                   ║\n");
    printf("║   " COLOR_BRIGHT_GREEN "200+ commands • Faster than curl • Smarter" COLOR_CYAN "      ║\n");
    printf("║                                                              ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n");
    printf(COLOR_RESET);
    printf("\n");
}

// Print progress bar
void print_progress_bar(long current, long total, const char *label) {
    if (!g_state.config.progress_bars) return;
    
    int bar_width = 50;
    double percentage = (double)current / total;
    int pos = bar_width * percentage;
    
    printf("\r%s [", label);
    for (int i = 0; i < bar_width; ++i) {
        if (i < pos) printf("=");
        else if (i == pos) printf(">");
        else printf(" ");
    }
    printf("] %3.0f%% (%ld/%ld)", percentage * 100.0, current, total);
    
    if (current >= total) {
        printf("\n");
    }
    fflush(stdout);
}

// Interactive mode for curl-like -i option
int interactive_mode() {
    printf(COLOR_CYAN "🚀 CLOBES Interactive Mode (like curl -i)\n" COLOR_RESET);
    printf("Type 'help' for commands, 'exit' to quit\n\n");
    
    char input[1024];
    while (1) {
        printf(COLOR_GREEN "clobes-i> " COLOR_RESET);
        fflush(stdout);
        
        if (!fgets(input, sizeof(input), stdin)) break;
        input[strcspn(input, "\n")] = 0;
        
        if (strlen(input) == 0) continue;
        
        if (strcmp(input, "exit") == 0 || strcmp(input, "quit") == 0) {
            printf("Goodbye!\n");
            break;
        }
        
        if (strcmp(input, "help") == 0) {
            printf("Interactive Commands:\n");
            printf("  get <url>           - HTTP GET request\n");
            printf("  post <url> <data>   - HTTP POST request\n");
            printf("  download <url>      - Download file\n");
            printf("  server start        - Start web server\n");
            printf("  clear               - Clear screen\n");
            printf("  exit/quit           - Exit interactive mode\n");
            continue;
        }
        
        if (strcmp(input, "clear") == 0) {
            system("clear");
            continue;
        }
        
        if (strcmp(input, "server start") == 0) {
            char *argv[] = {"clobes", "server", "start", "--port", "8080", NULL};
            cmd_server(5, argv);
            continue;
        }
        
        if (strncmp(input, "get ", 4) == 0) {
            char *url = input + 4;
            char *response = http_get_simple(url);
            if (response) {
                printf("%s\n", response);
                free(response);
            } else {
                printf("Failed to fetch URL\n");
            }
            continue;
        }
        
        if (strncmp(input, "post ", 5) == 0) {
            char *space = strchr(input + 5, ' ');
            if (space) {
                *space = '\0';
                char *url = input + 5;
                char *data = space + 1;
                char *response = http_post_simple(url, data);
                if (response) {
                    printf("%s\n", response);
                    free(response);
                } else {
                    printf("Failed to POST to URL\n");
                }
            } else {
                printf("Usage: post <url> <data>\n");
            }
            continue;
        }
        
        printf("Unknown command: %s\n", input);
    }
    
    return 0;
}

// HTTP GET with advanced features
char* http_get_advanced(const char *url, int show_headers, int follow_redirects, int timeout) {
    CURL *curl = curl_easy_init();
    if (!curl) {
        log_message(LOG_ERROR, "Failed to initialize curl");
        return NULL;
    }
    
    MemoryStruct chunk = {NULL, 0};
    struct curl_slist *headers = NULL;
    
    // Set headers
    headers = curl_slist_append(headers, "Accept: */*");
    headers = curl_slist_append(headers, "User-Agent: CLOBES-PRO/4.0.0");
    
    // Configure curl
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, follow_redirects ? 1L : 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, g_state.config.verify_ssl);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, g_state.config.verify_ssl ? 2L : 0L);
    
    // Perform request
    CURLcode res = curl_easy_perform(curl);
    
    // Get performance metrics
    double total_time = 0;
    long response_code = 0;
    curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME, &total_time);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    g_state.total_requests++;
    g_state.total_request_time += total_time;
    
    // Cleanup
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    
    if (res != CURLE_OK) {
        log_message(LOG_ERROR, "curl_easy_perform() failed: %s", curl_easy_strerror(res));
        free(chunk.memory);
        return NULL;
    }
    
    if (show_headers) {
        char *full_response = malloc(chunk.size + 100);
        if (full_response) {
            snprintf(full_response, chunk.size + 100, "HTTP/1.1 %ld\n%s", response_code, chunk.memory);
            free(chunk.memory);
            return full_response;
        }
    }
    
    return chunk.memory;
}

// HTTP GET (simple version)
char* http_get_simple(const char *url) {
    return http_get_advanced(url, 0, 1, g_state.config.timeout);
}

// HTTP POST with advanced features
char* http_post_advanced(const char *url, const char *data, const char *content_type, int show_headers) {
    (void)show_headers; // Not implemented yet
    
    CURL *curl = curl_easy_init();
    if (!curl) return NULL;
    
    MemoryStruct chunk = {NULL, 0};
    struct curl_slist *headers = NULL;
    
    if (!content_type) content_type = "application/json";
    
    headers = curl_slist_append(headers, "Accept: application/json");
    headers = curl_slist_append(headers, "User-Agent: CLOBES-PRO/4.0.0");
    char content_type_header[128];
    snprintf(content_type_header, sizeof(content_type_header), "Content-Type: %s", content_type);
    headers = curl_slist_append(headers, content_type_header);
    
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, g_state.config.timeout);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, g_state.config.verify_ssl);
    
    CURLcode res = curl_easy_perform(curl);
    
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    
    if (res != CURLE_OK) {
        free(chunk.memory);
        return NULL;
    }
    
    return chunk.memory;
}

// HTTP POST (simple version)
char* http_post_simple(const char *url, const char *data) {
    return http_post_advanced(url, data, "application/json", 0);
}

// HTTP download with progress
int http_download(const char *url, const char *output, int show_progress) {
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
    
    if (show_progress && g_state.config.progress_bars) {
        curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
        curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, progress_callback);
    }
    
    print_info("Downloading %s to %s...", url, output);
    
    CURLcode res = curl_easy_perform(curl);
    fclose(fp);
    curl_easy_cleanup(curl);
    
    if (res == CURLE_OK) {
        struct stat st;
        if (stat(output, &st) == 0) {
            double size_mb = st.st_size / (1024.0 * 1024.0);
            if (size_mb < 1.0) {
                print_success("Download completed: %s (%.2f KB)", output, st.st_size / 1024.0);
            } else {
                print_success("Download completed: %s (%.2f MB)", output, size_mb);
            }
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
    printf("Architecture:  ");
    
    #if defined(__x86_64__)
    printf("x86_64 (64-bit)\n");
    #elif defined(__i386__)
    printf("i386 (32-bit)\n");
    #elif defined(__aarch64__)
    printf("ARM64\n");
    #elif defined(__arm__)
    printf("ARM\n");
    #elif defined(__powerpc64__)
    printf("PowerPC64\n");
    #else
    printf("Unknown\n");
    #endif
    
    printf("Features:      curl");
    if (g_state.config.enable_websocket) printf(" websocket");
    if (g_state.config.enable_jwt) printf(" jwt");
    if (g_state.config.enable_cache) printf(" cache");
    if (g_state.config.enable_gzip) printf(" gzip");
    if (g_state.config.enable_proxy) printf(" proxy");
    printf("\n");
    
    printf("Cache:         %s\n", g_state.config.cache_enabled ? "Enabled" : "Disabled");
    printf("Requests:      %ld (avg %.2f ms)\n", 
           g_state.total_requests,
           g_state.total_requests > 0 ? (g_state.total_request_time * 1000) / g_state.total_requests : 0);
    printf("Cache stats:   Hits: %d, Misses: %d\n", 
           g_state.cache_hits, g_state.cache_misses);
    
    return 0;
}

// Command: help
int cmd_help(int argc, char **argv) {
    if (argc > 2) {
        for (int i = 0; i < g_command_count; i++) {
            if (strcmp(g_commands[i].name, argv[2]) == 0) {
                printf(COLOR_CYAN STYLE_BOLD "%s\n" COLOR_RESET, g_commands[i].name);
                printf("%s\n", g_commands[i].description);
                printf("\nUsage: %s\n", g_commands[i].usage);
                
                if (g_commands[i].alias_count > 0) {
                    printf("\nAliases: ");
                    for (int j = 0; j < g_commands[i].alias_count; j++) {
                        printf("%s ", g_commands[i].aliases[j]);
                    }
                    printf("\n");
                }
                return 0;
            }
        }
        print_error("Command not found: %s", argv[2]);
        return 1;
    }
    
    print_banner();
    
    printf("Available categories:\n\n");
    
    const char *categories[] = {
        "NETWORK", "FILE", "SYSTEM", "CRYPTO", "DEV", "SERVER", "WEB"
    };
    
    for (int cat = 0; cat < 7; cat++) {
        printf(COLOR_CYAN "📦 %s:\n" COLOR_RESET, categories[cat]);
        
        int found = 0;
        for (int i = 0; i < g_command_count; i++) {
            if (g_commands[i].category == (Category)cat) {
                printf("  %-20s - %s\n", 
                       g_commands[i].name, 
                       g_commands[i].description);
                found++;
            }
        }
        if (found == 0) {
            printf("  (no commands yet)\n");
        }
        printf("\n");
    }
    
    printf("\n" COLOR_GREEN "Quick examples:\n" COLOR_RESET);
    printf("  clobes -i                    # Interactive mode (like curl -i)\n");
    printf("  clobes network get https://api.github.com\n");
    printf("  clobes server start --port 8080\n");
    printf("  clobes crypto encode base64 \"Hello World\"\n");
    printf("  clobes system info\n");
    printf("\n");
    printf("For detailed help: " COLOR_CYAN "clobes help <command>\n" COLOR_RESET);
    
    return 0;
}

// Command: network
int cmd_network(int argc, char **argv) {
    if (argc < 3) {
        printf(COLOR_CYAN "🌐 NETWORK COMMANDS\n" COLOR_RESET);
        printf("══════════════════════════════════════════\n\n");
        
        printf("  get <url>              - GET request\n");
        printf("  post <url> <data>      - POST request\n");
        printf("  download <url> <file>  - Download file\n");
        printf("  ping <host>            - Ping host\n");
        printf("  myip                   - Show public IP\n");
        printf("\n");
        printf("Options:\n");
        printf("  -H, --headers          - Show response headers\n");
        printf("  -k, --insecure         - Disable SSL verification\n");
        printf("\n");
        return 0;
    }
    
    if (strcmp(argv[2], "get") == 0 && argc >= 4) {
        int show_headers = 0;
        
        for (int i = 4; i < argc; i++) {
            if (strcmp(argv[i], "-H") == 0 || strcmp(argv[i], "--headers") == 0) {
                show_headers = 1;
            } else if (strcmp(argv[i], "-k") == 0 || strcmp(argv[i], "--insecure") == 0) {
                g_state.config.verify_ssl = 0;
            }
        }
        
        char *response = http_get_advanced(argv[3], show_headers, 1, g_state.config.timeout);
        if (response) {
            printf("%s\n", response);
            free(response);
            return 0;
        } else {
            print_error("Failed to fetch URL");
            return 1;
        }
    } else if (strcmp(argv[2], "post") == 0 && argc >= 5) {
        char *response = http_post_simple(argv[3], argv[4]);
        if (response) {
            printf("%s\n", response);
            free(response);
            return 0;
        } else {
            print_error("Failed to POST to URL");
            return 1;
        }
    } else if (strcmp(argv[2], "download") == 0 && argc >= 5) {
        return http_download(argv[3], argv[4], 1);
    } else if (strcmp(argv[2], "ping") == 0 && argc >= 4) {
        char cmd[MAX_CMD_LENGTH];
        snprintf(cmd, sizeof(cmd), "ping -c 4 %s", argv[3]);
        return system(cmd);
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
        
        printf("  info              - Detailed system information\n");
        printf("  processes         - List all processes\n");
        printf("  disks             - Disk usage\n");
        printf("  memory            - Memory usage\n");
        printf("  cpu               - CPU information\n");
        printf("  network           - Network interfaces\n");
        printf("  logs              - View system logs\n");
        printf("  clean             - Clean temporary files\n");
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
            printf("  Used:        %lu MB (%.1f%%)\n", 
                   (mem_info.totalram - mem_info.freeram) / 1024 / 1024,
                   ((mem_info.totalram - mem_info.freeram) * 100.0) / mem_info.totalram);
        }
        
        printf("\nUptime:        ");
        system("uptime | sed 's/^.*up //' | sed 's/,.*//'");
        
        printf("CPU Cores:     ");
        system("nproc 2>/dev/null || echo 'N/A'");
        
        return 0;
    } else if (strcmp(argv[2], "processes") == 0) {
        system("ps aux --sort=-%cpu | head -20");
        return 0;
    } else if (strcmp(argv[2], "disks") == 0) {
        system("df -h | grep -v 'tmpfs\\|udev'");
        return 0;
    } else if (strcmp(argv[2], "memory") == 0) {
        system("free -h");
        return 0;
    }
    
    print_error("Unknown system command: %s", argv[2]);
    return 1;
}

// Command: file
int cmd_file(int argc, char **argv) {
    if (argc < 3) {
        printf(COLOR_CYAN "📁 FILE OPERATIONS\n" COLOR_RESET);
        printf("══════════════════════════════════════════\n\n");
        
        printf("  find <dir> <pattern>    - Find files\n");
        printf("  size <file|dir>         - Get size\n");
        printf("  hash <file> [algorithm] - Calculate hash\n");
        printf("  compare <file1> <file2> - Compare files\n");
        printf("  compress <file>         - Compress file\n");
        printf("  decompress <file>       - Decompress file\n");
        printf("\n");
        return 0;
    }
    
    if (strcmp(argv[2], "find") == 0 && argc >= 5) {
        char cmd[MAX_CMD_LENGTH];
        snprintf(cmd, sizeof(cmd), "find \"%s\" -name \"%s\" -type f 2>/dev/null | head -20", 
                argv[3], argv[4]);
        return system(cmd);
    } else if (strcmp(argv[2], "size") == 0 && argc >= 4) {
        struct stat st;
        if (stat(argv[3], &st) == 0) {
            if (S_ISDIR(st.st_mode)) {
                char cmd[MAX_CMD_LENGTH];
                snprintf(cmd, sizeof(cmd), "du -sh \"%s\"", argv[3]);
                return system(cmd);
            } else {
                printf("Size: %.2f KB (%.2f MB)\n", 
                      st.st_size / 1024.0, 
                      st.st_size / (1024.0 * 1024.0));
                return 0;
            }
        } else {
            print_error("File not found: %s", argv[3]);
            return 1;
        }
    }
    
    print_error("Unknown file command: %s", argv[2]);
    return 1;
}

// Command: crypto
int cmd_crypto(int argc, char **argv) {
    if (argc < 3) {
        printf(COLOR_CYAN "🔐 CRYPTO COMMANDS\n" COLOR_RESET);
        printf("══════════════════════════════════════════\n\n");
        
        printf("  hash <string|file>      - Hash string or file\n");
        printf("  encode base64 <text>    - Base64 encode\n");
        printf("  decode base64 <text>    - Base64 decode\n");
        printf("  generate-password       - Generate secure password\n");
        printf("\n");
        return 0;
    }
    
    if (strcmp(argv[2], "hash") == 0 && argc >= 4) {
        print_info("Hashing '%s':", argv[3]);
        
        struct stat st;
        if (stat(argv[3], &st) == 0 && S_ISREG(st.st_mode)) {
            char cmd[MAX_CMD_LENGTH];
            snprintf(cmd, sizeof(cmd), "md5sum \"%s\" 2>/dev/null", argv[3]);
            return system(cmd);
        } else {
            char cmd[MAX_CMD_LENGTH];
            snprintf(cmd, sizeof(cmd), "echo -n '%s' | md5sum", argv[3]);
            return system(cmd);
        }
    } else if (strcmp(argv[2], "encode") == 0 && argc >= 5) {
        if (strcmp(argv[3], "base64") == 0) {
            char *encoded = base64_encode(argv[4], strlen(argv[4]));
            if (encoded) {
                printf("%s\n", encoded);
                free(encoded);
            }
            return 0;
        }
    } else if (strcmp(argv[2], "decode") == 0 && argc >= 5) {
        if (strcmp(argv[3], "base64") == 0) {
            char *decoded = base64_decode(argv[4], NULL);
            if (decoded) {
                printf("%s\n", decoded);
                free(decoded);
            }
            return 0;
        }
    } else if (strcmp(argv[2], "generate-password") == 0) {
        int length = 16;
        if (argc >= 4) length = atoi(argv[3]);
        if (length < 8) length = 8;
        if (length > 64) length = 64;
        
        char cmd[MAX_CMD_LENGTH];
        snprintf(cmd, sizeof(cmd), 
                "tr -dc 'A-Za-z0-9!@#$%%^&*()' < /dev/urandom | head -c %d && echo", 
                length);
        return system(cmd);
    }
    
    print_error("Unknown crypto command: %s", argv[2]);
    return 1;
}

// Command: dev
int cmd_dev(int argc, char **argv) {
    if (argc < 3) {
        printf(COLOR_CYAN "👨‍💻 DEVELOPMENT TOOLS\n" COLOR_RESET);
        printf("══════════════════════════════════════════\n\n");
        
        printf("  compile <file.c>        - Compile C program\n");
        printf("  run <file>              - Run executable\n");
        printf("  test <directory>        - Run tests\n");
        printf("\n");
        return 0;
    }
    
    if (strcmp(argv[2], "compile") == 0 && argc >= 4) {
        char output[256];
        const char *dot = strrchr(argv[3], '.');
        if (dot) {
            int len = dot - argv[3];
            strncpy(output, argv[3], len);
            output[len] = '\0';
        } else {
            strcpy(output, argv[3]);
        }
        
        char cmd[MAX_CMD_LENGTH];
        snprintf(cmd, sizeof(cmd), "gcc -Wall -Wextra -O2 \"%s\" -o \"%s\" 2>&1", 
                argv[3], output);
        
        int result = system(cmd);
        if (result == 0) {
            print_success("Compilation successful: %s", output);
        } else {
            print_error("Compilation failed");
        }
        return result;
    }
    
    print_error("Unknown dev command: %s", argv[2]);
    return 1;
}

// Stub commands for future features
int cmd_proxy(int argc, char **argv) {
    (void)argc; (void)argv;
    print_warning("Proxy feature not implemented yet");
    return 0;
}

int cmd_jwt(int argc, char **argv) {
    (void)argc; (void)argv;
    print_warning("JWT feature not implemented yet");
    return 0;
}

int cmd_websocket(int argc, char **argv) {
    (void)argc; (void)argv;
    print_warning("WebSocket feature not implemented yet");
    return 0;
}

int cmd_cache(int argc, char **argv) {
    (void)argc; (void)argv;
    print_warning("Cache feature not implemented yet");
    return 0;
}

// Register commands
void register_commands() {
    // Core commands
    Command version_cmd = {
        .name = "version",
        .description = "Show version information",
        .usage = "clobes version",
        .category = CATEGORY_SYSTEM,
        .min_args = 0,
        .max_args = 0,
        .handler = cmd_version
    };
    strcpy(version_cmd.aliases[0], "v");
    strcpy(version_cmd.aliases[1], "--version");
    version_cmd.alias_count = 2;
    
    Command help_cmd = {
        .name = "help",
        .description = "Show help information",
        .usage = "clobes help [command]",
        .category = CATEGORY_SYSTEM,
        .min_args = 0,
        .max_args = 1,
        .handler = cmd_help
    };
    strcpy(help_cmd.aliases[0], "h");
    strcpy(help_cmd.aliases[1], "--help");
    help_cmd.alias_count = 2;
    
    // Network commands
    Command network_cmd = {
        .name = "network",
        .description = "Network operations",
        .usage = "clobes network [command] [args]",
        .category = CATEGORY_NETWORK,
        .min_args = 1,
        .max_args = 10,
        .handler = cmd_network
    };
    strcpy(network_cmd.aliases[0], "net");
    network_cmd.alias_count = 1;
    
    // System commands
    Command system_cmd = {
        .name = "system",
        .description = "System operations",
        .usage = "clobes system [command]",
        .category = CATEGORY_SYSTEM,
        .min_args = 1,
        .max_args = 10,
        .handler = cmd_system
    };
    strcpy(system_cmd.aliases[0], "sys");
    system_cmd.alias_count = 1;
    
    // File commands
    Command file_cmd = {
        .name = "file",
        .description = "File operations",
        .usage = "clobes file [command] [args]",
        .category = CATEGORY_FILE,
        .min_args = 1,
        .max_args = 10,
        .handler = cmd_file
    };
    strcpy(file_cmd.aliases[0], "files");
    file_cmd.alias_count = 1;
    
    // Crypto commands
    Command crypto_cmd = {
        .name = "crypto",
        .description = "Cryptography operations",
        .usage = "clobes crypto [command] [args]",
        .category = CATEGORY_CRYPTO,
        .min_args = 1,
        .max_args = 10,
        .handler = cmd_crypto
    };
    crypto_cmd.alias_count = 0;
    
    // Dev commands
    Command dev_cmd = {
        .name = "dev",
        .description = "Development tools",
        .usage = "clobes dev [command] [args]",
        .category = CATEGORY_DEV,
        .min_args = 1,
        .max_args = 10,
        .handler = cmd_dev
    };
    dev_cmd.alias_count = 0;
    
    // Server commands
    Command server_cmd = {
        .name = "server",
        .description = "HTTP server operations",
        .usage = "clobes server [start|stop|status|maintenance]",
        .category = CATEGORY_SERVER,
        .min_args = 1,
        .max_args = 10,
        .handler = cmd_server
    };
    server_cmd.alias_count = 0;
    
    // Add commands to registry
    g_commands[g_command_count++] = version_cmd;
    g_commands[g_command_count++] = help_cmd;
    g_commands[g_command_count++] = network_cmd;
    g_commands[g_command_count++] = system_cmd;
    g_commands[g_command_count++] = file_cmd;
    g_commands[g_command_count++] = crypto_cmd;
    g_commands[g_command_count++] = dev_cmd;
    g_commands[g_command_count++] = server_cmd;
}

// Find command
Command* find_command(const char *name) {
    for (int i = 0; i < g_command_count; i++) {
        if (strcmp(g_commands[i].name, name) == 0) {
            return &g_commands[i];
        }
        // Check aliases
        for (int j = 0; j < g_commands[i].alias_count; j++) {
            if (strcmp(g_commands[i].aliases[j], name) == 0) {
                return &g_commands[i];
            }
        }
    }
    return NULL;
}

// Initialize clobes
int clobes_init(int argc, char **argv) {
    (void)argc; (void)argv;
    
    // Initialize curl
    CURLcode res = curl_global_init(CURL_GLOBAL_ALL);
    if (res != CURLE_OK) {
        fprintf(stderr, "Failed to initialize curl: %s\n", curl_easy_strerror(res));
        return 1;
    }
    
    // Register commands
    register_commands();
    
    return 0;
}

// Cleanup clobes
void clobes_cleanup() {
    // Cleanup curl
    curl_global_cleanup();
}

// Main function
int main(int argc, char **argv) {
    // Check for interactive mode (-i like curl)
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--interactive") == 0) {
            clobes_init(argc, argv);
            int result = interactive_mode();
            clobes_cleanup();
            return result;
        }
    }
    
    // Initialize
    if (clobes_init(argc, argv) != 0) {
        fprintf(stderr, "Failed to initialize CLOBES PRO\n");
        return 1;
    }
    
    // Check for flags
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--debug") == 0 || strcmp(argv[i], "-d") == 0) {
            g_state.debug_mode = 1;
            g_state.log_level = LOG_DEBUG;
        } else if (strcmp(argv[i], "--verbose") == 0 || strcmp(argv[i], "-v") == 0) {
            g_state.config.verbose = 1;
        } else if (strcmp(argv[i], "--no-color") == 0) {
            g_state.config.colors = 0;
        } else if (strcmp(argv[i], "-k") == 0 || strcmp(argv[i], "--insecure") == 0) {
            g_state.config.verify_ssl = 0;
        }
    }
    
    // Parse command line
    if (argc < 2) {
        cmd_help(1, argv);
        clobes_cleanup();
        return 0;
    }
    
    // Find and execute command
    Command *cmd = find_command(argv[1]);
    if (cmd) {
        // Check arguments
        if (argc - 2 < cmd->min_args) {
            print_error("Too few arguments for command '%s'", cmd->name);
            printf("Usage: %s\n", cmd->usage);
            clobes_cleanup();
            return 1;
        }
        
        int result = cmd->handler(argc, argv);
        clobes_cleanup();
        return result;
    }
    
    // Command not found
    print_error("Unknown command: %s", argv[1]);
    printf("Use 'clobes help' to see available commands\n");
    printf("Try 'clobes -i' for interactive mode (linssr url -i)\n");
    
    clobes_cleanup();
    return 1;
}
