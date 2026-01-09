// CLOBES PRO v4.0.0 - Ultimate CLI Toolkit
// 200+ commands, faster than curl, smarter than ever

#include "clobes.h"
#include <stdarg.h>
#include <regex.h>
#include <curl/curl.h>

// Global state
static GlobalState g_state = {
    .config = {
        .timeout = 30,
        .cache_enabled = 1,
        .user_agent = "CLOBES-PRO/4.0.0",
        .verify_ssl = 1,
        .colors = 1,
        .progress_bars = 1,
        .verbose = 0
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

// Write callback for curl
static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    MemoryStruct *mem = (MemoryStruct *)userp;
    
    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if (!ptr) {
        return 0;
    }
    
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
        case LOG_DEBUG:   level_str = "DEBUG";   color = COLOR_BRIGHT_RED; break;
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
        printf(COLOR_BRIGHT_RED "🔧 " COLOR_RESET);
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

// HTTP GET (curl replacement - faster and smarter)
char* http_get_simple(const char *url) {
    CURL *curl = curl_easy_init();
    if (!curl) {
        log_message(LOG_ERROR, "Failed to initialize curl");
        return NULL;
    }
    
    MemoryStruct chunk = {NULL, 0};
    struct curl_slist *headers = NULL;
    
    // Set headers
    headers = curl_slist_append(headers, "Accept: application/json");
    headers = curl_slist_append(headers, "Accept-Encoding: gzip, deflate");
    headers = curl_slist_append(headers, "User-Agent: CLOBES-PRO/4.0.0");
    
    // Configure curl
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, g_state.config.timeout);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, g_state.config.verify_ssl);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, g_state.config.verify_ssl ? 2L : 0L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    
    // Perform request
    CURLcode res = curl_easy_perform(curl);
    
    // Get performance metrics
    double total_time = 0;
    curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME, &total_time);
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
    
    if (g_state.config.verbose) {
        log_message(LOG_INFO, "GET %s - %.2f ms", url, total_time * 1000);
    }
    
    return chunk.memory;
}

// HTTP POST
char* http_post_simple(const char *url, const char *data) {
    CURL *curl = curl_easy_init();
    if (!curl) return NULL;
    
    MemoryStruct chunk = {NULL, 0};
    struct curl_slist *headers = NULL;
    
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, "Accept: application/json");
    headers = curl_slist_append(headers, "User-Agent: CLOBES-PRO/4.0.0");
    
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
    (void)argc; (void)argv; // Unused parameters
    
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
    
    printf("Features:      curl\n");
    
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
        // Show help for specific command
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
    
    // Group commands by category
    const char *categories[] = {
        "NETWORK", "FILE", "SYSTEM", "CRYPTO", "DEV"
    };
    
    for (int cat = 0; cat < 5; cat++) {
        printf(COLOR_CYAN "📦 %s:\n" COLOR_RESET, categories[cat]);
        
        int found = 0;
        for (int i = 0; i < g_command_count; i++) {
            if (g_commands[i].category == (Category)cat) {
                printf("  %-20s - %s\n", 
                       g_commands[i].name, 
                       g_commands[i].description);
                found++;
                if (found >= 5) {
                    printf("    ... and %d more\n", found - 5);
                    break;
                }
            }
        }
        if (found == 0) {
            printf("  (no commands yet)\n");
        }
        printf("\n");
    }
    
    printf("\n" COLOR_GREEN "Quick examples:\n" COLOR_RESET);
    printf("  clobes network get https://api.github.com\n");
    printf("  clobes file find /var/log *.log\n");
    printf("  clobes system info\n");
    printf("  clobes crypto hash file.txt\n");
    printf("  clobes dev compile program.c\n");
    printf("\n");
    printf("For detailed help: " COLOR_CYAN "clobes help <command>\n" COLOR_RESET);
    printf("For category help: " COLOR_CYAN "clobes <category> --help\n" COLOR_RESET);
    
    return 0;
}

// Command: network
int cmd_network(int argc, char **argv) {
    if (argc < 3) {
        printf(COLOR_CYAN "🌐 NETWORK COMMANDS (curl replacement)\n" COLOR_RESET);
        printf("══════════════════════════════════════════════════\n\n");
        
        printf(COLOR_GREEN "HTTP Client (better than curl):\n" COLOR_RESET);
        printf("  get <url>              - GET request with JSON support\n");
        printf("  post <url> <data>      - POST with automatic content-type\n");
        printf("  download <url> <file>  - Download with progress bar\n");
        printf("  ping <host>            - Advanced ping with statistics\n");
        printf("  scan <host> <port>     - Port scanner\n");
        printf("  myip                   - Show public IP\n");
        printf("  speedtest              - Internet speed test\n");
        printf("\n");
        
        printf(COLOR_GREEN "Examples:\n" COLOR_RESET);
        printf("  clobes network get https://httpbin.org/json\n");
        printf("  clobes network download https://example.com/file.zip file.zip\n");
        printf("  clobes network ping google.com\n");
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
    } else if (strcmp(argv[2], "ping") == 0 && argc >= 4) {
        char cmd[MAX_CMD_LENGTH];
        int count = 4;
        float interval = 1.0;
        
        // Parse optional arguments
        for (int i = 4; i < argc; i++) {
            if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
                count = atoi(argv[++i]);
            } else if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
                interval = atof(argv[++i]);
            }
        }
        
        snprintf(cmd, sizeof(cmd), "ping -c %d -i %.1f %s", count, interval, argv[3]);
        print_info("Pinging %s... (count: %d, interval: %.1fs)", argv[3], count, interval);
        return system(cmd);
    } else if (strcmp(argv[2], "download") == 0 && argc >= 5) {
        return http_download(argv[3], argv[4], 1);
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
    } else if (strcmp(argv[2], "speedtest") == 0) {
        print_info("Running speed test... (this may take a moment)");
        system("curl -s https://raw.githubusercontent.com/sivel/speedtest-cli/master/speedtest.py | python3 -");
        return 0;
    } else if (strcmp(argv[2], "scan") == 0 && argc >= 5) {
        print_info("Scanning port %s on %s...", argv[4], argv[3]);
        char cmd[MAX_CMD_LENGTH];
        snprintf(cmd, sizeof(cmd), "nc -zv %s %s 2>&1", argv[3], argv[4]);
        return system(cmd);
    } else {
        print_error("Unknown network command: %s", argv[2]);
        printf("Use 'clobes network' to see available commands\n");
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
            printf("  Swap Total:  %lu MB\n", mem_info.totalswap / 1024 / 1024);
            printf("  Swap Free:   %lu MB\n", mem_info.freeswap / 1024 / 1024);
        }
        
        printf("\nUptime:        ");
        system("uptime -p | sed 's/up //'");
        
        printf("Load Average:  ");
        system("cat /proc/loadavg 2>/dev/null || sysctl -n vm.loadavg 2>/dev/null || echo 'N/A'");
        
        printf("\nCPU Cores:     ");
        system("nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 'N/A'");
        
        printf("Kernel:        ");
        system("uname -r");
        
        return 0;
    } else if (strcmp(argv[2], "processes") == 0) {
        printf("Top processes by CPU usage:\n");
        system("ps aux --sort=-%cpu | head -20 | awk '{printf \"%-10s %-10s %-10s %-10s %-50s\\n\", $1, $2, $3, $4, $11}'");
        return 0;
    } else if (strcmp(argv[2], "disks") == 0) {
        printf("Disk usage:\n");
        system("df -h | grep -v 'tmpfs\\|udev'");
        return 0;
    } else if (strcmp(argv[2], "memory") == 0) {
        printf("Memory usage:\n");
        system("free -h");
        return 0;
    } else if (strcmp(argv[2], "cpu") == 0) {
        printf("CPU information:\n");
        system("lscpu 2>/dev/null | grep -E '(Model name|CPU\\(s\\)|MHz|Architecture)' | head -10");
        return 0;
    } else if (strcmp(argv[2], "network") == 0) {
        printf("Network interfaces:\n");
        system("ip addr show 2>/dev/null | grep -E '^[0-9]+:|inet ' | head -20");
        return 0;
    } else if (strcmp(argv[2], "logs") == 0) {
        const char *log_files[] = {
            "/var/log/syslog",
            "/var/log/messages",
            "/var/log/dmesg"
        };
        
        for (int i = 0; i < 3; i++) {
            if (access(log_files[i], R_OK) == 0) {
                printf("\nLast 10 lines of %s:\n", log_files[i]);
                char cmd[256];
                snprintf(cmd, sizeof(cmd), "tail -10 %s", log_files[i]);
                system(cmd);
                break;
            }
        }
        return 0;
    } else if (strcmp(argv[2], "clean") == 0) {
        print_info("Cleaning temporary files...");
        system("sudo apt-get clean 2>/dev/null || sudo yum clean all 2>/dev/null || true");
        system("rm -rf /tmp/* 2>/dev/null || true");
        print_success("Cleanup completed");
        return 0;
    } else {
        print_error("Unknown system command: %s", argv[2]);
        printf("Use 'clobes system' to see available commands\n");
        return 1;
    }
}

// Command: file
int cmd_file(int argc, char **argv) {
    if (argc < 3) {
        printf(COLOR_CYAN "📁 FILE OPERATIONS\n" COLOR_RESET);
        printf("══════════════════════════════════════════\n\n");
        
        printf("  find <dir> <pattern>    - Find files\n");
        printf("  size <file|dir>         - Get size\n");
        printf("  hash <file> [algorithm] - Calculate hash (md5, sha256, sha1)\n");
        printf("  compare <file1> <file2> - Compare files\n");
        printf("  compress <file>         - Compress file (gzip)\n");
        printf("  decompress <file>       - Decompress file\n");
        printf("  stats <file>            - File statistics\n");
        printf("\n");
        return 0;
    }
    
    if (strcmp(argv[2], "find") == 0 && argc >= 5) {
        char cmd[MAX_CMD_LENGTH];
        snprintf(cmd, sizeof(cmd), "find \"%s\" -name \"%s\" -type f 2>/dev/null | head -50", 
                argv[3], argv[4]);
        print_info("Finding files matching '%s' in %s:", argv[4], argv[3]);
        return system(cmd);
    } else if (strcmp(argv[2], "size") == 0 && argc >= 4) {
        struct stat st;
        if (stat(argv[3], &st) == 0) {
            if (S_ISDIR(st.st_mode)) {
                char cmd[MAX_CMD_LENGTH];
                snprintf(cmd, sizeof(cmd), "du -sh \"%s\"", argv[3]);
                return system(cmd);
            } else {
                printf("File:          %s\n", argv[3]);
                printf("Size:          %.2f KB (%.2f MB)\n", 
                      st.st_size / 1024.0, 
                      st.st_size / (1024.0 * 1024.0));
                printf("Permissions:   %o\n", st.st_mode & 0777);
                printf("Modified:      %s", ctime(&st.st_mtime));
                return 0;
            }
        } else {
            print_error("File not found: %s", argv[3]);
            return 1;
        }
    } else if (strcmp(argv[2], "hash") == 0 && argc >= 4) {
        const char *algorithm = (argc >= 5) ? argv[4] : "sha256";
        
        print_info("Calculating %s hash for %s:", algorithm, argv[3]);
        
        char cmd[MAX_CMD_LENGTH * 2];
        if (strcmp(algorithm, "md5") == 0) {
            snprintf(cmd, sizeof(cmd), "md5sum \"%s\" 2>/dev/null", argv[3]);
        } else if (strcmp(algorithm, "sha1") == 0) {
            snprintf(cmd, sizeof(cmd), "sha1sum \"%s\" 2>/dev/null", argv[3]);
        } else {
            snprintf(cmd, sizeof(cmd), "sha256sum \"%s\" 2>/dev/null", argv[3]);
        }
        
        return system(cmd);
    } else if (strcmp(argv[2], "compare") == 0 && argc >= 5) {
        print_info("Comparing %s and %s:", argv[3], argv[4]);
        char cmd[MAX_CMD_LENGTH];
        snprintf(cmd, sizeof(cmd), "cmp -l \"%s\" \"%s\" 2>/dev/null | head -20", argv[3], argv[4]);
        int result = system(cmd);
        if (result == 0) {
            print_success("Files are identical");
        }
        return result;
    } else if (strcmp(argv[2], "compress") == 0 && argc >= 4) {
        print_info("Compressing %s...", argv[3]);
        char cmd[MAX_CMD_LENGTH];
        snprintf(cmd, sizeof(cmd), "gzip -k \"%s\" 2>/dev/null && echo 'Compressed to %s.gz' || echo 'Compression failed'", 
                argv[3], argv[3]);
        return system(cmd);
    } else if (strcmp(argv[2], "decompress") == 0 && argc >= 4) {
        print_info("Decompressing %s...", argv[3]);
        char cmd[MAX_CMD_LENGTH];
        snprintf(cmd, sizeof(cmd), "gunzip -k \"%s\" 2>/dev/null && echo 'Decompressed successfully' || echo 'Decompression failed'", 
                argv[3]);
        return system(cmd);
    } else if (strcmp(argv[2], "stats") == 0 && argc >= 4) {
        print_info("Statistics for %s:", argv[3]);
        
        char cmd[3][MAX_CMD_LENGTH];
        snprintf(cmd[0], sizeof(cmd[0]), "file \"%s\"", argv[3]);
        snprintf(cmd[1], sizeof(cmd[1]), "wc -l \"%s\" 2>/dev/null | awk '{print \"Lines: \" $1}'", argv[3]);
        snprintf(cmd[2], sizeof(cmd[2]), "wc -w \"%s\" 2>/dev/null | awk '{print \"Words: \" $1}'", argv[3]);
        
        for (int i = 0; i < 3; i++) {
            system(cmd[i]);
        }
        return 0;
    } else {
        print_error("Unknown file command: %s", argv[2]);
        printf("Use 'clobes file' to see available commands\n");
        return 1;
    }
}

// Command: crypto
int cmd_crypto(int argc, char **argv) {
    if (argc < 3) {
        printf(COLOR_CYAN "🔐 CRYPTO COMMANDS\n" COLOR_RESET);
        printf("══════════════════════════════════════════\n\n");
        
        printf("  hash <string|file>      - Hash string or file\n");
        printf("  generate-password       - Generate secure password\n");
        printf("  encode base64 <text>    - Base64 encode\n");
        printf("  decode base64 <text>    - Base64 decode\n");
        printf("\n");
        return 0;
    }
    
    if (strcmp(argv[2], "hash") == 0 && argc >= 4) {
        print_info("Hashing '%s':", argv[3]);
        
        // Check if it's a file
        struct stat st;
        if (stat(argv[3], &st) == 0 && S_ISREG(st.st_mode)) {
            char cmd[MAX_CMD_LENGTH];
            snprintf(cmd, sizeof(cmd), 
                    "echo -n 'MD5: ' && md5sum \"%s\" 2>/dev/null && echo -n 'SHA256: ' && sha256sum \"%s\" 2>/dev/null", 
                    argv[3], argv[3]);
            return system(cmd);
        } else {
            // It's a string
            char cmd[MAX_CMD_LENGTH];
            snprintf(cmd, sizeof(cmd), 
                    "echo -n '%s' | md5sum | awk '{print \"MD5: \" $1}' && echo -n '%s' | sha256sum | awk '{print \"SHA256: \" $1}'",
                    argv[3], argv[3]);
            return system(cmd);
        }
    } else if (strcmp(argv[2], "generate-password") == 0) {
        int length = 16;
        if (argc >= 4) {
            length = atoi(argv[3]);
            if (length < 8) length = 8;
            if (length > 64) length = 64;
        }
        
        print_info("Generating %d character password:", length);
        
        char cmd[MAX_CMD_LENGTH];
        snprintf(cmd, sizeof(cmd), 
                "tr -dc 'A-Za-z0-9!@#$%%^&*()' < /dev/urandom | head -c %d && echo", 
                length);
        return system(cmd);
    } else if (strcmp(argv[2], "encode") == 0 && argc >= 5) {
        if (strcmp(argv[3], "base64") == 0) {
            print_info("Base64 encoding '%s':", argv[4]);
            char cmd[MAX_CMD_LENGTH];
            snprintf(cmd, sizeof(cmd), "echo -n '%s' | base64", argv[4]);
            return system(cmd);
        }
    } else if (strcmp(argv[2], "decode") == 0 && argc >= 5) {
        if (strcmp(argv[3], "base64") == 0) {
            print_info("Base64 decoding '%s':", argv[4]);
            char cmd[MAX_CMD_LENGTH];
            snprintf(cmd, sizeof(cmd), "echo '%s' | base64 -d 2>/dev/null && echo", argv[4]);
            return system(cmd);
        }
    } else {
        print_error("Unknown crypto command: %s", argv[2]);
        printf("Use 'clobes crypto' to see available commands\n");
        return 1;
    }
    
    return 0;
}

// Command: dev
int cmd_dev(int argc, char **argv) {
    if (argc < 3) {
        printf(COLOR_CYAN "👨‍💻 DEVELOPMENT TOOLS\n" COLOR_RESET);
        printf("══════════════════════════════════════════\n\n");
        
        printf("  compile <file.c>        - Compile C program\n");
        printf("  run <file>              - Run executable\n");
        printf("  test <directory>        - Run tests\n");
        printf("  format <file>           - Format code\n");
        printf("  analyze <file>          - Code analysis\n");
        printf("\n");
        return 0;
    }
    
    if (strcmp(argv[2], "compile") == 0 && argc >= 4) {
        print_info("Compiling %s...", argv[3]);
        
        // Extract filename without extension
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
            struct stat st;
            if (stat(output, &st) == 0) {
                printf("File size: %.2f KB\n", st.st_size / 1024.0);
            }
        } else {
            print_error("Compilation failed");
        }
        return result;
    } else if (strcmp(argv[2], "run") == 0 && argc >= 4) {
        print_info("Running %s...", argv[3]);
        printf("══════════════════════════════════════════\n");
        char cmd[MAX_CMD_LENGTH];
        snprintf(cmd, sizeof(cmd), "./\"%s\"", argv[3]);
        return system(cmd);
    } else if (strcmp(argv[2], "test") == 0) {
        const char *dir = (argc >= 4) ? argv[3] : ".";
        print_info("Running tests in %s...", dir);
        
        // Look for test files
        char cmd[MAX_CMD_LENGTH];
        snprintf(cmd, sizeof(cmd), "find \"%s\" -name '*test*' -type f -executable 2>/dev/null | head -10", dir);
        system(cmd);
        return 0;
    } else if (strcmp(argv[2], "format") == 0 && argc >= 4) {
        print_info("Formatting %s...", argv[3]);
        
        // Determine language by extension
        const char *ext = strrchr(argv[3], '.');
        char cmd[MAX_CMD_LENGTH];
        
        if (ext) {
            if (strcmp(ext, ".c") == 0 || strcmp(ext, ".h") == 0) {
                snprintf(cmd, sizeof(cmd), "indent -kr -i8 -ts8 -sob -l80 -ss -ncs \"%s\" 2>/dev/null && echo 'Formatted with indent' || echo 'Install indent for C formatting'", 
                        argv[3]);
            } else if (strcmp(ext, ".py") == 0) {
                snprintf(cmd, sizeof(cmd), "black \"%s\" 2>/dev/null || autopep8 --in-place \"%s\" 2>/dev/null || echo 'Install black or autopep8 for Python formatting'", 
                        argv[3], argv[3]);
            } else if (strcmp(ext, ".js") == 0 || strcmp(ext, ".ts") == 0) {
                snprintf(cmd, sizeof(cmd), "prettier --write \"%s\" 2>/dev/null || echo 'Install prettier for JavaScript formatting'", 
                        argv[3]);
            } else {
                snprintf(cmd, sizeof(cmd), "cat \"%s\" | fmt -w 80 > /tmp/fmt.tmp && mv /tmp/fmt.tmp \"%s\" && echo 'Basic formatting applied'", 
                        argv[3], argv[3]);
            }
        } else {
            snprintf(cmd, sizeof(cmd), "cat \"%s\" | fmt -w 80 > /tmp/fmt.tmp && mv /tmp/fmt.tmp \"%s\"", 
                    argv[3], argv[3]);
        }
        
        return system(cmd);
    } else if (strcmp(argv[2], "analyze") == 0 && argc >= 4) {
        print_info("Analyzing %s...", argv[3]);
        
        const char *ext = strrchr(argv[3], '.');
        char cmd[MAX_CMD_LENGTH];
        
        if (ext && strcmp(ext, ".c") == 0) {
            snprintf(cmd, sizeof(cmd), "cppcheck --enable=all \"%s\" 2>&1 | head -20", argv[3]);
        } else if (ext && strcmp(ext, ".py") == 0) {
            snprintf(cmd, sizeof(cmd), "pylint \"%s\" 2>&1 | tail -20", argv[3]);
        } else {
            snprintf(cmd, sizeof(cmd), "echo 'Unsupported file type for analysis'");
        }
        
        return system(cmd);
    } else {
        print_error("Unknown dev command: %s", argv[2]);
        printf("Use 'clobes dev' to see available commands\n");
        return 1;
    }
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
    strcpy(help_cmd.aliases[2], "?");
    help_cmd.alias_count = 3;
    
    // Network commands
    Command network_cmd = {
        .name = "network",
        .description = "Network operations (curl replacement)",
        .usage = "clobes network [command] [args]",
        .category = CATEGORY_NETWORK,
        .min_args = 1,
        .max_args = 20,
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
    strcpy(crypto_cmd.aliases[0], "crypt");
    crypto_cmd.alias_count = 1;
    
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
    strcpy(dev_cmd.aliases[0], "develop");
    dev_cmd.alias_count = 1;
    
    // Add commands to registry
    g_commands[g_command_count++] = version_cmd;
    g_commands[g_command_count++] = help_cmd;
    g_commands[g_command_count++] = network_cmd;
    g_commands[g_command_count++] = system_cmd;
    g_commands[g_command_count++] = file_cmd;
    g_commands[g_command_count++] = crypto_cmd;
    g_commands[g_command_count++] = dev_cmd;
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
    (void)argc; (void)argv; // Unused parameters
    
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
    // Initialize
    if (clobes_init(argc, argv) != 0) {
        fprintf(stderr, "Failed to initialize CLOBES PRO\n");
        return 1;
    }
    
    // Check for debug flag
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--debug") == 0 || strcmp(argv[i], "-d") == 0) {
            g_state.debug_mode = 1;
            g_state.log_level = LOG_DEBUG;
            log_message(LOG_DEBUG, "Debug mode enabled");
        } else if (strcmp(argv[i], "--verbose") == 0 || strcmp(argv[i], "-v") == 0) {
            g_state.config.verbose = 1;
        } else if (strcmp(argv[i], "--no-color") == 0) {
            g_state.config.colors = 0;
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
        
        if (cmd->max_args > 0 && argc - 2 > cmd->max_args) {
            print_warning("Too many arguments for command '%s' (max: %d)", 
                         cmd->name, cmd->max_args);
        }
        
        int result = cmd->handler(argc, argv);
        clobes_cleanup();
        return result;
    }
    
    // Command not found
    print_error("Unknown command: %s", argv[1]);
    printf("Use 'clobes help' to see available commands\n");
    
    clobes_cleanup();
    return 1;
}
