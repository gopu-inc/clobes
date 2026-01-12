// CLOBES PRO ULTRA v5.0.0 - Alpine Thunder Edition
#include "clobes.h"
#include <stdarg.h>
#include <regex.h>

// Global state
GlobalState g_state = {
    .colors = 1,
    .debug_mode = 0,
    .total_requests = 0,
    .server_session = NULL
};

// Command registry
static Command g_commands[50];
static int g_command_count = 0;

// Server session
static ServerSession *g_server_session = NULL;

// MIME types database
static const MimeType mime_types[] = {
    {".html", "text/html; charset=utf-8"},
    {".htm", "text/html; charset=utf-8"},
    {".css", "text/css; charset=utf-8"},
    {".js", "application/javascript; charset=utf-8"},
    {".json", "application/json; charset=utf-8"},
    {".txt", "text/plain; charset=utf-8"},
    {".md", "text/markdown; charset=utf-8"},
    {".xml", "application/xml"},
    {".csv", "text/csv"},
    {".png", "image/png"},
    {".jpg", "image/jpeg"},
    {".jpeg", "image/jpeg"},
    {".gif", "image/gif"},
    {".ico", "image/x-icon"},
    {".svg", "image/svg+xml"},
    {".pdf", "application/pdf"},
    {".zip", "application/zip"},
    {".tar", "application/x-tar"},
    {".gz", "application/gzip"},
    {".mp3", "audio/mpeg"},
    {".mp4", "video/mp4"},
    {".webm", "video/webm"},
    {".woff", "font/woff"},
    {".woff2", "font/woff2"},
    {".ttf", "font/ttf"},
    {"", "application/octet-stream"}
};

// Memory structure for curl
typedef struct {
    char *memory;
    size_t size;
} MemoryStruct;

// Base64 table
static const char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// ==================== PRINT FUNCTIONS ====================

void print_colored(const char *color, const char *text) {
    if (g_state.colors) {
        printf("%s%s%s", color, text, COLOR_RESET);
    } else {
        printf("%s", text);
    }
}

void print_success(const char *format, ...) {
    va_list args;
    va_start(args, format);
    
    if (g_state.colors) {
        printf(COLOR_BRIGHT_GREEN "✓ " COLOR_RESET);
    } else {
        printf("[SUCCESS] ");
    }
    
    vprintf(format, args);
    printf("\n");
    
    va_end(args);
}

void print_error(const char *format, ...) {
    va_list args;
    va_start(args, format);
    
    if (g_state.colors) {
        fprintf(stderr, COLOR_BRIGHT_RED "✗ " COLOR_RESET);
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
    
    if (g_state.colors) {
        printf(COLOR_BRIGHT_YELLOW "⚠ " COLOR_RESET);
    } else {
        printf("[WARNING] ");
    }
    
    vprintf(format, args);
    printf("\n");
    
    va_end(args);
}

void print_info(const char *format, ...) {
    va_list args;
    va_start(args, format);
    
    if (g_state.colors) {
        printf(COLOR_BRIGHT_BLUE "ℹ " COLOR_RESET);
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
    
    if (g_state.colors) {
        printf(COLOR_MAGENTA "🐛 " COLOR_RESET);
    } else {
        printf("[DEBUG] ");
    }
    
    vprintf(format, args);
    printf("\n");
    
    va_end(args);
}

void print_banner() {
    if (!g_state.colors) {
        printf("CLOBES PRO ULTRA v%s\n", CLOBES_VERSION);
        return;
    }
    
    printf(COLOR_BRIGHT_CYAN STYLE_BOLD);
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║                                                              ║\n");
    printf("║   " COLOR_BRIGHT_WHITE "🚀 C L O B E S  P R O  U L T R A  v%s" COLOR_BRIGHT_CYAN "             ║\n", CLOBES_VERSION);
    printf("║   " COLOR_BRIGHT_GREEN "Alpine Thunder Edition • iSH Optimized" COLOR_BRIGHT_CYAN "           ║\n");
    printf("║                                                              ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n");
    printf(COLOR_RESET);
    printf("\n");
}

void print_progress_bar(long current, long total, const char *label) {
    int bar_width = 50;
    double percentage = (double)current / total;
    int pos = bar_width * percentage;
    
    printf("\r%s [", label);
    for (int i = 0; i < bar_width; ++i) {
        if (i < pos) printf("█");
        else if (i == pos) printf("▶");
        else printf("░");
    }
    printf("] %3.0f%% (%ld/%ld)", percentage * 100.0, current, total);
    
    if (current >= total) {
        printf("\n");
    }
    fflush(stdout);
}

void print_table_header(const char **headers, int count) {
    if (g_state.colors) {
        printf(COLOR_CYAN STYLE_BOLD);
    }
    
    printf("┌");
    for (int i = 0; i < count; i++) {
        printf("────────────────────");
        if (i < count - 1) printf("┬");
    }
    printf("┐\n");
    
    printf("│");
    for (int i = 0; i < count; i++) {
        printf(" %-18s │", headers[i]);
    }
    printf("\n");
    
    printf("├");
    for (int i = 0; i < count; i++) {
        printf("────────────────────");
        if (i < count - 1) printf("┼");
    }
    printf("┤\n");
    
    if (g_state.colors) {
        printf(COLOR_RESET);
    }
}

void print_table_row(const char **cells, int count) {
    printf("│");
    for (int i = 0; i < count; i++) {
        printf(" %-18s │", cells[i]);
    }
    printf("\n");
}

// ==================== UTILITY FUNCTIONS ====================

char* trim_string(char *str) {
    char *end;
    while (isspace((unsigned char)*str)) str++;
    if (*str == 0) return str;
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    end[1] = '\0';
    return str;
}

int file_exists(const char *path) {
    struct stat st;
    return (stat(path, &st) == 0 && S_ISREG(st.st_mode));
}

int dir_exists(const char *path) {
    struct stat st;
    return (stat(path, &st) == 0 && S_ISDIR(st.st_mode));
}

long get_file_size(const char *path) {
    struct stat st;
    if (stat(path, &st) == 0) {
        return st.st_size;
    }
    return -1;
}

char* get_local_ip() {
    static char ip[INET_ADDRSTRLEN] = "127.0.0.1";
    struct ifaddrs *ifaddr, *ifa;
    
    if (getifaddrs(&ifaddr) == -1) return ip;
    
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;
        
        if (ifa->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;
            char *current_ip = inet_ntoa(addr->sin_addr);
            
            if (strcmp(current_ip, "127.0.0.1") != 0) {
                strcpy(ip, current_ip);
                break;
            }
        }
    }
    
    freeifaddrs(ifaddr);
    return ip;
}

void generate_qr_code(const char *url) {
    printf(COLOR_CYAN "\n📱 QR Code Generation:\n" COLOR_RESET);
    printf("URL: %s\n", url);
    printf("Install qrencode: apk add qrencode\n");
}

void open_url(const char *url) {
    printf("🌐 Open this URL in your browser:\n");
    printf("%s\n", url);
}

int is_url(const char *str) {
    return strstr(str, "http://") == str || strstr(str, "https://") == str;
}

// ==================== CURL FUNCTIONS ====================

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

char* http_get(const char *url, int show_headers, int timeout) {
    CURL *curl = curl_easy_init();
    if (!curl) {
        print_error("Failed to initialize curl");
        return NULL;
    }
    
    MemoryStruct chunk = {NULL, 0};
    struct curl_slist *headers = NULL;
    
    if (show_headers) {
        headers = curl_slist_append(headers, "Accept: */*");
    }
    
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "CLOBES-PRO-ULTRA/5.0.0");
    
    CURLcode res = curl_easy_perform(curl);
    
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    
    g_state.total_requests++;
    
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    
    if (res != CURLE_OK) {
        print_error("Request failed: %s", curl_easy_strerror(res));
        free(chunk.memory);
        return NULL;
    }
    
    if (show_headers) {
        char *full_response = malloc(chunk.size + 100);
        if (full_response) {
            snprintf(full_response, chunk.size + 100, "HTTP %ld\n%s", http_code, chunk.memory);
            free(chunk.memory);
            return full_response;
        }
    }
    
    return chunk.memory;
}

char* http_post(const char *url, const char *data, const char *content_type) {
    CURL *curl = curl_easy_init();
    if (!curl) return NULL;
    
    MemoryStruct chunk = {NULL, 0};
    struct curl_slist *headers = NULL;
    
    headers = curl_slist_append(headers, "Accept: application/json");
    headers = curl_slist_append(headers, "User-Agent: CLOBES-PRO-ULTRA/5.0.0");
    
    char content_type_header[128];
    snprintf(content_type_header, sizeof(content_type_header), "Content-Type: %s", 
             content_type ? content_type : "application/json");
    headers = curl_slist_append(headers, content_type_header);
    
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    
    CURLcode res = curl_easy_perform(curl);
    
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    
    if (res != CURLE_OK) {
        free(chunk.memory);
        return NULL;
    }
    
    return chunk.memory;
}

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
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "CLOBES-PRO-ULTRA/5.0.0");
    
    print_info("Downloading: %s", url);
    
    if (show_progress) {
        print_progress_bar(0, 100, "Progress");
    }
    
    CURLcode res = curl_easy_perform(curl);
    fclose(fp);
    curl_easy_cleanup(curl);
    
    if (res == CURLE_OK) {
        struct stat st;
        if (stat(output, &st) == 0) {
            print_success("Download completed: %s (%.2f KB)", 
                         output, st.st_size / 1024.0);
        }
        return 0;
    } else {
        print_error("Download failed: %s", curl_easy_strerror(res));
        remove(output);
        return 1;
    }
}

// ==================== FILE OPERATIONS ====================

void file_info(const char *path) {
    struct stat st;
    
    if (stat(path, &st) != 0) {
        print_error("File not found: %s", path);
        return;
    }
    
    printf(COLOR_CYAN "📁 File Information:\n" COLOR_RESET);
    printf("Name:     %s\n", path);
    printf("Size:     %.2f KB (%.2f MB)\n", 
           st.st_size / 1024.0, 
           st.st_size / (1024.0 * 1024.0));
    
    printf("Type:     ");
    if (S_ISREG(st.st_mode)) printf("Regular file\n");
    else if (S_ISDIR(st.st_mode)) printf("Directory\n");
    else if (S_ISLNK(st.st_mode)) printf("Symbolic link\n");
    else printf("Special file\n");
    
    printf("Permissions: %o\n", st.st_mode & 0777);
    
    char time_buf[80];
    struct tm *tm_info = localtime(&st.st_mtime);
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);
    printf("Modified: %s\n", time_buf);
}

int find_files(const char *dir, const char *pattern, int recursive) {
    DIR *dp = opendir(dir);
    if (!dp) {
        print_error("Cannot open directory: %s", dir);
        return 0;
    }
    
    struct dirent *entry;
    int found = 0;
    
    while ((entry = readdir(dp)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        
        char full_path[1024];
        snprintf(full_path, sizeof(full_path), "%s/%s", dir, entry->d_name);
        
        struct stat st;
        stat(full_path, &st);
        
        // Check if matches pattern
        int match = 1;
        if (pattern && pattern[0] != '\0') {
            match = (strstr(entry->d_name, pattern) != NULL);
        }
        
        if (match) {
            printf("%s%s%s\n", 
                   S_ISDIR(st.st_mode) ? COLOR_BLUE : COLOR_GREEN,
                   entry->d_name,
                   COLOR_RESET);
            found++;
        }
        
        // Recursive search
        if (recursive && S_ISDIR(st.st_mode)) {
            find_files(full_path, pattern, recursive);
        }
    }
    
    closedir(dp);
    return found;
}

int calculate_hash(const char *path, const char *algorithm) {
    char cmd[1024];
    
    if (strcmp(algorithm, "md5") == 0) {
        snprintf(cmd, sizeof(cmd), "md5sum \"%s\" 2>/dev/null", path);
    } else if (strcmp(algorithm, "sha256") == 0) {
        snprintf(cmd, sizeof(cmd), "sha256sum \"%s\" 2>/dev/null", path);
    } else {
        print_error("Unsupported algorithm: %s", algorithm);
        return 1;
    }
    
    return system(cmd);
}

// ==================== SYSTEM OPERATIONS ====================

void system_info() {
    struct utsname uname_info;
    
    printf(COLOR_CYAN "💻 System Information:\n" COLOR_RESET);
    
    if (uname(&uname_info) == 0) {
        const char *headers[] = {"Field", "Value"};
        print_table_header(headers, 2);
        
        const char *row1[] = {"System", uname_info.sysname};
        print_table_row(row1, 2);
        
        const char *row2[] = {"Hostname", uname_info.nodename};
        print_table_row(row2, 2);
        
        const char *row3[] = {"Release", uname_info.release};
        print_table_row(row3, 2);
        
        const char *row4[] = {"Version", uname_info.version};
        print_table_row(row4, 2);
        
        const char *row5[] = {"Machine", uname_info.machine};
        print_table_row(row5, 2);
        
        printf("└────────────────────┴────────────────────┘\n");
    }
    
    struct sysinfo mem_info;
    if (sysinfo(&mem_info) == 0) {
        printf("\n" COLOR_CYAN "📊 Memory Information:\n" COLOR_RESET);
        printf("Total RAM:    %lu MB\n", mem_info.totalram / 1024 / 1024);
        printf("Free RAM:     %lu MB\n", mem_info.freeram / 1024 / 1024);
        printf("Used RAM:     %lu MB\n", 
               (mem_info.totalram - mem_info.freeram) / 1024 / 1024);
        
        double usage = ((mem_info.totalram - mem_info.freeram) * 100.0) / mem_info.totalram;
        printf("Usage:        %.1f%%\n", usage);
    }
    
    printf("\n" COLOR_CYAN "⏱️  Uptime:\n" COLOR_RESET);
    system("uptime -p 2>/dev/null || uptime");
}

void process_list(int detailed) {
    printf(COLOR_CYAN "📋 Running Processes:\n" COLOR_RESET);
    
    if (detailed) {
        system("ps aux --sort=-%cpu | head -20");
    } else {
        system("ps -ef --no-headers | wc -l | xargs echo 'Total processes:'");
        system("ps aux --sort=-%cpu | head -5");
    }
}

void disk_usage() {
    printf(COLOR_CYAN "💾 Disk Usage:\n" COLOR_RESET);
    system("df -h");
}

void memory_info() {
    printf(COLOR_CYAN "🧠 Memory Usage:\n" COLOR_RESET);
    system("free -h");
    
    printf("\n" COLOR_CYAN "📈 Top Memory Consumers:\n" COLOR_RESET);
    system("ps aux --sort=-%mem | head -10 | awk '{print $1, $4, $11}' | column -t");
}

void network_info() {
    printf(COLOR_CYAN "🌐 Network Information:\n" COLOR_RESET);
    
    char *local_ip = get_local_ip();
    printf("Local IP:    %s\n", local_ip);
    
    printf("Interfaces:\n");
    system("ip addr show 2>/dev/null || ifconfig 2>/dev/null | grep -E '^[a-zA-Z]|inet '");
}

void cpu_info() {
    printf(COLOR_CYAN "⚡ CPU Information:\n" COLOR_RESET);
    
    FILE *fp = fopen("/proc/cpuinfo", "r");
    if (fp) {
        char line[256];
        int cores = 0;
        
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, "processor")) cores++;
            if (strstr(line, "model name")) {
                char *model = strchr(line, ':');
                if (model) {
                    printf("Model:      %s", model + 2);
                    break;
                }
            }
        }
        fclose(fp);
        printf("Cores:      %d\n", cores);
    }
    
    printf("Load Average: ");
    system("cat /proc/loadavg 2>/dev/null || echo 'N/A'");
}

// ==================== CRYPTO OPERATIONS ====================

char* base64_encode(const char *input) {
    size_t len = strlen(input);
    size_t out_len = 4 * ((len + 2) / 3);
    char *encoded = malloc(out_len + 1);
    
    if (!encoded) return NULL;
    
    for (size_t i = 0, j = 0; i < len;) {
        uint32_t octet_a = i < len ? (unsigned char)input[i++] : 0;
        uint32_t octet_b = i < len ? (unsigned char)input[i++] : 0;
        uint32_t octet_c = i < len ? (unsigned char)input[i++] : 0;
        
        uint32_t triple = (octet_a << 16) | (octet_b << 8) | octet_c;
        
        encoded[j++] = base64_table[(triple >> 18) & 0x3F];
        encoded[j++] = base64_table[(triple >> 12) & 0x3F];
        encoded[j++] = base64_table[(triple >> 6) & 0x3F];
        encoded[j++] = base64_table[triple & 0x3F];
    }
    
    for (size_t i = 0; i < (3 - len % 3) % 3; i++) {
        encoded[out_len - 1 - i] = '=';
    }
    
    encoded[out_len] = '\0';
    return encoded;
}

char* base64_decode(const char *input) {
    size_t len = strlen(input);
    if (len % 4 != 0) return NULL;
    
    size_t out_len = len / 4 * 3;
    if (input[len - 1] == '=') out_len--;
    if (input[len - 2] == '=') out_len--;
    
    char *decoded = malloc(out_len + 1);
    if (!decoded) return NULL;
    
    for (size_t i = 0, j = 0; i < len;) {
        uint32_t sextet_a = input[i] == '=' ? 0 : strchr(base64_table, input[i]) - base64_table; i++;
        uint32_t sextet_b = input[i] == '=' ? 0 : strchr(base64_table, input[i]) - base64_table; i++;
        uint32_t sextet_c = input[i] == '=' ? 0 : strchr(base64_table, input[i]) - base64_table; i++;
        uint32_t sextet_d = input[i] == '=' ? 0 : strchr(base64_table, input[i]) - base64_table; i++;
        
        uint32_t triple = (sextet_a << 18) | (sextet_b << 12) | (sextet_c << 6) | sextet_d;
        
        if (j < out_len) decoded[j++] = (triple >> 16) & 0xFF;
        if (j < out_len) decoded[j++] = (triple >> 8) & 0xFF;
        if (j < out_len) decoded[j++] = triple & 0xFF;
    }
    
    decoded[out_len] = '\0';
    return decoded;
}

char* md5_hash(const char *input) {
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "echo -n '%s' | md5sum | awk '{print $1}'", input);
    
    FILE *fp = popen(cmd, "r");
    if (!fp) return NULL;
    
    static char hash[33];
    if (fgets(hash, sizeof(hash), fp)) {
        hash[strcspn(hash, "\n")] = 0;
    }
    
    pclose(fp);
    return hash;
}

char* sha256_hash(const char *input) {
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "echo -n '%s' | sha256sum | awk '{print $1}'", input);
    
    FILE *fp = popen(cmd, "r");
    if (!fp) return NULL;
    
    static char hash[65];
    if (fgets(hash, sizeof(hash), fp)) {
        hash[strcspn(hash, "\n")] = 0;
    }
    
    pclose(fp);
    return hash;
}

void generate_password(int length, int use_symbols) {
    if (length < 8) length = 8;
    if (length > 64) length = 64;
    
    printf(COLOR_CYAN "🔐 Generated Password:\n" COLOR_RESET);
    
    char cmd[1024];
    if (use_symbols) {
        snprintf(cmd, sizeof(cmd), 
                "tr -dc 'A-Za-z0-9!@#$%%^&*()_+-=[]{}|;:,.<>?' < /dev/urandom | head -c %d && echo", 
                length);
    } else {
        snprintf(cmd, sizeof(cmd), 
                "tr -dc 'A-Za-z0-9' < /dev/urandom | head -c %d && echo", 
                length);
    }
    
    system(cmd);
}

// ==================== SERVER OPERATIONS ====================

static const char* get_mime_type(const char *filename) {
    const char *dot = strrchr(filename, '.');
    if (!dot) return "text/plain; charset=utf-8";
    
    for (size_t i = 0; i < sizeof(mime_types) / sizeof(MimeType); i++) {
        if (strcasecmp(dot, mime_types[i].extension) == 0) {
            return mime_types[i].mime_type;
        }
    }
    return "application/octet-stream";
}

static void handle_client(int client_socket, const char *web_root) {
    char buffer[BUFFER_SIZE];
    int bytes_read = read(client_socket, buffer, sizeof(buffer) - 1);
    
    if (bytes_read > 0) {
        buffer[bytes_read] = '\0';
        
        // Parse request
        char method[16], path[256], protocol[16];
        sscanf(buffer, "%s %s %s", method, path, protocol);
        
        // Log request
        printf("%s - %s %s\n", 
               inet_ntoa(((struct sockaddr_in*)&client_socket)->sin_addr),
               method, path);
        
        // Prevent directory traversal
        if (strstr(path, "..")) {
            const char *response = "HTTP/1.1 403 Forbidden\r\n\r\n<h1>403 Forbidden</h1>";
            write(client_socket, response, strlen(response));
            close(client_socket);
            return;
        }
        
        // Default to index.html
        if (strcmp(path, "/") == 0) {
            strcpy(path, "/index.html");
        }
        
        // Build file path
        char file_path[512];
        snprintf(file_path, sizeof(file_path), "%s%s", web_root, path);
        
        // Check if file exists
        if (file_exists(file_path)) {
            FILE *file = fopen(file_path, "rb");
            if (file) {
                fseek(file, 0, SEEK_END);
                long file_size = ftell(file);
                fseek(file, 0, SEEK_SET);
                
                const char *mime_type = get_mime_type(file_path);
                
                // Send headers
                char headers[1024];
                snprintf(headers, sizeof(headers),
                        "HTTP/1.1 200 OK\r\n"
                        "Content-Type: %s\r\n"
                        "Content-Length: %ld\r\n"
                        "Connection: close\r\n"
                        "Server: CLOBES-PRO-ULTRA/5.0.0\r\n\r\n",
                        mime_type, file_size);
                
                write(client_socket, headers, strlen(headers));
                
                // Send file
                char file_buffer[BUFFER_SIZE];
                size_t bytes;
                while ((bytes = fread(file_buffer, 1, sizeof(file_buffer), file)) > 0) {
                    write(client_socket, file_buffer, bytes);
                }
                
                fclose(file);
            } else {
                const char *response = "HTTP/1.1 500 Internal Server Error\r\n\r\n<h1>500 Error</h1>";
                write(client_socket, response, strlen(response));
            }
        } else {
            const char *response = "HTTP/1.1 404 Not Found\r\n\r\n<h1>404 Not Found</h1>";
            write(client_socket, response, strlen(response));
        }
    }
    
    close(client_socket);
}

static void* server_thread_func(void *arg) {
    ServerSession *session = (ServerSession *)arg;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    
    // Create socket
    if ((session->server_socket = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        print_error("Socket creation failed");
        return NULL;
    }
    
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(session->port);
    
    // Bind socket
    if (bind(session->server_socket, (struct sockaddr *)&address, sizeof(address)) < 0) {
        print_error("Bind failed on port %d", session->port);
        close(session->server_socket);
        return NULL;
    }
    
    // Listen
    if (listen(session->server_socket, MAX_CLIENTS) < 0) {
        print_error("Listen failed");
        close(session->server_socket);
        return NULL;
    }
    
    print_success("HTTP Server started on port %d", session->port);
    print_info("Web root: %s", session->web_root);
    
    char local_url[256];
    snprintf(local_url, sizeof(local_url), "http://localhost:%d", session->port);
    print_info("Local URL: %s", local_url);
    
    char network_url[256];
    snprintf(network_url, sizeof(network_url), "http://%s:%d", get_local_ip(), session->port);
    print_info("Network URL: %s", network_url);
    
    printf("\n" COLOR_CYAN "Press Ctrl+C to stop the server\n" COLOR_RESET);
    
    // Main server loop
    while (session->running) {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(session->server_socket, &read_fds);
        
        struct timeval tv = {1, 0};
        int activity = select(session->server_socket + 1, &read_fds, NULL, NULL, &tv);
        
        if (activity > 0 && FD_ISSET(session->server_socket, &read_fds)) {
            int client_socket = accept(session->server_socket, 
                                      (struct sockaddr *)&address, 
                                      (socklen_t*)&addrlen);
            
            if (client_socket >= 0) {
                // Handle client in same thread for simplicity
                handle_client(client_socket, session->web_root);
            }
        }
    }
    
    close(session->server_socket);
    return NULL;
}

int start_http_server(int port, const char *web_root, int enable_listing) {
    // Create web root if it doesn't exist
    if (!dir_exists(web_root)) {
        mkdir(web_root, 0755);
        
        // Create default index.html
        char index_path[512];
        snprintf(index_path, sizeof(index_path), "%s/index.html", web_root);
        FILE *fp = fopen(index_path, "w");
        if (fp) {
            fprintf(fp, "<!DOCTYPE html>\n");
            fprintf(fp, "<html>\n");
            fprintf(fp, "<head>\n");
            fprintf(fp, "    <title>CLOBES PRO ULTRA Server</title>\n");
            fprintf(fp, "    <style>\n");
            fprintf(fp, "        body { font-family: Arial, sans-serif; margin: 40px; }\n");
            fprintf(fp, "        .container { max-width: 800px; margin: 0 auto; }\n");
            fprintf(fp, "        h1 { color: #0066cc; }\n");
            fprintf(fp, "    </style>\n");
            fprintf(fp, "</head>\n");
            fprintf(fp, "<body>\n");
            fprintf(fp, "    <div class=\"container\">\n");
            fprintf(fp, "        <h1>🚀 CLOBES PRO ULTRA Server v%s</h1>\n", CLOBES_VERSION);
            fprintf(fp, "        <p>Server is running successfully on Alpine iSH!</p>\n");
            fprintf(fp, "        <p>Port: %d</p>\n", port);
            fprintf(fp, "        <p>Web Root: %s</p>\n", web_root);
            fprintf(fp, "    </div>\n");
            fprintf(fp, "</body>\n");
            fprintf(fp, "</html>\n");
            fclose(fp);
        }
    }
    
    // Create server session
    g_server_session = malloc(sizeof(ServerSession));
    g_server_session->port = port;
    g_server_session->running = 1;
    strncpy(g_server_session->web_root, web_root, sizeof(g_server_session->web_root) - 1);
    g_state.server_session = g_server_session;
    
    // Start server thread
    if (pthread_create(&g_server_session->thread, NULL, server_thread_func, g_server_session) != 0) {
        print_error("Failed to start server thread");
        free(g_server_session);
        g_server_session = NULL;
        return 0;
    }
    
    return 1;
}

void stop_http_server() {
    if (g_server_session) {
        g_server_session->running = 0;
        pthread_join(g_server_session->thread, NULL);
        free(g_server_session);
        g_server_session = NULL;
        g_state.server_session = NULL;
        print_success("Server stopped");
    }
}

void server_status() {
    if (g_server_session) {
        printf(COLOR_GREEN "✅ Server is RUNNING\n" COLOR_RESET);
        printf("Port:     %d\n", g_server_session->port);
        printf("Web Root: %s\n", g_server_session->web_root);
        printf("URL:      http://localhost:%d\n", g_server_session->port);
    } else {
        printf(COLOR_RED "❌ Server is STOPPED\n" COLOR_RESET);
    }
}

// ==================== COMMAND HANDLERS ====================

int cmd_version(int argc, char **argv) {
    (void)argc; (void)argv;
    
    print_banner();
    
    printf("Version:       %s \"%s\"\n", CLOBES_VERSION, CLOBES_CODENAME);
    printf("Build:         %s\n", CLOBES_BUILD);
    printf("Platform:      Alpine Linux iSH\n");
    printf("Requests:      %d\n", g_state.total_requests);
    
    struct utsname uname_info;
    if (uname(&uname_info) == 0) {
        printf("System:        %s %s %s\n", 
               uname_info.sysname, uname_info.release, uname_info.machine);
    }
    
    return 0;
}

int cmd_help(int argc, char **argv) {
    if (argc > 2) {
        for (int i = 0; i < g_command_count; i++) {
            if (strcmp(g_commands[i].name, argv[2]) == 0) {
                printf(COLOR_CYAN STYLE_BOLD "%s\n" COLOR_RESET STYLE_BOLD, g_commands[i].name);
                printf("%s\n", g_commands[i].description);
                printf("\nUsage: %s\n", g_commands[i].usage);
                return 0;
            }
        }
        print_error("Command not found: %s", argv[2]);
        return 1;
    }
    
    print_banner();
    
    printf(COLOR_CYAN "📦 Available Commands:\n\n" COLOR_RESET);
    
    for (int i = 0; i < g_command_count; i++) {
        printf(COLOR_GREEN "  %-15s" COLOR_RESET " - %s\n", 
               g_commands[i].name, 
               g_commands[i].description);
    }
    
    printf("\n" COLOR_CYAN "🚀 Quick Start:\n" COLOR_RESET);
    printf("  clobes version                    # Show version\n");
    printf("  clobes network get <url>          # HTTP request\n");
    printf("  clobes server start --port 8080   # Start web server\n");
    printf("  clobes system info                # System information\n");
    printf("  clobes file info <path>           # File information\n");
    printf("  clobes crypto encode <text>       # Base64 encode\n");
    printf("\n" COLOR_CYAN "💡 Tips:\n" COLOR_RESET);
    printf("  Use -i for interactive mode\n");
    printf("  Use --no-color to disable colors\n");
    printf("  Use -v for verbose output\n");
    
    return 0;
}

int cmd_network(int argc, char **argv) {
    if (argc < 3) {
        printf(COLOR_CYAN "🌐 NETWORK COMMANDS\n" COLOR_RESET);
        printf("══════════════════════════════════════════\n\n");
        
        printf("  get <url>              - HTTP GET request\n");
        printf("  post <url> <data>      - HTTP POST request\n");
        printf("  download <url> <file>  - Download file\n");
        printf("  headers <url>          - Show response headers\n");
        printf("  myip                   - Show public IP\n");
        printf("  scan <host> <port>     - Port scan\n");
        printf("\nOptions:\n");
        printf("  -t, --timeout <sec>    - Timeout in seconds\n");
        printf("  -k, --insecure         - Disable SSL verification\n");
        printf("\n");
        return 0;
    }
    
    if (strcmp(argv[2], "get") == 0 && argc >= 4) {
        int timeout = 30;
        for (int i = 4; i < argc; i++) {
            if ((strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--timeout") == 0) && i + 1 < argc) {
                timeout = atoi(argv[++i]);
            }
        }
        
        char *response = http_get(argv[3], 0, timeout);
        if (response) {
            printf("%s\n", response);
            free(response);
            return 0;
        } else {
            print_error("Failed to fetch URL");
            return 1;
        }
    }
    else if (strcmp(argv[2], "headers") == 0 && argc >= 4) {
        char *response = http_get(argv[3], 1, 30);
        if (response) {
            printf("%s\n", response);
            free(response);
            return 0;
        } else {
            print_error("Failed to fetch headers");
            return 1;
        }
    }
    else if (strcmp(argv[2], "download") == 0 && argc >= 5) {
        return http_download(argv[3], argv[4], 1);
    }
    else if (strcmp(argv[2], "myip") == 0) {
        char *response = http_get("https://api.ipify.org", 0, 10);
        if (response) {
            printf("Public IP: %s\n", response);
            free(response);
            return 0;
        } else {
            print_error("Failed to get IP address");
            return 1;
        }
    }
    else if (strcmp(argv[2], "post") == 0 && argc >= 5) {
        char *response = http_post(argv[3], argv[4], "application/json");
        if (response) {
            printf("%s\n", response);
            free(response);
            return 0;
        } else {
            print_error("Failed to POST to URL");
            return 1;
        }
    }
    else if (strcmp(argv[2], "scan") == 0 && argc >= 5) {
        printf("Port scanning %s:%s...\n", argv[3], argv[4]);
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "nc -zv %s %s 2>&1", argv[3], argv[4]);
        return system(cmd);
    }
    
    print_error("Unknown network command: %s", argv[2]);
    return 1;
}

int cmd_system(int argc, char **argv) {
    if (argc < 3) {
        printf(COLOR_CYAN "💻 SYSTEM COMMANDS\n" COLOR_RESET);
        printf("══════════════════════════════════════════\n\n");
        
        printf("  info              - Detailed system information\n");
        printf("  processes         - List running processes\n");
        printf("  disks             - Disk usage information\n");
        printf("  memory            - Memory usage information\n");
        printf("  network           - Network information\n");
        printf("  cpu               - CPU information\n");
        printf("  users             - List logged in users\n");
        printf("  uptime            - System uptime\n");
        printf("\nOptions:\n");
        printf("  -d, --detailed    - Show detailed output\n");
        printf("\n");
        return 0;
    }
    
    int detailed = 0;
    for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--detailed") == 0) {
            detailed = 1;
        }
    }
    
    if (strcmp(argv[2], "info") == 0) {
        system_info();
        return 0;
    }
    else if (strcmp(argv[2], "processes") == 0) {
        process_list(detailed);
        return 0;
    }
    else if (strcmp(argv[2], "disks") == 0) {
        disk_usage();
        return 0;
    }
    else if (strcmp(argv[2], "memory") == 0) {
        memory_info();
        return 0;
    }
    else if (strcmp(argv[2], "network") == 0) {
        network_info();
        return 0;
    }
    else if (strcmp(argv[2], "cpu") == 0) {
        cpu_info();
        return 0;
    }
    else if (strcmp(argv[2], "users") == 0) {
        system("who");
        return 0;
    }
    else if (strcmp(argv[2], "uptime") == 0) {
        system("uptime");
        return 0;
    }
    
    print_error("Unknown system command: %s", argv[2]);
    return 1;
}

int cmd_file(int argc, char **argv) {
    if (argc < 3) {
        printf(COLOR_CYAN "📁 FILE OPERATIONS\n" COLOR_RESET);
        printf("══════════════════════════════════════════\n\n");
        
        printf("  info <path>          - File information\n");
        printf("  find <dir> <pattern> - Find files\n");
        printf("  hash <file> <algo>   - Calculate hash (md5, sha256)\n");
        printf("  size <path>          - Get file/directory size\n");
        printf("  compare <f1> <f2>    - Compare two files\n");
        printf("\nOptions:\n");
        printf("  -r, --recursive      - Recursive search\n");
        printf("\n");
        return 0;
    }
    
    if (strcmp(argv[2], "info") == 0 && argc >= 4) {
        file_info(argv[3]);
        return 0;
    }
    else if (strcmp(argv[2], "find") == 0 && argc >= 5) {
        int recursive = 0;
        for (int i = 5; i < argc; i++) {
            if (strcmp(argv[i], "-r") == 0 || strcmp(argv[i], "--recursive") == 0) {
                recursive = 1;
            }
        }
        
        int found = find_files(argv[3], argv[4], recursive);
        printf("\nFound %d file(s)\n", found);
        return 0;
    }
    else if (strcmp(argv[2], "hash") == 0 && argc >= 5) {
        return calculate_hash(argv[3], argv[4]);
    }
    else if (strcmp(argv[2], "size") == 0 && argc >= 4) {
        struct stat st;
        if (stat(argv[3], &st) == 0) {
            if (S_ISDIR(st.st_mode)) {
                char cmd[256];
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
    else if (strcmp(argv[2], "compare") == 0 && argc >= 5) {
        char cmd[512];
        snprintf(cmd, sizeof(cmd), "cmp \"%s\" \"%s\" 2>/dev/null || diff \"%s\" \"%s\"", 
                argv[3], argv[4], argv[3], argv[4]);
        return system(cmd);
    }
    
    print_error("Unknown file command: %s", argv[2]);
    return 1;
}

int cmd_crypto(int argc, char **argv) {
    if (argc < 3) {
        printf(COLOR_CYAN "🔐 CRYPTO COMMANDS\n" COLOR_RESET);
        printf("══════════════════════════════════════════\n\n");
        
        printf("  encode <text>         - Base64 encode\n");
        printf("  decode <text>         - Base64 decode\n");
        printf("  hash <text> <algo>    - Hash text (md5, sha256)\n");
        printf("  password <len>        - Generate secure password\n");
        printf("\n");
        return 0;
    }
    
    if (strcmp(argv[2], "encode") == 0 && argc >= 4) {
        char *encoded = base64_encode(argv[3]);
        if (encoded) {
            printf("%s\n", encoded);
            free(encoded);
        }
        return 0;
    }
    else if (strcmp(argv[2], "decode") == 0 && argc >= 4) {
        char *decoded = base64_decode(argv[3]);
        if (decoded) {
            printf("%s\n", decoded);
            free(decoded);
        }
        return 0;
    }
    else if (strcmp(argv[2], "hash") == 0 && argc >= 5) {
        if (strcmp(argv[4], "md5") == 0) {
            char *hash = md5_hash(argv[3]);
            printf("MD5: %s\n", hash);
        } else if (strcmp(argv[4], "sha256") == 0) {
            char *hash = sha256_hash(argv[3]);
            printf("SHA256: %s\n", hash);
        } else {
            print_error("Unsupported algorithm: %s", argv[4]);
            return 1;
        }
        return 0;
    }
    else if (strcmp(argv[2], "password") == 0) {
        int length = 16;
        int symbols = 1;
        
        if (argc >= 4) length = atoi(argv[3]);
        if (argc >= 5 && strcmp(argv[4], "--no-symbols") == 0) symbols = 0;
        
        generate_password(length, symbols);
        return 0;
    }
    
    print_error("Unknown crypto command: %s", argv[2]);
    return 1;
}

int cmd_server(int argc, char **argv) {
    if (argc < 3) {
        printf(COLOR_CYAN "🌐 HTTP SERVER COMMANDS\n" COLOR_RESET);
        printf("══════════════════════════════════════════\n\n");
        
        printf("  start                 - Start HTTP server\n");
        printf("  stop                  - Stop HTTP server\n");
        printf("  status                - Show server status\n");
        printf("\nOptions for start:\n");
        printf("  --port <number>       - Port number (default: 8080)\n");
        printf("  --root <path>         - Web root directory (default: ./www)\n");
        printf("  --qr                  - Generate QR code for URL\n");
        printf("  --open                - Show URL to open\n");
        printf("\n");
        return 0;
    }
    
    if (strcmp(argv[2], "start") == 0) {
        int port = 8080;
        char web_root[256] = "./www";
        int qr = 0, open_url = 0;
        
        for (int i = 3; i < argc; i++) {
            if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
                port = atoi(argv[++i]);
            } else if (strcmp(argv[i], "--root") == 0 && i + 1 < argc) {
                strncpy(web_root, argv[++i], sizeof(web_root) - 1);
            } else if (strcmp(argv[i], "--qr") == 0) {
                qr = 1;
            } else if (strcmp(argv[i], "--open") == 0) {
                open_url = 1;
            }
        }
        
        if (port < 1 || port > 65535) {
            print_error("Invalid port number: %d", port);
            return 1;
        }
        
        print_info("Starting HTTP server...");
        
        if (start_http_server(port, web_root, 1)) {
            if (qr) {
                char url[256];
                snprintf(url, sizeof(url), "http://%s:%d", get_local_ip(), port);
                generate_qr_code(url);
            }
            
            if (open_url) {
                char url[256];
                snprintf(url, sizeof(url), "http://localhost:%d", port);
                open_url(url);
            }
            
            // Wait for Ctrl+C
            signal(SIGINT, (void (*)(int))stop_http_server);
            
            while (g_server_session && g_server_session->running) {
                sleep(1);
            }
            
            return 0;
        } else {
            print_error("Failed to start server");
            return 1;
        }
    }
    else if (strcmp(argv[2], "stop") == 0) {
        stop_http_server();
        return 0;
    }
    else if (strcmp(argv[2], "status") == 0) {
        server_status();
        return 0;
    }
    
    print_error("Unknown server command: %s", argv[2]);
    return 1;
}

int cmd_dev(int argc, char **argv) {
    (void)argc; (void)argv;
    
    printf(COLOR_CYAN "👨‍💻 DEVELOPMENT TOOLS\n" COLOR_RESET);
    printf("══════════════════════════════════════════\n\n");
    
    printf("  Coming soon in next version!\n");
    printf("  - Code compilation\n");
    printf("  - API testing\n");
    printf("  - Web development tools\n");
    
    return 0;
}

int cmd_web(int argc, char **argv) {
    (void)argc; (void)argv;
    
    printf(COLOR_CYAN "🌐 WEB DEVELOPMENT\n" COLOR_RESET);
    printf("══════════════════════════════════════════\n\n");
    
    printf("  Available soon:\n");
    printf("  - HTML/CSS/JS minification\n");
    printf("  - Web asset optimization\n");
    printf("  - API client generator\n");
    
    return 0;
}

// ==================== INTERACTIVE MODE ====================

void print_welcome() {
    print_banner();
    
    printf(COLOR_CYAN "Welcome to CLOBES PRO ULTRA Interactive Mode!\n\n" COLOR_RESET);
    printf("Type 'help' for commands, 'exit' to quit\n");
    printf("Use 'clear' to clear screen\n\n");
}

int interactive_mode() {
    print_welcome();
    
    char input[1024];
    while (1) {
        if (g_state.colors) {
            printf(COLOR_GREEN "clobes> " COLOR_RESET);
        } else {
            printf("clobes> ");
        }
        
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
            print_welcome();
            continue;
        }
        
        if (strcmp(input, "help") == 0) {
            cmd_help(1, NULL);
            continue;
        }
        
        // Parse command
        char *argv[20];
        int argc = 0;
        char *token = strtok(input, " ");
        
        while (token && argc < 20) {
            argv[argc++] = token;
            token = strtok(NULL, " ");
        }
        
        if (argc > 0) {
            Command *cmd = find_command(argv[0]);
            if (cmd) {
                cmd->handler(argc, argv);
            } else {
                printf("Unknown command: %s\n", argv[0]);
            }
        }
    }
    
    return 0;
}

// ==================== COMMAND REGISTRY ====================

void register_commands() {
    // Core commands
    g_commands[g_command_count++] = (Command){
        .name = "version",
        .description = "Show version information",
        .usage = "clobes version",
        .handler = cmd_version
    };
    
    g_commands[g_command_count++] = (Command){
        .name = "help",
        .description = "Show help information",
        .usage = "clobes help [command]",
        .handler = cmd_help,
        .aliases = {{"h"}, {"--help"}},
        .alias_count = 2
    };
    
    // Network commands
    g_commands[g_command_count++] = (Command){
        .name = "network",
        .description = "Network operations",
        .usage = "clobes network [command] [args]",
        .handler = cmd_network,
        .aliases = {{"net"}},
        .alias_count = 1
    };
    
    // System commands
    g_commands[g_command_count++] = (Command){
        .name = "system",
        .description = "System operations",
        .usage = "clobes system [command] [args]",
        .handler = cmd_system,
        .aliases = {{"sys"}},
        .alias_count = 1
    };
    
    // File commands
    g_commands[g_command_count++] = (Command){
        .name = "file",
        .description = "File operations",
        .usage = "clobes file [command] [args]",
        .handler = cmd_file,
        .aliases = {{"files"}},
        .alias_count = 1
    };
    
    // Crypto commands
    g_commands[g_command_count++] = (Command){
        .name = "crypto",
        .description = "Cryptography operations",
        .usage = "clobes crypto [command] [args]",
        .handler = cmd_crypto
    };
    
    // Server commands
    g_commands[g_command_count++] = (Command){
        .name = "server",
        .description = "HTTP server operations",
        .usage = "clobes server [start|stop|status]",
        .handler = cmd_server
    };
    
    // Dev commands
    g_commands[g_command_count++] = (Command){
        .name = "dev",
        .description = "Development tools",
        .usage = "clobes dev",
        .handler = cmd_dev
    };
    
    // Web commands
    g_commands[g_command_count++] = (Command){
        .name = "web",
        .description = "Web development tools",
        .usage = "clobes web",
        .handler = cmd_web
    };
}

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

// ==================== MAIN FUNCTION ====================

int main(int argc, char **argv) {
    // Parse global flags
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--no-color") == 0) {
            g_state.colors = 0;
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            g_state.debug_mode = 1;
        }
    }
    
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
    
    // No command provided
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
    printf("\nUse 'clobes help' to see available commands\n");
    printf("Or try interactive mode: 'clobes -i'\n");
    
    curl_global_cleanup();
    return 1;
}
