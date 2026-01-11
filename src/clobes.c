// CLOBES PRO v4.1.0 - Ultimate CLI Toolkit with HTTP Server
#include "clobes.h"
#include <stdarg.h>
#include <dirent.h>
#include <sys/select.h>

// Global state
GlobalState g_state = {
    .config = {
        .timeout = 30,
        .cache_enabled = 1,
        .user_agent = "CLOBES-PRO/4.1.0",
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
    .log_level = LOG_INFO,
    .server_session = NULL
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

// MIME types database
static const MimeType mime_types[] = {
    {".html", "text/html; charset=utf-8"},
    {".htm", "text/html; charset=utf-8"},
    {".css", "text/css; charset=utf-8"},
    {".js", "application/javascript; charset=utf-8"},
    {".json", "application/json; charset=utf-8"},
    {".txt", "text/plain; charset=utf-8"},
    {".md", "text/markdown; charset=utf-8"},
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
    {"", "application/octet-stream"}
};

// Server session
static ServerSession *g_server_session = NULL;

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

// Base64 decode (version simplifiée pour Alpine)
char* base64_decode(const char *input, size_t *output_length) {
    size_t input_length = strlen(input);
    if (input_length % 4 != 0) return NULL;
    
    size_t output_len = input_length / 4 * 3;
    if (input[input_length - 1] == '=') output_len--;
    if (input[input_length - 2] == '=') output_len--;
    
    char *decoded = malloc(output_len + 1);
    if (!decoded) return NULL;
    
    size_t i, j;
    for (i = 0, j = 0; i < input_length;) {
        uint32_t sextet_a = input[i] == '=' ? 0 : strchr(base64_table, input[i]) - base64_table; i++;
        uint32_t sextet_b = input[i] == '=' ? 0 : strchr(base64_table, input[i]) - base64_table; i++;
        uint32_t sextet_c = input[i] == '=' ? 0 : strchr(base64_table, input[i]) - base64_table; i++;
        uint32_t sextet_d = input[i] == '=' ? 0 : strchr(base64_table, input[i]) - base64_table; i++;
        
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

// strcasecmp alternative pour Alpine
static int strcasecmp_alpine(const char *s1, const char *s2) {
    while (*s1 && *s2) {
        int diff = tolower((unsigned char)*s1) - tolower((unsigned char)*s2);
        if (diff != 0) return diff;
        s1++;
        s2++;
    }
    return tolower((unsigned char)*s1) - tolower((unsigned char)*s2);
}

// strtok_r alternative pour Alpine
static char* strtok_r_alpine(char *str, const char *delim, char **saveptr) {
    char *end;
    if (str == NULL) str = *saveptr;
    if (*str == '\0') {
        *saveptr = str;
        return NULL;
    }
    
    // Skip leading delimiters
    str += strspn(str, delim);
    if (*str == '\0') {
        *saveptr = str;
        return NULL;
    }
    
    // Find end of token
    end = str + strcspn(str, delim);
    if (*end == '\0') {
        *saveptr = end;
        return str;
    }
    
    // Terminate token and set saveptr
    *end = '\0';
    *saveptr = end + 1;
    return str;
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
    printf("║   " COLOR_BRIGHT_GREEN "200+ commands • HTTP Server • PHP Support" COLOR_CYAN "       ║\n");
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

// Check if file exists
int file_exists(const char *path) {
    struct stat st;
    return (stat(path, &st) == 0 && S_ISREG(st.st_mode));
}

// Check if directory exists
int dir_exists(const char *path) {
    struct stat st;
    return (stat(path, &st) == 0 && S_ISDIR(st.st_mode));
}

// Get file size
long get_file_size(const char *path) {
    struct stat st;
    if (stat(path, &st) == 0) {
        return st.st_size;
    }
    return -1;
}

// Get MIME type from extension
const char* get_mime_type(const char *filename) {
    const char *dot = strrchr(filename, '.');
    if (!dot) return "text/plain; charset=utf-8";
    
    for (size_t i = 0; i < sizeof(mime_types) / sizeof(MimeType); i++) {
        if (strcasecmp_alpine(dot, mime_types[i].extension) == 0) {
            return mime_types[i].mime_type;
        }
    }
    return "application/octet-stream";
}

// URL decode
void url_decode(char *dst, const char *src) {
    char a, b;
    while (*src) {
        if ((*src == '%') && ((a = src[1]) && (b = src[2])) && (isxdigit(a) && isxdigit(b))) {
            if (a >= 'a') a -= 'a' - 'A';
            if (a >= 'A') a -= ('A' - 10);
            else a -= '0';
            if (b >= 'a') b -= 'a' - 'A';
            if (b >= 'A') b -= ('A' - 10);
            else b -= '0';
            *dst++ = 16 * a + b;
            src += 3;
        } else if (*src == '+') {
            *dst++ = ' ';
            src++;
        } else {
            *dst++ = *src++;
        }
    }
    *dst = '\0';
}

// Get local IP address
char* get_local_ip() {
    static char ip[INET_ADDRSTRLEN] = "127.0.0.1";
    struct ifaddrs *ifaddr, *ifa;
    
    if (getifaddrs(&ifaddr) == -1) return ip;
    
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;
        
        // Check for IPv4 interface
        if (ifa->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;
            char *current_ip = inet_ntoa(addr->sin_addr);
            
            // Skip localhost and docker/virtual interfaces
            if (strcmp(current_ip, "127.0.0.1") != 0) {
                strcpy(ip, current_ip);
                break;
            }
        }
    }
    
    freeifaddrs(ifaddr);
    return ip;
}

// Generate QR code using qrencode if available
void generate_qr_code(const char *url) {
    printf(COLOR_CYAN "\n📱 QR Code pour l'URL:\n" COLOR_RESET);
    
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), 
             "which qrencode > /dev/null 2>&1 && "
             "qrencode -t UTF8 '%s' 2>/dev/null || "
             "echo 'Pour générer un QR code, installez qrencode:'\n"
             "echo '  Alpine: apk add qrencode'\n"
             "echo '  URL: %s'", 
             url, url);
    
    int result = system(cmd);
    if (result != 0) {
        printf("URL: %s\n", url);
    }
}

// Open browser with URL (simplifié pour iSH)
void open_browser(const char *url) {
    printf("URL: %s\n", url);
    printf("Ouvrez cette URL dans votre navigateur\n");
}

// Find index file in directory
char* find_index_file(const char *dir_path, struct ServerConfig *config) {
    static char index_path[512];
    
    for (int i = 0; i < 5 && config->index_files[i][0] != '\0'; i++) {
        snprintf(index_path, sizeof(index_path), "%s/%s", 
                dir_path, config->index_files[i]);
        
        if (file_exists(index_path)) {
            return index_path;
        }
    }
    return NULL;
}

// Parse HTTP request
int parse_http_request(const char *request, HttpRequest *req) {
    if (!request || !req) return 0;
    
    // Reset request structure
    memset(req, 0, sizeof(HttpRequest));
    
    // Parse first line (method, path, version)
    char first_line[1024];
    sscanf(request, "%1023[^\n]", first_line);
    
    char *saveptr;
    char *method = strtok_r_alpine(first_line, " ", &saveptr);
    char *path = strtok_r_alpine(NULL, " ", &saveptr);
    char *version = strtok_r_alpine(NULL, "\r\n", &saveptr);
    
    if (!method || !path || !version) return 0;
    
    strncpy(req->method, method, sizeof(req->method) - 1);
    strncpy(req->version, version, sizeof(req->version) - 1);
    
    // Split path and query string
    char *query_start = strchr(path, '?');
    if (query_start) {
        *query_start = '\0';
        strncpy(req->path, path, sizeof(req->path) - 1);
        strncpy(req->query_string, query_start + 1, sizeof(req->query_string) - 1);
    } else {
        strncpy(req->path, path, sizeof(req->path) - 1);
        req->query_string[0] = '\0';
    }
    
    return 1;
}

// Serve static file
void serve_static_file(int client_socket, const char *file_path, struct ServerConfig *config) {
    FILE *file = fopen(file_path, "rb");
    if (!file) {
        const char *response = "HTTP/1.1 404 Not Found\r\n"
                              "Content-Type: text/html; charset=utf-8\r\n"
                              "Connection: close\r\n\r\n"
                              "<!DOCTYPE html><html><head><title>404 Not Found</title>"
                              "<style>body{font-family:Arial,sans-serif;margin:40px}"
                              "h1{color:#d32f2f}.container{max-width:800px;margin:0 auto}"
                              "</style></head><body><div class='container'>"
                              "<h1>404 Not Found</h1><p>The requested file was not found on this server.</p>"
                              "<hr><p>CLOBES PRO Server v" CLOBES_VERSION "</p></div></body></html>";
        send(client_socket, response, strlen(response), 0);
        return;
    }
    
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    // Get MIME type
    const char *mime_type = get_mime_type(file_path);
    
    // Prepare headers
    char headers[1024];
    snprintf(headers, sizeof(headers),
             "HTTP/1.1 200 OK\r\n"
             "Content-Type: %s\r\n"
             "Content-Length: %ld\r\n"
             "Connection: %s\r\n"
             "Server: CLOBES-PRO/4.1.0\r\n"
             "X-Powered-By: CLOBES-PRO\r\n\r\n",
             mime_type, file_size,
             config->keep_alive ? "keep-alive" : "close");
    
    send(client_socket, headers, strlen(headers), 0);
    
    // Send file content
    char buffer[BUFFER_SIZE];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        if (send(client_socket, buffer, bytes_read, 0) <= 0) {
            break;
        }
    }
    
    fclose(file);
}

// Execute PHP file via CGI (version simplifiée)
void execute_php(int client_socket, const char *php_file, const char *query_string, struct ServerConfig *config) {
    const char *response = "HTTP/1.1 501 Not Implemented\r\n"
                          "Content-Type: text/html; charset=utf-8\r\n\r\n"
                          "<h1>PHP support not available on Alpine iSH</h1>"
                          "<p>PHP-CGI is not available in this environment.</p>";
    send(client_socket, response, strlen(response), 0);
}

// Generate directory listing
void generate_directory_listing(int client_socket, const char *dir_path, const char *request_path, struct ServerConfig *config) {
    DIR *dir = opendir(dir_path);
    if (!dir) {
        const char *response = "HTTP/1.1 403 Forbidden\r\n"
                              "Content-Type: text/html; charset=utf-8\r\n\r\n"
                              "<h1>403 Forbidden</h1>";
        send(client_socket, response, strlen(response), 0);
        return;
    }
    
    // Start HTML response
    const char *header = "HTTP/1.1 200 OK\r\n"
                        "Content-Type: text/html; charset=utf-8\r\n"
                        "Connection: close\r\n\r\n"
                        "<!DOCTYPE html>\n"
                        "<html>\n"
                        "<head>\n"
                        "    <title>Index of ";
    
    send(client_socket, header, strlen(header), 0);
    send(client_socket, request_path, strlen(request_path), 0);
    
    const char *head_cont = "</title>\n"
                           "    <style>\n"
                           "        body { font-family: Arial, sans-serif; margin: 40px; }\n"
                           "        h1 { color: #333; }\n"
                           "        table { border-collapse: collapse; width: 100%; }\n"
                           "        th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }\n"
                           "        th { background-color: #f2f2f2; }\n"
                           "        a { text-decoration: none; color: #0066cc; }\n"
                           "        a:hover { text-decoration: underline; }\n"
                           "        .file-icon { width: 20px; margin-right: 8px; }\n"
                           "    </style>\n"
                           "</head>\n"
                           "<body>\n"
                           "    <h1>Index of ";
    
    send(client_socket, head_cont, strlen(head_cont), 0);
    send(client_socket, request_path, strlen(request_path), 0);
    
    const char *body_start = "</h1>\n"
                            "    <table>\n"
                            "        <tr>\n"
                            "            <th>Name</th>\n"
                            "            <th>Size</th>\n"
                            "            <th>Modified</th>\n"
                            "        </tr>\n";
    
    send(client_socket, body_start, strlen(body_start), 0);
    
    // Parent directory link
    if (strcmp(request_path, "/") != 0) {
        const char *parent_link = "        <tr>\n"
                                 "            <td><a href=\"..\">../</a></td>\n"
                                 "            <td>-</td>\n"
                                 "            <td>-</td>\n"
                                 "        </tr>\n";
        send(client_socket, parent_link, strlen(parent_link), 0);
    }
    
    // List directory contents
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        
        char full_path[1024];
        snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, entry->d_name);
        
        struct stat st;
        stat(full_path, &st);
        
        char size_str[32];
        if (S_ISDIR(st.st_mode)) {
            strcpy(size_str, "-");
            strcat(entry->d_name, "/");
        } else {
            if (st.st_size < 1024) {
                snprintf(size_str, sizeof(size_str), "%lld B", (long long)st.st_size);
            } else if (st.st_size < 1024 * 1024) {
                snprintf(size_str, sizeof(size_str), "%.1f KB", st.st_size / 1024.0);
            } else {
                snprintf(size_str, sizeof(size_str), "%.1f MB", st.st_size / (1024.0 * 1024.0));
            }
        }
        
        char time_str[64];
        struct tm *tm_info = localtime(&st.st_mtime);
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M", tm_info);
        
        char row[512];
        snprintf(row, sizeof(row),
                 "        <tr>\n"
                 "            <td><a href=\"%s\">%s</a></td>\n"
                 "            <td>%s</td>\n"
                 "            <td>%s</td>\n"
                 "        </tr>\n",
                 entry->d_name, entry->d_name, size_str, time_str);
        
        send(client_socket, row, strlen(row), 0);
    }
    
    closedir(dir);
    
    // Footer
    const char *footer = "    </table>\n"
                        "    <hr>\n"
                        "    <p><em>CLOBES PRO Server v" CLOBES_VERSION "</em></p>\n"
                        "</body>\n"
                        "</html>\n";
    
    send(client_socket, footer, strlen(footer), 0);
}

// Handle HTTP request
void* handle_client_thread(void *arg) {
    ClientInfo *client = (ClientInfo *)arg;
    struct ServerConfig *config = g_server_session->config;
    
    char buffer[BUFFER_SIZE];
    int bytes_received = recv(client->socket, buffer, sizeof(buffer) - 1, 0);
    
    if (bytes_received > 0) {
        buffer[bytes_received] = '\0';
        
        // Parse request
        HttpRequest req;
        if (parse_http_request(buffer, &req)) {
            // Log access
            if (config->show_access_log) {
                printf("%s - - [%s] \"%s %s %s\"\n",
                       client->ip,
                       "TODO: timestamp",
                       req.method,
                       req.path,
                       req.version);
            }
            
            // Decode URL path
            char decoded_path[1024];
            url_decode(decoded_path, req.path);
            
            // Build file path
            char file_path[2048];
            if (strcmp(decoded_path, "/") == 0) {
                snprintf(file_path, sizeof(file_path), "%s", config->web_root);
            } else {
                snprintf(file_path, sizeof(file_path), "%s%s", config->web_root, decoded_path);
            }
            
            // Check if path is a directory
            if (dir_exists(file_path)) {
                char *index_file = find_index_file(file_path, config);
                if (index_file) {
                    // Serve index file
                    const char *ext = strrchr(index_file, '.');
                    if (ext && strcmp(ext, ".php") == 0 && config->enable_php) {
                        execute_php(client->socket, index_file, req.query_string, config);
                    } else {
                        serve_static_file(client->socket, index_file, config);
                    }
                } else if (config->enable_directory_listing) {
                    generate_directory_listing(client->socket, file_path, decoded_path, config);
                } else {
                    const char *response = "HTTP/1.1 403 Forbidden\r\n"
                                          "Content-Type: text/html; charset=utf-8\r\n\r\n"
                                          "<h1>403 Forbidden - Directory listing disabled</h1>";
                    send(client->socket, response, strlen(response), 0);
                }
            } else if (file_exists(file_path)) {
                // Serve file
                const char *ext = strrchr(file_path, '.');
                if (ext && strcmp(ext, ".php") == 0 && config->enable_php) {
                    execute_php(client->socket, file_path, req.query_string, config);
                } else {
                    serve_static_file(client->socket, file_path, config);
                }
            } else {
                // File not found
                const char *response = "HTTP/1.1 404 Not Found\r\n"
                                      "Content-Type: text/html; charset=utf-8\r\n\r\n"
                                      "<h1>404 Not Found</h1>";
                send(client->socket, response, strlen(response), 0);
            }
        }
    }
    
    close(client->socket);
    free(client);
    return NULL;
}

// Server thread to accept connections
void* server_accept_thread(void *arg) {
    ServerSession *session = (ServerSession *)arg;
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    
    while (session->running) {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(session->server_socket, &read_fds);
        
        struct timeval tv = {1, 0}; // 1 second timeout
        int activity = select(session->server_socket + 1, &read_fds, NULL, NULL, &tv);
        
        if (activity > 0 && FD_ISSET(session->server_socket, &read_fds)) {
            int client_socket = accept(session->server_socket,
                                      (struct sockaddr *)&client_addr,
                                      &client_len);
            
            if (client_socket >= 0) {
                if (session->client_count < MAX_CLIENTS) {
                    ClientInfo *client = malloc(sizeof(ClientInfo));
                    client->socket = client_socket;
                    client->address = client_addr;
                    client->connect_time = time(NULL);
                    inet_ntop(AF_INET, &client_addr.sin_addr, client->ip, INET_ADDRSTRLEN);
                    
                    pthread_create(&client->thread, NULL, handle_client_thread, client);
                    pthread_detach(client->thread);
                    
                    session->clients[session->client_count++] = *client;
                } else {
                    close(client_socket);
                }
            }
        }
    }
    
    return NULL;
}

// Start HTTP server
int http_server_start(struct ServerConfig *config) {
    int server_socket;
    struct sockaddr_in server_addr;
    
    // Create socket
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        print_error("Cannot create socket");
        return -1;
    }
    
    // Set socket options
    int opt = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        print_error("Cannot set socket options");
        close(server_socket);
        return -1;
    }
    
    // Bind socket
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(config->port);
    
    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        print_error("Cannot bind to port %d", config->port);
        close(server_socket);
        return -1;
    }
    
    // Listen for connections
    if (listen(server_socket, config->max_connections) < 0) {
        print_error("Cannot listen on socket");
        close(server_socket);
        return -1;
    }
    
    // Initialize server session
    g_server_session = malloc(sizeof(ServerSession));
    g_server_session->server_socket = server_socket;
    g_server_session->running = 1;
    g_server_session->client_count = 0;
    g_server_session->config = config;
    g_state.server_session = g_server_session;
    
    // Start accept thread
    pthread_create(&g_server_session->accept_thread, NULL, server_accept_thread, g_server_session);
    
    return server_socket;
}

// Stop HTTP server
void http_server_stop(ServerSession *session) {
    if (!session) return;
    
    session->running = 0;
    
    // Wait for accept thread
    pthread_join(session->accept_thread, NULL);
    
    // Close all client sockets
    for (int i = 0; i < session->client_count; i++) {
        close(session->clients[i].socket);
    }
    
    // Close server socket
    close(session->server_socket);
    
    free(session);
    g_server_session = NULL;
    g_state.server_session = NULL;
}

// Signal handler for server stop
void server_stop(int signal) {
    (void)signal;
    if (g_server_session) {
        print_info("\nShutting down server...");
        http_server_stop(g_server_session);
        print_success("Server stopped gracefully");
    }
    exit(0);
}

// Command: server (version simplifiée)
int cmd_server(int argc, char **argv) {
    if (argc < 3) {
        printf(COLOR_CYAN "🌐 SERVER COMMANDS\n" COLOR_RESET);
        printf("══════════════════════════════════════════\n\n");
        
        printf("  start                 - Start HTTP server\n");
        printf("  stop                  - Stop HTTP server\n");
        printf("  status                - Show server status\n");
        printf("\nOptions for start:\n");
        printf("  --port <number>       - Port number (default: 8080)\n");
        printf("  --root <path>         - Web root directory (default: ./www)\n");
        printf("  --listing             - Enable directory listing\n");
        printf("  --domain <name>       - Custom domain name\n");
        printf("  --qr                  - Generate QR code for URL\n");
        printf("  --open                - Show URL to open\n");
        printf("\n");
        return 0;
    }
    
    if (strcmp(argv[2], "start") == 0) {
        struct ServerConfig config = {
            .port = 8080,
            .web_root = "./www",
            .max_connections = 100,
            .timeout = 30,
            .keep_alive = 1,
            .show_access_log = 1,
            .maintenance_mode = 0,
            .enable_php = 0,
            .enable_directory_listing = 0,
            .custom_domain = "",
            .public_url_enabled = 0,
            .qr_code_enabled = 0,
            .auto_open_browser = 0
        };
        
        // Default index files
        strcpy(config.index_files[0], "index.html");
        strcpy(config.index_files[1], "index.htm");
        strcpy(config.index_files[2], "default.html");
        
        // Parse options
        for (int i = 3; i < argc; i++) {
            if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
                config.port = atoi(argv[++i]);
            } else if (strcmp(argv[i], "--root") == 0 && i + 1 < argc) {
                strncpy(config.web_root, argv[++i], sizeof(config.web_root) - 1);
            } else if (strcmp(argv[i], "--listing") == 0) {
                config.enable_directory_listing = 1;
            } else if (strcmp(argv[i], "--domain") == 0 && i + 1 < argc) {
                strncpy(config.custom_domain, argv[++i], sizeof(config.custom_domain) - 1);
            } else if (strcmp(argv[i], "--qr") == 0) {
                config.qr_code_enabled = 1;
            } else if (strcmp(argv[i], "--open") == 0) {
                config.auto_open_browser = 1;
            }
        }
        
        // Create web root if it doesn't exist
        if (!dir_exists(config.web_root)) {
            mkdir(config.web_root, 0755);
            print_info("Created web root directory: %s", config.web_root);
            
            // Create default index.html
            char index_path[512];
            snprintf(index_path, sizeof(index_path), "%s/index.html", config.web_root);
            FILE *fp = fopen(index_path, "w");
            if (fp) {
                fprintf(fp, "<!DOCTYPE html>\n");
                fprintf(fp, "<html>\n");
                fprintf(fp, "<head>\n");
                fprintf(fp, "    <title>CLOBES PRO Server</title>\n");
                fprintf(fp, "    <style>\n");
                fprintf(fp, "        body { font-family: Arial, sans-serif; margin: 40px; }\n");
                fprintf(fp, "        .container { max-width: 800px; margin: 0 auto; }\n");
                fprintf(fp, "        h1 { color: #0066cc; }\n");
                fprintf(fp, "        .success { color: #4CAF50; }\n");
                fprintf(fp, "</style>\n");
                fprintf(fp, "</head>\n");
                fprintf(fp, "<body>\n");
                fprintf(fp, "    <div class=\"container\">\n");
                fprintf(fp, "        <h1>🚀 CLOBES PRO Server v%s</h1>\n", CLOBES_VERSION);
                fprintf(fp, "        <p class=\"success\">✅ Server is running successfully!</p>\n");
                fprintf(fp, "        <p>Web root: %s</p>\n", config.web_root);
                fprintf(fp, "        <p>Port: %d</p>\n", config.port);
                fprintf(fp, "        <hr>\n");
                fprintf(fp, "        <p>To upload files, place them in the web root directory.</p>\n");
                fprintf(fp, "        <p>PHP support: Disabled (Not available on Alpine iSH)</p>\n");
                fprintf(fp, "    </div>\n");
                fprintf(fp, "</body>\n");
                fprintf(fp, "</html>\n");
                fclose(fp);
                print_success("Created default index.html");
            }
        }
        
        // Start server
        print_info("Starting CLOBES PRO HTTP Server...");
        printf(COLOR_CYAN "╔══════════════════════════════════════════════════════════════╗\n" COLOR_RESET);
        printf(COLOR_CYAN "║                    SERVER CONFIGURATION                     ║\n" COLOR_RESET);
        printf(COLOR_CYAN "╠══════════════════════════════════════════════════════════════╣\n" COLOR_RESET);
        printf("  Port:               %d\n", config.port);
        printf("  Web Root:           %s\n", config.web_root);
        printf("  PHP Support:        No (Alpine iSH limitation)\n");
        printf("  Directory Listing:  %s\n", config.enable_directory_listing ? "Enabled" : "Disabled");
        printf("  Max Connections:    %d\n", config.max_connections);
        printf(COLOR_CYAN "╠══════════════════════════════════════════════════════════════╣\n" COLOR_RESET);
        
        int server_socket = http_server_start(&config);
        if (server_socket < 0) {
            print_error("Failed to start server");
            return 1;
        }
        
        // Get local IP
        char *local_ip = get_local_ip();
        
        // Generate URLs
        char local_url[256];
        char network_url[256];
        
        snprintf(local_url, sizeof(local_url), "http://localhost:%d", config.port);
        snprintf(network_url, sizeof(network_url), "http://%s:%d", local_ip, config.port);
        
        printf(COLOR_GREEN "║                      SERVER STARTED                        ║\n" COLOR_RESET);
        printf(COLOR_CYAN "╠══════════════════════════════════════════════════════════════╣\n" COLOR_RESET);
        printf("  Local URL:          %s\n", local_url);
        printf("  Network URL:        %s\n", network_url);
        
        if (config.custom_domain[0] != '\0') {
            printf("  Custom Domain:      http://%s:%d\n", config.custom_domain, config.port);
        }
        
        printf(COLOR_CYAN "╠══════════════════════════════════════════════════════════════╣\n" COLOR_RESET);
        printf("  📁 Web Root:         %s\n", config.web_root);
        printf("  🔧 PHP Support:      ❌ Not available on Alpine iSH\n");
        printf("  📋 Directory List:   %s\n", config.enable_directory_listing ? "✅ Enabled" : "❌ Disabled");
        printf(COLOR_CYAN "╠══════════════════════════════════════════════════════════════╣\n" COLOR_RESET);
        printf("  💡 Press Ctrl+C to stop the server\n");
        printf(COLOR_CYAN "╚══════════════════════════════════════════════════════════════╝\n" COLOR_RESET);
        
        // Generate QR code
        if (config.qr_code_enabled) {
            generate_qr_code(network_url);
        }
        
        // Open browser
        if (config.auto_open_browser) {
            open_browser(local_url);
        }
        
        // Wait for server to run
        print_info("Server is running. Press Ctrl+C to stop.");
        
        // Install signal handler for Ctrl+C
        signal(SIGINT, server_stop);
        
        // Keep main thread alive
        while (g_server_session && g_server_session->running) {
            sleep(1);
        }
        
        return 0;
        
    } else if (strcmp(argv[2], "stop") == 0) {
        if (g_server_session) {
            print_info("Stopping server...");
            http_server_stop(g_server_session);
            print_success("Server stopped");
        } else {
            print_warning("No server is running");
        }
        return 0;
        
    } else if (strcmp(argv[2], "status") == 0) {
        if (g_server_session) {
            printf(COLOR_CYAN "Server Status: " COLOR_GREEN "RUNNING\n" COLOR_RESET);
            printf("Port: %d\n", g_server_session->config->port);
            printf("Clients: %d/%d\n", g_server_session->client_count, 
                   g_server_session->config->max_connections);
            printf("Web Root: %s\n", g_server_session->config->web_root);
        } else {
            printf(COLOR_CYAN "Server Status: " COLOR_RED "STOPPED\n" COLOR_RESET);
        }
        return 0;
    }
    
    print_error("Unknown server command: %s", argv[2]);
    return 1;
}

// Les autres fonctions restent les mêmes jusqu'à main...

// [Ici insérez les autres fonctions : interactive_mode, http_get_advanced, etc.
// mais simplifiées comme dans la version précédente]
// Pour gagner de l'espace, je montre seulement les changements critiques

// HTTP GET with advanced features (version Alpine)
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
    headers = curl_slist_append(headers, "User-Agent: CLOBES-PRO/4.1.0");
    
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
    
    // Cleanup
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    
    if (res != CURLE_OK) {
        log_message(LOG_ERROR, "curl_easy_perform() failed: %s", curl_easy_strerror(res));
        free(chunk.memory);
        return NULL;
    }
    
    return chunk.memory;
}

// HTTP GET (simple version)
char* http_get_simple(const char *url) {
    return http_get_advanced(url, 0, 1, g_state.config.timeout);
}

// [Continuez avec les autres fonctions mais simplifiées...]

// Main function
int main(int argc, char **argv) {
    // Check for interactive mode (-i like curl)
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--interactive") == 0) {
            // Initialize curl
            curl_global_init(CURL_GLOBAL_ALL);
            register_commands();
            int result = interactive_mode();
            curl_global_cleanup();
            return result;
        }
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