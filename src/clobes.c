// CLOBES PRO v4.0.0 - Ultimate CLI Toolkit
#include "clobes.h"
#include <stdarg.h>
#include <dirent.h>
#include <regex.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <pthread.h>

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
    .log_level = LOG_INFO,
    .ssl_ctx = NULL
};

// Server state
static int server_running = 0;
static int server_socket = -1;
static int ssl_server_socket = -1;
static pthread_t server_thread;
static pthread_t ssl_server_thread;
static ServerConfig *global_config = NULL;

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

// Default index files
static const char *default_index_files[] = {
    "index.html",
    "index.htm",
    "default.html",
    "default.htm",
    "index.php",
    NULL
};

// Favicon files to search for
static const char *favicon_files[] = {
    "favicon.ico",
    "favicon.png",
    "favicon.jpg",
    "favicon.svg",
    "favicon.gif",
    NULL
};

// MIME types
typedef struct {
    const char *extension;
    const char *mime_type;
    int compressible;
} MimeType;

static MimeType mime_types[] = {
    {".html", "text/html", 1},
    {".htm", "text/html", 1},
    {".css", "text/css", 1},
    {".js", "application/javascript", 1},
    {".json", "application/json", 1},
    {".xml", "application/xml", 1},
    {".txt", "text/plain", 1},
    {".pdf", "application/pdf", 0},
    {".zip", "application/zip", 0},
    {".tar", "application/x-tar", 0},
    {".gz", "application/gzip", 0},
    {".bz2", "application/x-bzip2", 0},
    {".jpg", "image/jpeg", 0},
    {".jpeg", "image/jpeg", 0},
    {".png", "image/png", 0},
    {".gif", "image/gif", 0},
    {".svg", "image/svg+xml", 1},
    {".ico", "image/x-icon", 0},
    {".bmp", "image/bmp", 0},
    {".webp", "image/webp", 0},
    {".mp3", "audio/mpeg", 0},
    {".wav", "audio/wav", 0},
    {".mp4", "video/mp4", 0},
    {".avi", "video/x-msvideo", 0},
    {".mov", "video/quicktime", 0},
    {".woff", "font/woff", 0},
    {".woff2", "font/woff2", 0},
    {".ttf", "font/ttf", 0},
    {".otf", "font/otf", 0},
    {".eot", "application/vnd.ms-fontobject", 0},
    {".csv", "text/csv", 1},
    {".doc", "application/msword", 0},
    {".docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", 0},
    {".xls", "application/vnd.ms-excel", 0},
    {".xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", 0},
    {".ppt", "application/vnd.ms-powerpoint", 0},
    {".pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation", 0},
    {".php", "application/x-httpd-php", 1},
    {".py", "text/x-python", 1},
    {".c", "text/x-c", 1},
    {".cpp", "text/x-c++", 1},
    {".h", "text/x-c", 1},
    {".java", "text/x-java", 1},
    {".sh", "application/x-sh", 1},
    {".pl", "application/x-perl", 1},
    {".rb", "application/x-ruby", 1},
    {".go", "text/x-go", 1},
    {".rs", "text/x-rust", 1},
    {".md", "text/markdown", 1},
    {NULL, "application/octet-stream", 0}
};

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
    printf("╚════════════════════════════════════════_value);
                send(client_socket, response->body, response->body_length, 0);
            }
        } else {
            send_http_response(client_socket, response);
        }
    } else {
        send_http_response(client_socket, response);
    }
}

// Send HTTP response over SSL
void ssl_send_http_response(SSL *ssl, HttpResponse *response) {
    char buffer[BUFFER_SIZE];
    
    // Send status line
    snprintf(buffer, sizeof(buffer), "HTTP/1.1 %d %s\r\n", 
             response->status_code, response->status_text);
    SSL_write(ssl, buffer, strlen(buffer));
    
    // Send headers
    for (int i = 0; i < response->header_count; i++) {
        snprintf(buffer, sizeof(buffer), "%s\r\n", response->headers[i]);
        SSL_write(ssl, buffer, strlen(buffer));
    }
    
    // End of headers
    SSL_write(ssl, "\r\n", 2);
    
    // Send body if exists
    if (response->body && response->body_length > 0) {
        SSL_write(ssl, response->body, response->body_length);
    }
}

// Free HTTP response
void free_http_response(HttpResponse *response) {
    if (response->body) {
        free(response->body);
        response->body = NULL;
    }
}

// Get MIME type for filename
char* get_mime_type(const char *filename) {
    const char *dot = strrchr(filename, '.');
    if (!dot) {
        return "application/octet-stream";
    }
    
    for (int i = 0; mime_types[i].extension != NULL; i++) {
        if (strcasecmp(dot, mime_types[i].extension) == 0) {
            return (char*)mime_types[i].mime_type;
        }
    }
    
    return "application/octet-stream";
}

// Check if file should be compressed
int should_compress_file(const char *filename, const char *mime_type) {
    if (!global_config || !global_config->enable_gzip) return 0;
    
    // Check MIME type compressibility
    for (int i = 0; mime_types[i].extension != NULL; i++) {
        if (strcmp(mime_types[i].mime_type, mime_type) == 0) {
            return mime_types[i].compressible;
        }
    }
    
    return 0;
}

// GZIP compression
int compress_gzip(const char *input, size_t input_size, char **output, size_t *output_size) {
    z_stream stream;
    int ret;
    
    *output = malloc(input_size + (input_size / 10) + 12);
    if (!*output) return -1;
    
    stream.zalloc = Z_NULL;
    stream.zfree = Z_NULL;
    stream.opaque = Z_NULL;
    
    ret = deflateInit2(&stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 
                      15 + 16, 8, Z_DEFAULT_STRATEGY);
    if (ret != Z_OK) {
        free(*output);
        return -1;
    }
    
    stream.next_in = (Bytef *)input;
    stream.avail_in = input_size;
    stream.next_out = (Bytef *)*output;
    stream.avail_out = input_size + (input_size / 10) + 12;
    
    ret = deflate(&stream, Z_FINISH);
    if (ret != Z_STREAM_END) {
        deflateEnd(&stream);
        free(*output);
        return -1;
    }
    
    *output_size = stream.total_out;
    
    deflateEnd(&stream);
    return 0;
}

// Get local IP address
char* get_local_ip() {
    static char ip[INET_ADDRSTRLEN] = "127.0.0.1";
    struct ifaddrs *ifaddr, *ifa;
    
    if (getifaddrs(&ifaddr) == -1) {
        return ip;
    }
    
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;
        
        // Check for IPv4
        if (ifa->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
            char *current_ip = inet_ntoa(sa->sin_addr);
            
            // Skip localhost and docker interfaces
            if (strcmp(current_ip, "127.0.0.1") == 0 ||
                strncmp(ifa->ifa_name, "docker", 6) == 0 ||
                strncmp(ifa->ifa_name, "lo", 2) == 0) {
                continue;
            }
            
            strncpy(ip, current_ip, sizeof(ip) - 1);
            break;
        }
    }
    
    freeifaddrs(ifaddr);
    return ip;
}

// Get public IP address
char* get_public_ip() {
    static char ip[64] = "Unknown";
    CURL *curl = curl_easy_init();
    
    if (!curl) {
        return ip;
    }
    
    MemoryStruct chunk = {NULL, 0};
    
    curl_easy_setopt(curl, CURLOPT_URL, "https://api.ipify.org");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
    
    CURLcode res = curl_easy_perform(curl);
    
    if (res == CURLE_OK && chunk.memory && chunk.size > 0) {
        strncpy(ip, chunk.memory, sizeof(ip) - 1);
        ip[sizeof(ip) - 1] = '\0';
    } else {
        // Fallback to other services
        curl_easy_setopt(curl, CURLOPT_URL, "https://ifconfig.me/ip");
        curl_easy_cleanup(curl);
        curl = curl_easy_init();
        
        if (curl) {
            chunk.memory = NULL;
            chunk.size = 0;
            
            curl_easy_setopt(curl, CURLOPT_URL, "https://ifconfig.me/ip");
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
            curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5);
            
            res = curl_easy_perform(curl);
            if (res == CURLE_OK && chunk.memory && chunk.size > 0) {
                strncpy(ip, chunk.memory, sizeof(ip) - 1);
                ip[sizeof(ip) - 1] = '\0';
            }
        }
    }
    
    if (chunk.memory) free(chunk.memory);
    if (curl) curl_easy_cleanup(curl);
    
    return ip;
}

// Find file in directory recursively
char* find_file_in_directory(const char *dir, const char *filename, int max_depth) {
    static char found_path[MAX_PATH];
    DIR *dp;
    struct dirent *entry;
    struct stat statbuf;
    
    if (max_depth < 0) return NULL;
    
    if ((dp = opendir(dir)) == NULL) {
        return NULL;
    }
    
    while ((entry = readdir(dp)) != NULL) {
        char path[MAX_PATH];
        snprintf(path, sizeof(path), "%s/%s", dir, entry->d_name);
        
        if (stat(path, &statbuf) == -1) continue;
        
        if (S_ISDIR(statbuf.st_mode)) {
            // Skip . and .. directories
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
                continue;
            
            // Recursive search in subdirectory
            char *result = find_file_in_directory(path, filename, max_depth - 1);
            if (result) {
                closedir(dp);
                return result;
            }
        } else {
            if (strcasecmp(entry->d_name, filename) == 0) {
                strncpy(found_path, path, sizeof(found_path) - 1);
                closedir(dp);
                return found_path;
            }
        }
    }
    
    closedir(dp);
    return NULL;
}

// Find favicon in web root or current directory
char* find_favicon(ServerConfig *config) {
    char *found = NULL;
    
    // First check web root
    for (int i = 0; favicon_files[i] != NULL; i++) {
        char path[MAX_PATH];
        snprintf(path, sizeof(path), "%s/%s", config->web_root, favicon_files[i]);
        
        struct stat st;
        if (stat(path, &st) == 0 && S_ISREG(st.st_mode)) {
            static char result[MAX_PATH];
            strncpy(result, path, sizeof(result) - 1);
            return result;
        }
    }
    
    // If not found and search_current_dir is enabled, search current directory
    if (config->search_current_dir) {
        for (int i = 0; favicon_files[i] != NULL; i++) {
            found = find_file_in_directory(config->current_directory, 
                                          favicon_files[i], 
                                          MAX_FAVICON_SEARCH_DEPTH);
            if (found) {
                return found;
            }
        }
    }
    
    return NULL;
}

// Create default files if they don't exist
int create_default_files(ServerConfig *config) {
    char index_path[MAX_PATH];
    snprintf(index_path, sizeof(index_path), "%s/index.html", config->web_root);
    
    struct stat st;
    if (stat(index_path, &st) != 0) {
        // Create default index.html
        FILE *fp = fopen(index_path, "w");
        if (fp) {
            fprintf(fp, "<!DOCTYPE html>\n");
            fprintf(fp, "<html lang=\"en\">\n");
            fprintf(fp, "<head>\n");
            fprintf(fp, "    <meta charset=\"UTF-8\">\n");
            fprintf(fp, "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n");
            fprintf(fp, "    <title>CLOBES PRO Web Server</title>\n");
            fprintf(fp, "    <style>\n");
            fprintf(fp, "        * { margin: 0; padding: 0; box-sizing: border-box; }\n");
            fprintf(fp, "        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; \n");
            fprintf(fp, "               background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%); \n");
            fprintf(fp, "               min-height: 100vh; color: white; }\n");
            fprintf(fp, "        .container { max-width: 1200px; margin: 0 auto; padding: 40px 20px; }\n");
            fprintf(fp, "        header { text-align: center; margin-bottom: 60px; }\n");
            fprintf(fp, "        .logo { font-size: 4rem; margin-bottom: 20px; }\n");
            fprintf(fp, "        h1 { font-size: 3rem; margin-bottom: 10px; }\n");
            fprintf(fp, "        .subtitle { font-size: 1.2rem; opacity: 0.9; margin-bottom: 40px; }\n");
            fprintf(fp, "        .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); \n");
            fprintf(fp, "                 gap: 30px; margin-bottom: 60px; }\n");
            fprintf(fp, "        .card { background: rgba(255, 255, 255, 0.1); backdrop-filter: blur(10px); \n");
            fprintf(fp, "                border-radius: 15px; padding: 30px; transition: transform 0.3s ease; }\n");
            fprintf(fp, "        .card:hover { transform: translateY(-5px); }\n");
            fprintf(fp, "        .card h2 { font-size: 1.5rem; margin-bottom: 15px; display: flex; align-items: center; gap: 10px; }\n");
            fprintf(fp, "        .card p { line-height: 1.6; margin-bottom: 20px; }\n");
            fprintf(fp, "        .features { list-style: none; }\n");
            fprintf(fp, "        .features li { margin-bottom: 10px; padding-left: 25px; position: relative; }\n");
            fprintf(fp, "        .features li:before { content: '✓'; position: absolute; left: 0; color: #4CAF50; }\n");
            fprintf(fp, "        .url-box { background: rgba(0, 0, 0, 0.2); padding: 20px; border-radius: 10px; \n");
            fprintf(fp, "                  margin: 40px 0; font-family: monospace; font-size: 1.1rem; \n");
            fprintf(fp, "                  word-break: break-all; }\n");
            fprintf(fp, "        footer { text-align: center; margin-top: 60px; padding-top: 40px; \n");
            fprintf(fp, "                 border-top: 1px solid rgba(255, 255, 255, 0.1); }\n");
            fprintf(fp, "        .btn { display: inline-block; background: #4CAF50; color: white; \n");
            fprintf(fp, "               padding: 12px 30px; border-radius: 50px; text-decoration: none; \n");
            fprintf(fp, "               font-weight: bold; transition: background 0.3s ease; }\n");
            fprintf(fp, "        .btn:hover { background: #45a049; }\n");
            fprintf(fp, "        @media (max-width: 768px) { h1 { font-size: 2rem; } .logo { font-size: 3rem; } }\n");
            fprintf(fp, "    </style>\n");
            
            // Try to find favicon and add it
            char *favicon_path = find_favicon(config);
            if (favicon_path) {
                fprintf(fp, "    <link rel=\"icon\" href=\"/favicon.ico\" type=\"image/x-icon\">\n");
            }
            
            fprintf(fp, "</head>\n");
            fprintf(fp, "<body>\n");
            fprintf(fp, "    <div class=\"container\">\n");
            fprintf(fp, "        <header>\n");
            fprintf(fp, "            <div class=\"logo\">🚀</div>\n");
            fprintf(fp, "            <h1>CLOBES PRO Web Server</h1>\n");
            fprintf(fp, "            <p class=\"subtitle\">Ultimate Command Line Toolkit v%s</p>\n", CLOBES_VERSION);
            fprintf(fp, "        </header>\n");
            fprintf(fp, "        \n");
            fprintf(fp, "        <div class=\"url-box\">\n");
            fprintf(fp, "            Server running at: http://%s:%d\n", get_local_ip(), config->port);
            fprintf(fp, "        </div>\n");
            fprintf(fp, "        \n");
            fprintf(fp, "        <div class=\"cards\">\n");
            fprintf(fp, "            <div class=\"card\">\n");
            fprintf(fp, "                <h2>📁 File Serving</h2>\n");
            fprintf(fp, "                <p>Serve static files including HTML, CSS, JavaScript, images, and more.</p>\n");
            fprintf(fp, "                <ul class=\"features\">\n");
            fprintf(fp, "                    <li>Automatic index.html detection</li>\n");
            fprintf(fp, "                    <li>Directory listing (optional)</li>\n");
            fprintf(fp, "                    <li>MIME type detection</li>\n");
            fprintf(fp, "                    <li>GZIP compression</li>\n");
            fprintf(fp, "                </ul>\n");
            fprintf(fp, "            </div>\n");
            fprintf(fp, "            \n");
            fprintf(fp, "            <div class=\"card\">\n");
            fprintf(fp, "                <h2>🔒 SSL/TLS Support</h2>\n");
            fprintf(fp, "                <p>Secure connections with HTTPS support using OpenSSL.</p>\n");
            fprintf(fp, "                <ul class=\"features\">\n");
            fprintf(fp, "                    <li>HTTPS on port 8443</li>\n");
            fprintf(fp, "                    <li>Self-signed certificates</li>\n");
            fprintf(fp, "                    <li>Custom certificate support</li>\n");
            fprintf(fp, "                    <li>SSL 3.0/TLS 1.2+</li>\n");
            fprintf(fp, "                </ul>\n");
            fprintf(fp, "            </div>\n");
            fprintf(fp, "            \n");
            fprintf(fp, "            <div class=\"card\">\n");
            fprintf(fp, "                <h2>🌐 Public Access</h2>\n");
            fprintf(fp, "                <p>Access your server from anywhere with public URL and QR code.</p>\n");
            fprintf(fp, "                <ul class=\"features\">\n");
            fprintf(fp, "                    <li>Public IP detection</li>\n");
            fprintf(fp, "                    <li>QR code generation</li>\n");
            fprintf(fp, "                    <li>Custom domain support</li>\n");
            fprintf(fp, "                    <li>Local network access</li>\n");
            fprintf(fp, "                </ul>\n");
            fprintf(fp, "            </div>\n");
            fprintf(fp, "        </div>\n");
            fprintf(fp, "        \n");
            fprintf(fp, "        <div style=\"text-align: center;\">\n");
            fprintf(fp, "            <a href=\"#\" class=\"btn\">Get Started</a>\n");
            fprintf(fp, "            <a href=\"/\" class=\"btn\" style=\"background: #2196F3; margin-left: 10px;\">Refresh</a>\n");
            fprintf(fp, "        </div>\n");
            fprintf(fp, "        \n");
            fprintf(fp, "        <footer>\n");
            fprintf(fp, "            <p>Powered by <strong>CLOBES PRO</strong> - Faster than curl, Smarter than wget</p>\n");
            fprintf(fp, "            <p style=\"margin-top: 10px; font-size: 0.9rem; opacity: 0.7;\">\n");
            fprintf(fp, "                Put your files in the <code>%s</code> directory to serve them.\n", config->web_root);
            fprintf(fp, "            </p>\n");
            fprintf(fp, "        </footer>\n");
            fprintf(fp, "    </div>\n");
            fprintf(fp, "    \n");
            fprintf(fp, "    <script>\n");
            fprintf(fp, "        // Auto-refresh URLs with current IP\n");
            fprintf(fp, "        document.addEventListener('DOMContentLoaded', function() {\n");
            fprintf(fp, "            const urlBox = document.querySelector('.url-box');\n");
            fprintf(fp, "            if (urlBox) {\n");
            fprintf(fp, "                const localIP = '%s';\n", get_local_ip());
            fprintf(fp, "                urlBox.innerHTML = `\n");
            fprintf(fp, "                    <strong>Access URLs:</strong><br>\n");
            fprintf(fp, "                    • Local: <a href=\"http://localhost:%d\" style=\"color: #4CAF50;\">http://localhost:%d</a><br>\n", config->port, config->port);
            fprintf(fp, "                    • Network: <a href=\"http://${localIP}:%d\" style=\"color: #4CAF50;\">http://${localIP}:%d</a>\n", config->port, config->port);
            fprintf(fp, "                `;\n");
            fprintf(fp, "            }\n");
            fprintf(fp, "        });\n");
            fprintf(fp, "    </script>\n");
            fprintf(fp, "</body>\n");
            fprintf(fp, "</html>\n");
            fclose(fp);
            print_info("Created default index.html at: %s", index_path);
        }
    }
    
    return 0;
}

// Generate public URL
char* generate_public_url(ServerConfig *config) {
    static char url[512];
    
    if (config->custom_domain[0] != '\0') {
        if (config->port != 80 && config->port != 443) {
            snprintf(url, sizeof(url), "http://%s:%d", config->custom_domain, config->port);
        } else {
            snprintf(url, sizeof(url), "http://%s", config->custom_domain);
        }
    } else {
        const char *public_ip = get_public_ip();
        if (strcmp(public_ip, "Unknown") == 0) {
            const char *local_ip = get_local_ip();
            snprintf(url, sizeof(url), "http://%s:%d", local_ip, config->port);
        } else {
            snprintf(url, sizeof(url), "http://%s:%d", public_ip, config->port);
        }
    }
    
    return url;
}

// Generate QR code
int generate_qr_code(const char *url, const char *output_file) {
    char cmd[1024];
    
    // Check if qrencode is installed
    if (system("which qrencode > /dev/null 2>&1") != 0) {
        print_warning("qrencode not installed. Install with: apk add qrencode");
        return 1;
    }
    
    if (output_file) {
        snprintf(cmd, sizeof(cmd), "qrencode -s 10 -l H -o \"%s\" \"%s\"", output_file, url);
    } else {
        // Print QR to terminal
        snprintf(cmd, sizeof(cmd), "qrencode -t UTF8 \"%s\"", url);
    }
    
    int result = system(cmd);
    if (result == 0 && output_file) {
        print_success("QR code saved to: %s", output_file);
    }
    
    return result;
}

// Initialize SSL context
int init_ssl_context(ServerConfig *config) {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    
    g_state.ssl_ctx = SSL_CTX_new(TLS_server_method());
    if (!g_state.ssl_ctx) {
        log_message(LOG_ERROR, "Failed to create SSL context");
        return -1;
    }
    
    // Load certificate and key
    if (SSL_CTX_use_certificate_file(g_state.ssl_ctx, config->ssl_cert, SSL_FILETYPE_PEM) <= 0) {
        log_message(LOG_ERROR, "Failed to load certificate: %s", config->ssl_cert);
        SSL_CTX_free(g_state.ssl_ctx);
        return -1;
    }
    
    if (SSL_CTX_use_PrivateKey_file(g_state.ssl_ctx, config->ssl_key, SSL_FILETYPE_PEM) <= 0) {
        log_message(LOG_ERROR, "Failed to load private key: %s", config->ssl_key);
        SSL_CTX_free(g_state.ssl_ctx);
        return -1;
    }
    
    // Verify private key
    if (!SSL_CTX_check_private_key(g_state.ssl_ctx)) {
        log_message(LOG_ERROR, "Private key does not match certificate");
        SSL_CTX_free(g_state.ssl_ctx);
        return -1;
    }
    
    return 0;
}

// Cleanup SSL
void cleanup_ssl() {
    if (g_state.ssl_ctx) {
        SSL_CTX_free(g_state.ssl_ctx);
        g_state.ssl_ctx = NULL;
    }
    EVP_cleanup();
}

// Serve static file (regular or SSL)
int serve_static_file(int client_socket, const char *filepath, ServerConfig *config, int use_ssl) {
    struct stat file_stat;
    FILE *file;
    char *file_content = NULL;
    size_t file_size = 0;
    
    // Check if file exists
    if (stat(filepath, &file_stat) < 0) {
        return 0;
    }
    
    // Check if it's a directory
    if (S_ISDIR(file_stat.st_mode)) {
        // Try to find index file
        for (int i = 0; default_index_files[i] != NULL; i++) {
            char index_path[MAX_PATH];
            snprintf(index_path, sizeof(index_path), "%s/%s", filepath, default_index_files[i]);
            
            if (stat(index_path, &file_stat) == 0 && S_ISREG(file_stat.st_mode)) {
                return serve_static_file(client_socket, index_path, config, use_ssl);
            }
        }
        
        // If directory listing is enabled
        if (config->allow_directory_listing) {
            if (use_ssl) {
                return ssl_serve_directory_listing(SSL_new(g_state.ssl_ctx), filepath, filepath, config);
            } else {
                return serve_directory_listing(client_socket, filepath, filepath, config, use_ssl);
            }
        }
        
        return 0;
    }
    
    // Open file
    file = fopen(filepath, "rb");
    if (!file) {
        return 0;
    }
    
    // Get file size
    fseek(file, 0, SEEK_END);
    file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    // Allocate memory and read file
    file_content = malloc(file_size);
    if (!file_content) {
        fclose(file);
        return 0;
    }
    
    fread(file_content, 1, file_size, file);
    fclose(file);
    
    // Get MIME type
    const char *mime_type = get_mime_type(filepath);
    
    // Prepare response
    HttpResponse response;
    response.status_code = 200;
    strcpy(response.status_text, "OK");
    response.header_count = 0;
    response.compressed = 0;
    
    // Check if we should compress
    char *compressed_data = NULL;
    size_t compressed_size = 0;
    
    if (should_compress_file(filepath, mime_type) && file_size > 1024) {
        if (compress_gzip(file_content, file_size, &compressed_data, &compressed_size) == 0) {
            // Only use compression if it actually reduces size
            if (compressed_size < file_size * 0.9) {
                response.compressed = 1;
                response.body = compressed_data;
                response.body_length = compressed_size;
                
                snprintf(response.headers[response.header_count++], MAX_HEADER_SIZE,
                        "Content-Encoding: gzip");
                snprintf(response.headers[response.header_count++], MAX_HEADER_SIZE,
                        "Content-Length: %zu", compressed_size);
            } else {
                free(compressed_data);
                response.body = file_content;
                response.body_length = file_size;
                snprintf(response.headers[response.header_count++], MAX_HEADER_SIZE,
                        "Content-Length: %zu", file_size);
            }
        } else {
            response.body = file_content;
            response.body_length = file_size;
            snprintf(response.headers[response.header_count++], MAX_HEADER_SIZE,
                    "Content-Length: %zu", file_size);
        }
    } else {
        response.body = file_content;
        response.body_length = file_size;
        snprintf(response.headers[response.header_count++], MAX_HEADER_SIZE,
                "Content-Length: %zu", file_size);
    }
    
    // Add headers
    snprintf(response.headers[response.header_count++], MAX_HEADER_SIZE,
             "Content-Type: %s", mime_type);
    snprintf(response.headers[response.header_count++], MAX_HEADER_SIZE,
             "Connection: close");
    snprintf(response.headers[response.header_count++], MAX_HEADER_SIZE,
             "Server: CLOBES-PRO/4.0.0");
    
    if (config->enable_gzip && response.compressed) {
        snprintf(response.headers[response.header_count++], MAX_HEADER_SIZE,
                "Vary: Accept-Encoding");
    }
    
    // Send response
    if (use_ssl) {
        SSL *ssl = SSL_new(g_state.ssl_ctx);
        SSL_set_fd(ssl, client_socket);
        if (SSL_accept(ssl) <= 0) {
            SSL_free(ssl);
            free_http_response(&response);
            return 0;
        }
        ssl_send_http_response(ssl, &response);
        SSL_shutdown(ssl);
        SSL_free(ssl);
    } else {
        send_http_response(client_socket, &response);
    }
    
    // Cleanup
    free_http_response(&response);
    if (response.compressed && compressed_data != response.body) {
        free(compressed_data);
    }
    if (!response.compressed) {
        free(file_content);
    }
    
    return 1;
}

// SSL version of serve_static_file
int ssl_serve_static_file(SSL *ssl, const char *filepath, ServerConfig *config) {
    return serve_static_file(SSL_get_fd(ssl), filepath, config, 1);
}

// Serve directory listing (regular or SSL)
int serve_directory_listing(int client_socket, const char *path, const char *request_path, ServerConfig *config, int use_ssl) {
    DIR *dir;
    struct dirent *entry;
    char html[65536];
    int pos = 0;
    
    dir = opendir(path);
    if (!dir) {
        return 0;
    }
    
    // Generate HTML directory listing
    pos += snprintf(html + pos, sizeof(html) - pos,
                   "<!DOCTYPE html>\n"
                   "<html>\n"
                   "<head>\n"
                   "    <title>Index of %s</title>\n"
                   "    <style>\n"
                   "        body { font-family: Arial, sans-serif; margin: 40px; background-color: #f5f5f5; }\n"
                   "        h1 { color: #333; border-bottom: 2px solid #4CAF50; padding-bottom: 10px; }\n"
                   "        table { border-collapse: collapse; width: 100%%; background: white; box-shadow: 0 2px 10px rgba(0,0,0,0.1); border-radius: 8px; overflow: hidden; }\n"
                   "        th, td { padding: 12px 15px; text-align: left; border-bottom: 1px solid #ddd; }\n"
                   "        th { background-color: #4CAF50; color: white; font-weight: bold; }\n"
                   "        tr:hover { background-color: #f5f5f5; }\n"
                   "        a { text-decoration: none; color: #0066cc; font-weight: 500; }\n"
                   "        a:hover { text-decoration: underline; color: #004499; }\n"
                   "        .size { color: #666; font-family: monospace; }\n"
                   "        .dir { font-weight: bold; color: #2c3e50; }\n"
                   "        .file { color: #34495e; }\n"
                   "        .icon { margin-right: 8px; }\n"
                   "        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }\n"
                   "        .back-btn { background: #4CAF50; color: white; padding: 8px 16px; border-radius: 4px; text-decoration: none; }\n"
                   "        .back-btn:hover { background: #45a049; }\n"
                   "        .server-info { margin-top: 30px; padding: 15px; background: #e8f4f8; border-radius: 6px; font-size: 0.9em; color: #2c3e50; }\n"
                   "    </style>\n"
                   "</head>\n"
                   "<body>\n"
                   "    <div class=\"header\">\n"
                   "        <h1>📁 Index of %s</h1>\n"
                   "        <a href=\"../\" class=\"back-btn\">⬆ Parent Directory</a>\n"
                   "    </div>\n"
                   "    <table>\n"
                   "        <thead>\n"
                   "            <tr>\n"
                   "                <th>Name</th>\n"
                   "                <th>Size</th>\n"
                   "                <th>Last Modified</th>\n"
                   "                <th>Type</th>\n"
                   "            </tr>\n"
                   "        </thead>\n"
                   "        <tbody>\n",
                   request_path, request_path);
    
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        
        char full_path[MAX_PATH];
        struct stat file_stat;
        char size_str[32];
        char time_str[64];
        char type_str[32];
        char icon[16];
        
        snprintf(full_path, sizeof(full_path), "%s/%s", path, entry->d_name);
        
        if (stat(full_path, &file_stat) == 0) {
            if (S_ISDIR(file_stat.st_mode)) {
                strcpy(icon, "📁");
                strcpy(type_str, "Directory");
                strcpy(size_str, "-");
                snprintf(html + pos, sizeof(html) - pos,
                        "        <tr class=\"dir\">\n"
                        "            <td><span class=\"icon\">%s</span><a href=\"%s/\">%s/</a></td>\n"
                        "            <td class=\"size\">%s</td>\n",
                        icon, entry->d_name, entry->d_name, size_str);
            } else {
                strcpy(icon, "📄");
                strcpy(type_str, "File");
                
                // Format file size
                if (file_stat.st_size < 1024) {
                    snprintf(size_str, sizeof(size_str), "%ld B", (long)file_stat.st_size);
                } else if (file_stat.st_size < 1024 * 1024) {
                    snprintf(size_str, sizeof(size_str), "%.1f KB", 
                            file_stat.st_size / 1024.0);
                } else if (file_stat.st_size < 1024 * 1024 * 1024) {
                    snprintf(size_str, sizeof(size_str), "%.1f MB", 
                            file_stat.st_size / (1024.0 * 1024.0));
                } else {
                    snprintf(size_str, sizeof(size_str), "%.1f GB", 
                            file_stat.st_size / (1024.0 * 1024.0 * 1024.0));
                }
                
                // Get file extension for type
                const char *dot = strrchr(entry->d_name, '.');
                if (dot) {
                    snprintf(type_str, sizeof(type_str), "%s File", dot + 1);
                } else {
                    strcpy(type_str, "File");
                }
                
                snprintf(html + pos, sizeof(html) - pos,
                        "        <tr class=\"file\">\n"
                        "            <td><span class=\"icon\">%s</span><a href=\"%s\">%s</a></td>\n"
                        "            <td class=\"size\">%s</td>\n",
                        icon, entry->d_name, entry->d_name, size_str);
            }
            
            // Format time
            struct tm *tm_info = localtime(&file_stat.st_mtime);
            strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
            
            pos += snprintf(html + pos, sizeof(html) - pos,
                           "            <td>%s</td>\n"
                           "            <td>%s</td>\n"
                           "        </tr>\n",
                           time_str, type_str);
        }
    }
    
    closedir(dir);
    
    pos += snprintf(html + pos, sizeof(html) - pos,
                   "        </tbody>\n"
                   "    </table>\n"
                   "    \n"
                   "    <div class=\"server-info\">\n"
                   "        <p><strong>Server:</strong> CLOBES PRO v%s</p>\n"
                   "        <p><strong>Path:</strong> %s</p>\n"
                   "        <p><strong>Generated:</strong> ",
                   CLOBES_VERSION, request_path);
    
    // Add current time
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char current_time[64];
    strftime(current_time, sizeof(current_time), "%Y-%m-%d %H:%M:%S", tm_info);
    pos += snprintf(html + pos, sizeof(html) - pos, "%s</p>\n", current_time);
    
    pos += snprintf(html + pos, sizeof(html) - pos,
                   "    </div>\n"
                   "</body>\n"
                   "</html>\n");
    
    // Prepare and send response
    HttpResponse response;
    response.status_code = 200;
    strcpy(response.status_text, "OK");
    response.header_count = 0;
    response.body = strdup(html);
    response.body_length = strlen(html);
    response.compressed = 0;
    
    // Compress if enabled and beneficial
    if (config->enable_gzip && response.body_length > 1024) {
        char *compressed;
        size_t compressed_size;
        if (compress_gzip(response.body, response.body_length, &compressed, &compressed_size) == 0) {
            if (compressed_size < response.body_length * 0.9) {
                free(response.body);
                response.body = compressed;
                response.body_length = compressed_size;
                response.compressed = 1;
                snprintf(response.headers[response.header_count++], MAX_HEADER_SIZE,
                        "Content-Encoding: gzip");
            } else {
                free(compressed);
            }
        }
    }
    
    snprintf(response.headers[response.header_count++], MAX_HEADER_SIZE,
             "Content-Type: text/html");
    snprintf(response.headers[response.header_count++], MAX_HEADER_SIZE,
             "Content-Length: %zu", response.body_length);
    snprintf(response.headers[response.header_count++], MAX_HEADER_SIZE,
             "Connection: close");
    snprintf(response.headers[response.header_count++], MAX_HEADER_SIZE,
             "Server: CLOBES-PRO/4.0.0");
    
    if (response.compressed) {
        snprintf(response.headers[response.header_count++], MAX_HEADER_SIZE,
                "Vary: Accept-Encoding");
    }
    
    // Send response
    if (use_ssl) {
        SSL *ssl = SSL_new(g_state.ssl_ctx);
        SSL_set_fd(ssl, client_socket);
        if (SSL_accept(ssl) <= 0) {
            SSL_free(ssl);
            free_http_response(&response);
            return 0;
        }
        ssl_send_http_response(ssl, &response);
        SSL_shutdown(ssl);
        SSL_free(ssl);
    } else {
        send_http_response(client_socket, &response);
    }
    
    free_http_response(&response);
    return 1;
}

// SSL version of serve_directory_listing
int ssl_serve_directory_listing(SSL *ssl, const char *path, const char *request_path, ServerConfig *config) {
    return serve_directory_listing(SSL_get_fd(ssl), path, request_path, config, 1);
}

// Serve default page (regular or SSL)
int serve_default_page(int client_socket, ServerConfig *config, int use_ssl) {
    // Create default files if they don't exist
    create_default_files(config);
    
    // Try to serve index.html
    char index_path[MAX_PATH];
    snprintf(index_path, sizeof(index_path), "%s/index.html", config->web_root);
    
    struct stat st;
    if (stat(index_path, &st) == 0 && S_ISREG(st.st_mode)) {
        return serve_static_file(client_socket, index_path, config, use_ssl);
    }
    
    // Fallback to generated default page
    char html[4096];
    snprintf(html, sizeof(html),
            "<!DOCTYPE html>\n"
            "<html>\n"
            "<head>\n"
            "    <title>CLOBES PRO Web Server</title>\n"
            "    <style>\n"
            "        body { font-family: Arial, sans-serif; margin: 0; padding: 0; background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%); min-height: 100vh; display: flex; align-items: center; justify-content: center; }\n"
            "        .container { background: rgba(255, 255, 255, 0.95); padding: 40px; border-radius: 15px; box-shadow: 0 20px 60px rgba(0,0,0,0.3); max-width: 800px; width: 90%%; text-align: center; }\n"
            "        h1 { color: #2c3e50; margin-bottom: 10px; }\n"
            "        .subtitle { color: #7f8c8d; margin-bottom: 30px; font-size: 1.2em; }\n"
            "        .features { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 30px 0; }\n"
            "        .feature { background: #f8f9fa; padding: 20px; border-radius: 10px; transition: transform 0.3s; }\n"
            "        .feature:hover { transform: translateY(-5px); box-shadow: 0 10px 20px rgba(0,0,0,0.1); }\n"
            "        .feature-icon { font-size: 2.5em; margin-bottom: 15px; }\n"
            "        .url-box { background: #e8f4f8; padding: 20px; border-radius: 10px; margin: 30px 0; font-family: monospace; font-size: 1.2em; word-break: break-all; }\n"
            "        .url-box a { color: #2c3e50; text-decoration: none; font-weight: bold; }\n"
            "        .url-box a:hover { text-decoration: underline; }\n"
            "        .btn { display: inline-block; background: #4CAF50; color: white; padding: 12px 30px; border-radius: 50px; text-decoration: none; font-weight: bold; margin: 10px; transition: background 0.3s; }\n"
            "        .btn:hover { background: #45a049; }\n"
            "        .btn.secondary { background: #3498db; }\n"
            "        .btn.secondary:hover { background: #2980b9; }\n"
            "        .info { margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee; color: #7f8c8d; font-size: 0.9em; }\n"
            "    </style>\n"
            "</head>\n"
            "<body>\n"
            "    <div class=\"container\">\n"
            "        <div style=\"font-size: 4em; margin-bottom: 20px;\">🚀</div>\n"
            "        <h1>CLOBES PRO Web Server</h1>\n"
            "        <p class=\"subtitle\">Ultimate Command Line Toolkit v%s</p>\n"
            "        \n"
            "        <div class=\"url-box\">\n"
            "            <strong>Server is running!</strong><br>\n"
            "            Access via: \n"
            "            <a href=\"http://localhost:%d\">http://localhost:%d</a><br>\n"
            "            <a href=\"http://%s:%d\">http://%s:%d</a>\n"
            "        </div>\n"
            "        \n"
            "        <div class=\"features\">\n"
            "            <div class=\"feature\">\n"
            "                <div class=\"feature-icon\">📁</div>\n"
            "                <h3>File Serving</h3>\n"
            "                <p>Serve static files with automatic MIME type detection</p>\n"
            "            </div>\n"
            "            <div class=\"feature\">\n"
            "                <div class=\"feature-icon\">🔒</div>\n"
            "                <h3>SSL/TLS</h3>\n"
            "                <p>Secure HTTPS connections with OpenSSL</p>\n"
            "            </div>\n"
            "            <div class=\"feature\">\n"
            "                <div class=\"feature-icon\">⚡</div>\n"
            "                <h3>GZIP Compression</h3>\n"
            "                <p>Automatic compression for faster loading</p>\n"
            "            </div>\n"
            "            <div class=\"feature\">\n"
            "                <div class=\"feature-icon\">🌐</div>\n"
            "                <h3>Public Access</h3>\n"
            "                <p>QR codes and public URL generation</p>\n"
            "            </div>\n"
            "        </div>\n"
            "        \n"
            "        <div>\n"
            "            <a href=\"/\" class=\"btn\">Refresh</a>\n"
            "            <a href=\"#\" onclick=\"window.location.reload()\" class=\"btn secondary\">Restart</a>\n"
            "        </div>\n"
            "        \n"
            "        <div class=\"info\">\n"
            "            <p>Put your files in <code>%s</code> to serve them automatically.</p>\n"
            "            <p>Default files: index.html, index.htm, default.html</p>\n"
            "        </div>\n"
            "    </div>\n"
            "</body>\n"
            "</html>\n",
            CLOBES_VERSION, config->port, config->port, 
            get_local_ip(), config->port, get_local_ip(), config->port,
            config->web_root);
    
    HttpResponse response;
    response.status_code = 200;
    strcpy(response.status_text, "OK");
    response.header_count = 0;
    response.body = strdup(html);
    response.body_length = strlen(html);
    response.compressed = 0;
    
    // Compress if enabled
    if (config->enable_gzip && response.body_length > 1024) {
        char *compressed;
        size_t compressed_size;
        if (compress_gzip(response.body, response.body_length, &compressed, &compressed_size) == 0) {
            if (compressed_size < response.body_length * 0.9) {
                free(response.body);
                response.body = compressed;
                response.body_length = compressed_size;
                response.compressed = 1;
                snprintf(response.headers[response.header_count++], MAX_HEADER_SIZE,
                        "Content-Encoding: gzip");
            } else {
                free(compressed);
            }
        }
    }
    
    snprintf(response.headers[response.header_count++], MAX_HEADER_SIZE,
             "Content-Type: text/html");
    snprintf(response.headers[response.header_count++], MAX_HEADER_SIZE,
             "Content-Length: %zu", response.body_length);
    snprintf(response.headers[response.header_count++], MAX_HEADER_SIZE,
             "Connection: close");
    snprintf(response.headers[response.header_count++], MAX_HEADER_SIZE,
             "Server: CLOBES-PRO/4.0.0");
    
    if (response.compressed) {
        snprintf(response.headers[response.header_count++], MAX_HEADER_SIZE,
                "Vary: Accept-Encoding");
    }
    
    // Send response
    if (use_ssl) {
        SSL *ssl = SSL_new(g_state.ssl_ctx);
        SSL_set_fd(ssl, client_socket);
        if (SSL_accept(ssl) <= 0) {
            SSL_free(ssl);
            free_http_response(&response);
            return 0;
        }
        ssl_send_http_response(ssl, &response);
        SSL_shutdown(ssl);
        SSL_free(ssl);
    } else {
        send_http_response(client_socket, &response);
    }
    
    free_http_response(&response);
    return 1;
}

// SSL version of serve_default_page
int ssl_serve_default_page(SSL *ssl, ServerConfig *config) {
    return serve_default_page(SSL_get_fd(ssl), config, 1);
}

// Parse HTTP request
int parse_http_request(int client_socket, HttpRequest *request, ServerConfig *config) {
    char buffer[BUFFER_SIZE];
    int bytes_read;
    
    // Read first line
    bytes_read = read(client_socket, buffer, sizeof(buffer) - 1);
    if (bytes_read <= 0) {
        return 0;
    }
    buffer[bytes_read] = '\0';
    
    // Parse request line
    char *line = strtok(buffer, "\r\n");
    if (!line) return 0;
    
    sscanf(line, "%15s %4095s %15s", 
           request->method, request->path, request->protocol);
    
    // Parse headers
    request->header_count = 0;
    request->accept_gzip = 0;
    
    while ((line = strtok(NULL, "\r\n")) != NULL) {
        if (strlen(line) == 0) break; // Empty line indicates end of headers
        
        if (request->header_count < MAX_HEADERS) {
            strncpy(request->headers[request->header_count], line, MAX_HEADER_SIZE - 1);
            request->headers[request->header_count][MAX_HEADER_SIZE - 1] = '\0';
            
            // Check for Accept-Encoding header
            if (strncasecmp(line, "Accept-Encoding:", 15) == 0) {
                if (strstr(line, "gzip") != NULL && config->enable_gzip) {
                    request->accept_gzip = 1;
                }
            }
            
            request->header_count++;
        }
    }
    
    // For now, we don't parse body for GET requests
    request->body = NULL;
    request->body_length = 0;
    
    return 1;
}

// SSL version of parse_http_request
int ssl_parse_http_request(SSL *ssl, HttpRequest *request, ServerConfig *config) {
    char buffer[BUFFER_SIZE];
    int bytes_read;
    
    // Read first line
    bytes_read = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (bytes_read <= 0) {
        return 0;
    }
    buffer[bytes_read] = '\0';
    
    // Parse request line
    char *line = strtok(buffer, "\r\n");
    if (!line) return 0;
    
    sscanf(line, "%15s %4095s %15s", 
           request->method, request->path, request->protocol);
    
    // Parse headers
    request->header_count = 0;
    request->accept_gzip = 0;
    
    while ((line = strtok(NULL, "\r\n")) != NULL) {
        if (strlen(line) == 0) break; // Empty line indicates end of headers
        
        if (request->header_count < MAX_HEADERS) {
            strncpy(request->headers[request->header_count], line, MAX_HEADER_SIZE - 1);
            request->headers[request->header_count][MAX_HEADER_SIZE - 1] = '\0';
            
            // Check for Accept-Encoding header
            if (strncasecmp(line, "Accept-Encoding:", 15) == 0) {
                if (strstr(line, "gzip") != NULL && config->enable_gzip) {
                    request->accept_gzip = 1;
                }
            }
            
            request->header_count++;
        }
    }
    
    // For now, we don't parse body for GET requests
    request->body = NULL;
    request->body_length = 0;
    
    return 1;
}

// Handle client connection (non-SSL)
int server_handle_client(int client_socket, ServerConfig *config) {
    HttpRequest request;
    
    if (!parse_http_request(client_socket, &request, config)) {
        close(client_socket);
        return 0;
    }
    
    // Log access
    if (config->show_access_log) {
        char client_ip[INET_ADDRSTRLEN];
        struct sockaddr_in addr;
        socklen_t addr_len = sizeof(addr);
        
        getpeername(client_socket, (struct sockaddr*)&addr, &addr_len);
        inet_ntop(AF_INET, &addr.sin_addr, client_ip, sizeof(client_ip));
        
        time_t now = time(NULL);
        char time_str[64];
        struct tm *tm_info = localtime(&now);
        strftime(time_str, sizeof(time_str), "%d/%b/%Y:%H:%M:%S %z", tm_info);
        
        printf("%s - - [%s] \"%s %s %s\" -\n", 
               client_ip, time_str, request.method, request.path, request.protocol);
    }
    
    // Handle request
    char filepath[MAX_PATH];
    
    // Remove query string if present
    char *question = strchr(request.path, '?');
    if (question) *question = '\0';
    
    // Special handling for favicon
    if (strcmp(request.path, "/favicon.ico") == 0) {
        char *favicon_path = find_favicon(config);
        if (favicon_path) {
            serve_static_file(client_socket, favicon_path, config, 0);
            close(client_socket);
            return 1;
        }
    }
    
    // Default to index if path is "/"
    if (strcmp(request.path, "/") == 0) {
        snprintf(filepath, sizeof(filepath), "%s", config->web_root);
        
        // Try to serve index file
        int served = 0;
        for (int i = 0; default_index_files[i] != NULL; i++) {
            char index_path[MAX_PATH];
            snprintf(index_path, sizeof(index_path), "%s/%s", 
                    config->web_root, default_index_files[i]);
            
            if (serve_static_file(client_socket, index_path, config, 0)) {
                served = 1;
                break;
            }
        }
        
        // If no index file found, serve default page
        if (!served) {
            serve_default_page(client_socket, config, 0);
        }
    } else {
        // Build full path
        snprintf(filepath, sizeof(filepath), "%s%s", config->web_root, request.path);
        
        // Check if file exists and serve it
        if (!serve_static_file(client_socket, filepath, config, 0)) {
            // File not found - send 404
            HttpResponse response;
            response.status_code = 404;
            strcpy(response.status_text, "Not Found");
            response.header_count = 0;
            response.compressed = 0;
            
            char *html = "<!DOCTYPE html><html><head><title>404 Not Found</title><style>body{font-family:Arial,sans-serif;margin:40px;text-align:center;}h1{color:#e74c3c;}.container{max-width:600px;margin:0 auto;}</style></head><body><div class=\"container\"><h1>404 Not Found</h1><p>The requested resource was not found on this server.</p><p><a href=\"/\">Go to homepage</a></p></div></body></html>";
            response.body = strdup(html);
            response.body_length = strlen(html);
            
            snprintf(response.headers[response.header_count++], MAX_HEADER_SIZE,
                     "Content-Type: text/html");
            snprintf(response.headers[response.header_count++], MAX_HEADER_SIZE,
                     "Content-Length: %zu", response.body_length);
            snprintf(response.headers[response.header_count++], MAX_HEADER_SIZE,
                     "Connection: close");
            snprintf(response.headers[response.header_count++], MAX_HEADER_SIZE,
                     "Server: CLOBES-PRO/4.0.0");
            
            send_http_response(client_socket, &response);
            free_http_response(&response);
        }
    }
    
    close(client_socket);
    return 1;
}

// Handle SSL client connection
int ssl_server_handle_client(SSL *ssl, ServerConfig *config) {
    HttpRequest request;
    
    if (!ssl_parse_http_request(ssl, &request, config)) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
        return 0;
    }
    
    // Log access
    if (config->show_access_log) {
        char client_ip[INET_ADDRSTRLEN];
        struct sockaddr_in addr;
        socklen_t addr_len = sizeof(addr);
        
        getpeername(SSL_get_fd(ssl), (struct sockaddr*)&addr, &addr_len);
        inet_ntop(AF_INET, &addr.sin_addr, client_ip, sizeof(client_ip));
        
        time_t now = time(NULL);
        char time_str[64];
        struct tm *tm_info = localtime(&now);
        strftime(time_str, sizeof(time_str), "%d/%b/%Y:%H:%M:%S %z", tm_info);
        
        printf("%s - - [%s] \"%s %s %s\" [HTTPS]\n", 
               client_ip, time_str, request.method, request.path, request.protocol);
    }
    
    // Handle request
    char filepath[MAX_PATH];
    
    // Remove query string if present
    char *question = strchr(request.path, '?');
    if (question) *question = '\0';
    
    // Special handling for favicon
    if (strcmp(request.path, "/favicon.ico") == 0) {
        char *favicon_path = find_favicon(config);
        if (favicon_path) {
            ssl_serve_static_file(ssl, favicon_path, config);
            SSL_shutdown(ssl);
            SSL_free(ssl);
            return 1;
        }
    }
    
    // Default to index if path is "/"
    if (strcmp(request.path, "/") == 0) {
        snprintf(filepath, sizeof(filepath), "%s", config->web_root);
        
        // Try to serve index file
        int served = 0;
        for (int i = 0; default_index_files[i] != NULL; i++) {
            char index_path[MAX_PATH];
            snprintf(index_path, sizeof(index_path), "%s/%s", 
                    config->web_root, default_index_files[i]);
            
            if (ssl_serve_static_file(ssl, index_path, config)) {
                served = 1;
                break;
            }
        }
        
        // If no index file found, serve default page
        if (!served) {
            ssl_serve_default_page(ssl, config);
        }
    } else {
        // Build full path
        snprintf(filepath, sizeof(filepath), "%s%s", config->web_root, request.path);
        
        // Check if file exists and serve it
        if (!ssl_serve_static_file(ssl, filepath, config)) {
            // File not found - send 404
            HttpResponse response;
            response.status_code = 404;
            strcpy(response.status_text, "Not Found");
            response.header_count = 0;
            response.compressed = 0;
            
            char *html = "<!DOCTYPE html><html><head><title>404 Not Found</title><style>body{font-family:Arial,sans-serif;margin:40px;text-align:center;}h1{color:#e74c3c;}.container{max-width:600px;margin:0 auto;}</style></head><body><div class=\"container\"><h1>404 Not Found</h1><p>The requested resource was not found on this server.</p><p><a href=\"/\">Go to homepage</a></p></div></body></html>";
            response.body = strdup(html);
            response.body_length = strlen(html);
            
            snprintf(response.headers[response.header_count++], MAX_HEADER_SIZE,
                     "Content-Type: text/html");
            snprintf(response.headers[response.header_count++], MAX_HEADER_SIZE,
                     "Content-Length: %zu", response.body_length);
            snprintf(response.headers[response.header_count++], MAX_HEADER_SIZE,
                     "Connection: close");
            snprintf(response.headers[response.header_count++], MAX_HEADER_SIZE,
                     "Server: CLOBES-PRO/4.0.0");
            
            ssl_send_http_response(ssl, &response);
            free_http_response(&response);
        }
    }
    
    SSL_shutdown(ssl);
    SSL_free(ssl);
    return 1;
}

// Server thread function (non-SSL)
void* server_thread_func(void *arg) {
    ServerConfig *config = (ServerConfig *)arg;
    
    // Create socket
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        print_error("Failed to create socket");
        return NULL;
    }
    
    // Set socket options
    int opt = 1;
    setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    // Bind socket
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(config->port);
    
    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        print_error("Failed to bind socket to port %d", config->port);
        close(server_socket);
        return NULL;
    }
    
    // Listen for connections
    if (listen(server_socket, config->max_connections) < 0) {
        print_error("Failed to listen on socket");
        close(server_socket);
        return NULL;
    }
    
    print_success("HTTP server started on port %d", config->port);
    print_info("Web root: %s", config->web_root);
    print_info("Local URL: http://localhost:%d", config->port);
    print_info("Network URL: http://%s:%d", get_local_ip(), config->port);
    
    server_running = 1;
    
    // Main server loop
    while (server_running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        
        fd_set read_fds;
        struct timeval timeout;
        
        FD_ZERO(&read_fds);
        FD_SET(server_socket, &read_fds);
        
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        
        int ready = select(server_socket + 1, &read_fds, NULL, NULL, &timeout);
        
        if (ready < 0) {
            if (errno != EINTR) {
                print_error("Select error");
                break;
            }
        } else if (ready > 0 && FD_ISSET(server_socket, &read_fds)) {
            int client_socket = accept(server_socket, 
                                      (struct sockaddr *)&client_addr, 
                                      &client_len);
            
            if (client_socket >= 0) {
                // Handle client in same thread (simple implementation)
                server_handle_client(client_socket, config);
            }
        }
    }
    
    close(server_socket);
    server_socket = -1;
    return NULL;
}

// SSL Server thread function
void* ssl_server_thread_func(void *arg) {
    ServerConfig *config = (ServerConfig *)arg;
    
    // Create socket
    ssl_server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (ssl_server_socket < 0) {
        print_error("Failed to create SSL socket");
        return NULL;
    }
    
    // Set socket options
    int opt = 1;
    setsockopt(ssl_server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    // Bind socket
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(config->ssl_port);
    
    if (bind(ssl_server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        print_error("Failed to bind SSL socket to port %d", config->ssl_port);
        close(ssl_server_socket);
        return NULL;
    }
    
    // Listen for connections
    if (listen(ssl_server_socket, config->max_connections) < 0) {
        print_error("Failed to listen on SSL socket");
        close(ssl_server_socket);
        return NULL;
    }
    
    print_success("HTTPS server started on port %d", config->ssl_port);
    
    // Main server loop for SSL
    while (server_running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        
        fd_set read_fds;
        struct timeval timeout;
        
        FD_ZERO(&read_fds);
        FD_SET(ssl_server_socket, &read_fds);
        
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        
        int ready = select(ssl_server_socket + 1, &read_fds, NULL, NULL, &timeout);
        
        if (ready < 0) {
            if (errno != EINTR) {
                print_error("SSL Select error");
                break;
            }
        } else if (ready > 0 && FD_ISSET(ssl_server_socket, &read_fds)) {
            int client_socket = accept(ssl_server_socket, 
                                      (struct sockaddr *)&client_addr, 
                                      &client_len);
            
            if (client_socket >= 0) {
                // Create SSL connection
                SSL *ssl = SSL_new(g_state.ssl_ctx);
                SSL_set_fd(ssl, client_socket);
                
                if (SSL_accept(ssl) <= 0) {
                    ERR_print_errors_fp(stderr);
                    SSL_free(ssl);
                    close(client_socket);
                } else {
                    // Handle SSL client
                    ssl_server_handle_client(ssl, config);
                }
            }
        }
    }
    
    close(ssl_server_socket);
    ssl_server_socket = -1;
    return NULL;
}

// Start HTTP server
int http_server_start(ServerConfig *config) {
    // Get current directory
    if (getcwd(config->current_directory, sizeof(config->current_directory)) == NULL) {
        strcpy(config->current_directory, ".");
    }
    
    // Create web root directory if it doesn't exist
    struct stat st;
    if (stat(config->web_root, &st) != 0) {
        if (mkdir(config->web_root, 0755) != 0) {
            print_error("Failed to create web root directory: %s", config->web_root);
            return 1;
        }
        print_info("Created web root directory: %s", config->web_root);
    }
    
    // Create default files
    create_default_files(config);
    
    // Start HTTP server thread
    if (pthread_create(&server_thread, NULL, server_thread_func, config) != 0) {
        print_error("Failed to create server thread");
        return 1;
    }
    
    // Start SSL server if enabled
    if (config->enable_ssl) {
        // Initialize SSL
        if (init_ssl_context(config) != 0) {
            print_error("Failed to initialize SSL context");
            // Continue without SSL
            config->enable_ssl = 0;
        } else {
            // Start SSL server thread
            if (pthread_create(&ssl_server_thread, NULL, ssl_server_thread_func, config) != 0) {
                print_error("Failed to create SSL server thread");
                config->enable_ssl = 0;
            } else {
                pthread_detach(ssl_server_thread);
            }
        }
    }
    
    // Detach threads
    pthread_detach(server_thread);
    
    global_config = config;
    
    return 0;
}

// Print server information
void print_server_info(ServerConfig *config, const char *public_url) {
    printf("\n" COLOR_CYAN STYLE_BOLD "🚀 CLOBES PRO WEB SERVER\n" COLOR_RESET);
    printf("══════════════════════════════════════════\n\n");
    
    printf(COLOR_GREEN "✓ Server Status: " COLOR_BRIGHT_GREEN "RUNNING\n" COLOR_RESET);
    printf("HTTP Port:       %d\n", config->port);
    if (config->enable_ssl) {
        printf("HTTPS Port:      %d " COLOR_GREEN "(SSL Enabled)\n" COLOR_RESET, config->ssl_port);
    }
    printf("Web Root:        %s\n", config->web_root);
    printf("Directory List:  %s\n", config->allow_directory_listing ? "Enabled" : "Disabled");
    printf("GZIP Compression:%s\n", config->enable_gzip ? "Enabled" : "Disabled");
    printf("Max Connections: %d\n", config->max_connections);
    
    printf("\n" COLOR_CYAN "🔗 Access URLs:\n" COLOR_RESET);
    printf("Local HTTP:      http://localhost:%d\n", config->port);
    printf("Network HTTP:    http://%s:%d\n", get_local_ip(), config->port);
    if (config->enable_ssl) {
        printf("Local HTTPS:     https://localhost:%d\n", config->ssl_port);
        printf("Network HTTPS:   https://%s:%d\n", get_local_ip(), config->ssl_port);
    }
    
    if (public_url) {
        printf("Public URL:      %s\n", public_url);
    }
    
    // Try to find favicon
    char *favicon_path = find_favicon(config);
    if (favicon_path) {
        printf("Favicon:         Found at %s\n", favicon_path);
    }
    
    printf("\n" COLOR_CYAN "📁 Quick Start:\n" COLOR_RESET);
    printf("1. Put files in: %s\n", config->web_root);
    printf("2. Default file: index.html (auto-created)\n");
    printf("3. Favicon:      favicon.ico (auto-detected)\n");
    printf("4. Access from browser using URLs above\n");
    
    if (config->generate_qr_code && public_url) {
        printf("\n" COLOR_CYAN "📱 QR Code (Scan with phone):\n" COLOR_RESET);
        generate_qr_code(public_url, NULL);
    }
    
    printf("\n" COLOR_YELLOW "Press Ctrl+C to stop the server\n" COLOR_RESET);
    printf("\n" COLOR_BRIGHT_CYAN "Server logs will appear below:\n" COLOR_RESET);
    printf("══════════════════════════════════════════\n");
}

// Server stop function
void server_stop(int signal) {
    (void)signal;
    printf("\n\n" COLOR_YELLOW "Stopping server..." COLOR_RESET "\n");
    
    server_running = 0;
    
    if (server_socket != -1) {
        close(server_socket);
        server_socket = -1;
    }
    
    if (ssl_server_socket != -1) {
        close(ssl_server_socket);
        ssl_server_socket = -1;
    }
    
    cleanup_ssl();
    
    printf(COLOR_GREEN "✓ Server stopped successfully\n" COLOR_RESET);
    exit(0);
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
    printf(" ssl");
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
    printf("  clobes server start --port 8080 --ssl --gzip --public --qr\n");
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

// Command: server
int cmd_server(int argc, char **argv) {
    if (argc < 3) {
        printf(COLOR_CYAN "🌐 HTTP SERVER COMMANDS\n" COLOR_RESET);
        printf("══════════════════════════════════════════\n\n");
        
        printf("  start [options]        - Start HTTP/HTTPS server\n");
        printf("  stop                   - Stop server\n");
        printf("  status                 - Server status\n");
        printf("\n");
        printf("Options:\n");
        printf("  --port <num>           - HTTP port (default: 8080)\n");
        printf("  --ssl-port <num>       - HTTPS port (default: 8443)\n");
        printf("  --root <path>          - Web root directory (default: ./www)\n");
        printf("  --public               - Generate public URL\n");
        printf("  --qr                   - Show QR code\n");
        printf("  --dir-list             - Enable directory listing\n");
        printf("  --ssl                  - Enable HTTPS/SSL\n");
        printf("  --gzip                 - Enable GZIP compression\n");
        printf("  --cert <file>          - SSL certificate file\n");
        printf("  --key <file>           - SSL private key file\n");
        printf("  --domain <domain>      - Custom domain\n");
        printf("  --search-favicon       - Search for favicon in current dir\n");
        printf("\n");
        printf("Examples:\n");
        printf("  clobes server start --port 8080\n");
        printf("  clobes server start --ssl --gzip --public --qr\n");
        printf("  clobes server start --root ./public --dir-list\n");
        return 0;
    }
    
    if (strcmp(argv[2], "start") == 0) {
        ServerConfig config = {
            .port = 8080,
            .ssl_port = 8443,
            .max_connections = 100,
            .timeout = 30,
            .keep_alive = 1,
            .worker_threads = 4,
            .enable_ssl = 0,
            .enable_gzip = 0,
            .show_access_log = 1,
            .maintenance_mode = 0,
            .allow_directory_listing = 0,
            .enable_public_url = 0,
            .generate_qr_code = 0,
            .auto_find_favicon = 1,
            .search_current_dir = 0
        };
        
        strcpy(config.ip_address, "0.0.0.0");
        strcpy(config.web_root, "./www");
        strcpy(config.maintenance_message, "Server is under maintenance");
        strcpy(config.custom_domain, "");
        strcpy(config.ssl_cert, "cert.pem");
        strcpy(config.ssl_key, "key.pem");
        strcpy(config.current_directory, ".");
        
        // Parse options
        for (int i = 3; i < argc; i++) {
            if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
                config.port = atoi(argv[++i]);
            } else if (strcmp(argv[i], "--ssl-port") == 0 && i + 1 < argc) {
                config.ssl_port = atoi(argv[++i]);
            } else if (strcmp(argv[i], "--root") == 0 && i + 1 < argc) {
                strncpy(config.web_root, argv[++i], sizeof(config.web_root) - 1);
            } else if (strcmp(argv[i], "--public") == 0) {
                config.enable_public_url = 1;
            } else if (strcmp(argv[i], "--qr") == 0) {
                config.generate_qr_code = 1;
            } else if (strcmp(argv[i], "--dir-list") == 0) {
                config.allow_directory_listing = 1;
            } else if (strcmp(argv[i], "--ssl") == 0) {
                config.enable_ssl = 1;
            } else if (strcmp(argv[i], "--gzip") == 0) {
                config.enable_gzip = 1;
            } else if (strcmp(argv[i], "--cert") == 0 && i + 1 < argc) {
                strncpy(config.ssl_cert, argv[++i], sizeof(config.ssl_cert) - 1);
            } else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
                strncpy(config.ssl_key, argv[++i], sizeof(config.ssl_key) - 1);
            } else if (strcmp(argv[i], "--domain") == 0 && i + 1 < argc) {
                strncpy(config.custom_domain, argv[++i], sizeof(config.custom_domain) - 1);
            } else if (strcmp(argv[i], "--search-favicon") == 0) {
                config.search_current_dir = 1;
            } else if (strcmp(argv[i], "--no-log") == 0) {
                config.show_access_log = 0;
            } else if (strcmp(argv[i], "--help") == 0) {
                return cmd_server(2, argv);
            } else if (strcmp(argv[i], "-h") == 0) {
                return cmd_server(2, argv);
            }
        }
        
        // Check port range
        if (config.port < 1 || config.port > 65535) {
            print_error("Invalid HTTP port number: %d", config.port);
            return 1;
        }
        
        if (config.enable_ssl && (config.ssl_port < 1 || config.ssl_port > 65535)) {
            print_error("Invalid HTTPS port number: %d", config.ssl_port);
            return 1;
        }
        
        print_info("Starting HTTP server on port %d...", config.port);
        if (config.enable_ssl) {
            print_info("Starting HTTPS server on port %d...", config.ssl_port);
            
            // Check for SSL certificate
            struct stat st;
            if (stat(config.ssl_cert, &st) != 0 || stat(config.ssl_key, &st) != 0) {
                print_warning("SSL certificate not found. Generating self-signed certificate...");
                char cmd[512];
                snprintf(cmd, sizeof(cmd),
                        "openssl req -x509 -newkey rsa:4096 -keyout %s -out %s -days 365 -nodes "
                        "-subj \"/C=FR/ST=Paris/L=Paris/O=CLOBES/CN=localhost\" 2>/dev/null",
                        config.ssl_key, config.ssl_cert);
                system(cmd);
                print_success("Self-signed certificate generated");
            }
        }
        
        // Start server
        if (http_server_start(&config) != 0) {
            print_error("Failed to start server");
            return 1;
        }
        
        // Generate public URL if requested
        char *public_url = NULL;
        if (config.enable_public_url) {
            public_url = generate_public_url(&config);
            if (public_url) {
                print_info("Public URL: %s", public_url);
            }
        }
        
        // Print server info
        print_server_info(&config, public_url);
        
        // Install signal handler for Ctrl+C
        signal(SIGINT, server_stop);
        signal(SIGTERM, server_stop);
        
        // Wait for server to run
        while (server_running) {
            sleep(1);
        }
        
        return 0;
        
    } else if (strcmp(argv[2], "stop") == 0) {
        server_stop(0);
        print_success("Server stopped");
        return 0;
    } else if (strcmp(argv[2], "status") == 0) {
        printf("Server status: %s\n", server_running ? "Running" : "Stopped");
        if (server_running && global_config) {
            printf("Port: %d\n", global_config->port);
            if (global_config->enable_ssl) {
                printf("SSL Port: %d\n", global_config->ssl_port);
            }
            printf("Web Root: %s\n", global_config->web_root);
        }
        return 0;
    }
    
    print_error("Unknown server command: %s", argv[2]);
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
        .description = "HTTP/HTTPS server operations",
        .usage = "clobes server [start|stop|status] [options]",
        .category = CATEGORY_SERVER,
        .min_args = 1,
        .max_args = 20,
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
    
    // Initialize OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    
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
    
    // Cleanup OpenSSL
    cleanup_ssl();
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
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
    printf("Try 'clobes -i' for interactive mode (like curl -i)\n");
    
    clobes_cleanup();
    return 1;
}
