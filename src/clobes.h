#ifndef CLOBES_PRO_H
#define CLOBES_PRO_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/utsname.h>
#include <sys/sysinfo.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <libgen.h>
#include <ifaddrs.h>
#include <pthread.h>
#include <curl/curl.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>

// Version
#define CLOBES_VERSION "4.1.0"
#define CLOBES_CODENAME "Thunderbolt Plus"
#define CLOBES_BUILD __DATE__ " " __TIME__

// Constants
#define MAX_CMD_LENGTH 8192
#define MAX_OUTPUT_SIZE 65536
#define MAX_ARGS 128
#define MAX_PATH 4096
#define MAX_URL 2048
#define MAX_CLIENTS 100
#define BUFFER_SIZE 8192
#define DEFAULT_PORT 8080
#define DEFAULT_SSL_PORT 8443
#define MAX_MIME_TYPES 50

// Colors
#define COLOR_RESET     "\033[0m"
#define COLOR_RED       "\033[31m"
#define COLOR_GREEN     "\033[32m"
#define COLOR_YELLOW    "\033[33m"
#define COLOR_BLUE      "\033[34m"
#define COLOR_MAGENTA   "\033[35m"
#define COLOR_CYAN      "\033[36m"
#define COLOR_WHITE     "\033[37m"
#define COLOR_BRIGHT_RED     "\033[91m"
#define COLOR_BRIGHT_GREEN   "\033[92m"
#define COLOR_BRIGHT_YELLOW  "\033[93m"
#define COLOR_BRIGHT_BLUE    "\033[94m"
#define COLOR_BRIGHT_CYAN    "\033[96m"
#define COLOR_BRIGHT_WHITE   "\033[97m"

// Styles
#define STYLE_BOLD      "\033[1m"
#define STYLE_UNDERLINE "\033[4m"

// Log levels
typedef enum {
    LOG_FATAL = 0,
    LOG_ERROR,
    LOG_WARNING,
    LOG_INFO,
    LOG_DEBUG,
    LOG_TRACE
} LogLevel;

// Command categories
typedef enum {
    CATEGORY_NETWORK,
    CATEGORY_FILE,
    CATEGORY_SYSTEM,
    CATEGORY_CRYPTO,
    CATEGORY_DEV,
    CATEGORY_SERVER,
    CATEGORY_WEB,
    CATEGORY_UNKNOWN
} Category;

// MIME type structure
typedef struct {
    char extension[16];
    char mime_type[64];
} MimeType;

// Client connection structure
typedef struct {
    int socket;
    struct sockaddr_in address;
    time_t connect_time;
    pthread_t thread;
    char ip[INET_ADDRSTRLEN];
} ClientInfo;

// Server session structure
typedef struct {
    int server_socket;
    int running;
    int client_count;
    ClientInfo clients[MAX_CLIENTS];
    pthread_t accept_thread;
    ServerConfig *config;
} ServerSession;

// Server Configuration
typedef struct {
    int port;
    int ssl_port;
    char ip_address[64];
    int max_connections;
    int timeout;
    int keep_alive;
    int worker_threads;
    char ssl_cert[256];
    char ssl_key[256];
    int enable_ssl;
    int enable_gzip;
    char web_root[256];
    int show_access_log;
    int maintenance_mode;
    char maintenance_message[1024];
    // New fields
    int enable_php;
    char index_files[5][32];
    char php_cgi_path[256];
    int enable_directory_listing;
    char custom_domain[256];
    int public_url_enabled;
    int qr_code_enabled;
    int auto_open_browser;
    char default_page[256];
} ServerConfig;

// Command structure
typedef struct {
    char name[32];
    char description[256];
    char usage[512];
    Category category;
    int min_args;
    int max_args;
    int (*handler)(int, char**);
    char aliases[5][16];
    int alias_count;
} Command;

// Configuration
typedef struct {
    int timeout;
    int cache_enabled;
    char user_agent[128];
    int verify_ssl;
    int colors;
    int progress_bars;
    int verbose;
    // New features
    int enable_websocket;
    int enable_jwt;
    int enable_cache;
    int enable_gzip;
    int enable_proxy;
} Config;

// Global state
typedef struct {
    Config config;
    int cache_hits;
    int cache_misses;
    long total_requests;
    double total_request_time;
    int debug_mode;
    LogLevel log_level;
    ServerSession *server_session;
} GlobalState;

// HTTP Request structure
typedef struct {
    char method[16];
    char path[1024];
    char version[16];
    char query_string[1024];
    char headers[10][256];
    int header_count;
    char body[8192];
} HttpRequest;

// Function prototypes

// Logging
void log_message(LogLevel level, const char *format, ...);
void print_success(const char *format, ...);
void print_error(const char *format, ...);
void print_warning(const char *format, ...);
void print_info(const char *format, ...);
void print_debug(const char *format, ...);
void print_banner();
void print_progress_bar(long current, long total, const char *label);

// HTTP client
char* http_get_simple(const char *url);
char* http_get_advanced(const char *url, int show_headers, int follow_redirects, int timeout);
char* http_post_simple(const char *url, const char *data);
char* http_post_advanced(const char *url, const char *data, const char *content_type, int show_headers);
int http_download(const char *url, const char *output, int show_progress);

// Base64 functions
char* base64_encode(const char *input, size_t length);
char* base64_decode(const char *input, size_t *output_length);

// Server functions
int cmd_server(int argc, char **argv);
int http_server_start(ServerConfig *config);
void http_server_stop(ServerSession *session);
void server_handle_request(int client_socket, ServerConfig *config);
int parse_http_request(const char *request, HttpRequest *req);
void serve_static_file(int client_socket, const char *file_path, ServerConfig *config);
void execute_php(int client_socket, const char *php_file, const char *query_string, ServerConfig *config);
void generate_directory_listing(int client_socket, const char *dir_path, const char *request_path, ServerConfig *config);
const char* get_mime_type(const char *filename);
void url_decode(char *dst, const char *src);
char* get_local_ip();
void generate_qr_code(const char *url);
void open_browser(const char *url);
char* find_index_file(const char *dir_path, ServerConfig *config);

// Commands
int cmd_version(int argc, char **argv);
int cmd_help(int argc, char **argv);
int cmd_network(int argc, char **argv);
int cmd_system(int argc, char **argv);
int cmd_file(int argc, char **argv);
int cmd_crypto(int argc, char **argv);
int cmd_dev(int argc, char **argv);
int cmd_proxy(int argc, char **argv);
int cmd_jwt(int argc, char **argv);
int cmd_websocket(int argc, char **argv);
int cmd_cache(int argc, char **argv);

// Interactive mode
int interactive_mode();

// Registry
void register_commands();
Command* find_command(const char *name);

// Initialization
int clobes_init(int argc, char **argv);
void clobes_cleanup();

// Utility functions
int file_exists(const char *path);
int dir_exists(const char *path);
long get_file_size(const char *path);

// Main
int main(int argc, char **argv);

// Global state
extern GlobalState g_state;

#endif // CLOBES_PRO_H
