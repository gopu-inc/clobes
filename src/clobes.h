#ifndef CLOBES_PRO_ULTRA_H
#define CLOBES_PRO_ULTRA_H

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
#include <dirent.h>
#include <pthread.h>
#include <curl/curl.h>

// Version
#define CLOBES_VERSION "5.0.0"
#define CLOBES_CODENAME "Alpine Thunder"
#define CLOBES_BUILD __DATE__ " " __TIME__

// Constants
#define MAX_CMD_LENGTH 8192
#define MAX_OUTPUT_SIZE 65536
#define MAX_PATH 4096
#define BUFFER_SIZE 8192
#define DEFAULT_PORT 8080
#define MAX_CLIENTS 10
#define MAX_MIME_TYPES 30

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

// Styles
#define STYLE_BOLD      "\033[1m"
#define STYLE_UNDERLINE "\033[4m"

// MIME type structure
typedef struct {
    char extension[16];
    char mime_type[64];
} MimeType;

// Client connection structure
typedef struct {
    int socket;
    struct sockaddr_in address;
    char ip[INET_ADDRSTRLEN];
} ClientInfo;

// Server session structure
typedef struct {
    int server_socket;
    int running;
    int port;
    char web_root[256];
    pthread_t thread;
} ServerSession;

// Command structure
typedef struct {
    char name[32];
    char description[256];
    char usage[512];
    int (*handler)(int, char**);
    char aliases[3][16];
    int alias_count;
} Command;

// Global state
typedef struct {
    int colors;
    int debug_mode;
    int total_requests;
    ServerSession *server_session;
} GlobalState;

// Function prototypes
void print_success(const char *format, ...);
void print_error(const char *format, ...);
void print_warning(const char *format, ...);
void print_info(const char *format, ... print_info(const char *format, ...);
void);
void print_debug(const char *format, ...);
void print_banner();
void print_progress_bar(long current, long total, const char *label);
void print_table_header(const char **headers, int count);
void print_table_row(const char **cells, int count);

// HTTP client
char* http_get(const char *url, int show_headers, int timeout);
char* http_post(const char *url, const char *data, const char *content_type);
int http_download(const char *url, const char *output, int show_progress);

// File operations
int file_exists(const char *path);
int dir_exists(const char *path);
long get_file_size(const char *path);
void file_info(const char *path);
int find_files(const char *dir, const char *pattern, int recursive);
int calculate_hash(const char *path, const char *algorithm);

// System operations
void system_info();
void process_list(int detailed);
void disk_usage();
void memory_info();
void network_info();
 print_debug(const char *format, ...);
void print_banner();
void print_progress_bar(long current, long total, const char *label);
void print_table_header(const char **headers, int count);
void print_table_row(const char **cells, int count);

// HTTP client
char* http_get(const char *url, int show_headers, int timeout);
char* http_post(const char *url, const char *data, const char *content_type);
int http_download(const char *url, const char *output, int show_progress);

// File operations
int file_exists(const char *path);
int dir_exists(const char *path);
long get_file_size(const char *path);
void file_info(const char *path);
int find_files(const char *dir, const char *pattern, int recursive);
int calculate_hash(const char *path, const char *algorithm);

// System operations
void system_info();
void process_list(int detailed);
void disk_usage();
void memory_info();
void network_info();
void cpu_info();

// Crypto operations
void cpu_info();

// Crypto operations
char*char* base64_encode(const char *input);
 base64_encode(const char *input);
char* base64_decode(const char *char* base64_decode(const char *input);
input);
char* md5_hash(const char *char* md5_hash(const char *input);
char* sha256_hash(constinput);
char* sha256_hash(const char * char *input);
void generate_password(int length,input);
void generate_password(int length, int use_symbols);

// Server int use_symbols);

// Server operations operations
int start_http_server
int start_http_server(int port, const char *web_root(int port, const char *web_root, int enable_listing);
void stop_, int enable_listing);
void stop_http_server();
void server_status();

http_server();
void server_status();

// Commands
int cmd_version(int// Commands
int cmd_version(int argc, argc, char **argv);
int cmd_help char **argv);
int cmd_help(int argc, char **argv);
int(int argc, char **argv);
int cmd_ cmd_network(int argc, char **argv);
network(int argc, char **argv);
int cmd_system(int argc, charint cmd_system(int argc, char **argv **argv);
int cmd_file(int argc, char);
int cmd_file(int argc, char **argv);
int cmd_crypto(int **argv);
int cmd_crypto(int argc, char **argv);
int cmd_server(int argc, char **argv);
int cmd_server(int argc, char **argv);
int cmd argc, char **argv);
int cmd_dev(int argc, char **argv);
_dev(int argc, char **argv);
int cmdint cmd_web(int argc, char **argv_web(int argc, char **argv);

// Interactive mode
int interactive_mode);

// Interactive mode
int interactive_mode();
void();
void print_welcome();

// Registry
void print_welcome();

// Registry
void register_commands();
Command* find_command register_commands();
Command* find_command(const char *name);
void print_command(const char *name);
void print_command_list();

// Utilities
char* get_local_ip();
void generate_qr_code_list();

// Utilities
char* get_local_ip();
void generate_qr_code(const char(const char *url);
void open_url(const char *url);
void open_url(const char *url);
int is_url *url);
int is_url(const char *str);
char* trim_string(char *str);
void print_col(const char *str);
char* trim_string(char *str);
void print_colored(const char *color, const charored(const char *color, const char *text *text);

// Main
int main(int argc);

// Main
int main(int argc, char **argv);

// Global state
extern GlobalState g_state;

#endif // C, char **argv);

// Global state
extern GlobalState g_state;

#endif // CLOBES_PRO_ULTRA_H
