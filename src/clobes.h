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

// Version
#define CLOBES_VERSION "4.1.0"
#define CLOBES_CODENAME "Alpine Edition"
#define CLOBES_BUILD __DATE__ " " __TIME__

// Constants
#define MAX_CMD_LENGTH 8192
#define MAX_OUTPUT_SIZE 65536
#define MAX_PATH 4096
#define BUFFER_SIZE 8192
#define DEFAULT_PORT 8080

// Colors
#define COLOR_RESET     "\033[0m"
#define COLOR_RED       "\033[31m"
#define COLOR_GREEN     "\033[32m"
#define COLOR_YELLOW    "\033[33m"
#define COLOR_BLUE      "\033[34m"
#define COLOR_CYAN      "\033[36m"

// Log levels
typedef enum {
    LOG_ERROR,
    LOG_WARNING,
    LOG_INFO,
    LOG_DEBUG
} LogLevel;

// Command categories
typedef enum {
    CATEGORY_NETWORK,
    CATEGORY_SYSTEM,
    CATEGORY_SERVER,
    CATEGORY_CRYPTO
} Category;

// Command structure
typedef struct {
    char name[32];
    char description[256];
    char usage[512];
    Category category;
    int (*handler)(int, char**);
} Command;

// Configuration
typedef struct {
    int timeout;
    int verify_ssl;
    int colors;
} Config;

// Global state
typedef struct {
    Config config;
    int debug_mode;
} GlobalState;

// Server Configuration
typedef struct {
    int port;
    char web_root[256];
    int show_access_log;
} ServerConfig;

// Function prototypes
void print_success(const char *format, ...);
void print_error(const char *format, ...);
void print_warning(const char *format, ...);
void print_info(const char *format, ...);
void print_banner();

// HTTP client
char* http_get_simple(const char *url);
int http_download(const char *url, const char *output);

// Commands
int cmd_version(int argc, char **argv);
int cmd_help(int argc, char **argv);
int cmd_network(int argc, char **argv);
int cmd_system(int argc, char **argv);
int cmd_crypto(int argc, char **argv);
int cmd_server(int argc, char **argv);

// Registry
void register_commands();
Command* find_command(const char *name);

// Main
int main(int argc, char **argv);

// Global state
extern GlobalState g_state;

#endif // CLOBES_PRO_H
