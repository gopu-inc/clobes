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

// SEULEMENT curl pour commencer
#include <curl/curl.h>

// Version
#define CLOBES_VERSION "4.0.0"
#define CLOBES_CODENAME "Thunderbolt"
#define CLOBES_BUILD __DATE__ " " __TIME__

// Constants - réduisez pour commencer
#define MAX_CMD_LENGTH 2048
#define MAX_OUTPUT_SIZE 65536
#define MAX_ARGS 128
#define MAX_PATH 4096

// Couleurs simplifiées
#define COLOR_RESET     "\033[0m"
#define COLOR_RED       "\033[31m"
#define COLOR_GREEN     "\033[32m"
#define COLOR_YELLOW    "\033[33m"
#define COLOR_BLUE      "\033[34m"
#define COLOR_CYAN      "\033[36m"
#define COLOR_WHITE     "\033[37m"
#define COLOR_BRIGHT_RED     "\033[91m"
#define COLOR_BRIGHT_GREEN   "\033[92m"
#define COLOR_BRIGHT_YELLOW  "\033[93m"
#define COLOR_BRIGHT_CYAN    "\033[96m"

// Styles
#define STYLE_BOLD      "\033[1m"

// Log levels
typedef enum {
    LOG_FATAL = 0,
    LOG_ERROR,
    LOG_WARNING,
    LOG_INFO,
    LOG_DEBUG,
    LOG_TRACE
} LogLevel;

// Command categories - réduisez
typedef enum {
    CATEGORY_NETWORK,
    CATEGORY_FILE,
    CATEGORY_SYSTEM,
    CATEGORY_CRYPTO,
    CATEGORY_DEV,
    CATEGORY_UNKNOWN
} Category;

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
} GlobalState;

// Function prototypes - SEULEMENT les fonctions que vous utilisez
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
char* http_post_simple(const char *url, const char *data);
int http_download(const char *url, const char *output, int show_progress);

// Commands
int cmd_version(int argc, char **argv);
int cmd_help(int argc, char **argv);
int cmd_network(int argc, char **argv);
int cmd_system(int argc, char **argv);
int cmd_file(int argc, char **argv);
int cmd_crypto(int argc, char **argv);
int cmd_dev(int argc, char **argv);

// Registry
void register_commands();
Command* find_command(const char *name);

// Initialization
int clobes_init(int argc, char **argv);
void clobes_cleanup();

// Main
int main(int argc, char **argv);

#endif // CLOBES_PRO_H
