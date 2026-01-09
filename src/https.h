#ifndef CLOBES_HTTPS_H
#define CLOBES_HTTPS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define MAX_CLIENTS 100
#define BUFFER_SIZE 8192
#define MAX_HEADERS 50
#define MAX_ROUTES 100
#define DEFAULT_PORT 8080
#define DEFAULT_SSL_PORT 8443
#define MAX_POST_SIZE 10485760 // 10MB

// HTTP Methods
typedef enum {
    HTTP_GET,
    HTTP_POST,
    HTTP_PUT,
    HTTP_DELETE,
    HTTP_HEAD,
    HTTP_OPTIONS,
    HTTP_PATCH,
    HTTP_UNKNOWN
} HttpMethod;

// HTTP Request Structure
typedef struct {
    HttpMethod method;
    char path[1024];
    char protocol[16];
    char headers[MAX_HEADERS][2][256];
    int header_count;
    char *body;
    size_t body_size;
    char client_ip[INET_ADDRSTRLEN];
    int client_port;
} HttpRequest;

// HTTP Response Structure
typedef struct {
    int status_code;
    char status_text[64];
    char headers[MAX_HEADERS][2][256];
    int header_count;
    char *body;
    size_t body_size;
    int keep_alive;
} HttpResponse;

// Route Handler
typedef struct {
    char method[16];
    char path[1024];
    void (*handler)(HttpRequest*, HttpResponse*);
} Route;

// Server Configuration
typedef struct {
    int port;
    int ssl_port;
    char *ip_address;
    int max_connections;
    int timeout;
    int keep_alive;
    int worker_threads;
    char *ssl_cert;
    char *ssl_key;
    int enable_ssl;
    int enable_gzip;
    char *web_root;
    int show_access_log;
    int maintenance_mode;
    char maintenance_message[1024];
} ServerConfig;

// Server Statistics
typedef struct {
    unsigned long total_requests;
    unsigned long total_errors;
    unsigned long active_connections;
    unsigned long bytes_sent;
    unsigned long bytes_received;
    time_t start_time;
    double avg_response_time;
} ServerStats;

// Function Prototypes

// Server Core
int http_server_start(ServerConfig *config);
int https_server_start(ServerConfig *config);
void server_stop(int signal);
void server_handle_client(int client_socket, struct sockaddr_in *client_addr, ServerConfig *config);
void *thread_worker(void *arg);

// Request/Response
HttpRequest* http_parse_request(const char *raw_request, int client_socket);
void http_free_request(HttpRequest *req);
HttpResponse* http_create_response();
void http_set_header(HttpResponse *resp, const char *key, const char *value);
void http_set_body(HttpResponse *resp, const char *content, size_t length);
void http_set_body_file(HttpResponse *resp, const char *filename);
void http_send_response(int client_socket, SSL *ssl, HttpResponse *resp, ServerConfig *config);
void http_free_response(HttpResponse *resp);

// Routing
void route_add(const char *method, const char *path, void (*handler)(HttpRequest*, HttpResponse*));
void route_handle(HttpRequest *req, HttpResponse *resp);
void route_serve_static(HttpRequest *req, HttpResponse *resp, ServerConfig *config);

// Built-in Handlers
void handler_root(HttpRequest *req, HttpResponse *resp);
void handler_api_info(HttpRequest *req, HttpResponse *resp);
void handler_api_stats(HttpRequest *req, HttpResponse *resp);
void handler_upload(HttpRequest *req, HttpResponse *resp);
void handler_download(HttpRequest *req, HttpResponse *resp);
void handler_execute(HttpRequest *req, HttpResponse *resp);
void handler_websocket(HttpRequest *req, HttpResponse *resp);

// Utilities
char* http_method_to_string(HttpMethod method);
HttpMethod http_string_to_method(const char *method);
char* http_status_text(int status_code);
char* url_decode(const char *str);
char* url_encode(const char *str);
char* get_mime_type(const char *filename);
void generate_etag(char *etag, const char *content, size_t length);
int file_exists(const char *path);
size_t get_file_size(const char *path);
char* read_file(const char *path, size_t *size);

// SSL/TLS
SSL_CTX* create_ssl_context();
int configure_ssl_context(SSL_CTX *ctx, const char *cert_file, const char *key_file);

// Logging
void access_log(const char *client_ip, HttpRequest *req, HttpResponse *resp, int response_time);
void error_log(const char *message, ...);

// Statistics
ServerStats* get_server_stats();
void stats_update_request(int response_time, size_t bytes_sent, size_t bytes_received);
void stats_display();

// Maintenance
void maintenance_enable(const char *message);
void maintenance_disable();
int is_maintenance_mode();

// Security
int validate_request(HttpRequest *req);
int rate_limit_check(const char *client_ip);
void add_cors_headers(HttpResponse *resp);
void add_security_headers(HttpResponse *resp);

// Compression
char* gzip_compress(const char *data, size_t size, size_t *compressed_size);
char* deflate_compress(const char *data, size_t size, size_t *compressed_size);

#endif // CLOBES_HTTPS_H
