#include "https.h"
#include "clobes.h"
#include <dirent.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

// Global server state
static ServerConfig g_server_config = {
    .port = DEFAULT_PORT,
    .ssl_port = DEFAULT_SSL_PORT,
    .ip_address = "0.0.0.0",
    .max_connections = MAX_CLIENTS,
    .timeout = 30,
    .keep_alive = 1,
    .worker_threads = 10,
    .ssl_cert = NULL,
    .ssl_key = NULL,
    .enable_ssl = 0,
    .enable_gzip = 1,
    .web_root = "./www",
    .show_access_log = 1,
    .maintenance_mode = 0,
    .maintenance_message = "Server is under maintenance. Please try again later."
};

static ServerStats g_server_stats = {0};
static Route g_routes[MAX_ROUTES];
static int g_route_count = 0;
static int g_server_running = 0;
static int g_server_socket = -1;
static SSL_CTX *g_ssl_ctx = NULL;

// Command handler for server commands
int cmd_server(int argc, char **argv) {
    if (argc < 3) {
        printf(COLOR_CYAN "🚀 SERVER COMMANDS\n" COLOR_RESET);
        printf("══════════════════════════════════════════\n\n");
        
        printf("  start [options]        - Start HTTP/HTTPS server\n");
        printf("  stop                   - Stop running server\n");
        printf("  status                 - Show server status\n");
        printf("  stats                  - Show server statistics\n");
        printf("  maintenance on/off     - Enable/disable maintenance mode\n");
        printf("\n");
        printf("Options:\n");
        printf("  --port <num>           - Port (default: 8080)\n");
        printf("  --ssl-port <num>       - SSL Port (default: 8443)\n");
        printf("  --ip <address>         - IP address (default: 0.0.0.0)\n");
        printf("  --ssl                  - Enable HTTPS\n");
        printf("  --cert <file>          - SSL certificate file\n");
        printf("  --key <file>           - SSL private key\n");
        printf("  --webroot <dir>        - Web root directory\n");
        printf("  --workers <num>        - Worker threads\n");
        printf("\n");
        printf("Examples:\n");
        printf("  clobes server start --port 8080\n");
        printf("  clobes server start --ssl --port 8443 --cert cert.pem --key key.pem\n");
        printf("  clobes server start --ip 192.168.1.100 --port 4301\n");
        return 0;
    }
    
    if (strcmp(argv[2], "start") == 0) {
        // Parse options
        for (int i = 3; i < argc; i++) {
            if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
                g_server_config.port = atoi(argv[++i]);
            } else if (strcmp(argv[i], "--ssl-port") == 0 && i + 1 < argc) {
                g_server_config.ssl_port = atoi(argv[++i]);
            } else if (strcmp(argv[i], "--ip") == 0 && i + 1 < argc) {
                g_server_config.ip_address = argv[++i];
            } else if (strcmp(argv[i], "--ssl") == 0) {
                g_server_config.enable_ssl = 1;
            } else if (strcmp(argv[i], "--cert") == 0 && i + 1 < argc) {
                g_server_config.ssl_cert = argv[++i];
            } else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
                g_server_config.ssl_key = argv[++i];
            } else if (strcmp(argv[i], "--webroot") == 0 && i + 1 < argc) {
                g_server_config.web_root = argv[++i];
            } else if (strcmp(argv[i], "--workers") == 0 && i + 1 < argc) {
                g_server_config.worker_threads = atoi(argv[++i]);
            }
        }
        
        print_info("Starting CLOBES Server on %s:%d...", 
                  g_server_config.ip_address, g_server_config.port);
        
        // Create webroot directory if it doesn't exist
        struct stat st = {0};
        if (stat(g_server_config.web_root, &st) == -1) {
            mkdir(g_server_config.web_root, 0755);
            print_info("Created web root directory: %s", g_server_config.web_root);
            
            // Create default index.html
            char index_path[1024];
            snprintf(index_path, sizeof(index_path), "%s/index.html", g_server_config.web_root);
            FILE *fp = fopen(index_path, "w");
            if (fp) {
                fprintf(fp, "<!DOCTYPE html>\n");
                fprintf(fp, "<html>\n");
                fprintf(fp, "<head><title>CLOBES Server</title></head>\n");
                fprintf(fp, "<body>\n");
                fprintf(fp, "<h1>🚀 CLOBES PRO Server v%s</h1>\n", CLOBES_VERSION);
                fprintf(fp, "<p>Your powerful web server is running!</p>\n");
                fprintf(fp, "</body>\n");
                fprintf(fp, "</html>\n");
                fclose(fp);
            }
        }
        
        // Register default routes
        route_add("GET", "/", handler_root);
        route_add("GET", "/api/info", handler_api_info);
        route_add("GET", "/api/stats", handler_api_stats);
        route_add("POST", "/api/upload", handler_upload);
        route_add("GET", "/api/download", handler_download);
        
        // Start server
        if (g_server_config.enable_ssl) {
            if (https_server_start(&g_server_config) == 0) {
                print_success("HTTPS Server started on https://%s:%d", 
                            g_server_config.ip_address, g_server_config.port);
                printf("Web root: %s\n", g_server_config.web_root);
                printf("Press Ctrl+C to stop\n");
            } else {
                print_error("Failed to start HTTPS server");
                return 1;
            }
        } else {
            if (http_server_start(&g_server_config) == 0) {
                print_success("HTTP Server started on http://%s:%d", 
                            g_server_config.ip_address, g_server_config.port);
                printf("Web root: %s\n", g_server_config.web_root);
                printf("Press Ctrl+C to stop\n");
            } else {
                print_error("Failed to start HTTP server");
                return 1;
            }
        }
        
        return 0;
        
    } else if (strcmp(argv[2], "stop") == 0) {
        if (g_server_running) {
            print_info("Stopping server...");
            server_stop(0);
            print_success("Server stopped");
        } else {
            print_warning("Server is not running");
        }
        return 0;
        
    } else if (strcmp(argv[2], "status") == 0) {
        if (g_server_running) {
            print_success("Server is RUNNING");
            printf("Address: %s:%d\n", g_server_config.ip_address, g_server_config.port);
            printf("Protocol: %s\n", g_server_config.enable_ssl ? "HTTPS" : "HTTP");
            printf("Web root: %s\n", g_server_config.web_root);
            printf("Active connections: %lu\n", g_server_stats.active_connections);
            printf("Total requests: %lu\n", g_server_stats.total_requests);
        } else {
            print_error("Server is NOT running");
        }
        return 0;
        
    } else if (strcmp(argv[2], "stats") == 0) {
        stats_display();
        return 0;
        
    } else if (strcmp(argv[2], "maintenance") == 0 && argc >= 4) {
        if (strcmp(argv[3], "on") == 0) {
            const char *message = (argc >= 5) ? argv[4] : "Server is under maintenance";
            maintenance_enable(message);
            print_success("Maintenance mode enabled");
        } else if (strcmp(argv[3], "off") == 0) {
            maintenance_disable();
            print_success("Maintenance mode disabled");
        }
        return 0;
    }
    
    print_error("Unknown server command: %s", argv[2]);
    return 1;
}

// HTTP Server Implementation
int http_server_start(ServerConfig *config) {
    struct sockaddr_in server_addr;
    int opt = 1;
    
    // Create socket
    g_server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (g_server_socket < 0) {
        error_log("Socket creation failed");
        return -1;
    }
    
    // Set socket options
    if (setsockopt(g_server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        error_log("Setsockopt failed");
        close(g_server_socket);
        return -1;
    }
    
    // Configure server address
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(config->port);
    server_addr.sin_addr.s_addr = inet_addr(config->ip_address);
    
    // Bind socket
    if (bind(g_server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        error_log("Bind failed: %s", strerror(errno));
        close(g_server_socket);
        return -1;
    }
    
    // Listen for connections
    if (listen(g_server_socket, config->max_connections) < 0) {
        error_log("Listen failed");
        close(g_server_socket);
        return -1;
    }
    
    g_server_running = 1;
    g_server_stats.start_time = time(NULL);
    
    print_info("Server listening on %s:%d", config->ip_address, config->port);
    
    // Main server loop
    while (g_server_running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        
        int client_socket = accept(g_server_socket, 
                                  (struct sockaddr *)&client_addr, 
                                  &client_len);
        
        if (client_socket < 0) {
            if (g_server_running) {
                error_log("Accept failed");
            }
            continue;
        }
        
        // Handle client in a separate thread (simplified - in real version use thread pool)
        server_handle_client(client_socket, &client_addr, config);
    }
    
    return 0;
}

void server_handle_client(int client_socket, struct sockaddr_in *client_addr, ServerConfig *config) {
    char buffer[BUFFER_SIZE];
    char client_ip[INET_ADDRSTRLEN];
    
    inet_ntop(AF_INET, &(client_addr->sin_addr), client_ip, INET_ADDRSTRLEN);
    
    // Receive request
    ssize_t bytes_received = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
    if (bytes_received <= 0) {
        close(client_socket);
        return;
    }
    
    buffer[bytes_received] = '\0';
    
    // Parse request
    HttpRequest *req = http_parse_request(buffer, client_socket);
    if (!req) {
        close(client_socket);
        return;
    }
    
    strcpy(req->client_ip, client_ip);
    req->client_port = ntohs(client_addr->sin_port);
    
    // Create response
    HttpResponse *resp = http_create_response();
    
    // Handle request
    if (config->maintenance_mode) {
        resp->status_code = 503;
        strcpy(resp->status_text, "Service Unavailable");
        http_set_body(resp, config->maintenance_message, strlen(config->maintenance_message));
    } else {
        route_handle(req, resp);
    }
    
    // Send response
    http_send_response(client_socket, NULL, resp, config);
    
    // Cleanup
    http_free_request(req);
    http_free_response(resp);
    
    if (!config->keep_alive) {
        close(client_socket);
    }
    
    // Update stats
    stats_update_request(0, resp->body_size, bytes_received);
}

// Basic HTTP parsing (simplified)
HttpRequest* http_parse_request(const char *raw_request, int client_socket) {
    HttpRequest *req = calloc(1, sizeof(HttpRequest));
    if (!req) return NULL;
    
    // Parse first line
    char method[16], path[1024], protocol[16];
    if (sscanf(raw_request, "%15s %1023s %15s", method, path, protocol) != 3) {
        free(req);
        return NULL;
    }
    
    req->method = http_string_to_method(method);
    strcpy(req->path, path);
    strcpy(req->protocol, protocol);
    
    return req;
}

HttpResponse* http_create_response() {
    HttpResponse *resp = calloc(1, sizeof(HttpResponse));
    if (!resp) return NULL;
    
    resp->status_code = 200;
    strcpy(resp->status_text, "OK");
    resp->keep_alive = 1;
    
    // Add default headers
    http_set_header(resp, "Server", "CLOBES-PRO/4.0.0");
    http_set_header(resp, "Connection", "keep-alive");
    
    return resp;
}

void http_set_header(HttpResponse *resp, const char *key, const char *value) {
    if (resp->header_count < MAX_HEADERS) {
        strncpy(resp->headers[resp->header_count][0], key, 255);
        strncpy(resp->headers[resp->header_count][1], value, 255);
        resp->header_count++;
    }
}

void http_set_body(HttpResponse *resp, const char *content, size_t length) {
    if (resp->body) free(resp->body);
    resp->body = malloc(length + 1);
    if (resp->body) {
        memcpy(resp->body, content, length);
        resp->body[length] = '\0';
        resp->body_size = length;
        http_set_header(resp, "Content-Length", "0"); // Should be actual length
    }
}

void http_send_response(int client_socket, SSL *ssl, HttpResponse *resp, ServerConfig *config) {
    char response[BUFFER_SIZE];
    int pos = 0;
    
    // Status line
    pos += snprintf(response + pos, BUFFER_SIZE - pos, 
                   "HTTP/1.1 %d %s\r\n", resp->status_code, resp->status_text);
    
    // Headers
    for (int i = 0; i < resp->header_count; i++) {
        pos += snprintf(response + pos, BUFFER_SIZE - pos, 
                       "%s: %s\r\n", 
                       resp->headers[i][0], resp->headers[i][1]);
    }
    
    // End of headers
    pos += snprintf(response + pos, BUFFER_SIZE - pos, "\r\n");
    
    // Send headers
    if (ssl) {
        SSL_write(ssl, response, pos);
    } else {
        send(client_socket, response, pos, 0);
    }
    
    // Send body
    if (resp->body && resp->body_size > 0) {
        if (ssl) {
            SSL_write(ssl, resp->body, resp->body_size);
        } else {
            send(client_socket, resp->body, resp->body_size, 0);
        }
    }
}

// Route handling
void route_add(const char *method, const char *path, void (*handler)(HttpRequest*, HttpResponse*)) {
    if (g_route_count < MAX_ROUTES) {
        strcpy(g_routes[g_route_count].method, method);
        strcpy(g_routes[g_route_count].path, path);
        g_routes[g_route_count].handler = handler;
        g_route_count++;
    }
}

void route_handle(HttpRequest *req, HttpResponse *resp) {
    // Check static files first
    if (req->method == HTTP_GET) {
        char filepath[2048];
        snprintf(filepath, sizeof(filepath), "%s%s", g_server_config.web_root, req->path);
        
        if (strcmp(req->path, "/") == 0) {
            strcat(filepath, "index.html");
        }
        
        if (file_exists(filepath)) {
            size_t file_size;
            char *content = read_file(filepath, &file_size);
            if (content) {
                http_set_body(resp, content, file_size);
                free(content);
                
                const char *ext = strrchr(filepath, '.');
                if (ext) {
                    if (strcmp(ext, ".html") == 0) {
                        http_set_header(resp, "Content-Type", "text/html");
                    } else if (strcmp(ext, ".css") == 0) {
                        http_set_header(resp, "Content-Type", "text/css");
                    } else if (strcmp(ext, ".js") == 0) {
                        http_set_header(resp, "Content-Type", "application/javascript");
                    } else if (strcmp(ext, ".json") == 0) {
                        http_set_header(resp, "Content-Type", "application/json");
                    }
                }
                return;
            }
        }
    }
    
    // Check registered routes
    for (int i = 0; i < g_route_count; i++) {
        if (strcmp(g_routes[i].method, http_method_to_string(req->method)) == 0 &&
            strcmp(g_routes[i].path, req->path) == 0) {
            g_routes[i].handler(req, resp);
            return;
        }
    }
    
    // 404 Not Found
    resp->status_code = 404;
    strcpy(resp->status_text, "Not Found");
    http_set_body(resp, "<h1>404 Not Found</h1>", 22);
    http_set_header(resp, "Content-Type", "text/html");
}

// Handler implementations
void handler_root(HttpRequest *req, HttpResponse *resp) {
    char html[1024];
    snprintf(html, sizeof(html),
             "<!DOCTYPE html>\n"
             "<html>\n"
             "<head><title>CLOBES Server</title></head>\n"
             "<body>\n"
             "<h1>🚀 CLOBES PRO Server v%s</h1>\n"
             "<p>Your powerful web server is running!</p>\n"
             "<ul>\n"
             "<li><a href='/api/info'>Server Info</a></li>\n"
             "<li><a href='/api/stats'>Statistics</a></li>\n"
             "</ul>\n"
             "</body>\n"
             "</html>", CLOBES_VERSION);
    
    http_set_body(resp, html, strlen(html));
    http_set_header(resp, "Content-Type", "text/html");
}

void handler_api_info(HttpRequest *req, HttpResponse *resp) {
    char json[1024];
    snprintf(json, sizeof(json),
             "{\n"
             "  \"server\": \"CLOBES-PRO\",\n"
             "  \"version\": \"%s\",\n"
             "  \"status\": \"running\",\n"
             "  \"port\": %d,\n"
             "  \"ssl\": %s,\n"
             "  \"start_time\": %ld\n"
             "}",
             CLOBES_VERSION,
             g_server_config.port,
             g_server_config.enable_ssl ? "true" : "false",
             g_server_stats.start_time);
    
    http_set_body(resp, json, strlen(json));
    http_set_header(resp, "Content-Type", "application/json");
}

void handler_api_stats(HttpRequest *req, HttpResponse *resp) {
    char json[1024];
    snprintf(json, sizeof(json),
             "{\n"
             "  \"total_requests\": %lu,\n"
             "  \"total_errors\": %lu,\n"
             "  \"active_connections\": %lu,\n"
             "  \"bytes_sent\": %lu,\n"
             "  \"bytes_received\": %lu,\n"
             "  \"uptime\": %ld\n"
             "}",
             g_server_stats.total_requests,
             g_server_stats.total_errors,
             g_server_stats.active_connections,
             g_server_stats.bytes_sent,
             g_server_stats.bytes_received,
             time(NULL) - g_server_stats.start_time);
    
    http_set_body(resp, json, strlen(json));
    http_set_header(resp, "Content-Type", "application/json");
}

// Utility functions
char* http_method_to_string(HttpMethod method) {
    switch (method) {
        case HTTP_GET: return "GET";
        case HTTP_POST: return "POST";
        case HTTP_PUT: return "PUT";
        case HTTP_DELETE: return "DELETE";
        case HTTP_HEAD: return "HEAD";
        case HTTP_OPTIONS: return "OPTIONS";
        case HTTP_PATCH: return "PATCH";
        default: return "UNKNOWN";
    }
}

HttpMethod http_string_to_method(const char *method) {
    if (strcmp(method, "GET") == 0) return HTTP_GET;
    if (strcmp(method, "POST") == 0) return HTTP_POST;
    if (strcmp(method, "PUT") == 0) return HTTP_PUT;
    if (strcmp(method, "DELETE") == 0) return HTTP_DELETE;
    if (strcmp(method, "HEAD") == 0) return HTTP_HEAD;
    if (strcmp(method, "OPTIONS") == 0) return HTTP_OPTIONS;
    if (strcmp(method, "PATCH") == 0) return HTTP_PATCH;
    return HTTP_UNKNOWN;
}

int file_exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0;
}

char* read_file(const char *path, size_t *size) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return NULL;
    
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    char *content = malloc(file_size + 1);
    if (!content) {
        fclose(fp);
        return NULL;
    }
    
    fread(content, 1, file_size, fp);
    content[file_size] = '\0';
    fclose(fp);
    
    if (size) *size = file_size;
    return content;
}

// Statistics
void stats_update_request(int response_time, size_t bytes_sent, size_t bytes_received) {
    g_server_stats.total_requests++;
    g_server_stats.bytes_sent += bytes_sent;
    g_server_stats.bytes_received += bytes_received;
}

void stats_display() {
    if (!g_server_running) {
        print_error("Server is not running");
        return;
    }
    
    long uptime = time(NULL) - g_server_stats.start_time;
    long hours = uptime / 3600;
    long minutes = (uptime % 3600) / 60;
    long seconds = uptime % 60;
    
    printf(COLOR_CYAN "📊 SERVER STATISTICS\n" COLOR_RESET);
    printf("══════════════════════════════════════════\n\n");
    printf("Uptime:           %02ld:%02ld:%02ld\n", hours, minutes, seconds);
    printf("Total Requests:   %lu\n", g_server_stats.total_requests);
    printf("Total Errors:     %lu\n", g_server_stats.total_errors);
    printf("Active Conn:      %lu\n", g_server_stats.active_connections);
    printf("Bytes Sent:       %.2f MB\n", g_server_stats.bytes_sent / (1024.0 * 1024.0));
    printf("Bytes Received:   %.2f MB\n", g_server_stats.bytes_received / (1024.0 * 1024.0));
    printf("Avg Response:     %.2f ms\n", g_server_stats.avg_response_time);
    printf("\n");
}

// Maintenance
void maintenance_enable(const char *message) {
    g_server_config.maintenance_mode = 1;
    strncpy(g_server_config.maintenance_message, message, 
            sizeof(g_server_config.maintenance_message) - 1);
}

void maintenance_disable() {
    g_server_config.maintenance_mode = 0;
}

// Server stop
void server_stop(int signal) {
    (void)signal;
    g_server_running = 0;
    if (g_server_socket != -1) {
        close(g_server_socket);
        g_server_socket = -1;
    }
    if (g_ssl_ctx) {
        SSL_CTX_free(g_ssl_ctx);
        g_ssl_ctx = NULL;
    }
}
