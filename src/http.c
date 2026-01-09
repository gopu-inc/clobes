// HTTP Server implementation for CLOBES
#include "clobes.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <fcntl.h>

// Server state
static ServerConfig g_server_config = {
    .port = DEFAULT_PORT,
    .ssl_port = DEFAULT_SSL_PORT,
    .ip_address = "0.0.0.0",
    .max_connections = MAX_CLIENTS,
    .timeout = 30,
    .keep_alive = 1,
    .worker_threads = 4,
    .ssl_cert = "",
    .ssl_key = "",
    .enable_ssl = 0,
    .enable_gzip = 1,
    .web_root = "./www",
    .show_access_log = 1,
    .maintenance_mode = 0,
    .maintenance_message = "Server is under maintenance. Please try again later."
};

static int g_server_running = 0;
static int g_server_socket = -1;

// Get MIME type for file extension
const char* get_mime_type(const char *filename) {
    const char *ext = strrchr(filename, '.');
    if (!ext) return "application/octet-stream";
    
    ext++; // Skip the dot
    
    if (strcasecmp(ext, "html") == 0 || strcasecmp(ext, "htm") == 0) {
        return "text/html; charset=utf-8";
    } else if (strcasecmp(ext, "css") == 0) {
        return "text/css";
    } else if (strcasecmp(ext, "js") == 0) {
        return "application/javascript";
    } else if (strcasecmp(ext, "json") == 0) {
        return "application/json";
    } else if (strcasecmp(ext, "xml") == 0) {
        return "application/xml";
    } else if (strcasecmp(ext, "svg") == 0) {
        return "image/svg+xml";
    } else if (strcasecmp(ext, "png") == 0) {
        return "image/png";
    } else if (strcasecmp(ext, "jpg") == 0 || strcasecmp(ext, "jpeg") == 0) {
        return "image/jpeg";
    } else if (strcasecmp(ext, "gif") == 0) {
        return "image/gif";
    } else if (strcasecmp(ext, "ico") == 0) {
        return "image/x-icon";
    } else if (strcasecmp(ext, "txt") == 0) {
        return "text/plain";
    } else if (strcasecmp(ext, "pdf") == 0) {
        return "application/pdf";
    } else if (strcasecmp(ext, "zip") == 0) {
        return "application/zip";
    } else if (strcasecmp(ext, "yaml") == 0 || strcasecmp(ext, "yml") == 0) {
        return "application/x-yaml";
    } else if (strcasecmp(ext, "csv") == 0) {
        return "text/csv";
    } else if (strcasecmp(ext, "cfg") == 0 || strcasecmp(ext, "conf") == 0) {
        return "text/plain";
    } else if (strcasecmp(ext, "md") == 0) {
        return "text/markdown";
    } else if (strcasecmp(ext, "mp4") == 0) {
        return "video/mp4";
    } else if (strcasecmp(ext, "mp3") == 0) {
        return "audio/mpeg";
    }
    
    return "application/octet-stream";
}

// Read file content
char* read_file_content(const char *filename, size_t *size) {
    FILE *file = fopen(filename, "rb");
    if (!file) return NULL;
    
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    char *content = (char*)malloc(file_size + 1);
    if (!content) {
        fclose(file);
        return NULL;
    }
    
    fread(content, 1, file_size, file);
    content[file_size] = '\0';
    fclose(file);
    
    if (size) *size = file_size;
    return content;
}

// Send HTTP response
void send_http_response(int client_socket, int status_code, const char *status_text, 
                       const char *content_type, const char *body, size_t body_len) {
    char headers[1024];
    time_t now = time(NULL);
    struct tm *tm_info = gmtime(&now);
    char date_buffer[64];
    strftime(date_buffer, sizeof(date_buffer), "%a, %d %b %Y %H:%M:%S GMT", tm_info);
    
    snprintf(headers, sizeof(headers),
             "HTTP/1.1 %d %s\r\n"
             "Server: CLOBES-PRO/4.0.0\r\n"
             "Date: %s\r\n"
             "Connection: %s\r\n"
             "Content-Type: %s\r\n"
             "Content-Length: %zu\r\n"
             "\r\n",
             status_code, status_text,
             date_buffer,
             g_server_config.keep_alive ? "keep-alive" : "close",
             content_type,
             body_len);
    
    send(client_socket, headers, strlen(headers), 0);
    if (body && body_len > 0) {
        send(client_socket, body, body_len, 0);
    }
}

// Send file
void send_file_response(int client_socket, const char *filepath) {
    size_t file_size;
    char *content = read_file_content(filepath, &file_size);
    
    if (!content) {
        const char *not_found = "<h1>404 Not Found</h1>";
        send_http_response(client_socket, 404, "Not Found", 
                          "text/html", not_found, strlen(not_found));
        return;
    }
    
    const char *mime_type = get_mime_type(filepath);
    send_http_response(client_socket, 200, "OK", mime_type, content, file_size);
    
    free(content);
}

// Handle directory listing
void send_directory_listing(int client_socket, const char *dirpath, const char *request_path) {
    char listing[8192];
    char *ptr = listing;
    
    ptr += snprintf(ptr, sizeof(listing) - (ptr - listing),
                   "<!DOCTYPE html>\n"
                   "<html>\n"
                   "<head><title>Index of %s</title></head>\n"
                   "<body>\n"
                   "<h1>Index of %s</h1>\n"
                   "<hr>\n"
                   "<pre>\n",
                   request_path, request_path);
    
    DIR *dir = opendir(dirpath);
    if (dir) {
        struct dirent *entry;
        
        // Add parent directory link
        if (strcmp(request_path, "/") != 0) {
            ptr += snprintf(ptr, sizeof(listing) - (ptr - listing),
                           "<a href=\"../\">../</a>\n");
        }
        
        while ((entry = readdir(dir)) != NULL) {
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
                continue;
            }
            
            char fullpath[512];
            snprintf(fullpath, sizeof(fullpath), "%s/%s", dirpath, entry->d_name);
            
            struct stat st;
            if (stat(fullpath, &st) == 0) {
                char time_str[64];
                strftime(time_str, sizeof(time_str), "%d-%b-%Y %H:%M", localtime(&st.st_mtime));
                
                if (S_ISDIR(st.st_mode)) {
                    ptr += snprintf(ptr, sizeof(listing) - (ptr - listing),
                                   "<a href=\"%s/\">%s/</a>%*s%s\n",
                                   entry->d_name, entry->d_name,
                                   50 - (int)strlen(entry->d_name), "", time_str);
                } else {
                    char size_str[32];
                    if (st.st_size < 1024) {
                        snprintf(size_str, sizeof(size_str), "%ld", st.st_size);
                    } else if (st.st_size < 1024 * 1024) {
                        snprintf(size_str, sizeof(size_str), "%.1fK", st.st_size / 1024.0);
                    } else {
                        snprintf(size_str, sizeof(size_str), "%.1fM", st.st_size / (1024.0 * 1024.0));
                    }
                    
                    ptr += snprintf(ptr, sizeof(listing) - (ptr - listing),
                                   "<a href=\"%s\">%s</a>%*s%s %12s\n",
                                   entry->d_name, entry->d_name,
                                   50 - (int)strlen(entry->d_name), "", time_str, size_str);
                }
            }
        }
        closedir(dir);
    }
    
    snprintf(ptr, sizeof(listing) - (ptr - listing),
             "</pre>\n<hr>\n<address>CLOBES-PRO/4.0.0 Server</address>\n</body>\n</html>");
    
    send_http_response(client_socket, 200, "OK", "text/html", listing, strlen(listing));
}

// Handle HTTP request
void handle_http_request(int client_socket, const char *request) {
    char method[16], path[1024], protocol[16];
    
    // Parse request line
    if (sscanf(request, "%15s %1023s %15s", method, path, protocol) != 3) {
        const char *bad_request = "HTTP/1.1 400 Bad Request\r\n\r\n";
        send(client_socket, bad_request, strlen(bad_request), 0);
        return;
    }
    
    // Maintenance mode
    if (g_server_config.maintenance_mode) {
        send_http_response(client_socket, 503, "Service Unavailable",
                          "text/html", g_server_config.maintenance_message,
                          strlen(g_server_config.maintenance_message));
        return;
    }
    
    // Security: prevent path traversal
    if (strstr(path, "..") != NULL) {
        const char *forbidden = "<h1>403 Forbidden</h1>";
        send_http_response(client_socket, 403, "Forbidden", 
                          "text/html", forbidden, strlen(forbidden));
        return;
    }
    
    // Default to index.html for root
    if (strcmp(path, "/") == 0) {
        strcpy(path, "/index.html");
    }
    
    // Build full path
    char fullpath[1024];
    snprintf(fullpath, sizeof(fullpath), "%s%s", g_server_config.web_root, path);
    
    // Check if file exists
    struct stat st;
    if (stat(fullpath, &st) == 0) {
        if (S_ISDIR(st.st_mode)) {
            // Send directory listing
            send_directory_listing(client_socket, fullpath, path);
        } else {
            // Send file
            send_file_response(client_socket, fullpath);
        }
    } else {
        // File not found
        const char *not_found = "<html><body><h1>404 Not Found</h1><p>The requested URL was not found on this server.</p></body></html>";
        send_http_response(client_socket, 404, "Not Found", 
                          "text/html", not_found, strlen(not_found));
    }
}

// Handle client connection
void server_handle_client(int client_socket) {
    char buffer[BUFFER_SIZE];
    ssize_t bytes_received = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
    
    if (bytes_received > 0) {
        buffer[bytes_received] = '\0';
        handle_http_request(client_socket, buffer);
    }
    
    close(client_socket);
}

// Start HTTP server
int http_server_start(ServerConfig *config) {
    struct sockaddr_in server_addr;
    int opt = 1;
    
    // Create socket
    g_server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (g_server_socket < 0) {
        perror("Socket creation failed");
        return -1;
    }
    
    // Set socket options
    if (setsockopt(g_server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("Setsockopt failed");
        close(g_server_socket);
        return -1;
    }
    
    // Configure server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(config->port);
    server_addr.sin_addr.s_addr = inet_addr(config->ip_address);
    
    // Bind socket
    if (bind(g_server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(g_server_socket);
        return -1;
    }
    
    // Listen for connections
    if (listen(g_server_socket, config->max_connections) < 0) {
        perror("Listen failed");
        close(g_server_socket);
        return -1;
    }
    
    g_server_running = 1;
    
    // Create webroot directory if it doesn't exist
    struct stat st = {0};
    if (stat(config->web_root, &st) == -1) {
        mkdir(config->web_root, 0755);
        
        // Create default index.html
        char index_path[512];
        snprintf(index_path, sizeof(index_path), "%s/index.html", config->web_root);
        FILE *fp = fopen(index_path, "w");
        if (fp) {
            fprintf(fp, "<!DOCTYPE html>\n");
            fprintf(fp, "<html>\n");
            fprintf(fp, "<head>\n");
            fprintf(fp, "    <title>CLOBES PRO Server</title>\n");
            fprintf(fp, "    <style>\n");
            fprintf(fp, "        body { font-family: Arial, sans-serif; margin: 40px; }\n");
            fprintf(fp, "        .container { max-width: 800px; margin: 0 auto; }\n");
            fprintf(fp, "        h1 { color: #333; }\n");
            fprintf(fp, "        .features { margin: 20px 0; }\n");
            fprintf(fp, "        .feature { background: #f5f5f5; padding: 10px; margin: 5px 0; border-radius: 5px; }\n");
            fprintf(fp, "    </style>\n");
            fprintf(fp, "</head>\n");
            fprintf(fp, "<body>\n");
            fprintf(fp, "    <div class=\"container\">\n");
            fprintf(fp, "        <h1>🚀 CLOBES PRO Web Server v%s</h1>\n", CLOBES_VERSION);
            fprintf(fp, "        <p>Your powerful web server is running!</p>\n");
            fprintf(fp, "        \n");
            fprintf(fp, "        <div class=\"features\">\n");
            fprintf(fp, "            <div class=\"feature\">✅ Supports: HTML, CSS, JS, JSON, XML, SVG, PNG, JPG, GIF</div>\n");
            fprintf(fp, "            <div class=\"feature\">✅ Directory listing</div>\n");
            fprintf(fp, "            <div class=\"feature\">✅ Maintenance mode</div>\n");
            fprintf(fp, "            <div class=\"feature\">✅ Keep-alive connections</div>\n");
            fprintf(fp, "        </div>\n");
            fprintf(fp, "        \n");
            fprintf(fp, "        <h2>Quick Start</h2>\n");
            fprintf(fp, "        <p>Add your files to the <code>%s</code> directory.</p>\n", config->web_root);
            fprintf(fp, "        \n");
            fprintf(fp, "        <h2>Server Commands</h2>\n");
            fprintf(fp, "        <pre>\n");
            fprintf(fp, "clobes server start --port %d\n", config->port);
            fprintf(fp, "clobes server stop\n");
            fprintf(fp, "clobes server status\n");
            fprintf(fp, "clobes server maintenance on \"Message\"\n");
            fprintf(fp, "        </pre>\n");
            fprintf(fp, "    </div>\n");
            fprintf(fp, "</body>\n");
            fprintf(fp, "</html>\n");
            fclose(fp);
        }
    }
    
    print_info("Server started on http://%s:%d", config->ip_address, config->port);
    print_info("Web root: %s", config->web_root);
    print_info("Press Ctrl+C to stop");
    
    // Main server loop
    while (g_server_running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        
        int client_socket = accept(g_server_socket, 
                                  (struct sockaddr *)&client_addr, 
                                  &client_len);
        
        if (client_socket < 0) {
            if (g_server_running) {
                perror("Accept failed");
            }
            continue;
        }
        
        // Get client IP
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
        
        if (g_server_config.show_access_log) {
            printf("[%s] Connected\n", client_ip);
        }
        
        // Handle client (in main thread for simplicity)
        server_handle_client(client_socket);
    }
    
    return 0;
}

// Stop server
void server_stop(int signal) {
    (void)signal;
    g_server_running = 0;
    if (g_server_socket != -1) {
        close(g_server_socket);
        g_server_socket = -1;
    }
    print_info("Server stopped");
}

// Command: server
int cmd_server(int argc, char **argv) {
    if (argc < 3) {
        printf(COLOR_CYAN "🚀 SERVER COMMANDS\n" COLOR_RESET);
        printf("══════════════════════════════════════════\n\n");
        
        printf("  start [options]        - Start HTTP server\n");
        printf("  stop                   - Stop server\n");
        printf("  status                 - Show server status\n");
        printf("  maintenance on/off     - Enable/disable maintenance mode\n");
        printf("\n");
        printf("Options:\n");
        printf("  --port <num>           - Port (default: 8080)\n");
        printf("  --ip <address>         - IP address (default: 0.0.0.0)\n");
        printf("  --webroot <dir>        - Web root directory (default: ./www)\n");
        printf("  --ssl                  - Enable HTTPS (not implemented yet)\n");
        printf("\n");
        printf("Examples:\n");
        printf("  clobes server start --port 8080\n");
        printf("  clobes server start --ip 192.168.1.100 --port 4301\n");
        printf("  clobes server start --webroot /var/www/html\n");
        return 0;
    }
    
    if (strcmp(argv[2], "start") == 0) {
        // Parse options
        for (int i = 3; i < argc; i++) {
            if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
                g_server_config.port = atoi(argv[++i]);
            } else if (strcmp(argv[i], "--ip") == 0 && i + 1 < argc) {
                strncpy(g_server_config.ip_address, argv[++i], sizeof(g_server_config.ip_address) - 1);
            } else if (strcmp(argv[i], "--webroot") == 0 && i + 1 < argc) {
                strncpy(g_server_config.web_root, argv[++i], sizeof(g_server_config.web_root) - 1);
            } else if (strcmp(argv[i], "--ssl") == 0) {
                g_server_config.enable_ssl = 1;
                print_warning("HTTPS not implemented yet. Using HTTP.");
            }
        }
        
        // Install signal handler for Ctrl+C
        signal(SIGINT, server_stop);
        signal(SIGTERM, server_stop);
        
        return http_server_start(&g_server_config);
        
    } else if (strcmp(argv[2], "stop") == 0) {
        if (g_server_running) {
            server_stop(0);
            print_success("Server stopped");
        } else {
            print_warning("Server is not running");
        }
        return 0;
        
    } else if (strcmp(argv[2], "status") == 0) {
        if (g_server_running) {
            print_success("Server is RUNNING");
            printf("Address: http://%s:%d\n", g_server_config.ip_address, g_server_config.port);
            printf("Web root: %s\n", g_server_config.web_root);
            printf("Maintenance: %s\n", g_server_config.maintenance_mode ? "ON" : "OFF");
        } else {
            print_error("Server is NOT running");
        }
        return 0;
        
    } else if (strcmp(argv[2], "maintenance") == 0 && argc >= 4) {
        if (strcmp(argv[3], "on") == 0) {
            g_server_config.maintenance_mode = 1;
            if (argc >= 5) {
                strncpy(g_server_config.maintenance_message, argv[4], 
                       sizeof(g_server_config.maintenance_message) - 1);
            }
            print_success("Maintenance mode ENABLED");
        } else if (strcmp(argv[3], "off") == 0) {
            g_server_config.maintenance_mode = 0;
            print_success("Maintenance mode DISABLED");
        }
        return 0;
    }
    
    print_error("Unknown server command: %s", argv[2]);
    return 1;
}
