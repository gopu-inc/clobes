// CLOBES PRO HTTP Server Implementation
#include "clobes.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <dirent.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <pthread.h>

// Server global state
static int server_running = 0;
static int server_socket = -1;
static pthread_t server_thread;
static ServerConfig *global_config = NULL;

// Default index files
static const char *default_index_files[] = {
    "index.html",
    "index.htm",
    "default.html",
    "default.htm",
    NULL
};

// MIME types
typedef struct {
    const char *extension;
    const char *mime_type;
} MimeType;

static MimeType mime_types[] = {
    {".html", "text/html"},
    {".htm", "text/html"},
    {".css", "text/css"},
    {".js", "application/javascript"},
    {".json", "application/json"},
    {".xml", "application/xml"},
    {".txt", "text/plain"},
    {".pdf", "application/pdf"},
    {".zip", "application/zip"},
    {".tar", "application/x-tar"},
    {".gz", "application/gzip"},
    {".bz2", "application/x-bzip2"},
    {".jpg", "image/jpeg"},
    {".jpeg", "image/jpeg"},
    {".png", "image/png"},
    {".gif", "image/gif"},
    {".svg", "image/svg+xml"},
    {".ico", "image/x-icon"},
    {".bmp", "image/bmp"},
    {".webp", "image/webp"},
    {".mp3", "audio/mpeg"},
    {".wav", "audio/wav"},
    {".mp4", "video/mp4"},
    {".avi", "video/x-msvideo"},
    {".mov", "video/quicktime"},
    {".woff", "font/woff"},
    {".woff2", "font/woff2"},
    {".ttf", "font/ttf"},
    {".otf", "font/otf"},
    {".eot", "application/vnd.ms-fontobject"},
    {".csv", "text/csv"},
    {".doc", "application/msword"},
    {".docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
    {".xls", "application/vnd.ms-excel"},
    {".xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
    {".ppt", "application/vnd.ms-powerpoint"},
    {".pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation"},
    {".php", "application/x-httpd-php"},
    {".py", "text/x-python"},
    {".c", "text/x-c"},
    {".cpp", "text/x-c++"},
    {".h", "text/x-c"},
    {".java", "text/x-java"},
    {".sh", "application/x-sh"},
    {".pl", "application/x-perl"},
    {".rb", "application/x-ruby"},
    {".go", "text/x-go"},
    {".rs", "text/x-rust"},
    {".md", "text/markdown"},
    {NULL, "application/octet-stream"}
};

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

// Get public IP address using external service
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

// Generate QR code (using external qrencode tool)
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

// Parse HTTP request
int parse_http_request(int client_socket, HttpRequest *request) {
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
    while ((line = strtok(NULL, "\r\n")) != NULL) {
        if (strlen(line) == 0) break; // Empty line indicates end of headers
        
        if (request->header_count < MAX_HEADERS) {
            strncpy(request->headers[request->header_count], line, MAX_HEADER_SIZE - 1);
            request->headers[request->header_count][MAX_HEADER_SIZE - 1] = '\0';
            request->header_count++;
        }
    }
    
    // For now, we don't parse body for GET requests
    request->body = NULL;
    request->body_length = 0;
    
    return 1;
}

// Send HTTP response
void send_http_response(int client_socket, HttpResponse *response) {
    char buffer[BUFFER_SIZE];
    
    // Send status line
    snprintf(buffer, sizeof(buffer), "HTTP/1.1 %d %s\r\n", 
             response->status_code, response->status_text);
    send(client_socket, buffer, strlen(buffer), 0);
    
    // Send headers
    for (int i = 0; i < response->header_count; i++) {
        snprintf(buffer, sizeof(buffer), "%s\r\n", response->headers[i]);
        send(client_socket, buffer, strlen(buffer), 0);
    }
    
    // End of headers
    send(client_socket, "\r\n", 2, 0);
    
    // Send body if exists
    if (response->body && response->body_length > 0) {
        send(client_socket, response->body, response->body_length, 0);
    }
}

// Free HTTP response
void free_http_response(HttpResponse *response) {
    if (response->body) {
        free(response->body);
        response->body = NULL;
    }
}

// Serve static file
int serve_static_file(int client_socket, const char *filepath, ServerConfig *config) {
    struct stat file_stat;
    FILE *file;
    char buffer[BUFFER_SIZE];
    size_t bytes_read;
    
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
                return serve_static_file(client_socket, index_path, config);
            }
        }
        
        // If directory listing is enabled
        if (config->allow_directory_listing) {
            return serve_directory_listing(client_socket, filepath, filepath, config);
        }
        
        return 0;
    }
    
    // Open file
    file = fopen(filepath, "rb");
    if (!file) {
        return 0;
    }
    
    // Get MIME type
    const char *mime_type = get_mime_type(filepath);
    
    // Prepare response
    HttpResponse response;
    response.status_code = 200;
    strcpy(response.status_text, "OK");
    response.header_count = 0;
    
    // Add headers
    snprintf(response.headers[response.header_count++], MAX_HEADER_SIZE,
             "Content-Type: %s", mime_type);
    snprintf(response.headers[response.header_count++], MAX_HEADER_SIZE,
             "Content-Length: %ld", (long)file_stat.st_size);
    snprintf(response.headers[response.header_count++], MAX_HEADER_SIZE,
             "Connection: close");
    snprintf(response.headers[response.header_count++], MAX_HEADER_SIZE,
             "Server: CLOBES-PRO/4.0.0");
    
    // Allocate memory for body
    response.body = malloc(file_stat.st_size);
    if (!response.body) {
        fclose(file);
        return 0;
    }
    
    // Read file content
    size_t total_read = 0;
    while (total_read < (size_t)file_stat.st_size) {
        bytes_read = fread(response.body + total_read, 1, 
                          file_stat.st_size - total_read, file);
        if (bytes_read <= 0) break;
        total_read += bytes_read;
    }
    
    response.body_length = total_read;
    
    // Send response
    send_http_response(client_socket, &response);
    
    // Cleanup
    free_http_response(&response);
    fclose(file);
    
    return 1;
}

// Serve directory listing
int serve_directory_listing(int client_socket, const char *path, const char *request_path, ServerConfig *config) {
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
                   "        body { font-family: Arial, sans-serif; margin: 40px; }\n"
                   "        h1 { color: #333; }\n"
                   "        table { border-collapse: collapse; width: 100%%; }\n"
                   "        th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }\n"
                   "        th { background-color: #f2f2f2; }\n"
                   "        a { text-decoration: none; color: #0066cc; }\n"
                   "        a:hover { text-decoration: underline; }\n"
                   "        .size { color: #666; }\n"
                   "        .dir { font-weight: bold; }\n"
                   "    </style>\n"
                   "</head>\n"
                   "<body>\n"
                   "    <h1>Index of %s</h1>\n"
                   "    <table>\n"
                   "        <tr>\n"
                   "            <th>Name</th>\n"
                   "            <th>Size</th>\n"
                   "            <th>Last Modified</th>\n"
                   "        </tr>\n"
                   "        <tr>\n"
                   "            <td><a href=\"../\">Parent Directory</a></td>\n"
                   "            <td>-</td>\n"
                   "            <td>-</td>\n"
                   "        </tr>\n",
                   request_path, request_path);
    
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        
        char full_path[MAX_PATH];
        struct stat file_stat;
        char size_str[32];
        char time_str[64];
        
        snprintf(full_path, sizeof(full_path), "%s/%s", path, entry->d_name);
        
        if (stat(full_path, &file_stat) == 0) {
            if (S_ISDIR(file_stat.st_mode)) {
                strcpy(size_str, "-");
                snprintf(html + pos, sizeof(html) - pos,
                        "        <tr class=\"dir\">\n"
                        "            <td><a href=\"%s/\">📁 %s/</a></td>\n"
                        "            <td>%s</td>\n",
                        entry->d_name, entry->d_name, size_str);
            } else {
                // Format file size
                if (file_stat.st_size < 1024) {
                    snprintf(size_str, sizeof(size_str), "%ld B", (long)file_stat.st_size);
                } else if (file_stat.st_size < 1024 * 1024) {
                    snprintf(size_str, sizeof(size_str), "%.1f KB", 
                            file_stat.st_size / 1024.0);
                } else {
                    snprintf(size_str, sizeof(size_str), "%.1f MB", 
                            file_stat.st_size / (1024.0 * 1024.0));
                }
                
                snprintf(html + pos, sizeof(html) - pos,
                        "        <tr>\n"
                        "            <td><a href=\"%s\">📄 %s</a></td>\n"
                        "            <td class=\"size\">%s</td>\n",
                        entry->d_name, entry->d_name, size_str);
            }
            
            // Format time
            struct tm *tm_info = localtime(&file_stat.st_mtime);
            strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
            
            pos += snprintf(html + pos, sizeof(html) - pos,
                           "            <td>%s</td>\n"
                           "        </tr>\n",
                           time_str);
        }
    }
    
    closedir(dir);
    
    pos += snprintf(html + pos, sizeof(html) - pos,
                   "    </table>\n"
                   "    <hr>\n"
                   "    <p><em>Served by CLOBES PRO v%s</em></p>\n"
                   "</body>\n"
                   "</html>\n",
                   CLOBES_VERSION);
    
    // Send response
    HttpResponse response;
    response.status_code = 200;
    strcpy(response.status_text, "OK");
    response.header_count = 0;
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
    
    return 1;
}

// Serve default page
int serve_default_page(int client_socket, ServerConfig *config) {
    char html[2048];
    
    snprintf(html, sizeof(html),
            "<!DOCTYPE html>\n"
            "<html>\n"
            "<head>\n"
            "    <title>CLOBES PRO Web Server</title>\n"
            "    <style>\n"
            "        body { font-family: Arial, sans-serif; margin: 40px; text-align: center; }\n"
            "        h1 { color: #2c3e50; }\n"
            "        .logo { font-size: 48px; margin: 20px; }\n"
            "        .info { background-color: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px auto; max-width: 600px; }\n"
            "        .url { font-family: monospace; background-color: #e9ecef; padding: 10px; border-radius: 4px; }\n"
            "        .status { color: #28a745; font-weight: bold; }\n"
            "    </style>\n"
            "</head>\n"
            "<body>\n"
            "    <div class=\"logo\">🚀</div>\n"
            "    <h1>CLOBES PRO Web Server</h1>\n"
            "    <div class=\"info\">\n"
            "        <p><span class=\"status\">✓ Server is running</span></p>\n"
            "        <p>Version: %s</p>\n"
            "        <p>Port: %d</p>\n"
            "        <p>Web Root: %s</p>\n"
            "        <p>Access your files at: <span class=\"url\">http://%s:%d</span></p>\n"
            "    </div>\n"
            "    <p><em>Put your HTML files in the web root directory to serve them.</em></p>\n"
            "</body>\n"
            "</html>\n",
            CLOBES_VERSION, config->port, config->web_root, 
            get_local_ip(), config->port);
    
    HttpResponse response;
    response.status_code = 200;
    strcpy(response.status_text, "OK");
    response.header_count = 0;
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
    
    return 1;
}

// Handle client connection
int server_handle_client(int client_socket, ServerConfig *config) {
    HttpRequest request;
    
    if (!parse_http_request(client_socket, &request)) {
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
        
        printf("[%s] %s %s\n", client_ip, request.method, request.path);
    }
    
    // Handle request
    char filepath[MAX_PATH];
    
    // Remove query string if present
    char *question = strchr(request.path, '?');
    if (question) *question = '\0';
    
    // Default to index if path is "/"
    if (strcmp(request.path, "/") == 0) {
        snprintf(filepath, sizeof(filepath), "%s", config->web_root);
        
        // Try to serve index file
        int served = 0;
        for (int i = 0; default_index_files[i] != NULL; i++) {
            char index_path[MAX_PATH];
            snprintf(index_path, sizeof(index_path), "%s/%s", 
                    config->web_root, default_index_files[i]);
            
            if (serve_static_file(client_socket, index_path, config)) {
                served = 1;
                break;
            }
        }
        
        // If no index file found, serve default page
        if (!served) {
            serve_default_page(client_socket, config);
        }
    } else {
        // Build full path
        snprintf(filepath, sizeof(filepath), "%s%s", config->web_root, request.path);
        
        // Check if file exists and serve it
        if (!serve_static_file(client_socket, filepath, config)) {
            // File not found - send 404
            HttpResponse response;
            response.status_code = 404;
            strcpy(response.status_text, "Not Found");
            response.header_count = 0;
            response.body = strdup("<!DOCTYPE html><html><head><title>404 Not Found</title></head><body><h1>404 Not Found</h1><p>The requested file was not found on this server.</p></body></html>");
            response.body_length = strlen(response.body);
            
            snprintf(response.headers[response.header_count++], MAX_HEADER_SIZE,
                     "Content-Type: text/html");
            snprintf(response.headers[response.header_count++], MAX_HEADER_SIZE,
                     "Content-Length: %zu", response.body_length);
            snprintf(response.headers[response.header_count++], MAX_HEADER_SIZE,
                     "Connection: close");
            
            send_http_response(client_socket, &response);
            free_http_response(&response);
        }
    }
    
    close(client_socket);
    return 1;
}

// Server thread function
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
    print_info("Local URL: http://%s:%d", get_local_ip(), config->port);
    
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
    return NULL;
}

// Start HTTP server
int http_server_start(ServerConfig *config) {
    // Create web root directory if it doesn't exist
    struct stat st;
    if (stat(config->web_root, &st) != 0) {
        if (mkdir(config->web_root, 0755) != 0) {
            print_error("Failed to create web root directory: %s", config->web_root);
            return 1;
        }
        print_info("Created web root directory: %s", config->web_root);
    }
    
    // Start server thread
    if (pthread_create(&server_thread, NULL, server_thread_func, config) != 0) {
        print_error("Failed to create server thread");
        return 1;
    }
    
    // Detach thread
    pthread_detach(server_thread);
    
    global_config = config;
    
    return 0;
}

// Print server information
void print_server_info(ServerConfig *config, const char *public_url) {
    printf("\n" COLOR_CYAN STYLE_BOLD "🚀 CLOBES PRO WEB SERVER\n" COLOR_RESET);
    printf("══════════════════════════════════════════\n\n");
    
    printf(COLOR_GREEN "✓ Server Status: " COLOR_BRIGHT_GREEN "RUNNING\n" COLOR_RESET);
    printf("Port:            %d\n", config->port);
    printf("Web Root:        %s\n", config->web_root);
    printf("Directory List:  %s\n", config->allow_directory_listing ? "Enabled" : "Disabled");
    printf("Max Connections: %d\n", config->max_connections);
    
    printf("\n" COLOR_CYAN "🔗 Access URLs:\n" COLOR_RESET);
    printf("Local:           http://localhost:%d\n", config->port);
    printf("Network:         http://%s:%d\n", get_local_ip(), config->port);
    
    if (public_url) {
        printf("Public:          %s\n", public_url);
    }
    
    printf("\n" COLOR_CYAN "📁 Quick Start:\n" COLOR_RESET);
    printf("1. Put HTML files in: %s\n", config->web_root);
    printf("2. Access from browser using URLs above\n");
    printf("3. Default file: index.html\n");
    
    if (config->generate_qr_code && public_url) {
        printf("\n" COLOR_CYAN "📱 QR Code:\n" COLOR_RESET);
        generate_qr_code(public_url, NULL);
    }
    
    printf("\n" COLOR_YELLOW "Press Ctrl+C to stop the server\n" COLOR_RESET);
}
