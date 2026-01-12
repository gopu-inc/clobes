# Makefile for CLOBES PRO
CC = gcc
CFLAGS = -Wall -Wextra -O2 -D_GNU_SOURCE
LDFLAGS = -lcurl -lpthread -lm -lssl -lcrypto -lz
TARGET = clobes
SRC_DIR = src
OBJ_DIR = obj

SOURCES = $(wildcard $(SRC_DIR)/*.c)
OBJECTS = $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(SOURCES))

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -o $@ $(LDFLAGS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

install: $(TARGET)
	cp $(TARGET) /usr/local/bin/
	chmod +x /usr/local/bin/$(TARGET)

clean:
	rm -rf $(OBJ_DIR) $(TARGET) www/favicon.ico qr_code.png

cert:
	openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/C=FR/ST=Paris/L=Paris/O=CLOBES/CN=localhost"

test:
	@echo "Creating test files..."
	@mkdir -p www/images
	@echo "<!DOCTYPE html><html><head><title>Test</title></head><body><h1>Test Page</h1></body></html>" > www/test.html
	@echo "This is a test text file." > www/test.txt
	@echo "Test data" > www/data.json
	@echo "Done!"

run: $(TARGET)
	./$(TARGET) server start --port 8080 --public --qr

.PHONY: all clean install cert test run
