CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c99 -I./src -pthread -D_GNU_SOURCE
LDFLAGS = -lcurl -lssl -lcrypto -lpthread -lz -ljansson
TARGET = clobes

# Source files
SRC = src/clobes.c src/http.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)

clean:
	rm -f $(TARGET)

install:
	cp $(TARGET) /usr/local/bin/
	mkdir -p /etc/clobes/
	cp -r www/ /etc/clobes/
	cp ssl/* /etc/clobes/ 2>/dev/null || true

uninstall:
	rm -f /usr/local/bin/$(TARGET)

.PHONY: all clean install uninstall
