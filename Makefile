CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c99 -I./src
LDFLAGS = -lcurl -lssl -lcrypto -lpthread
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
	mkdir -p ./www
    mkdir /usr/clobes
    touch /usr/clobes/www

uninstall:
	rm -f /usr/local/bin/$(TARGET)

.PHONY: all clean install uninstall
