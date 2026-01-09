CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c99 -I./src
LDFLAGS = -lcurl
TARGET = clobes

# Source files
SRC = src/clobes.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)

clean:
	rm -f $(TARGET)

install:
	cp $(TARGET) /usr/local/bin/

uninstall:
	rm -f /usr/local/bin/$(TARGET)

.PHONY: all clean install uninstall
