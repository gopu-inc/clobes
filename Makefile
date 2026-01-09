CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c99
LDFLAGS = -lcurl
TARGET = clobes

all: $(TARGET)

$(TARGET): clobes.c
	$(CC) $(CFLAGS) clobes.c -o $(TARGET) $(LDFLAGS)

clean:
	rm -f $(TARGET)

install:
	cp $(TARGET) /usr/local/bin/

uninstall:
	rm -f /usr/local/bin/$(TARGET)

.PHONY: all clean install uninstall
