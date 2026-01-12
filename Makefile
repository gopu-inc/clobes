# CLOBES PRO Makefile for Alpine iSH

CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c99 -pthread
LIBS = -lcurl -lpthread

TARGET = clobes
SRC = src/clobes.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

clean:
	rm -f $(TARGET)

install:
	cp $(TARGET) /usr/local/bin/

uninstall:
	rm -f /usr/local/bin/$(TARGET)

test:
	./$(TARGET) version
	./$(TARGET) help

.PHONY: all clean install uninstall test
