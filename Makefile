# CLOBES PRO ULTRA Makefile for Alpine iSH

CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c99 -pthread
LIBS = -lcurl -lpthread

TARGET = clobes
SRC = src/clobes.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

debug: CFLAGS += -g -DDEBUG
debug: clean all

install:
	cp $(TARGET) /usr/local/bin/
	chmod +x /usr/local/bin/$(TARGET)
	@echo "✅ CLOBES PRO ULTRA installed successfully!"

uninstall:
	rm -f /usr/local/bin/$(TARGET)
	@echo "✅ CLOBES PRO ULTRA uninstalled!"

clean:
	rm -f $(TARGET)

test: $(TARGET)
	@echo "🧪 Running tests..."
	./$(TARGET) version
	./$(TARGET) help
	./$(TARGET) system info
	@echo "✅ Tests passed!"

setup:
	@echo "📦 Setting up CLOBES PRO ULTRA..."
	apk add curl-dev build-base
	make
	make install
	@echo "🚀 Setup complete! Run 'clobes version' to verify."

.PHONY: all debug install uninstall clean test setup
