# Makefile for CLOBES PRO
CC = gcc
CFLAGS = -Wall -Wextra -O3 -std=c99 -march=native -flto -DCLOBES_PRO -DUSE_SSL -DUSE_JSON
LIBS = -lcurl -ljansson -lssl -lcrypto -lm -lpthread -lz
TARGET = clobes
SRC = src/clobes.c
OBJ = src/clobes.o

# Performance flags
PERF_FLAGS = -funroll-loops -ftree-vectorize -fomit-frame-pointer
SEC_FLAGS = -D_FORTIFY_SOURCE=2 -fstack-protector-strong
DEBUG_FLAGS = -g -DDEBUG

# Colors
RED = \033[0;31m
GREEN = \033[0;32m
YELLOW = \033[1;33m
BLUE = \033[0;34m
CYAN = \033[0;36m
MAGENTA = \033[0;35m
NC = \033[0m

.PHONY: all build release debug install clean test bench profile

all: release

release: CFLAGS += $(PERF_FLAGS) $(SEC_FLAGS) -DNDEBUG
release: clean build
	@echo "$(GREEN)🚀 Release build optimized$(NC)"
	@strip $(TARGET) 2>/dev/null || true
	@echo "$(BLUE)📏 Size:$$(stat -c%s $(TARGET) 2>/dev/null || echo "?") bytes$(NC)"

debug: CFLAGS += $(DEBUG_FLAGS) -O0
debug: clean build
	@echo "$(CYAN)🐛 Debug build with symbols$(NC)"

build: $(TARGET)

$(TARGET): $(OBJ)
	@echo "$(BLUE)🔨 Building $(TARGET) with optimizations...$(NC)"
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJ) $(LIBS)
	@echo "$(GREEN)✅ $(TARGET) built$(NC)"

$(OBJ): $(SRC) src/clobes.h
	@echo "$(BLUE)📝 Compiling $(SRC)...$(NC)"
	$(CC) $(CFLAGS) -c $(SRC) -o $(OBJ)

install: release
	@echo "$(GREEN)📦 Installing CLOBES PRO...$(NC)"
	@chmod +x install.sh
	@sudo ./install.sh || echo "$(YELLOW)⚠️  Use: sudo make install$(NC)"

uninstall:
	@echo "$(YELLOW)🗑️  Uninstalling...$(NC)"
	@sudo clobes-uninstall 2>/dev/null || echo "$(RED)❌ Uninstaller not found$(NC)"

clean:
	@echo "$(BLUE)🧹 Cleaning...$(NC)"
	rm -f $(TARGET) $(OBJ) src/*.o
	@echo "$(GREEN)✅ Cleaned$(NC)"

test: build
	@echo "$(CYAN)🧪 Running tests...$(NC)"
	./$(TARGET) version
	./$(TARGET) --help | head -5
	@echo "$(GREEN)✅ Basic tests passed$(NC)"

bench: build
	@echo "$(MAGENTA)⚡ Benchmarking...$(NC)"
	@time ./$(TARGET) network get https://httpbin.org/get > /dev/null
	@echo "$(GREEN)✅ Benchmark complete$(NC)"

profile: CFLAGS += -pg
profile: clean build
	@echo "$(CYAN)📊 Profiling build created$(NC)"
	@echo "Run with: ./$(TARGET) [command]"
	@echo "Analyze: gprof $(TARGET) gmon.out"

docker:
	@echo "$(BLUE)🐳 Building Docker image...$(NC)"
	@docker build -t clobes-pro:latest . 2>/dev/null || echo "$(YELLOW)⚠️  Dockerfile not found$(NC)"

package: release
	@echo "$(GREEN)📦 Creating package...$(NC)"
	@if command -v zarch >/dev/null 2>&1; then \
		zarch build @za.json; \
		PACKAGE=$$(ls *.zv 2>/dev/null | head -1); \
		if [ -f "$$PACKAGE" ]; then \
			echo "✅ Package: $$PACKAGE"; \
		fi; \
	else \
		tar -czf clobes-pro-$$(date +%Y%m%d).tar.gz src/ bin/ lib/ @za.json install.sh; \
		echo "✅ Archive: clobes-pro-$$(date +%Y%m%d).tar.gz"; \
	fi

help:
	@echo "$(CYAN)CLOBES PRO Makefile Commands:$(NC)"
	@echo "  $(GREEN)make$(NC)            - Build release (default)"
	@echo "  $(GREEN)make release$(NC)    - Optimized release build"
	@echo "  $(GREEN)make debug$(NC)      - Debug build with symbols"
	@echo "  $(GREEN)make install$(NC)    - Install system-wide"
	@echo "  $(GREEN)make uninstall$(NC)  - Uninstall from system"
	@echo "  $(GREEN)make clean$(NC)      - Clean build files"
	@echo "  $(GREEN)make test$(NC)       - Run basic tests"
	@echo "  $(GREEN)make bench$(NC)      - Performance benchmark"
	@echo "  $(GREEN)make profile$(NC)    - Create profiling build"
	@echo "  $(GREEN)make package$(NC)    - Create distributable package"
	@echo "  $(GREEN)make docker$(NC)     - Build Docker image"
	@echo "  $(GREEN)make help$(NC)       - Show this help"
	@echo ""
	@echo "$(YELLOW)CLOBES PRO v4.0.0 - Ultimate CLI Toolkit$(NC)"

.DEFAULT_GOAL := help

install-user:
@echo "$(GREEN)📦 Installing CLOBES PRO for current user...$(NC)"
@mkdir -p ~/.local/bin
@cp clobes ~/.local/bin/
@chmod 755 ~/.local/bin/clobes
@mkdir -p ~/.config/clobes
@cp config/user.json ~/.config/clobes/config.pro.json 2>/dev/null || \\
echo '{"ui":{"colors":true}}' > ~/.config/clobes/config.pro.json
@if ! echo "$$PATH" | grep -q "$$HOME/.local/bin"; then \\
echo 'export PATH="$$HOME/.local/bin:$$PATH"' >> ~/.bashrc; \\
echo 'export PATH="$$HOME/.local/bin:$$PATH"' >> ~/.profile; \\
echo "$(BLUE)✓ Added ~/.local/bin to PATH$(NC)"; \\
fi
@echo "$(GREEN)✅ CLOBES PRO installed for current user$(NC)"
@echo ""
@echo "You may need to restart your shell or run:"
@echo "  source ~/.bashrc"
@echo ""
@echo "Then test with:"
@echo "  clobes version"

install-user:
@echo "$(GREEN)📦 Installing CLOBES PRO for current user...$(NC)"
@mkdir -p ~/.local/bin
@cp clobes ~/.local/bin/
@chmod 755 ~/.local/bin/clobes
@mkdir -p ~/.config/clobes
@cp config/user.json ~/.config/clobes/config.pro.json 2>/dev/null || \\
echo '{"ui":{"colors":true}}' > ~/.config/clobes/config.pro.json
@if ! echo "$$PATH" | grep -q "$$HOME/.local/bin"; then \\
echo 'export PATH="$$HOME/.local/bin:$$PATH"' >> ~/.bashrc; \\
echo 'export PATH="$$HOME/.local/bin:$$PATH"' >> ~/.profile; \\
echo "$(BLUE)✓ Added ~/.local/bin to PATH$(NC)"; \\
fi
@echo "$(GREEN)✅ CLOBES PRO installed for current user$(NC)"
@echo ""
@echo "You may need to restart your shell or run:"
@echo "  source ~/.bashrc"
@echo ""
@echo "Then test with:"
@echo "  clobes version"
