# Compiler and flags
CC = gcc
CFLAGS = -Wall -g -O2 -Isrc
LDFLAGS =

# Directories
SRC_DIR = src
POLICY_DIR = $(SRC_DIR)/syscall_policy
BUILD_DIR = build
BIN = tracer

# Source files (recursive)
SRCS = $(wildcard $(SRC_DIR)/*.c) \
       $(wildcard $(POLICY_DIR)/*.c)

# Object files (mirror directory structure)
OBJS = $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/%.o, $(SRCS))

# Default target
all: $(BIN)

# Link
$(BIN): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $@ $(LDFLAGS)

# Compile rule (handles subdirectories)
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

# Clean
clean:
	rm -rf $(BUILD_DIR) $(BIN)

.PHONY: all clean
