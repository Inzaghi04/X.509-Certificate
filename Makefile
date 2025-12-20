# Compiler
CC := gcc

# Target
TARGET := x509_demo

# Source files
SRC := main.c
OBJ := $(SRC:.c=.o)

# OpenSSL flags (MSYS2 UCRT64)
OPENSSL_CFLAGS := $(shell pkg-config --cflags openssl)
OPENSSL_LIBS   := $(shell pkg-config --libs openssl)

# Compile flags
CFLAGS := -Wall -Wextra -g $(OPENSSL_CFLAGS)

# Link flags
LDFLAGS := $(OPENSSL_LIBS)

# Default target
all: $(TARGET)

# Link
$(TARGET): $(OBJ)
	$(CC) $(OBJ) -o $@ $(LDFLAGS)

# Compile
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean
clean:
	rm -f $(TARGET) $(OBJ)

.PHONY: all clean
