.PHONY: all clean run

# Compiler and flags
CLANG ?= clang
BPFTOOL ?= bpftool
CFLAGS = -O2 -g -Wall
BPF_CFLAGS = -O2 -g -target bpf

# Directories and files
SRC_DIR = src
KERN_SRC = $(SRC_DIR)/io_profiler_kern.c
USER_SRC = $(SRC_DIR)/io_profiler_user.c
BPF_OBJ = $(SRC_DIR)/io_profiler_kern.o
BPF_SKEL = $(SRC_DIR)/io_profiler_kern.skel.h
VMLINUX_H = $(SRC_DIR)/vmlinux.h
OUTPUT = io_profiler

# Default target
all: $(OUTPUT)

# Rule to build the final output binary
$(OUTPUT): $(BPF_OBJ) $(BPF_SKEL) $(USER_SRC)
	$(CC) $(CFLAGS) -I$(SRC_DIR) $(USER_SRC) -o $(OUTPUT) -lbpf -lelf -lz

# Rule to compile BPF kernel object
$(BPF_OBJ): $(KERN_SRC) $(VMLINUX_H)
	$(CLANG) $(BPF_CFLAGS) -c $(KERN_SRC) -o $(BPF_OBJ) -I$(SRC_DIR)

# Rule to generate BPF skeleton
$(BPF_SKEL): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $(BPF_OBJ) > $(BPF_SKEL)

# Rule to generate vmlinux.h if missing
$(VMLINUX_H):
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX_H)

# Run the program
run: all
	sudo ./$(OUTPUT)

# Clean up all generated files
clean:
	rm -f $(OUTPUT) $(SRC_DIR)/*.o $(SRC_DIR)/*.skel.h $(SRC_DIR)/vmlinux.h