# Compiler settings
CC=gcc
CXX=g++

# Detect OS type
UNAME_S := $(shell uname -s)

# Detect number of CPU cores based on OS
ifeq ($(UNAME_S),Darwin) # macOS
    NPROC=$(shell sysctl -n hw.ncpu)
    UNSUPPORTED_FLAGS=-fuse-linker-plugin -fprefetch-loop-arrays -fno-semantic-interposition
else
    NPROC=$(shell nproc)
    UNSUPPORTED_FLAGS=
endif

# Include directories
INCLUDES=-I. -I./sha256 -I./base58 -I./rmd160 -I./xxhash -I./bloom

# XXHash Implementation define
XXH_FLAGS=-DXXH_PRIVATE_API -DXXH_IMPLEMENTATION

# Detect available CPU features
HAS_AVX2 := $(shell $(CC) -mavx2 -dM -E - < /dev/null 2>/dev/null | grep -c "AVX2")
HAS_AVX512 := $(shell $(CC) -mavx512f -dM -E - < /dev/null 2>/dev/null | grep -c "AVX512F")
HAS_SSE2 := $(shell $(CC) -msse2 -dM -E - < /dev/null 2>/dev/null | grep -c "SSE2")

# Set architecture-specific flags
ARCH_FLAGS=-m64 -march=native -mtune=native

ifeq ($(HAS_AVX512),1)
    ARCH_FLAGS += -mavx512f -mavx512vl -mavx512bw -mavx512dq
else ifeq ($(HAS_AVX2),1)
    ARCH_FLAGS += -mavx2
else ifeq ($(HAS_SSE2),1)
    ARCH_FLAGS += -msse2
endif

# Advanced optimization flags
OPTFLAGS=$(ARCH_FLAGS) -Ofast -ftree-vectorize -flto \
         $(filter-out $(UNSUPPORTED_FLAGS), \
         -funroll-loops -pipe -fomit-frame-pointer \
         -fmerge-all-constants -fno-stack-protector \
         -fno-math-errno -fno-trapping-math) \
         -DXXH_INLINE_ALL

# Debug flags
ifeq ($(DEBUG),1)
    OPTFLAGS=-g -O0 -DDEBUG
endif

# Warning flags
ifeq ($(UNAME_S),Darwin)
    WFLAGS=-Wall -Wextra -Wno-deprecated-copy -Wno-unused-result -Wno-unknown-pragmas
else
    WFLAGS=-Wall -Wextra -Wno-deprecated-copy -Wno-unused-result
endif

# C specific flags
CFLAGS=$(OPTFLAGS) $(WFLAGS) $(INCLUDES) $(XXH_FLAGS) -std=c11

# C++ specific flags
CXXFLAGS=$(OPTFLAGS) $(WFLAGS) $(INCLUDES) $(XXH_FLAGS) -std=c++11

# Linker flags
LDFLAGS=$(OPTFLAGS)
LIBS=-lgmp -lpthread -lm

# Output binary
TARGET=keydivision

# Source files
C_SOURCES=sha256/sha256.c \
        base58/base58.c \
        rmd160/rmd160.c \
        gmpecc.c \
        util.c \
        keydivision.c \
        xxhash/xxhash.c

CPP_SOURCES=bloom/bloom.cpp

# Generate object file names
C_OBJECTS=$(C_SOURCES:.c=.o)
CPP_OBJECTS=$(CPP_SOURCES:.cpp=.o)
OBJECTS=$(C_OBJECTS) $(CPP_OBJECTS)

# Generate dependency files
DEPS=$(OBJECTS:.o=.d)

# Default target
all: $(TARGET)

# Include dependency files
-include $(DEPS)

# Compile C files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Compile C++ files
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Link everything together
$(TARGET): $(OBJECTS)
	$(CXX) $(LDFLAGS) -o $@ $(OBJECTS) $(LIBS)

# Clean target
clean:
	rm -f $(TARGET) $(OBJECTS) $(DEPS)
	rm -f *~ *.d

# Deep clean
distclean: clean
	rm -f *.dat
	rm -f checkpoint_*.dat

# Run with optimal thread count
run: $(TARGET)
	./$(TARGET) -t $(NPROC)

# Memory check
memcheck: $(TARGET)
	valgrind --leak-check=full --show-leak-kinds=all ./$(TARGET)

.PHONY: all clean distclean run memcheck config

# Print build configuration
config:
	@echo "C Compiler: $(CC)"
	@echo "C++ Compiler: $(CXX)"
	@echo "CPU Cores: $(NPROC)"
	@echo "Architecture Flags: $(ARCH_FLAGS)"
	@echo "Optimization Flags: $(OPTFLAGS)"
	@echo "Operating System: $(UNAME_S)"
