# Default target for building pubdiv
default:
	g++ -m64 -march=native -mtune=native -mssse3 -Wall -Wextra -Wno-deprecated-copy -Ofast -ftree-vectorize -flto -c oldbloom/bloom.cpp -o oldbloom.o
	g++ -m64 -march=native -mtune=native -mssse3 -Wall -Wextra -Wno-deprecated-copy -Ofast -ftree-vectorize -flto -c bloom/bloom.cpp -o bloom.o
	gcc -m64 -march=native -mtune=native -mssse3 -Wall -Wextra -Wno-unused-parameter -Ofast -ftree-vectorize -c base58/base58.c -o base58.o
	gcc -m64 -march=native -mtune=native -mssse3 -Wall -Wextra -Ofast -ftree-vectorize -c rmd160/rmd160.c -o rmd160.o
	gcc -m64 -march=native -mtune=native -mssse3 -Wall -Wextra -Ofast -ftree-vectorize -c sha256/sha256.c -o sha256.o
	g++ -m64 -march=native -mtune=native -mssse3 -Wall -Wextra -Wno-deprecated-copy -Ofast -ftree-vectorize -c sha3/sha3.c -o sha3.o
	g++ -m64 -march=native -mtune=native -mssse3 -Wall -Wextra -Wno-deprecated-copy -Ofast -ftree-vectorize -c sha3/keccak.c -o keccak.o
	gcc -m64 -march=native -mtune=native -mssse3 -Wall -Wextra -Ofast -ftree-vectorize -c xxhash/xxhash.c -o xxhash.o
	gcc -m64 -march=native -mtune=native -mssse3 -Wall -Wextra -Wno-deprecated-copy -Ofast -ftree-vectorize -c util.c -o util.o
	g++ -m64 -march=native -mtune=native -mssse3 -Wall -Wextra -Wno-deprecated-copy -Ofast -ftree-vectorize -c secp256k1/Int.cpp -o Int.o
	g++ -m64 -march=native -mtune=native -mssse3 -Wall -Wextra -Wno-deprecated-copy -Ofast -ftree-vectorize -c secp256k1/Point.cpp -o Point.o
	g++ -m64 -march=native -mtune=native -mssse3 -Wall -Wextra -Wno-deprecated-copy -Ofast -ftree-vectorize -c secp256k1/SECP256K1.cpp -o SECP256K1.o
	g++ -m64 -march=native -mtune=native -mssse3 -Wall -Wextra -Wno-deprecated-copy -Ofast -ftree-vectorize -c secp256k1/IntMod.cpp -o IntMod.o
	g++ -m64 -march=native -mtune=native -mssse3 -Wall -Wextra -Wno-deprecated-copy -Ofast -ftree-vectorize -flto -c secp256k1/Random.cpp -o Random.o
	g++ -m64 -march=native -mtune=native -mssse3 -Wall -Wextra -Wno-deprecated-copy -Ofast -ftree-vectorize -flto -c secp256k1/IntGroup.cpp -o IntGroup.o
	g++ -m64 -march=native -mtune=native -mssse3 -Wall -Wextra -Wno-deprecated-copy -Ofast -o hash/ripemd160.o -ftree-vectorize -flto -c hash/ripemd160.cpp
	g++ -m64 -march=native -mtune=native -mssse3 -Wall -Wextra -Wno-deprecated-copy -Ofast -o hash/sha256.o -ftree-vectorize -flto -c hash/sha256.cpp
	g++ -m64 -march=native -mtune=native -mssse3 -Wall -Wextra -Wno-deprecated-copy -Ofast -o hash/ripemd160_sse.o -ftree-vectorize -flto -c hash/ripemd160_sse.cpp
	g++ -m64 -march=native -mtune=native -mssse3 -Wall -Wextra -Wno-deprecated-copy -Ofast -o hash/sha256_sse.o -ftree-vectorize -flto -c hash/sha256_sse.cpp
	g++ -m64 -march=native -mtune=native -mssse3 -Wall -Wextra -Wno-deprecated-copy -Ofast -ftree-vectorize -flto -std=c++11 -I/usr/local/include -c keydivision.c -o div.o
	gcc -m64 -march=native -mtune=native -mssse3 -Wall -Wextra -Wno-deprecated-copy -Ofast -ftree-vectorize -o Auto AutoDivision.c gmpecc.c util.o bloom.o base58.o sha256.o rmd160.o xxhash.o -lgmp -pthread
	g++ -m64 -march=native -mtune=native -mssse3 -Wall -Wextra -Wno-deprecated-copy -Ofast -ftree-vectorize -o keyhunt keyhunt.cpp base58.o rmd160.o hash/ripemd160.o hash/ripemd160_sse.o hash/sha256.o hash/sha256_sse.o bloom.o oldbloom.o xxhash.o util.o Int.o Point.o SECP256K1.o IntMod.o Random.o IntGroup.o sha3.o keccak.o -lm -lpthread
	g++ -m64 -march=native -mtune=native -mssse3 -pthread -Ofast -flto \
		bloom.o base58.o rmd160.o sha3.o keccak.o xxhash.o util.o \
		Int.o Point.o SECP256K1.o IntMod.o Random.o IntGroup.o \
		hash/ripemd160.o hash/sha256.o hash/ripemd160_sse.o hash/sha256_sse.o \
		div.o -o div -lgmp
	g++ -m64 -march=native -mtune=native -mssse3 -Wall -Wextra -Ofast -ftree-vectorize -flto -std=c++11 -o run run.cpp
	rm -r *.o

# Debug target for test.cpp
debug:
	g++ -m64 -march=native -mtune=native -mssse3 -Wall -Wextra -g -std=c++11 -o DebugTest \
		secp256k1/Int.cpp secp256k1/Point.cpp secp256k1/SECP256K1.cpp secp256k1/IntMod.cpp \
		secp256k1/Random.cpp secp256k1/IntGroup.cpp hash/ripemd160.cpp hash/sha256.cpp \
		hash/ripemd160_sse.cpp hash/sha256_sse.cpp util.c secp256k1/test.cpp

# Target for building and running run.cpp
run:
	g++ -m64 -march=native -mtune=native -mssse3 -Wall -Wextra -Ofast -ftree-vectorize -flto -std=c++11 -o run run.cpp keyhunt div
	./run <input_pubkey> <target_pubkey>

clean:
	rm -f *.o div DebugEC DebugTest hash/*.o run

.PHONY: default debug clean run
