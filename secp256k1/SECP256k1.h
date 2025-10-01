/*
 * This file is part of the BSGS distribution (https://github.com/JeanLucPons/BSGS).
 * Copyright (c) 2020 Jean Luc PONS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef SECP256K1H
#define SECP256K1H

#include "Point.h"
#include <vector>

// Platform-specific SIMD detection
#ifdef _MSC_VER
// Windows
#include <intrin.h>
#elif defined(__APPLE__)
// macOS
#if defined(__clang__)
// Include only specific headers needed
#if __has_include(<smmintrin.h>)
#include <smmintrin.h> // SSE4.1
#endif
#endif
#else
// Linux and others
#include <cpuid.h>
#if defined(__SSE4_1__)
#include <smmintrin.h>
#endif
#if defined(__AVX2__)
#include <immintrin.h>
#endif
#endif

// Address type
#define P2PKH 0
#define P2SH 1
#define BECH32 2

class Secp256K1
{

public:
  Secp256K1();
  ~Secp256K1();
  void Init();
  Point ComputePublicKey(Int *privKey);
  Point NextKey(Point &key);
  bool EC(Point &p);
  Int GetY(Int x, bool isEven);

  Point ScalarMultiplication(Point &P, Int *scalar, bool debug = false);
  bool VerifyPoint(Point &p, const char *label);
  Point GetIdentity();

  char *GetPublicKeyHex(bool compressed, Point &p);
  void GetPublicKeyHex(bool compressed, Point &pubKey, char *dst);

  char *GetPublicKeyRaw(bool compressed, Point &p);
  void GetPublicKeyRaw(bool compressed, Point &pubKey, char *dst);

  bool ParsePublicKeyHex(char *str, Point &p, bool &isCompressed);

  void GetHash160(int type, bool compressed,
                  Point &k0, Point &k1, Point &k2, Point &k3,
                  uint8_t *h0, uint8_t *h1, uint8_t *h2, uint8_t *h3);

  void GetHash160(int type, bool compressed, Point &pubKey, unsigned char *hash);

  void GetHash160_fromX(int type, unsigned char prefix,
                        Int *k0, Int *k1, Int *k2, Int *k3,
                        uint8_t *h0, uint8_t *h1, uint8_t *h2, uint8_t *h3);

  Point Add(Point &p1, Point &p2);
  Point Add2(Point &p1, Point &p2);
  Point AddDirect(Point &p1, Point &p2);
  Point Double(Point &p);
  Point DoubleDirect(Point &p);
  Point Negation(Point &p);
  Point SubtractPoints(Point &P1, Point &P2);

  Point G;   // Generator
  Int P;     // Prime for the finite field
  Int order; // Curve order

// Fast point halving (division by 2)
  Point HalvePoint(Point &p);
  Point HalvePointFast(Point &p);
  std::vector<Point> BatchHalve(std::vector<Point> &points);
    
    // Batch inversion for optimization
  void BatchModInverse(std::vector<Int*> &values, std::vector<Int> &results);
    
    // Hash function for collision detection
  uint64_t HashPoint(const Point &p);
    
    // Optimized subtraction by small values
  Point SubtractSmall(Point &p, int value);

private:
  uint8_t GetByte(char *str, int idx);
  Point GTable[256 * 32]; // Generator table

  Int half_mod_p;
  bool half_mod_initialized = false;
    
  void InitHalfMod();

  // SIMD support flags
  static bool hasSSE2;
  static bool hasSSE3;
  static bool hasSSSE3;
  static bool hasSSE41;
  static bool hasSSE42;
  static bool hasAVX;
  static bool hasAVX2;
  static void DetectSIMD();
};

#endif // SECP256K1H
