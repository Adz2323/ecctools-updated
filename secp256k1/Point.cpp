#include "Point.h"
#include <stdio.h>

Point::Point()
{
  Clear();
}

Point::Point(const Point &p)
{
  x.Set((Int *)&p.x);
  y.Set((Int *)&p.y);
  z.Set((Int *)&p.z);
}

Point::Point(Int *cx, Int *cy, Int *cz)
{
  x.Set(cx);
  y.Set(cy);
  z.Set(cz);
}

Point::Point(Int *cx, Int *cz)
{
  x.Set(cx);
  z.Set(cz);
}

void Point::Clear()
{
  x.SetInt32(0);
  y.SetInt32(0);
  z.SetInt32(1);
}

void Point::setInfinity()
{
  x.SetInt32(0);
  y.SetInt32(0);
  z.SetInt32(0);
}

void Point::Set(Int *cx, Int *cy, Int *cz)
{
  x.Set(cx);
  y.Set(cy);
  z.Set(cz);
}

Point::~Point()
{
}

void Point::Set(const Point &p)
{
  x.Set((Int *)&p.x);
  y.Set((Int *)&p.y);
  z.Set((Int *)&p.z);
}

bool Point::isZero()
{
  return z.IsZero();
}

bool Point::isOne()
{
  return z.IsOne();
}

void Point::Reduce()
{
  if (!isZero())
  {
    Int i(&z);
    i.ModInv();
    x.ModMulK1(&x, &i);
    y.ModMulK1(&y, &i);
    z.SetInt32(1);
  }
}

bool Point::equals(Point &p)
{
  // Handle infinity cases
  if (isZero() || p.isZero())
  {
    return isZero() && p.isZero();
  }

  // If either point isn't normalized, normalize them
  if (!isOne() || !p.isOne())
  {
    // Create copies for reduction
    Point p1(*this);
    Point p2(p);
    p1.Reduce();
    p2.Reduce();

    // Compare normalized coordinates
    return p1.x.IsEqual(&p2.x) && p1.y.IsEqual(&p2.y);
  }

  // Both points are already normalized
  return x.IsEqual(&p.x) && y.IsEqual(&p.y);
}

bool Point::debugEquals(Point &p)
{
  printf("\nDebug Point Comparison:\n");
  printf("Point 1 (this):\n");
  printf("  x: %s\n", x.GetBase16());
  printf("  y: %s\n", y.GetBase16());
  printf("  z: %s\n", z.GetBase16());
  printf("  isZero: %s\n", isZero() ? "true" : "false");
  printf("  isOne: %s\n", isOne() ? "true" : "false");

  printf("Point 2 (parameter):\n");
  printf("  x: %s\n", p.x.GetBase16());
  printf("  y: %s\n", p.y.GetBase16());
  printf("  z: %s\n", p.z.GetBase16());
  printf("  isZero: %s\n", p.isZero() ? "true" : "false");
  printf("  isOne: %s\n", p.isOne() ? "true" : "false");

  bool result = equals(p);
  printf("Equality result: %s\n", result ? "true" : "false");

  return result;
}

bool Point::isOnCurve()
{
  if (isZero())
    return true;

  // Normalize point first
  Point p(*this);
  p.Reduce();

  // For secp256k1: y² = x³ + 7
  Int y2, x3, seven;

  y2.ModSquareK1(&p.y);   // y²
  x3.ModSquareK1(&p.x);   // x²
  x3.ModMulK1(&x3, &p.x); // x³
  seven.SetInt32(7);      // 7
  x3.ModAdd(&seven);      // x³ + 7

  return y2.IsEqual(&x3); // y² ?= x³ + 7
}