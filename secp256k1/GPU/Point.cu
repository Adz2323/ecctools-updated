#include "Point.cuh"
#include <stdio.h>

__host__ Point::Point()
{
    Clear();
}

__host__ Point::Point(const Point &p)
{
    x.Set((Int *)&p.x);
    y.Set((Int *)&p.y);
    z.Set((Int *)&p.z);
}

__host__ Point::Point(Int *cx, Int *cy, Int *cz)
{
    x.Set(cx);
    y.Set(cy);
    z.Set(cz);
}

__host__ Point::Point(Int *cx, Int *cz)
{
    x.Set(cx);
    z.Set(cz);
}

__device__ __host__ void Point::Clear()
{
    x.SetInt32(0);
    y.SetInt32(0);
    z.SetInt32(1);
}

__device__ __host__ void Point::setInfinity()
{
    x.SetInt32(0);
    y.SetInt32(0);
    z.SetInt32(0);
}

__device__ __host__ void Point::Set(Int *cx, Int *cy, Int *cz)
{
    x.Set(cx);
    y.Set(cy);
    z.Set(cz);
}

__host__ Point::~Point()
{
}

__device__ __host__ void Point::Set(const Point &p)
{
    x.Set((Int *)&p.x);
    y.Set((Int *)&p.y);
    z.Set((Int *)&p.z);
}

__device__ __host__ bool Point::isZero()
{
    return z.IsZero();
}

__device__ __host__ bool Point::isOne()
{
    return z.IsOne();
}

__device__ __host__ void Point::Reduce()
{
    if (!isZero() && !isOne())
    {
        Int i(&z);
        i.ModInv();
        x.ModMulK1(&x, &i);
        y.ModMulK1(&y, &i);
        z.SetInt32(1);
    }
}

__device__ __host__ bool Point::equals(Point &p)
{
    // Fast infinity check
    if (isZero() || p.isZero())
        return isZero() && p.isZero();

    // Avoid memory allocations by using stack
    if (!isOne() || !p.isOne())
    {
        Int i1, i2, x1, x2, y1, y2;

        // Normalize first point
        if (!isOne())
        {
            i1.Set(&z);
            i1.ModInv();
            x1.Set(&x);
            x1.ModMulK1(&i1);
            y1.Set(&y);
            y1.ModMulK1(&i1);
        }
        else
        {
            x1.Set(&x);
            y1.Set(&y);
        }

        // Normalize second point
        if (!p.isOne())
        {
            i2.Set(&p.z);
            i2.ModInv();
            x2.Set(&p.x);
            x2.ModMulK1(&i2);
            y2.Set(&p.y);
            y2.ModMulK1(&i2);
        }
        else
        {
            x2.Set(&p.x);
            y2.Set(&p.y);
        }

        return x1.IsEqual(&x2) && y1.IsEqual(&y2);
    }

    return x.IsEqual(&p.x) && y.IsEqual(&p.y);
}

__device__ __host__ bool Point::debugEquals(Point &p)
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

__device__ __host__ bool Point::isOnCurve()
{
    if (isZero())
        return true;

    if (!isOne())
    {
        // y²z = x³ + 7z³
        Int y2, x3, z2, z3, temp;

        y2.ModSquareK1(&y);
        x3.ModSquareK1(&x);
        x3.ModMulK1(&x3, &x);

        z2.ModSquareK1(&z);
        z3.ModMulK1(&z2, &z);
        temp.SetInt32(7);
        z3.ModMulK1(&z3, &temp);

        x3.ModAdd(&z3);

        y2.ModMulK1(&y2, &z); // Multiply y² by z

        return y2.IsEqual(&x3);
    }

    // Already normalized case
    Int y2, x3;
    y2.ModSquareK1(&y);
    x3.ModSquareK1(&x);
    x3.ModMulK1(&x3, &x);
    Int _7((int64_t)7);
    x3.ModAdd(&_7);

    return y2.IsEqual(&x3);
}