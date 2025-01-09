#ifndef POINT_CUH
#define POINT_CUH

#include "Int.h"
#include <cuda_runtime.h>

class Point
{
public:
    // Host functions
    __host__ Point();
    __host__ Point(Int *cx, Int *cy, Int *cz);
    __host__ Point(Int *cx, Int *cz);
    __host__ Point(const Point &p);
    __host__ ~Point();

    // Device functions
    __device__ __host__ bool isZero();
    __device__ __host__ bool equals(Point &p);
    __device__ __host__ bool debugEquals(Point &p);
    __device__ __host__ void Set(const Point &p);
    __device__ __host__ void Set(Int *cx, Int *cy, Int *cz);
    __device__ __host__ void Clear();
    __device__ __host__ void Reduce();
    __device__ __host__ void setInfinity();
    __device__ __host__ bool isOnCurve();
    __device__ __host__ bool isOne();

    // Member variables
    Int x;
    Int y;
    Int z;
};

#endif // POINT_CUH