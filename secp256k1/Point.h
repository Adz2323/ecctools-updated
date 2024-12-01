#ifndef POINTH
#define POINTH

#include "Int.h"

class Point
{

public:
  Point();
  Point(Int *cx, Int *cy, Int *cz);
  Point(Int *cx, Int *cz);
  Point(const Point &p);
  ~Point();

  bool isZero();
  bool equals(Point &p);
  bool debugEquals(Point &p); // Added debug equality method
  void Set(const Point &p);
  void Set(Int *cx, Int *cy, Int *cz);
  void Clear();
  void Reduce();
  void setInfinity();
  bool isOnCurve(); // Added validation method
  bool isOne();     // Added z=1 check method

  Int x;
  Int y;
  Int z;
};

#endif // POINTH