//
// Encrypted version of math.h.
//
// This mirrors the functions in math.h, taking encrypted versions of
// the inputs and production encrypted outputs.
//
// We should also include some decrypted scalar versions of the
// functions that take 2 arguments at some point.
//
#include "SHEInt.h"
#include "SHEFp.h"

// "macros" (actually inline functions, but the originals in the unencrypted
// space are macros).
inline SHEInt fpclassify(const SHEFp &x) {
  // FP_SUBNormal is the only case we don't check explicitly
  SHEUInt8 fpClass(x.getExp().getPublicKey(), FP_SUBNORMAL);
  fpClass = x.isNan().select(FP_NAN, fpClass);
  fpClass = x.isInf().select(FP_INFINITE, fpClass);
  fpClass = x.isZero().select(FP_ZERO, fpClass);
  fpClass = x.isNormal().select(FP_NORMAL, fpClass);
  return fpClass;
}
inline SHEBool isfinite(const SHEFp &x) { return x.isFinite(); }
// this macro return -1 for -INF, and 1 for INF (otherwise it returns zero)
inline SHEInt isinf(const SHEFp &x)
{
  SHEInt8 inf(x.isInf());
  return x.getSign().select(-inf, inf);
}
inline SHEBool isnan(const SHEFp &x) { return x.isNan(); }
inline SHEBool isnormal(const SHEFp &x) { return x.isNormal(); }

inline SHEBool signbit(const SHEFp &x) { return x.getSign(); }
inline SHEBool isunordered(const SHEFp &x, const SHEFp &y)
{ return x.isNan() || y.isNan(); }
inline SHEBool isgreater(const SHEFp &x, const SHEFp &y) { return x > y; }
inline SHEBool isgreaterequal(const SHEFp &x, const SHEFp &y)
{ return x >= y;}
inline SHEBool isless(const SHEFp &x, const SHEFp &y) { return x < y; }
inline SHEBool islessequal(const SHEFp &x, const SHEFp &y) { return x <= y; }
inline SHEBool islessgreater(const SHEFp &x, const SHEFp &y)
{ return (x < y) || (x > y); }

// utility functions
void SHEMathSetLog(std::ostream &str);

// functions, (implemented in SHEMath.cpp)
SHEFp acos(const SHEFp &);
SHEFp acosh(const SHEFp &);
SHEFp asin(const SHEFp &);
SHEFp asinh(const SHEFp &);
SHEFp atan(const SHEFp &);
SHEFp atan2(const SHEFp &, const SHEFp &);
SHEFp atanh(const SHEFp &);
SHEFp cbrt(const SHEFp &);
SHEFp ceil(const SHEFp &);
SHEFp copysign(const SHEFp &, const SHEFp &);
SHEFp cos(const SHEFp &);
SHEFp cosh(const SHEFp &);
SHEFp erf(const SHEFp &);
SHEFp erfc(const SHEFp &);
SHEFp exp(const SHEFp &);
SHEFp exp2(const SHEFp &);
SHEFp expm1(const SHEFp &);
SHEFp fabs(const SHEFp &);
SHEFp fdim(const SHEFp &, const SHEFp &);
SHEFp floor(const SHEFp &);
SHEFp fma(const SHEFp &, const SHEFp &, const SHEFp &);
SHEFp fmax(const SHEFp &, const SHEFp &);
SHEFp fmin(const SHEFp &, const SHEFp &);
SHEFp fmod(const SHEFp &, const SHEFp &);
SHEFp frexp(const SHEFp &, SHEInt &);
SHEFp hypot(const SHEFp &, const SHEFp &);
SHEInt ilogb(const SHEFp &);
SHEFp j0(const SHEFp &);
SHEFp j1(const SHEFp &);
SHEFp jn(const SHEInt &, const SHEFp &);
SHEFp ldexp(const SHEFp &, const SHEInt &);
SHEFp lgamma(const SHEFp &);
SHEFp log(const SHEFp &);
SHEFp log10(const SHEFp &);
SHEFp log1p(const SHEFp &);
SHEFp log2(const SHEFp &);
SHEFp logb(const SHEFp &);
SHEInt lrint(const SHEFp &);
SHEInt lround(const SHEFp &);
SHEFp modf(const SHEFp &, SHEFp &);
//SHEFp nan(const char *);
SHEFp nearbyint(const SHEFp &);
SHEFp nextafter(const SHEFp &, const SHEFp &);
//SHEFp nexttoward(const SHEFp &, long const SHEFp &);
SHEFp pow(const SHEFp &, const SHEFp &);
SHEFp remainder(const SHEFp &, const SHEFp &);
SHEFp remquo(const SHEFp &, const SHEFp &, SHEInt &);
SHEFp rint(const SHEFp &);
SHEFp round(const SHEFp &);
SHEFp scalbn(const SHEFp &, const SHEInt &);
SHEFp sin(const SHEFp &);
SHEFp sqrt(const SHEFp &);
SHEFp tan(const SHEFp &);
SHEFp tanh(const SHEFp &);
SHEFp tgamma(const SHEFp &);
SHEFp trunc(const SHEFp &);
SHEFp y0(const SHEFp &);
SHEFp y1(const SHEFp &);
SHEFp yn(const SHEInt &, const SHEFp &);
