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
SHEFp atan2(shemaxfloat_t, const SHEFp &);
SHEFp atan2(const SHEFp &, shemaxfloat_t);
SHEFp atanh(const SHEFp &);
SHEFp cbrt(const SHEFp &);
SHEFp ceil(const SHEFp &);
SHEFp copysign(const SHEFp &, const SHEFp &);
SHEFp copysign(shemaxfloat_t, const SHEFp &);
SHEFp copysign(const SHEFp &, shemaxfloat_t);
SHEFp cos(const SHEFp &);
SHEFp cosh(const SHEFp &);
SHEFp erf(const SHEFp &);
SHEFp erfc(const SHEFp &);
SHEFp exp(const SHEFp &);
SHEFp exp2(const SHEFp &);
SHEFp expm1(const SHEFp &);
SHEFp fabs(const SHEFp &);
SHEFp fdim(const SHEFp &, const SHEFp &);
SHEFp fdim(shemaxfloat_t, const SHEFp &);
SHEFp fdim(const SHEFp &, shemaxfloat_t);
SHEFp floor(const SHEFp &);
SHEFp fma(const SHEFp &, const SHEFp &, const SHEFp &);
SHEFp fma(shemaxfloat_t, const SHEFp &, const SHEFp &);
SHEFp fma(const SHEFp &, shemaxfloat_t, const SHEFp &);
SHEFp fma(const SHEFp &, const SHEFp &, shemaxfloat_t);
SHEFp fma(const SHEFp &, shemaxfloat_t, shemaxfloat_t);
SHEFp fma(shemaxfloat_t, const SHEFp &, shemaxfloat_t);
SHEFp fma(shemaxfloat_t, shemaxfloat_t, const SHEFp &);
SHEFp fmax(const SHEFp &, const SHEFp &);
SHEFp fmax(shemaxfloat_t, const SHEFp &);
SHEFp fmax(const SHEFp &, shemaxfloat_t);
SHEFp fmin(const SHEFp &, const SHEFp &);
SHEFp fmin(shemaxfloat_t, const SHEFp &);
SHEFp fmin(const SHEFp &, shemaxfloat_t);
SHEFp fmod(const SHEFp &, const SHEFp &);
SHEFp fmod(shemaxfloat_t, const SHEFp &);
SHEFp fmod(const SHEFp &, shemaxfloat_t);
SHEFp frexp(const SHEFp &, SHEInt &);
SHEFp hypot(const SHEFp &, const SHEFp &);
SHEFp hypot(shemaxfloat_t, const SHEFp &);
SHEFp hypot(const SHEFp &, shemaxfloat_t);
SHEInt ilogb(const SHEFp &);
SHEFp j0(const SHEFp &);
SHEFp j1(const SHEFp &);
SHEFp jn(const SHEInt &, const SHEFp &);
SHEFp jn(uint64_t, const SHEFp &);
SHEFp jn(const SHEInt &, shemaxfloat_t);
SHEFp ldexp(const SHEFp &, const SHEInt &);
SHEFp ldexp(const SHEFp &, int64_t);
SHEFp ldexp(shemaxfloat_t, const SHEInt &);
SHEFp lgamma(const SHEFp &);
SHEFp lgamma_r(const SHEFp &, SHEInt &);
SHEFp log(const SHEFp &);
SHEFp log10(const SHEFp &);
SHEFp log1p(const SHEFp &);
SHEFp log2(const SHEFp &);
SHEFp logb(const SHEFp &);
SHEInt lrint(const SHEFp &);
SHEInt lround(const SHEFp &);
SHEFp modf(const SHEFp &, SHEFp &);
SHEFp modf(shemaxfloat_t, SHEFp &);
SHEFp modf(const SHEFp &, shemaxfloat_t);
//SHEFp nan(const char *);
SHEFp nearbyint(const SHEFp &);
SHEFp nextafter(const SHEFp &, const SHEFp &);
SHEFp nextafter(shemaxfloat_t, const SHEFp &);
SHEFp nextafter(const SHEFp &, shemaxfloat_t);
// with SHEFp being general, these are identical to nextafter
inline SHEFp nexttoward(const SHEFp & a, const SHEFp & b)
{ return nextafter(a,b); }
inline SHEFp nexttoward(shemaxfloat_t a, const SHEFp & b)
{ return nextafter(a,b); }
inline SHEFp nexttoward(const SHEFp & a, shemaxfloat_t b)
{ return nextafter(a,b); }
SHEFp pow(const SHEFp &, const SHEFp &);
SHEFp pow(shemaxfloat_t, const SHEFp &);
SHEFp pow(const SHEFp &, shemaxfloat_t);
SHEFp remainder(const SHEFp &, const SHEFp &);
SHEFp remainder(shemaxfloat_t, const SHEFp &);
SHEFp remainder(const SHEFp &, shemaxfloat_t);
SHEFp remquo(const SHEFp &, const SHEFp &, SHEInt &);
SHEFp remquo(shemaxfloat_t, const SHEFp &, SHEInt &);
SHEFp remquo(const SHEFp &, shemaxfloat_t, SHEInt &);
SHEFp rint(const SHEFp &);
SHEFp round(const SHEFp &);
SHEFp scalbn(const SHEFp &, const SHEInt &);
SHEFp scalbn(shemaxfloat_t, const SHEInt &);
SHEFp scalbn(const SHEFp &, uint64_t);
SHEFp sin(const SHEFp &);
SHEFp sinh(const SHEFp &);
SHEFp sqrt(const SHEFp &);
SHEFp tan(const SHEFp &);
SHEFp tanh(const SHEFp &);
SHEFp tgamma(const SHEFp &);
SHEFp trunc(const SHEFp &);
SHEFp y0(const SHEFp &);
SHEFp y1(const SHEFp &);
SHEFp yn(const SHEInt &, const SHEFp &);
SHEFp yn(uint64_t, const SHEFp &);
SHEFp yn(const SHEInt &, shemaxfloat_t);
