//
// Implement Math.h in Encrypted variables
//
#include "SHEInt.h"
#include "SHEFp.h"
#include "SHEMath.h"
#include "math.h"

#define SHE_ARRAY_SIZE(t) (sizeof(t)/sizeof(t[0]))

static std::ostream *sheMathLog = nullptr;

void SHEMathSetLog(std::ostream &str)
{
   sheMathLog = &str;
}

// copy sign without costing  any capacity!
SHEFp copysign(const SHEFp &a, const SHEFp &b)
{
  SHEFp result(b);
  result.setSign(a.getSign());
  return result;
}

// simple functions we could probably make inline in math.h
SHEFp fmax(const SHEFp &a, const SHEFp &b) { return select((a>b), a, b); }
SHEFp fmin(const SHEFp &a, const SHEFp &b) { return select((a<b), a, b); }
SHEFp fabs(const SHEFp &a) { return a.abs(); }

// Trig functions use the power series.

// reduce to a to a mod pi/2
// q is the pi/2 quadrant from 0 to 2pi.
static SHEFp trigReduce(const SHEFp &a, SHEInt &q)
{
  SHEInt sign = a.getSign();
  SHEFp aabs(a.abs());
  if (sheMathLog)
    (*sheMathLog) << "trigReduce(" << (SHEFpSummary) a
                  << ") sign= " << (SHEIntSummary) sign
                  << ", a.abs()=" << (SHEFpSummary) aabs
                  << std::endl;

  aabs /= M_PI_2;
  std::cout << "  +aabs div pi/2=" << (SHEFpSummary) aabs << std::endl;
  // we should pass a bitSize to toSHEInt based on our SHEFp size?
  SHEInt n = aabs.toSHEInt();
  std::cout << "  +n=" << (SHEIntSummary) n;
  q=n;
  q.reset(2,true);
  std::cout << " q=" << (SHEIntSummary) q << std::endl;
  SHEFp nfp(aabs,n); // a more controlled cast.
  nfp *= M_PI_2;
  aabs = a.abs() - nfp;
  std::cout << "  +aabs reduced=" << (SHEFpSummary) aabs
            << "--a.abs()=" << (SHEFpSummary) a.abs()
            << "- ((SHEFp)n)*M_PI_2) = " << (SHEFpSummary) nfp
            << std::endl;
  q = sign.select(3-q,q);
  if (sheMathLog)
   (*sheMathLog) << "  +aabs reset=" << (SHEFpSummary) aabs << " q="
                 << (SHEIntSummary) q << std::endl;
  return aabs;
}
SHEFp cosb(const SHEFp &a)
{
  SHEFp theta(a);
  SHEFp result(theta,1.0);
  SHEFp x(theta,1.0);
  // use inverse factorial because it will give a definite
  // ending for the loop as it approaches zero.
  shemaxfloat_t invFactorial = 1.0;
  shemaxfloat_t minfloat = a.getMin();
  theta *= theta;
  if (sheMathLog) {
    (*sheMathLog) << "cos(" << (SHEFpSummary)a << ") = " << std::endl
                  << " step 0 : x^0=" << (SHEFpSummary) x << " +"
                  << invFactorial << "*x^0=" << (SHEFpSummary) x
                  << " result=" <<(SHEFpSummary)result << std::endl;
  }
  for (int i=2; i < SHEMATH_TRIG_LOOP_COUNT; i+=2) {
    // do the division unencrypted and them
    // multiply
    invFactorial /= (double)((i-1)*(i));
    // once invFactorial goes to zero, we can't proceed further
    if (invFactorial == 0.0 || invFactorial < minfloat) {
      if (sheMathLog)
        (*sheMathLog) << " step " << i << " : invFactorial=" << invFactorial
                      << " < " << minfloat << std::endl;
      break;
    }
    x *= theta;
    SHEFp term = x*invFactorial;
    if (sheMathLog)
      (*sheMathLog) << " step " << i << " : x^" << i
                    << "=" << (SHEFpSummary) x << " ";
    if (i&2) {
      result -= term;
      if (sheMathLog) (*sheMathLog) << "-";
    } else {
      result += term;
      if (sheMathLog) (*sheMathLog) << "+";
    }
    if (sheMathLog)
      (*sheMathLog) << invFactorial
                    << "*x^" << i << "=" << (SHEFpSummary)term
                    << " result=" <<(SHEFpSummary)result << std::endl;
  }
  return result;
}


SHEFp cos(const SHEFp &a)
{
  SHEInt q(a.getSign(), (uint64_t)0);
  SHEFp theta = trigReduce(a,q);
  SHEFpBool rev(q);
  rev.reset(1,true);
  theta = rev.select(M_PI_2-theta,theta);
  SHEFp result = cosb(theta);
  // switch(q)
  std::cout << "cos qin=" << (SHEIntSummary) q
            << " q.bit[0]=" << (SHEIntSummary) q.getBitHigh(0)
            << " q.bit[1]=" << (SHEIntSummary) q.getBitHigh(1) ;
  q = q.getBitHigh(0) ^ q.getBitHigh(1);
  std::cout << " qout=" << (SHEIntSummary) q << std::endl;
  result = SHEFpBool(q).select(-result,result);
  return result;
}

SHEFp sinb(const SHEFp &a)
{
  SHEFp theta(a);
  SHEFp result(theta,1.0);
  SHEFp x(theta);
  shemaxfloat_t invFactorial = 1.0;
  shemaxfloat_t minfloat = a.getMin();
  result = x;
  if (sheMathLog)
    (*sheMathLog) << "sin(" << (SHEFpSummary)a << ") = " << std::endl
                  << " step 1 : x=" << (SHEFpSummary) x << " +"
                  << invFactorial << "*x=" << (SHEFpSummary) x
                  << " result=" <<(SHEFpSummary)result << std::endl;
  theta *= theta;
  for (int i=3; i < SHEMATH_TRIG_LOOP_COUNT; i+=2) {
    // do the division unencrypted and them
    // multiply
    invFactorial /= (double)((i-1)*(i));
    // once invFactorial goes to zero, we can't proceed further
    if (invFactorial == 0.0 || invFactorial < minfloat) {
      if (sheMathLog)
        (*sheMathLog) << " step " << i << " : invFactorial=" << invFactorial
                      << " < " << minfloat << std::endl;
      break;
    }
    x *= theta;
    SHEFp term = invFactorial*x;
    if (sheMathLog)
      (*sheMathLog) << " step " << i << " : x^" << i
                    << "=" << (SHEFpSummary) x << " ";
    if (i&2) {
      result -= term;
      if (sheMathLog) (*sheMathLog) << "-";
    } else {
      result += term;
      if (sheMathLog) (*sheMathLog) << "+";
    }
    if (sheMathLog)
      (*sheMathLog) << invFactorial
                    << "*x^" << i << "=" << (SHEFpSummary)term
                    << " result=" <<(SHEFpSummary)result << std::endl;
  }
  return result;
}

SHEFp sin(const SHEFp &a)
{
  // q is the quadrant.
  SHEInt q(a.getSign(), (uint64_t)0);
  SHEFp theta = trigReduce(a,q);
  SHEFpBool rev(q);
  rev.reset(1,true);
  theta = rev.select(M_PI_2-theta,theta);
  SHEFp result = sinb(theta);
  // switch(q)
  result = SHEFpBool(q.getBitHigh(0)).select(-result, result);
  return result;
}


// tan and tanh need these magic constants hoefully 18 of them is enough
shemaxfloat_t zigzag[] =
{1.0, 2.0, 16.0, 272.0, 7936.0, 353792.0, 22368256.0, 1903757312.0,
 209865342976.0, 29088885112832.0, 4951498053124096.0, 1015423886506852352.0,
 246921480190207983616.0, 70251601603943959887872.0,
 23119184187809597841473536.0 };

SHEFp tanb(const SHEFp &a)
{
  SHEFp theta(a);
  SHEFp result(theta);
  SHEFp x(theta);
  shemaxfloat_t invFactorial = 1.0;
  shemaxfloat_t minfloat = a.getMin();
  result = theta;
  theta *= theta;
  if (sheMathLog)
    (*sheMathLog) << "tan(" << (SHEFpSummary) a << ")=" << std::endl
                  << " step 1 : x"
                  << "=" << (SHEFpSummary) x << " "
                  << invFactorial
                  << "*" << 1.0 << "*x = 1.0"
                  << " result=" <<(SHEFpSummary)result << std::endl;
  for (int i=3; i < SHEMATH_TRIG_LOOP_COUNT; i+=2) {
    // do the division unencrypted and them
    // multiply
    invFactorial /= (double)(i-1)*(i);
    if (invFactorial == 0.0 || invFactorial < minfloat) {
      if (sheMathLog)
        (*sheMathLog) << " step " << i << " : invFactorial=" << invFactorial
                      << " < " << minfloat << std::endl;
      break;
    }
    helib::assertTrue(i/2 < SHE_ARRAY_SIZE(zigzag), "zigzag table overflow");
    x *= theta;
    SHEFp term = x*(invFactorial*zigzag[i/2]);
    result += term;
    if (sheMathLog)
      (*sheMathLog) << " step " << i << " : x^" << i
                    << "=" << (SHEFpSummary) x << " "
                    << invFactorial
                    << "*" << zigzag[i/2]
                    << "*x^" << i << "=" << (SHEFpSummary) term
                    << " result=" <<(SHEFpSummary)result << std::endl;
  }
  return result;
}

SHEFp tan(const SHEFp &a)
{
  // q is the quadrant.
  SHEInt q(a.getSign(), (uint64_t)0);
  SHEFp theta = trigReduce(a,q);
  SHEFpBool rev(q);
  rev.reset(1,true);
  theta = rev.select(M_PI_2-theta,theta);
  SHEFp result = tanb(theta);
  std::cout << "tan rev=" << (SHEIntSummary) rev << " q=" <<(SHEIntSummary)q
            << std::endl;
  result = rev.select(-result, result);
  return result;
}

// Power and logs....
// exp with a power series
SHEFp exp(const SHEFp &a)
{
  SHEFp result(a,1.0);
  SHEFp x(a);
  shemaxfloat_t invFactorial = 1.0;
  shemaxfloat_t minfloat = a.getMin();
  if (sheMathLog)
    (*sheMathLog) << "exp(" << (SHEFpSummary) a << ")=" << std::endl
                  << " step 0 : x^0=" << (SHEFpSummary) result << " 1.0*x^0="
                  << (SHEFpSummary) result << " result="
                  << (SHEFpSummary) result << std::endl;
  result += x;
  if (sheMathLog)
    (*sheMathLog) << " step 1 : x=" << (SHEFpSummary)x << " "
                  << invFactorial << "*x=" << (SHEFpSummary)x
                  << " result=" <<(SHEFpSummary)result << std::endl;
  for (int i=2; i < SHEMATH_TRIG_LOOP_COUNT; i++) {
    // do the division unencrypted and them
    // multiply
    invFactorial /= (double)i;
    // once invFactorial goes to zero, the caclulation can't
    // proceed further
    if (invFactorial == 0.0 || invFactorial < minfloat) {
      if (sheMathLog)
        (*sheMathLog) << " step " << i << " : invFactorial=" << invFactorial
                      << " < " << minfloat << std::endl;
      break;
    }
    x *= a;
    SHEFp term=x*invFactorial;
    result += term;
    if (sheMathLog)
      (*sheMathLog) << " step " << i << " : x^" << i
                    << "=" << (SHEFpSummary) x << " "
                    << invFactorial
                    << "*x^" << i << "=" << (SHEFpSummary) term
                    << " result=" <<(SHEFpSummary)result << std::endl;
  }
  return result;
}

SHEFp exp2(const SHEFp &a)
{
  return exp(a*M_LN2);
}

// log1p calculates log(x+1).
SHEFp log1p(const SHEFp &a)
{
  SHEFp x(a);
  SHEFp result_1(x+1);
  shemaxfloat_t minfloat = a.getMin();

  if (sheMathLog)
    (*sheMathLog) << "log1p(" << (SHEFpSummary) a << ")=" << std::endl
                  << "--------------- log1p section 1 --------------------"
                  << std::endl
                  << " step 1 : x=" << (SHEFpSummary)x << " "
                  << 1.0 << "*x=" << (SHEFpSummary)x
                  << " result=" << (SHEFpSummary)result_1 << std::endl;

  // This is only good close to 1
  for (int i=2; i < SHEMATH_LN_LOOP_COUNT; i++) {
    shemaxfloat_t invDenominator = 1.0/(double)i;
    if (invDenominator < minfloat) {
      if (sheMathLog)
        (*sheMathLog) << " step " << i << " : invDenominator="
                      << invDenominator << " < " << minfloat << std::endl;
      break;
    }
    x *= x;
    if (sheMathLog)
      (*sheMathLog) << " step " << i << " : x^" << i << "="
                     << (SHEFpSummary)x << " ";
    SHEFp term = x*invDenominator;
    if (i & 1) {
      result_1 -= term;
      if (sheMathLog) (*sheMathLog) << "-";
    } else {
      result_1 += term;
      if (sheMathLog) (*sheMathLog) << "+";
    }
    if (sheMathLog)
      (*sheMathLog) << invDenominator << "*x^" << i << "="
                    << (SHEFpSummary)term << " result="
                    << (SHEFpSummary) result_1 << std::endl;
  }
  if (sheMathLog)
    (*sheMathLog) << "--------------- log1p section 2 --------------------"
                  << std::endl;
  // We should use a table here, even though we will have to search
  // the whole table to get a result. For now use a very simple
  // caclulus equation:
  // ln a = integral(1->a) 1/x dx
  SHEFp result(a, 0.0);
  x = 1.0;
  // note:Loop count must be even!
  // Using Simson's rule: sn= delta_x/3*(f0 + 4f1 + 2f2 + 4f3 + 2f4 + 4f5 + f6)
  SHEFp deltaX(a/SHEMATH_LN_LOOP_COUNT);
  SHEFp deltaX3(deltaX/3);
  if (sheMathLog)
    (*sheMathLog) << " setup : x="  << (SHEFpSummary) x
                  << " deltaX=" << (SHEFpSummary) deltaX
                  << " deltaX/3=" << (SHEFpSummary) deltaX3 << std::endl;
  for (int i=0; i < SHEMATH_LN_LOOP_COUNT; i++) {
    // we multiply the coefficient to our constant 1
    if ((i==0) || i==(SHEMATH_LN_LOOP_COUNT-1)) {
      SHEFp f = 1.0/x;    // = f(x)
      result += f*deltaX3;
      if (sheMathLog)
        (*sheMathLog) << " step " << i << " : x=" << (SHEFpSummary) x
                      << " f(x)=" << (SHEFpSummary) f << " result="
                      << (SHEFpSummary) result << std::endl;
    } else if (i & 1) {
      SHEFp f = 4.0/x;    // = 4*f(x)
      result += f*deltaX3;
      if (sheMathLog)
        (*sheMathLog) << " step " << i << " : x=" << (SHEFpSummary) x
                      << " 4*f(x)=" << (SHEFpSummary) f << " result="
                      << (SHEFpSummary) result << std::endl;
    } else {
      SHEFp f = 2.0/x;    // = 2*f(x)
      result += f*deltaX3;
      if (sheMathLog)
        (*sheMathLog) << " step " << i << " : x=" << (SHEFpSummary) x
                      << " 2*f(x)=" << (SHEFpSummary) f << " result="
                      << (SHEFpSummary) result << std::endl;
    }
    x += deltaX;
  }

  // close to 1
  result = SHEFpBool(a.abs() < 1e-3).select(result_1, result);
  result = SHEFpBool(a <= -1.0).select((shemaxfloat_t)NAN, result);
  return result;
}

// use log1p to calculate other logs
SHEFp log(const SHEFp &a) { return log1p(a-1.0); }
SHEFp log10(const SHEFp &a) { return log(a)/M_LN10; }
SHEFp log2(const SHEFp &a) { return log(a)/M_LN2; }
SHEFp expm1(const SHEFp &a) { return exp(a-1); }

// get the exponent
SHEFp logb(const SHEFp &a)
{
  SHEInt exp(a.getUnbiasedExp()); // fetch the unbiased Exp
  SHEFp result(exp); // turn it into a float
  // reset the size to the same size as 'a'
  result.reset(a.getExp().getSize(),a.getMantissa().getSize());
  return result;
}

static inline SHEInt getPowerSign(const SHEInt &aSign, const SHEFp &b)
{
  SHEInt8 intb(b.toSHEInt());

  // we need to fetch int and fract of b.
  // sign = (intb & 1) * a.sign
  // nan = (fractb &1 == 0) -- fix this.
  return intb.getBit(0) && aSign;
}


// use exp and log to calculate power (probably a faster way of doing this
SHEFp pow(const SHEFp &a, const SHEFp &b)
{
  SHEFp ln_a = log(a.abs());
  SHEFp result = exp(ln_a*b);
  result.setSign(getPowerSign(a.getSign(),b));
  return result;
}

SHEFp pow(shemaxfloat_t a, const SHEFp &b)
{
  shemaxfloat_t ln_a = shemaxfloat_log(shemaxfloat_abs(a));
  SHEFp result = exp(ln_a*b);
  result.setSign(b.toSHEInt().getBit(0) && std::signbit(a));
  return result;
}

SHEFp pow(const SHEFp &a, shemaxfloat_t b)
{
  SHEFp ln_a = log(a.abs());
  SHEFp result = exp(ln_a*b);
  result.setSign(a.getSign() && ((uint64_t)b&1));
  return result;
}

// there is definately faster ways of doing sqrt, but
// This way has the advantage to knowning when to exit a loop
SHEFp sqrt(const SHEFp &a)
{
  return pow(a,SHEFp(a,.5));
}

// integer and fraction operations
SHEFp frexp(const SHEFp &a, SHEInt &exp)
{
  SHEFp result(a);
  exp = a.getUnbiasedExp();
  result.setUnbiasedExp(0);
  return result;
}

SHEFp trunc(const SHEFp &a) { return a.trunc(); }
SHEFp ceil(const SHEFp &a)
{
  SHEFp result(a.trunc());
  SHEFp inc = select(a.fract().isZero(),result,result+1.0);
  return select(a.getSign(), inc, result);
}

SHEFp floor(const SHEFp &a)
{
  SHEFp result(a.trunc());
  SHEFp dec = select(a.fract().isZero(),result,result-1.0);
  return select(a.getSign(), result, dec);
}

SHEFp rint(const SHEFp &a)
{
  SHEFp pos(a+.5);
  SHEFp neg(a-.5);
  return select(a.getSign(),pos,neg).trunc();
}
SHEFp round(const SHEFp &a)
{
  return (a+.5).trunc();
}
SHEFp nearbyint(const SHEFp &a) { return rint(a); }
SHEInt lrint(const SHEFp &a) { return rint(a).toSHEInt(); }
SHEInt lround(const SHEFp &a) { return round(a).toSHEInt(); }
SHEInt ilogb(const SHEFp &a) { return a.getUnbiasedExp(); }

// most of these are not yet implemented
SHEFp acos(const SHEFp &a) { return a; }
SHEFp acosh(const SHEFp &a) { return a; }
SHEFp cosh(const SHEFp &a) { return a; }
SHEFp asin(const SHEFp &a) { return a; }
SHEFp asinh(const SHEFp &a) { return a; }
SHEFp sinh(const SHEFp &a) { return a; }
SHEFp atan(const SHEFp &a) { return a; }
SHEFp atan2(const SHEFp &a, const SHEFp &b) { return a; }
SHEFp atanh(const SHEFp &a) { return a; }
SHEFp tanh(const SHEFp &a) { return a; }
//
SHEFp cbrt(const SHEFp &a) { return a; }
SHEFp erf(const SHEFp &a) { return a; }
SHEFp erfc(const SHEFp &a) { return a; }
SHEFp fdim(const SHEFp &a, const SHEFp &b) { return a; }
SHEFp fma(const SHEFp &a, const SHEFp &b, const SHEFp &c) { return a; }
SHEFp fmod(const SHEFp &a, const SHEFp &b) { return a; }
SHEFp hypot(const SHEFp &a, const SHEFp &b) { return a; }
SHEFp j0(const SHEFp &a) { return a; }
SHEFp j1(const SHEFp &a) { return a; }
SHEFp jn(const SHEInt &n, const SHEFp &a) { return a; }
SHEFp ldexp(const SHEFp &a, const SHEInt &n) { return a; }
SHEFp lgamma(const SHEFp &a) { return a; }
SHEFp modf(const SHEFp &a, SHEFp &b) { return a; }
//SHEFp nan(const char *) { return a; }
SHEFp nextafter(const SHEFp &a, const SHEFp &b) { return a; }
//SHEFp nexttoward(const SHEFp &, const SHEFp &) { return a; }
SHEFp remainder(const SHEFp &a, const SHEFp &b) { return a; }
SHEFp remquo(const SHEFp &a, const SHEFp &b, SHEInt &c) { return a; }
SHEFp scalbn(const SHEFp &a, const SHEInt &b) { return a; }
SHEFp tgamma(const SHEFp &a) { return a; }
SHEFp y0(const SHEFp &a) { return a; }
SHEFp y1(const SHEFp &a) { return a; }
SHEFp yn(const SHEInt &n, const SHEFp &a) { return a; }
