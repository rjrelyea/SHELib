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
  SHEFp result(a);
  result.setSign(b.getSign());
  return result;
}

SHEFp copysign(shemaxfloat_t a, const SHEFp &b)
{
  SHEFp result(b,a);
  result.setSign(b.getSign());
  return result;
}

SHEFp copysign(const SHEFp &a, shemaxfloat_t b)
{
  SHEFp result(a,b);
  result.setSign(SHEBool(a.getSign(),std::signbit(b)));
  return result;
}

// simple functions we could probably make inline in math.h
SHEFp fmax(const SHEFp &a,  const SHEFp &b) { return select((a>b), a, b); }
SHEFp fmax(shemaxfloat_t a, const SHEFp &b) { return select((a>b), a, b); }
SHEFp fmax(const SHEFp &a,  shemaxfloat_t b) { return select((a>b), a, b); }
SHEFp fmin(const SHEFp &a,  const SHEFp &b) { return select((a<b), a, b); }
SHEFp fmin(shemaxfloat_t a, const SHEFp &b) { return select((a<b), a, b); }
SHEFp fmin(const SHEFp &a,  shemaxfloat_t b) { return select((a<b), a, b); }
SHEFp fabs(const SHEFp &a) { return a.abs(); }
SHEFp fdim(const SHEFp &a,  const SHEFp &b ) { return fmax(a-b,0.0); }
SHEFp fdim(shemaxfloat_t a, const SHEFp &b ) { return fmax(a-b,0.0); }
SHEFp fdim(const SHEFp &a,  shemaxfloat_t b) { return fmax(a-b,0.0); }
// ideally we put off the normalize on the multiply until after the add...
SHEFp fma(const SHEFp &a,  const SHEFp &b,  const SHEFp &c ) { return a*b + c; }
SHEFp fma(shemaxfloat_t a, const SHEFp &b,  const SHEFp &c ) { return a*b + c; }
SHEFp fma(const SHEFp &a,  shemaxfloat_t b, const SHEFp &c ) { return a*b + c; }
SHEFp fma(const SHEFp &a,  const SHEFp &b,  shemaxfloat_t c) { return a*b + c; }
SHEFp fma(const SHEFp &a,  shemaxfloat_t b, shemaxfloat_t c) { return a*b + c; }
SHEFp fma(shemaxfloat_t a, const SHEFp &b,  shemaxfloat_t c) { return a*b + c; }
SHEFp fma(shemaxfloat_t a,  shemaxfloat_t b, const SHEFp &c) { return a*b + c; }

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

  SHEFp n=aabs;
  n /= M_PI_2;
  // we should pass a bitSize to toSHEInt based on our SHEFp size?
  q=n.toSHEInt();
  q.reset(2,true);
  aabs = n.fract() * M_PI_2;
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

SHEFp coshb(const SHEFp &a)
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
    result += term;
    if (sheMathLog)
      (*sheMathLog) << " step " << i << " : x^" << i
                    << "=" << (SHEFpSummary) x << " +"
                    << invFactorial
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
  q = q.getBitHigh(0) ^ q.getBitHigh(1);
  result = SHEFpBool(q).select(-result,result);
  return result;
}

SHEFp acos(const SHEFp &a)
  { return M_PI_2-asin(a); }

SHEFp cosh(const SHEFp &a)
{
  SHEInt q(a.getSign(), (uint64_t)0);
  SHEFp theta = trigReduce(a,q);
  SHEFpBool rev(q);
  rev.reset(1,true);
  theta = rev.select(M_PI_2-theta,theta);
  SHEFp result = coshb(theta);
  q = q.getBitHigh(0) ^ q.getBitHigh(1);
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

SHEFp sinhb(const SHEFp &a)
{
  SHEFp theta(a);
  SHEFp result(theta,1.0);
  SHEFp x(theta);
  shemaxfloat_t invFactorial = 1.0;
  shemaxfloat_t minfloat = a.getMin();
  result = x;
  if (sheMathLog)
    (*sheMathLog) << "sinh(" << (SHEFpSummary)a << ") = " << std::endl
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
    result += term;
    if (sheMathLog)
      (*sheMathLog) << " step " << i << " : x^" << i
                    << "=" << (SHEFpSummary) x << " +"
                    << invFactorial
                    << "*x^" << i << "=" << (SHEFpSummary)term
                    << " result=" <<(SHEFpSummary)result << std::endl;
  }
  return result;
}

SHEFp asinhb(const SHEFp &a) {
  SHEFp theta(a);
  SHEFp result(theta,1.0);
  SHEFp x(theta);
  shemaxfloat_t coefficient = 1.0;
  shemaxfloat_t term = .9;  // when to terminate the loop
  shemaxfloat_t minfloat = a.getMin();
  result = x;
  if (sheMathLog)
    (*sheMathLog) << "asinh(" << (SHEFpSummary)a << ") = " << std::endl
                  << " step 1 : x=" << (SHEFpSummary) x << " +"
                  << coefficient << "*x=" << (SHEFpSummary) x
                  << " result=" <<(SHEFpSummary)result << std::endl;
  theta *= theta;
  for (int i=3; i < SHEMATH_TRIG_LOOP_COUNT; i+=2) {
    // do the division unencrypted and them
    // multiply
    coefficient *= (double)(i-2)/(double)(i-1);
    double fcoefficient = coefficient/(double)i;
    // this detects when it is no longer possible to add more
    // results based on the floating point percision for normal
    // valid inputs.
    term *= (double)(i-2)/(double)(i-1);
    term *= .81;
    // once coefficient goes to zero, we can't proceed further
    if (term == 0.0 || term < minfloat) {
      if (sheMathLog)
        (*sheMathLog) << " step " << i << " : term=" << term
                      << " < " << minfloat << std::endl;
      break;
    }
    x *= theta;
    SHEFp term = fcoefficient*x;
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
      (*sheMathLog) << fcoefficient
                    << "*x^" << i << "=" << (SHEFpSummary)term
                    << " result=" <<(SHEFpSummary)result << std::endl;
    result += term;
    if (sheMathLog)
      (*sheMathLog) << " step " << i << " : x^" << i
                    << "=" << (SHEFpSummary) x << " +"
                    << fcoefficient
                    << "*x^" << i << "=" << (SHEFpSummary)term
                    << " result=" <<(SHEFpSummary)result << std::endl;
  }
  // result is only valid for inputs between -1 and 1 inclusive
  result = select(a.abs() > 1.0, NAN, result);
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

SHEFp asinb(const SHEFp &a) {
  SHEFp theta(a);
  SHEFp result(theta,1.0);
  SHEFp x(theta);
  shemaxfloat_t coefficient = 1.0;
  shemaxfloat_t terminate = .9;  // when to terminate the loop
  shemaxfloat_t minfloat = a.getMin();
  result = x;
  if (sheMathLog)
    (*sheMathLog) << "asin(" << (SHEFpSummary)a << ") =" << std::endl
                  << " step 1 : x=" << (SHEFpSummary) x << " +"
                  << coefficient << "*x=" << (SHEFpSummary) x
                  << " result=" <<(SHEFpSummary)result << std::endl;
  theta *= theta;
  for (int i=3; i < SHEMATH_ARC_LOOP_COUNT; i+=2) {
    // do the division unencrypted and them
    // multiply
    coefficient *= (double)(i-2)/(double)(i-1);
    double fcoefficient = coefficient/(double)i;
    // this detects when it is no longer possible to add more
    // results based on the floating point percision for normal
    // valid inputs.
    terminate  *= (double)(i-2)/(double)(i-1);
    terminate *= .81;
    // once coefficient goes to zero, we can't proceed further
    if (terminate == 0.0 || terminate < minfloat) {
      if (sheMathLog)
        (*sheMathLog) << " step " << i << " : term=" << terminate
                      << " < " << minfloat << std::endl;
      break;
    }
    x *= theta;
    SHEFp term = fcoefficient*x;
    result += term;
    if (sheMathLog)
      (*sheMathLog) << " step " << i << " : x^" << i
                    << "=" << (SHEFpSummary) x << " +"
                    << fcoefficient
                    << "*x^" << i << "=" << (SHEFpSummary)term
                    << " result=" <<(SHEFpSummary)result << std::endl;
  }
  return result;
}

SHEFp asin(const SHEFp &a)
{
  SHEFp result = asinb(a);
  // the above is good except when a is close to 1.0, then we need
  // the transform below
  SHEFp transform=sqrt(1-a*a);
  SHEFp resultHigh = M_PI_2 - asinb(transform);
  result = select(a.abs() > M_SQRT1_2, copysign(resultHigh,a), result);
  // result is only valid for inputs between -1 and 1 inclusive
  result = select(a.abs() > 1.0, NAN, result);
  return result;
}

SHEFp sinh(const SHEFp &a) {
  // q is the quadrant.
  SHEInt q(a.getSign(), (uint64_t)0);
  SHEFp theta = trigReduce(a,q);
  SHEFpBool rev(q);
  rev.reset(1,true);
  theta = rev.select(M_PI_2-theta,theta);
  SHEFp result = sinhb(theta);
  // switch(q)
  result = SHEFpBool(q.getBitHigh(0)).select(-result, result);
  return result;
}



// tan and tanh need these magic constants hopefully 17777777 of them is enough
shemaxfloat_t taylor_tan[] = {
#ifdef SHEFP_USE_DOUBLE
  +1.00000000000000E+00, +3.33333333333333E-01,
  +1.33333333333333E-01, +5.39682539682540E-02,
  +2.18694885361552E-02, +8.86323552990220E-03,
  +3.59212803657248E-03, +1.45583433917050E-03,
  +5.90027463286219E-04, +2.39129100628593E-04,
  +9.69153838863717E-05, +3.92783258380507E-05,
  +1.59189050485676E-05, +6.45168929248486E-06,
  +2.61477121671397E-06, +1.05972685053282E-06,
  +4.29491095269173E-07
#else
  +1.00000000000000000000000000000E+00, +3.33333333333333333342368351437E-01,
  +1.33333333333333333339657846006E-01, +5.39682539682539682545921004564E-02,
  +2.18694885361552028211589967024E-02, +8.86323552990219656898713022561E-03,
  +3.59212803657248101694694601693E-03, +1.45583433917049656577375702513E-03,
  +5.90027463286218677914110174610E-04, +2.39129100628592788514526631884E-04,
  +9.69153838863716870502102676988E-05, +3.92783258380506872029330339973E-05,
  +1.59189050485676058423009938597E-05, +6.45168929248486274756231032580E-06,
  +2.61477121671397178921995365722E-06, +1.05972685053282340400410922393E-06,
  +4.29491095269172544223167813564E-07
#endif
};

SHEFp tanb(const SHEFp &a)
{
  SHEFp theta(a);
  SHEFp result(theta);
  SHEFp x(theta);
  shemaxfloat_t minfloat = a.getMin();
  result = theta;
  theta *= theta;
  if (sheMathLog)
    (*sheMathLog) << "tan(" << (SHEFpSummary) a << ")=" << std::endl
                  << " step 1 : x"
                  << "=" << (SHEFpSummary) x << " "
                  << taylor_tan[0]
                  << "*" << "*x = " << (SHEFpSummary) x
                  << " result=" <<(SHEFpSummary)result << std::endl;
  for (int i=3; i < SHEMATH_TRIG_LOOP_COUNT; i+=2) {
    helib::assertTrue(i/2 < SHE_ARRAY_SIZE(taylor_tan),
                      "tangent taylor series table overflow");
    // grab the fully calculated taylor series coefficent
    shemaxfloat_t taylor = taylor_tan[i/2];
    if (taylor == 0.0 || taylor < minfloat) {
      if (sheMathLog)
        (*sheMathLog) << " step " << i << " : taylor=" << taylor
                      << " < " << minfloat << std::endl;
      break;
    }
    x *= theta;
    SHEFp term = x*taylor;
    result += term;
    if (sheMathLog)
      (*sheMathLog) << " step " << i << " : x^" << i
                    << "=" << (SHEFpSummary) x << " "
                    << taylor << "**x^" << i << "=" << (SHEFpSummary) term
                    << " result=" <<(SHEFpSummary)result << std::endl;
  }
  return result;
}

SHEFp tanhb(const SHEFp &a)
{
  SHEFp theta(a);
  SHEFp result(theta);
  SHEFp x(theta);
  shemaxfloat_t minfloat = a.getMin();
  result = theta;
  theta *= theta;
  if (sheMathLog)
    (*sheMathLog) << "tan(" << (SHEFpSummary) a << ")=" << std::endl
                  << " step 1 : x"
                  << "=" << (SHEFpSummary) x << " "
                  << taylor_tan[0]
                  << "*" << "*x = " << (SHEFpSummary) x
                  << " result=" <<(SHEFpSummary)result << std::endl;
  for (int i=3; i < SHEMATH_TRIG_LOOP_COUNT; i+=2) {
    helib::assertTrue(i/2 < SHE_ARRAY_SIZE(taylor_tan),
                      "tangent taylor series table overflow");
    // grab the fully calculated taylor series coefficent
    shemaxfloat_t taylor = taylor_tan[i/2];
    if (taylor == 0.0 || taylor < minfloat) {
      if (sheMathLog)
        (*sheMathLog) << " step " << i << " : taylor=" << taylor
                      << " < " << minfloat << std::endl;
      break;
    }
    x *= theta;
    SHEFp term = x*taylor;
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
      (*sheMathLog) << taylor
                    << "*x^" << i << "=" << (SHEFpSummary)term
                    << " result=" <<(SHEFpSummary)result << std::endl;
  }
  return result;
}

SHEFp atanb(const SHEFp &a)
{
  SHEFp theta(a);
  SHEFp result(theta,1.0);
  SHEFp x(theta);
  result = x;
  if (sheMathLog)
    (*sheMathLog) << "atan(" << (SHEFpSummary)a << ") = " << std::endl
                  << " step 1 : x=" << (SHEFpSummary) x << "+x="
                  << (SHEFpSummary) x << " result=" <<(SHEFpSummary)result
                  << std::endl;
  theta *= theta;
  for (int i=3; i < SHEMATH_TRIG_LOOP_COUNT; i+=2) {
    // do the division unencrypted and them
    // multiply
    double coefficient = 1.0/(double)(i);
    x *= theta;
    SHEFp term = coefficient*x;
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
      (*sheMathLog) << coefficient
                    << "*x^" << i << "=" << (SHEFpSummary)term
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
  result = rev.select(-result, result);
  return result;
}

SHEFp atan(const SHEFp &a)
{
  SHEFp x(a);
  SHEFp result(a,0.0);
  SHEFp pi_2(a,0.0);
  SHEFpBool largeTan=a.abs()>1.0;
  pi_2 = largeTan.select(M_PI_2,0.0);
  pi_2.setSign(a.getSign());
  // tansform -1.0/a transforms x - 1/3*x^3 + 1/5*x^5...
  //                       to  -1/x+1/(3*x^3)-1/(5*x^5)...
  // by doing the select here, we only need to
  // run the power serise oncewe do the transform on the input
  x = largeTan.select(-1.0/a, a);
  result =  pi_2 + atanb(x);
  return result;
}

SHEFp atan2(const SHEFp &a, const SHEFp &b)
{
  SHEFp result=atan(a/b);
  SHEFp zero(a,0.0);
  SHEFp pi(a,M_PI);
  SHEFp pi2(a,M_PI_2);
  SHEInt aSign=a.getSign();
  SHEInt bSign=b.getSign();
  zero.setSign(aSign);
  pi.setSign(aSign);
  SHEFpBool aZero=a.isZero();
  SHEFpBool bZero=b.isZero();
  SHEFpBool aLTZero=a < 0.0;
  SHEFpBool aGTZero=a > 0.0;
  SHEFpBool bLTZero=b < 0.0;
  SHEFpBool bGTZero=b > 0.0;
  SHEFpBool aInf=a.isInf();
  SHEFpBool bInf=b.isInf();
  // handle all of the atan2 exceptional cases
  result = select(aZero && bLTZero, zero, result);
  result = select(aZero && bGTZero, pi, result);
  pi2.setSign(aLTZero);
  result = select(bZero && !aZero, pi2, result);
  result = select(aZero && bZero && bSign, pi, result);
  result = select(aZero && bZero && !bSign, zero, result);
  pi2.setSign(aSign);
  result = select(aInf && !bInf,  pi2, result);
  zero.setSign(aLTZero);
  pi.setSign(aLTZero);
  result = select(bInf && bSign && !aZero, pi, result);
  result = select(bInf && !bSign && !aZero, zero, result);
  pi2 = M_PI_2+M_PI_4;
  pi2.setSign(aSign);
  result = select(aInf && bInf && bSign,  pi2, result);
  pi2 = M_PI_4;
  pi2.setSign(aSign);
  result = select(aInf && bInf && !bSign,  pi2, result);
  result = select(a.isNan() || b.isNan(),  NAN, result);
  return result;
}

SHEFp tanh(const SHEFp &a)
{
  // q is the quadrant.
  SHEInt q(a.getSign(), (uint64_t)0);
  SHEFp theta = trigReduce(a,q);
  SHEFpBool rev(q);
  rev.reset(1,true);
  theta = rev.select(M_PI_2-theta,theta);
  SHEFp result = tanhb(theta);
  result = rev.select(-result, result);
  return result;
}

// last of the hyperbolic trig functions, use their
// basic definitions for now..
SHEFp acosh(const SHEFp &a) { return log(a+sqrt(a*a-1.0)); }
SHEFp asinh(const SHEFp &a) { return log(a+sqrt(a*a+1.0)); }
SHEFp atanh(const SHEFp &a) { return .5*log((a+1.0)/(1.0-a)); }

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

// a is small and close to zero
static SHEFp _log1p(const SHEFp &x)
{
  SHEFp x2(x);
  SHEFp result(x);

  if (sheMathLog)
    (*sheMathLog) << "_log1p(" << (SHEFpSummary) x << ")=" << std::flush;
  x2 *= x;
  result=(-.25)*x2 + ((shemaxfloat_t)1.0/(shemaxfloat_t)3.0)*x + (-.5);
  result *= x2;
  result += x;
  if (sheMathLog) (*sheMathLog) << (SHEFpSummary) result << std::endl;
  return result;
}

// tables for ln and inv of
// +5.0000E-01,+5.3125E-01,
// +5.6250E-01,+5.9375E-01,
// +6.2500E-01,+6.5625E-01,
// +6.8750E-01,+7.1875E-01,
// +7.5000E-01,+7.8125E-01,
// +8.1250E-01,+8.4375E-01,
// +8.7500E-01,+9.0625E-01,
// +9.3750E-01,+9.6875E-01,
static std::vector<shemaxfloat_t> lnTable = {
#ifdef SHEFP_USE_DOUBLE
  -6.93147180559945E-01,-6.32522558743510E-01,
  -5.75364144903562E-01,-5.21296923633286E-01,
  -4.70003629245736E-01,-4.21213465076304E-01,
  -3.74693449441411E-01,-3.30241686870577E-01,
  -2.87682072451781E-01,-2.46860077931526E-01,
  -2.07639364778244E-01,-1.69899036795397E-01,
  -1.33531392624523E-01,-9.84400728132525E-02,
  -6.45385211375712E-02,-3.17486983145803E-02
#else
  -6.93147180559945309428690474185E-01,-6.32522558743510466834191613428E-01,
  -5.75364144903561854885350179689E-01,-5.21296923633286087083459764413E-01,
  -4.70003629245735553651317981116E-01,-4.21213465076303550594294042297E-01,
  -3.74693449441410693601063261471E-01,-3.30241686870576856292812742422E-01,
  -2.87682072451780927442675089845E-01,-2.46860077931525797887498015204E-01,
  -2.07639364778244501623946996482E-01,-1.69899036795397472899334795349E-01,
  -1.33531392624522623151618952453E-01,-9.84400728132525199034455649916E-02,
  -6.45385211375711716720788603541E-02,-3.17486983145803011579241890289E-02
#endif
};
static std::vector<shemaxfloat_t> lnInvTable = {
#ifdef SHEFP_USE_DOUBLE
  +2.00000000000000E+00,+1.88235294117647E+00,
  +1.77777777777778E+00,+1.68421052631579E+00,
  +1.60000000000000E+00,+1.52380952380952E+00,
  +1.45454545454545E+00,+1.39130434782609E+00,
  +1.33333333333333E+00,+1.28000000000000E+00,
  +1.23076923076923E+00,+1.18518518518519E+00,
  +1.14285714285714E+00,+1.10344827586207E+00,
  +1.06666666666667E+00,+1.03225806451613E+00
#else
  +2.00000000000000000000000000000E+00,+1.88235294117647058824167177749E+00,
  +1.77777777777777777775368439617E+00,+1.68421052631578947364997256297E+00,
  +1.60000000000000000002168404345E+00,+1.52380952380952380950315805386E+00,
  +1.45454545454545454549397098809E+00,+1.39130434782608695650288344048E+00,
  +1.33333333333333333336947340575E+00,+1.27999999999999999997397914786E+00,
  +1.23076923076923076924744926419E+00,+1.18518518518518518520526300319E+00,
  +1.14285714285714285712736854039E+00,+1.10344827586206896549107098204E+00,
  +1.06666666666666666671726276805E+00,+1.03225806451612903223008510523E+00
#endif
};

// a is < 1 (exp == 0 (unbiased))
static SHEFp _log(const SHEFp &a, SHEFp &log1p_)
{
  if (sheMathLog)
    (*sheMathLog) << "_log(" << (SHEFpSummary) a << ")=" << std::endl;
  SHEInt mantissa(a.getMantissa());
  SHEFpBool notDenormal = mantissa.getBitHigh(0);
  // first handle the denormal case.
  // we look for the first '1' bit, fetch the corresponding
  // ln and inverse for that bit position
  int depth = 5;
  SHEBool lbreak(mantissa,false);
  SHEFp ln(a, 0.0);
  SHEFp inv(a, 1.0);
  SHEInt mantissaDenormal(mantissa);
  // handle the denormal case. Find the first '1'
  // bit. If we can't find one in the first 5
  // bits, just drop into the log1p with the rest
  for (int i=1; i < depth; i++) {
    SHEBool currentBit = mantissa.getBitHigh(i);
    SHEFpBool found= currentBit && !lbreak;
    // ln(2^-(i+1)) = (i+1)*ln(2)
    ln = found.select(-((shemaxfloat_t)(i+1))*M_LN2, ln);
    // 1.0/(2^-(i+1)) = 2^(i+1)
    inv = found.select(((shemaxfloat_t)(1<<i))*2.0, inv);
    // reset it if found
    mantissaDenormal.setBitHigh(i,SHEBool(found).select(0,currentBit));
    lbreak = lbreak.select(found,lbreak);
  }
  // if the first 5 bits are zero, then ln and inv are really both infinity,
  // and the log is simply ln(mantissaDenormal). We calculate the final ln
  // as logp1(x) = log(x+1), so we need to subtract 1 from our mantissa
  mantissaDenormal = select(ln==0.0,
                            mantissaDenormal + SHEInt(mantissaDenormal,~0),
                            mantissaDenormal);
  if (sheMathLog)
    (*sheMathLog) << " denormal ln=" << (SHEFpSummary) ln  << std::endl
                  << " denormal inv=" << (SHEFpSummary) inv  << std::endl;
  // normal normalized case (more common), use the top 5 bits to select
  // the ln and inf from table 2
  SHEInt index(mantissa);
  // grab high bits 1-4 (bit zero is 1)
  index >>= (mantissa.getSize() - 5);
  index.reset(4,true);
  if (sheMathLog)
    (*sheMathLog) << " normal index=" << (SHEIntSummary) index  << std::endl;
  // select the values from the table (only size 16, so managable)
  // once this completes ln has the correct value (either table, or denormal
  // ln value from the loop above, same with inv.
  ln = notDenormal.select(getVector(a,lnTable,index),ln);
  inv = notDenormal.select(getVector(a,lnInvTable,index),inv);
  if (sheMathLog)
    (*sheMathLog) << " ln=" << (SHEFpSummary) ln  << std::endl
                  << " inv=" << (SHEFpSummary) inv  << std::endl;
  SHEFp fract(a);
  // now find the final fraction in our normalized case.
  // we do this by clearing out the bits use used in the index
  SHEInt mantissaClear(mantissa);
  SHEBool zbit(mantissa,false);
  for (int i=0; i < 5; i++) {
    mantissaClear.setBitHigh(i,zbit);
  }
  // now set fract to the correct adjusted mantissa
  fract.setMantissa(SHEBool(notDenormal).select(mantissaClear,
                                                mantissaDenormal));
  // we've cleared bits, turn it back into a usable float.
  // The multiply will handle this denormal number and normalize
  // at the end, so skip the normalize step here.
  //fract.normalize();
  if (sheMathLog)
    (*sheMathLog) << " fract=" << (SHEFpSummary) fract  << std::endl;
  // we split a into high + fract = high * (1 + fract*high^-1)
  // let inv=high^-1, and ln(high) is then looked up in our lnTable/lnInvTable
  // ln(high + fract) = ln(high) + ln (1+fract*inv)
  //                  = ln + log1p(fract*inv)
  log1p_ = _log1p(fract*inv);
  SHEFp result = ln + log1p_;
  return result;
}

// for now just return based on log
SHEFp log1p(const SHEFp &a)
{
  // if a is small enough, use the _log1p(a) function
  // otherise use the log(a+1).
  return select(a.abs() <= 1.0,_log1p(a), log(a+1.0));
}

SHEFp log(const SHEFp &a)
{
  SHEFpBool needNan(a.getSign() || a.isNan() || a.isZero());
  SHEFpBool needInf(a.isInf());
  // the exponent gives us the large portion of the log
  // already... exponent = floor(log2(a));
  SHEInt exp(a.getUnbiasedExp());
  SHEFp result(a,exp);
  SHEFp log1p_(a,0.0);
  //convert log2(a) to log_e
  result *= M_LN2;
  SHEFp a_(a);
  // now get the log of just the mantissa
  a_.setUnbiasedExp(0);
  // a is now between 0 and .9999999999, which is quicker
  // to calculate our log as
  // ln(a)=ln(manissa*2^exp) = ln(mantissa)+ln(2^exp)
  //                         = ln(mantissa) + exp*ln(2)
  result += _log(a_,log1p_);
  // get better precision if our exponent == 1.
  result = select(exp == 1, log1p_, result);
  result = needInf.select(INFINITY, result);
  result = needNan.select(NAN, result);
  return result;
}

SHEFp log10(const SHEFp &a)
{
  SHEFpBool needNan(a.getSign() || a.isNan() || a.isZero());
  SHEFpBool needInf(a.isInf());
  // the exponent gives us the large portion of the log
  // already... This mirrors the ln function except
  // we use M_LOG10E to convert ln values to log10 values
  SHEInt exp(a.getUnbiasedExp());
  SHEFp result(a,exp);
  result *= M_LN2;
  SHEFp a_(a);
  SHEFp log1p_(a,0.0);
  a_.setUnbiasedExp(0);
  // a is now between 0 and .9999999999, which is quicker
  // to calculate
  result += _log(a_,log1p_);
  // get better precision if our exponent == 1.
  result = select(exp == 1, log1p_, result);
  result *= M_LOG10E;
  result = needInf.select(INFINITY, result);
  result = needNan.select(NAN, result);
  return result;
}

SHEFp log2(const SHEFp &a)
{
  SHEFpBool needNan(a.getSign() || a.isNan() || a.isZero());
  SHEFpBool needInf(a.isInf());
  // floating point number is mantissa*2^exp, so
  // log2(f) = log2(mantissa) + log2(2^exp)
  //         = ln(mantissa)/M_LN2 + exp
  SHEInt exp(a.getUnbiasedExp());
  SHEFp result(a,exp);
  SHEFp a_(a);
  SHEFp log1p_(a,0.0);
  a_.setUnbiasedExp(0);
  result += _log(a_, log1p_)*M_LOG2E;
  // get better precision if our exponent == 1.
  result = select(exp == 1, log1p_*M_LOG2E, result);
  result = needInf.select(INFINITY, result);
  result = needNan.select(NAN, result);
  return result;
}

SHEFp expm1(const SHEFp &a) { return exp(a-1); }

// get the exponent
SHEFp logb(const SHEFp &a)
{
  SHEInt exp(a.getUnbiasedExp()-1); // fetch the unbiased Exp
  SHEFp result(exp); // turn it into a float
  // reset the size to the same size as 'a'
  result.reset(a.getExp().getSize(),a.getMantissa().getSize());
  return result;
}

// use exp and log to calculate power (probably a faster way of doing this?)
// like power ladders used in modular exp functions (at lest for the integer
// portion of b. But then we still need logs for the fractional portion
SHEFp pow(const SHEFp &a, const SHEFp &b)
{
  SHEBool odd = b.toSHEInt().getBit(0);
  SHEInt fract(b.fract().getMantissa());
  SHEBool hasFract=!fract.isZero();
  fract.reset(3,true); // use the last 3 bits to handle rounding
  SHEBool evenRoot = hasFract && fract.isZero();
  SHEFp ln_a = log(a.abs());
  SHEFp result = exp(ln_a*b);
  result.setSign(odd && a.getSign());
  result = select(evenRoot && a.getSign(), NAN, result);
  result = select(a.isZero(), 0.0, result);
  return result;
}

SHEFp pow(shemaxfloat_t a, const SHEFp &b)
{
  if (a == 0.0) {
    return SHEFp(b,0.0);
  }
  SHEBool odd = b.toSHEInt().getBit(0);
  SHEInt fract(b.fract().getMantissa());
  SHEBool hasFract=!fract.isZero();
  fract.reset(3,true); // use the last 3 bits to handle rounding
  SHEBool evenRoot = hasFract && fract.isZero();
  // a is unencrypted, use the system library
  shemaxfloat_t ln_a = shemaxfloat_log(shemaxfloat_abs(a));
  SHEFp result = exp(ln_a*b);
  result.setSign(odd && std::signbit(a));
  result = select(evenRoot && std::signbit(a), NAN, result);
  return result;
}

SHEFp pow(const SHEFp &a, shemaxfloat_t b)
{
  if (b == 0.0) {
    return SHEFp(a,1.0);
  }
  bool odd=((uint64_t)b)&1;
  // I could do a lot of manipulation of b to get it's
  // evenness status, but it's easier just to let the system
  // library tell me if it should produce a nan on a negative a
  bool evenRoot=std::isnan(shemaxfloat_pow(-1.0,b));
  SHEFp ln_a = log(a.abs());
  SHEFp result = exp(ln_a*b);
  //sort the sign
  result.setSign(a.getSign() && odd);
  result = select(evenRoot &a.getSign(), NAN, result);
  result = select(a.isZero(), 0.0, result);
  return result;
}

// there is definately faster ways of doing sqrt,
// use Newton's to calculate sqrt
SHEFp sqrt(const SHEFp &a)
{
  SHEFp y(a);
  SHEInt exp = y.getUnbiasedExp();
  exp >>= 1;
  y.setUnbiasedExp(exp);
  y *= .5;
  if (sheMathLog)
    (*sheMathLog) << "sqrt(" << (SHEFpSummary)a << ") = " << std::endl
                  << " step 0 : y0=" << (SHEFpSummary) y
                  << std::endl;
  for (int i=0; i < SHEMATH_NEWTON_LOOP_COUNT; i++) {
    // newton's for 1/sqrt. we calculate 1/sqrt because it doesn't
    // require multiple divisions in the loop, and only one division
    // at the end.
    y=.5*y*(3.0-a*y*y);
    if (sheMathLog) (*sheMathLog) << " step " << (i+1) << ": y" << (i+1) << "="
                                  << (SHEFpSummary) y << std::endl;
  }
  y = 1.0/y;
  y = select(a.isInf(), INFINITY, y);
  y = select(a.getSign(), NAN, y);
  y = select(a.isZero(), 0.0, y);
  return y;
}

// see comment for sqrt
SHEFp cbrt(const SHEFp &a)
{
  SHEFp y(a.abs());
  SHEInt exp = y.getUnbiasedExp();
  exp = exp/3;
  y.setUnbiasedExp(exp);
  y *= (1.0/3.0);
  if (sheMathLog)
    (*sheMathLog) << "cqrt(" << (SHEFpSummary)a << ") = " << std::endl
                  << " step 0 : y0=" << (SHEFpSummary) y
                  << std::endl;
  for (int i=0; i < SHEMATH_NEWTON_LOOP_COUNT; i++) {
    // newton's for 1/cbrt. we calculate 1/cbrt because it doesn't
    // require multiple divisions in the loop, and only one division
    // at the end.
    y=(1.0/3.0)*y*(4.0-a*y*y*y);
    if (sheMathLog) (*sheMathLog) << " step " << (i+1) << ": y" << (i+1) << "="
                                  << (SHEFpSummary) y << std::endl;
  }
  y = 1.0/y;
  y = select(a.isInf(), INFINITY, y);
  y = select(a.getSign(), NAN, y);
  y = select(a.isZero(), 0.0, y);
  return y;
}

// operate on floating point exponent and
// mantissa.
SHEFp frexp(const SHEFp &a, SHEInt &exp)
{
  SHEFp result(a);
  exp = a.getUnbiasedExp();
  result.setUnbiasedExp(0);
  return result;
}

SHEFp ldexp(const SHEFp &a, const SHEInt &n)
{
  SHEFp result(a);
  result.setUnbiasedExp(n+1);
  return result;
}

SHEFp ldexp(const SHEFp &a, int64_t n)
{
  SHEFp result(a);
  result.setUnbiasedExp(n+1);
  return result;
}

SHEFp ldexp(shemaxfloat_t f, const SHEInt &n)
{
  // get an appropriately sized fp based on n
  // future, we can look at the precision of 'f'
  // to guess how bit an fp we need.
  SHEFp result(n.getPublicKey(),f*2,n.getSize(),n.getSize()*3);
  result.setUnbiasedExp(n);
  return result;
}


SHEFp hypot(const SHEFp &a, const SHEFp &b) { return sqrt(a*a +b*b); }
SHEFp hypot(shemaxfloat_t a, const SHEFp &b) { return sqrt(a*a +b*b); }
SHEFp hypot(const SHEFp &a, shemaxfloat_t b) { return sqrt(a*a +b*b); }

static uint64_t
getExpMax(int expSize)
{
  return (1ULL<<(expSize-1))-1;
}

static int64_t
getExpMin(int expSize)
{
  return -(int64_t)getExpMax(expSize);
}

SHEFp scalbn(const SHEFp &a, const SHEInt &b)
{
  int expSize = a.getExp().getSize();
  SHEFp result(a);
  SHEInt exp = a.getUnbiasedExp() + b;
  SHEFpBool needNan = a.isNan();
  SHEFpBool needInf = (exp > getExpMax(expSize)) || a.isInf();
  SHEFpBool needZero= (exp <= getExpMin(expSize)) || a.isZero();
  result.setUnbiasedExp(exp);
  result = needNan.select(NAN, result);
  result = needInf.select(INFINITY, result);
  result = needZero.select(0.0, result);
  // keep the sign
  result.setSign(a.getSign());
  return result;
}

SHEFp scalbn(const SHEFp &a, int64_t b)
{
  int expSize = a.getExp().getSize();
  SHEFp result(a);
  SHEInt exp = a.getUnbiasedExp() + b;
  SHEFpBool needNan = a.isNan();
  SHEFpBool needInf = (exp > getExpMax(expSize)) || a.isInf();
  SHEFpBool needZero= (exp <= getExpMin(expSize)) || a.isZero();
  result.setUnbiasedExp(exp);
  result = needNan.select(NAN, result);
  result = needInf.select(INFINITY, result);
  result = needZero.select(0.0, result);
  // keep the sign
  result.setSign(a.getSign());
  return result;
}

SHEFp scalbn(shemaxfloat_t a, const SHEInt &b)
{
  if (std::isnan(a) || std::isinf(a) || (a == 0.0)) {
    return SHEFp(b.getPublicKey(), a, b.getSize(), b.getSize()*3);
  }
  // get an appropriately sized fp based on n
  // future, we can look at the precision of 'f'
  // to guess how bit an fp we need.
  SHEFp result(b.getPublicKey(),a,b.getSize(),b.getSize()*3);
  int expSize = result.getExp().getSize();
  SHEInt exp = result.getUnbiasedExp() + b;
  result.setUnbiasedExp(exp);
  return result;
}

#ifdef SHEFP_USE_DOUBLE
#define shemaxfloat_nextafter(x,y) nextafter(x,y)
#define shemaxfloat_nextafter(x,y) nextafter(x,y)
#else
#define shemaxfloat_nextafter(x,y) nextafterl(x,y)
#define shemaxfloat_nextafter(x,y) nextafterl(x,y)
#endif

SHEFp nextafter(const SHEFp &a, const SHEFp &b)
{
  SHEFp result(a);
  SHEInt mantissa(a.getMantissa());
  mantissa.reset(mantissa.getSize()+1, true);
  mantissa.reset(mantissa.getSize(), false);
  SHEInt addr(mantissa,(uint64_t)1);
  addr = (a<b).select(-1,addr);
  mantissa += addr;
  SHEInt overflow = mantissa.getBitHigh(0);
  mantissa = overflow.select(mantissa >> 1, mantissa);
  mantissa.reset(mantissa.getSize()-1, true);
  result.setMantissa(mantissa);
  SHEInt exp=result.getUnbiasedExp() + overflow;
  result.setUnbiasedExp(exp);
  result.normalize(); //sigh
  result = select(a == b, a, result);
  return result;
}

SHEFp nextafter(const SHEFp &a, shemaxfloat_t b)
{
  SHEFp result(a);
  SHEInt mantissa(a.getMantissa());
  mantissa.reset(mantissa.getSize()+1, true);
  mantissa.reset(mantissa.getSize(), false);
  SHEInt addr(mantissa,(uint64_t)1);
  addr = (a<b).select(-1,addr);
  mantissa += addr;
  SHEInt overflow = mantissa.getBitHigh(0);
  mantissa = overflow.select(mantissa >> 1, mantissa);
  mantissa.reset(mantissa.getSize()-1, true);
  result.setMantissa(mantissa);
  SHEInt exp=result.getUnbiasedExp() + overflow;
  result.setUnbiasedExp(exp);
  result.normalize(); //sigh
  result = select(a == b, a, result);
  return result;
}

SHEFp nextafter(shemaxfloat_t a, const SHEFp &b)
{
  SHEFp result(b,a);
  // use the library.
  result = select(a<b, shemaxfloat_nextafter(a, a+.01), result);
  result = select(a>b, shemaxfloat_nextafter(a, a-.01), result);
  result = select(b.isNan(), NAN, result);
  return result;
}

// integer and fraction operations
SHEFp modf(const SHEFp &a, SHEFp &b)
{
  b = a.trunc();
  return a.fract();
}

SHEFp trunc(const SHEFp &a) { return a.trunc(); }
SHEFp ceil(const SHEFp &a)
{
  SHEFp result(a.trunc());
  return select(!a.getSign() && a.hasFract(), result+1.0, result);
}

SHEFp floor(const SHEFp &a)
{
  SHEFp result(a.trunc());
  return select(a.getSign() && a.hasFract(), result-1.0, result);
}

SHEFp round(const SHEFp &a)
{
  SHEFp result((a.abs()+.5).trunc());
  result.setSign(a.getSign());
  return result;
}

SHEFp rint(const SHEFp &a)
{
  return (a+.5).trunc();
}

SHEFp nearbyint(const SHEFp &a) { return rint(a); }
SHEInt lrint(const SHEFp &a) { return rint(a).toSHEInt(); }
SHEInt lround(const SHEFp &a) { return round(a).toSHEInt(); }
SHEInt ilogb(const SHEFp &a) { return a.getUnbiasedExp()-1; }

// remainder functions
SHEFp fmod(const SHEFp &a, const SHEFp &b)
{
  SHEFp n = floor(a/b);
  return a-n*b;
}

SHEFp fmod(shemaxfloat_t a, const SHEFp &b)
{
  SHEFp n = floor(a/b);
  return a-n*b;
}

SHEFp fmod(const SHEFp &a, shemaxfloat_t b)
{
  SHEFp n = floor(a/b);
  return a-n*b;
}

SHEFp remainder(const SHEFp &a, const SHEFp &b)
{
  SHEFp n = round(a/b);
  return a-n*b;
}

SHEFp remainder(shemaxfloat_t a, const SHEFp &b)
{
  SHEFp n = round(a/b);
  return a-n*b;
}

SHEFp remainder(const SHEFp &a, shemaxfloat_t b)
{
  SHEFp n = round(a/b);
  return a-n*b;
}

SHEFp remquo(const SHEFp &a, const SHEFp &b, SHEInt &q)
{
  SHEFp n = round(a/b);
  q = n.toSHEInt(q.getSize());
  return a-n*b;
}

SHEFp remquo(shemaxfloat_t a, const SHEFp &b, SHEInt &q)
{
  SHEFp n = round(a/b);
  q = n.toSHEInt(q.getSize());
  return a-n*b;
}

SHEFp remquo(const SHEFp &a, shemaxfloat_t b, SHEInt &q)
{
  SHEFp n = round(a/b);
  q = n.toSHEInt(q.getSize());
  return a-n*b;
}

//
// these are not yet implemented
SHEFp erf(const SHEFp &a)
{
  SHEFp result(a, 0.0);
  SHEFp x(a, 0.0);
  // note:Loop count must be even!
  // Using Simson's rule: sn= delta_x/3*(f0 + 4f1 + 2f2 + 4f3 + 2f4 + 4f5 + f6)
  SHEFp deltaX(a/(SHEMATH_INTEGRAL_LOOP_COUNT-1));
  SHEFp deltaX3(deltaX/3.0);
  SHEFp deltaX4_3((4.0/3.0)*deltaX);
  SHEFp deltaX2_3((2.0/3.0)*deltaX);
  if (sheMathLog)
    (*sheMathLog) << "erf(" << (SHEFpSummary) a << ")" << std::endl
                  << "*setup : x="  << (SHEFpSummary) x
                  << " deltaX=" << (SHEFpSummary) deltaX
                  << " deltaX/3=" << (SHEFpSummary) deltaX3 << std::endl;
  for (int i=0; i < SHEMATH_INTEGRAL_LOOP_COUNT; i++) {
    // we multiply the coefficient to our constant 1
    SHEFp f = exp(-x*x);    // = f(x)
    if ((i==0) || i==(SHEMATH_INTEGRAL_LOOP_COUNT-1)) {
      result += f*deltaX3;
    } else if (i & 1) {
      result += f*deltaX4_3;
    } else {
      result += f*deltaX2_3;
    }
     if (sheMathLog)
        (*sheMathLog) << "*step " << i << " : x=" << (SHEFpSummary) x
                      << " f(x)=" << (SHEFpSummary) f << " result="
                      << (SHEFpSummary) result << std::endl;
    x += deltaX;
  }

  // close to 1
  return M_2_SQRTPI * result;
}

SHEFp erfc(const SHEFp &a) { return 1.0  - erf(a); }

SHEFp j0(const SHEFp &a)
{
  SHEFp term(a,1.0);
  SHEFp x(a.abs());
  SHEFp x2=x*x;
  // result is good for x < 1.0
  SHEFp result(a,1.0);
  for (int i=1; i < SHEMATH_BESSEL_LOOP_COUNT; i++) {
    term*=1.0/((double)(4*i*i))*x2; // (1/(2^2i(i!)^2)) * x^2i
    if (i&1) {
      result -= term;
    } else {
      result += term;
    }
  }
  // result2 is good for x >= 1.0
  SHEFp result2(1.0/sqrt(x));
  result2 *= cos(x-M_PI_4);
  result2 *= M_2_SQRTPI;
  result=select(x<1.0, result, result2);
  copysign(result, a);
  return result;
}

SHEFp y0(const SHEFp &a)
{
  SHEFp jterm(a,1.0);
  SHEFp x(a.abs());
  SHEFp x2=x*x;
  SHEFp j0_const=.5772+log(.5*a);// need a more precise gamma
  double Hi=0.0;
  // result is good for x < 1.0
  SHEFp result(j0_const);
  for (int i=1; i < SHEMATH_BESSEL_LOOP_COUNT; i++) {
    jterm*=1.0/((double)(4*i*i))*x2; // (1/(2^2i(i!)^2)) * x^2i
    Hi += 1.0/(double)i;
    SHEFp term = jterm *(j0_const-Hi);
    if (i&1) {
      result -= term;
    } else {
      result += term;
    }
  }
  // result2 is good for x >= 1.0
  SHEFp result2(1.0/sqrt(x));
  result2 *= sin(x-M_PI_4);
  result2 *= M_2_SQRTPI;
  result=select(x<1.0, result, result2);
  copysign(result, a);
  return result;
}

SHEFp tgamma(const SHEFp &a)
{
  SHEFp result(a, 0.0);
  SHEFp t(a, 0.0);
  SHEFp x(a-1.0);
  // note:Loop count must be even!
  // Using Simson's rule: sn= delta_x/3*(f0 + 4f1 + 2f2 + 4f3 + 2f4 + 4f5 + f6)
  shemaxfloat_t minfloat = a.getMin();
  // The integral is from '0' to infinity, which is really from 0 until f goes
  // to zero. This is dominated by exp(-t), but allow t^x. A better gues would
  // be to divide log(minfloat) by -x
  shemaxfloat_t deltaT = (log(minfloat)/-6.0)/(SHEMATH_INTEGRAL_LOOP_COUNT-1);
  shemaxfloat_t  deltaT3 = deltaT/3.0;
  shemaxfloat_t deltaT4_3 = (4.0/3.0)*deltaT;
  shemaxfloat_t  deltaT2_3 = (2.0/3.0)*deltaT;
  if (sheMathLog)
    (*sheMathLog) << "gamma(" << (SHEFpSummary) a << ")" << std::endl
                  << "*setup : t="  << (SHEFpSummary) t
                  << " x="  << (SHEFpSummary) x
                  << " deltaT=" << deltaT << std::endl;
  t = deltaT; // since the first term is zero, we can skip the calculation
  for (int i=1; i < SHEMATH_INTEGRAL_LOOP_COUNT; i++) {
    // we multiply the coefficient to our constant 1
    SHEFp tp = pow(t,x);
    SHEFp ep = exp(-t);
    SHEFp f = tp*ep;    // = f(t)
    // first and last terms multiply by deltaT/3.0
    // second, second to last terms, and alternating terms
    //   multiply by 4*deltaT/3.0
    // middle terms multiply by 2*deltaT/3.0, Loop_count needs
    // to be odd and >= 3.
    if ((i==0) || i==(SHEMATH_INTEGRAL_LOOP_COUNT-1)) {
      result += f*deltaT3;
    } else if (i & 1) {
      result += f*deltaT4_3;
    } else {
      result += f*deltaT2_3;
    }
     if (sheMathLog)
        (*sheMathLog) << "*step " << i << " : t=" << (SHEFpSummary) t
                      << " f(t)=" << (SHEFpSummary) f << " result="
                      << (SHEFpSummary) result << std::endl;
    x += deltaT;
  }

  return result;
}

// There are better ways of doing this, but at least this 'works'
SHEFp lgamma_r(const SHEFp &a, SHEInt &signp)
{
  SHEFp gamma=tgamma(a);
  SHEInt8 signOut(a.getExp(), 1);
  // ideally we should just return gamma.getSign(), but this emulates
  // the real math.h semantics of -1 = negative and 1 = positive or zero
  signp = (gamma.getSign() && !gamma.isZero()).select(-1, signOut);
  return log(gamma.abs());
}


SHEFp lgamma(const SHEFp &a)
{
  SHEFp gamma=tgamma(a);
  // the normal library returns signp in a global
  // That's not safe at all in our library since
  // we need a public key to initialize the global
  // and there isn't necessarily one available. apps
  // that need sign can call lgamma_r.
  return log(gamma.abs());
}

// obviously there's a better way than this.
SHEFp j1(const SHEFp &a) { return jn(1,a); }

// these next two can do better by copying the jn function and
// allowing more unencrypted operations before we drop into
// encrypted operations, getting some performance without
// suffering precision loss
SHEFp jn(uint64_t n, const SHEFp &a)
{
  SHEInt ni(a.getSign().getPublicKey(), n, SHEInt::getBitSize(n), false);
  return jn(ni, a);
}

SHEFp jn(const SHEInt &n, shemaxfloat_t a)
{
  return jn(n, SHEFp(n.getPublicKey(),a));
}

SHEFp jn(const SHEInt &n, const SHEFp &a)
{
  SHEFp result(a, 0.0);
  SHEFp nf(a,n);
  shemaxfloat_t x=0.0;
  // note:Loop count must be even!
  // Using Simson's rule: sn= delta_x/3*(f0 + 4f1 + 2f2 + 4f3 + 2f4 + 4f5 + f6)
  shemaxfloat_t deltaX = M_PI/(SHEMATH_INTEGRAL_LOOP_COUNT-1);
  shemaxfloat_t deltaX3 = deltaX/3.0;
  shemaxfloat_t deltaX4_3 = (4.0/3.0)*deltaX;
  shemaxfloat_t deltaX2_3 = (2.0/3.0)*deltaX;
  if (sheMathLog)
    (*sheMathLog) << "jn(" << (SHEFpSummary) a << ")" << std::endl
                  << "*setup : x="  << x
                  << " deltaX=" << deltaX
                  << " deltaX/3=" << deltaX3 << std::endl;
  for (int i=0; i < SHEMATH_INTEGRAL_LOOP_COUNT; i++) {
    // we multiply the coefficient to our constant 1
    SHEFp f = cos(nf*x) - a*shemaxfloat_sin(x);    // = f(x)
    if ((i==0) || i==(SHEMATH_INTEGRAL_LOOP_COUNT-1)) {
      result += f*deltaX3;
    } else if (i & 1) {
      result += f*deltaX4_3;
    } else {
      result += f*deltaX2_3;
    }
     if (sheMathLog)
        (*sheMathLog) << "*step " << i << " : x=" << x
                      << " f(x)=" << (SHEFpSummary) f << " result="
                      << (SHEFpSummary) result << std::endl;
    x += deltaX;
  }

  // close to 1
  return M_1_PI * result;
}

// obviously there's a better way than this.
SHEFp y1(const SHEFp &a) { return yn(1,a); }

// these next two can do better by copying the jn function and
// allowing more unencrypted operations before we drop into
// encrypted operations, getting some performance without
// suffering precision loss
SHEFp yn(uint64_t n, const SHEFp &a)
{
  SHEInt ni(a.getSign().getPublicKey(), n, SHEInt::getBitSize(n), false);
  return yn(ni, a);
}

SHEFp yn(const SHEInt &n, shemaxfloat_t a)
{
  return yn(n, SHEFp(n.getPublicKey(),a));
}

SHEFp yn(const SHEInt &n, const SHEFp &a)
{
  SHEFp result(a, 0.0);
  SHEFp nf(a,n);
  shemaxfloat_t x=0.0;
  // note:Loop count must be even!
  // Using Simson's rule: sn= delta_x/3*(f0 + 4f1 + 2f2 + 4f3 + 2f4 + 4f5 + f6)
  shemaxfloat_t deltaX = M_PI/(SHEMATH_INTEGRAL_LOOP_COUNT-1);
  shemaxfloat_t deltaX3 = deltaX/3.0;
  shemaxfloat_t deltaX4_3 = (4.0/3.0)*deltaX;
  shemaxfloat_t deltaX2_3 = (2.0/3.0)*deltaX;
  if (sheMathLog)
    (*sheMathLog) << "yn(" << (SHEFpSummary) a << ")" << std::endl
                  << "*setup : x="  << x
                  << " deltaX=" << deltaX
                  << " deltaX/3=" << deltaX3 << std::endl;
  for (int i=0; i < SHEMATH_INTEGRAL_LOOP_COUNT; i++) {
    // we multiply the coefficient to our constant 1
    SHEFp f = sin(a*shemaxfloat_sin(x) - nf*x);    // = f(x)
    if ((i==0) || i==(SHEMATH_INTEGRAL_LOOP_COUNT-1)) {
      result += f*deltaX3;
    } else if (i & 1) {
      result += f*deltaX4_3;
    } else {
      result += f*deltaX2_3;
    }
     if (sheMathLog)
        (*sheMathLog) << "*step " << i << " : x=" << x
                      << " f(x)=" << (SHEFpSummary) f << " result="
                      << (SHEFpSummary) result << std::endl;
    x += deltaX;
  }

  // close to 1
  return M_1_PI * result;
}
//SHEFp nan(const char *) { return a; }
