//
// implement basic integer operations for Homomorphic values
//
#include <iostream>
#include "SHEFp.h"
#include "SHEInt.h"
#include "SHEKey.h"
#include "SHEio.h"
#include "SHEMagic.h"
#include <helib/helib.h>
#include <helib/binaryArith.h>
#include <helib/intraSlot.h>
#include "helibio.h"

#ifdef DEBUG
SHEPrivateKey *SHEFp::debugPrivKey = nullptr;
#endif

std::ostream *SHEFp::log = nullptr;
uint64_t SHEFp::nextTmp = 0;
SHEFpLabelHash SHEFp::labelHash;


// special Exponent codings by size
static inline uint64_t mkSpecialExp(int size)
{
    return (1ULL<<size)-1;
}

static inline uint64_t mkBiasExp(int size)
{
    return (1ULL<<(size-1))-1;
}

static inline uint64_t mkNanSignal(int size)
{
    return 1ULL << (size-1);
}

static inline uint64_t mkNanMantissa(int size, bool signal)
{
  uint64_t nan = 1ULL << (size-2);
  if (signal) {
    nan |= mkNanSignal(size);
  }
  return nan;
}


static const int SHE_UINT64_SHIFT=sizeof(uint64_t)*CHAR_BIT-1;
// two functions to crack the mantissa and exponent from a native
// double. Internally we use IEEE format except we keep the explicit
// one in the mantissa for convinience. We use the native system to convert
// to and from our internal representation (both input and decrypt).
// note: we will truncate some precision in LongDouble and ExtendedFloat.
// This is because the the latter returns more than uint64_t. We can fix
// the latter by using shemaxfloat_t for mult. The former will need
// to add arbitrary length ints to SHEInt constructor and decrypt (SHEInt
// can already handle arbitrary length internally). This is not a priority
// since such large floating point numbers (or integers for that matter)
// are not yet practical peformancewise.
static uint64_t i_mantissa(shemaxfloat_t d, uint64_t mantissaSize) {
    int exp;
    // clamp the size to uint64_t
    if (mantissaSize > sizeof(uint64_t)*CHAR_BIT) {
      mantissaSize = sizeof(uint64_t)*CHAR_BIT;
    }
    if (std::isnan(d)) { return mkNanMantissa(mantissaSize, issignaling(d)); }
    if (std::isinf(d)) { return 0; }
    shemaxfloat_t m = shemaxfloat_frexp(d,&exp);
    uint64_t mult = 1UL << (SHE_UINT64_SHIFT);
    uint64_t mantissa = (uint64_t)(m * (shemaxfloat_t)mult); // capture
    mantissa = mantissa >> (SHE_UINT64_SHIFT - mantissaSize); // truncate
    return mantissa;
}
static uint64_t i_exp(shemaxfloat_t d, uint64_t expSize) {
    int exp_orig;
    uint64_t exp;
    if (!std::isfinite(d)) { return mkSpecialExp(expSize); }
    (void) shemaxfloat_frexp(d,&exp_orig);
    return (uint64_t) exp;
}

SHEFp::SHEFp(const SHEPublicKey &pubKey, shemaxfloat_t myFloat,
               int expSize, int mantissaSize, const char *label) :
              sign(pubKey, std::signbit(myFloat), 1, true),
              exp(pubKey, i_exp(myFloat, expSize), expSize, true),
              mantissa(pubKey, i_mantissa(myFloat, mantissaSize),
                       mantissaSize, true)
{
  if (label) labelHash[this]=label;
  // if our mantissa was too big for uint64, we need to shift the result
  // back into place
  if (mantissaSize > sizeof(uint64_t)*CHAR_BIT) {
    mantissa <<= mantissaSize - sizeof(uint64_t)*CHAR_BIT;
  }
}

SHEFp::SHEFp(const SHEFp &model, shemaxfloat_t myFloat,const char *label)
               : sign(model.sign, std::signbit(myFloat)),
                 exp(model.exp, i_exp(myFloat,model.exp.getSize())),
                 mantissa(model.mantissa,
                          i_mantissa(myFloat, model.mantissa.getSize()))
{
  if (label) labelHash[this]=label;
  // if our mantissa was too big for uint64, we need to shift the result
  // back into place
  if (model.mantissa.getSize() > sizeof(uint64_t)*CHAR_BIT) {
    mantissa <<= model.mantissa.getSize() - sizeof(uint64_t)*CHAR_BIT;
  }
}

SHEFp::SHEFp(const SHEPublicKey &pubKey, const unsigned char *encryptedInt,
             int size, const char *label) : sign(pubKey,0,1,true),
             exp(pubKey, 0, 1, true), mantissa(pubKey, 0, 1, true)
{
  if (label) labelHash[this]=label;
  std::string s((const char *)encryptedInt, size);
  std::stringstream ss(s);
  read(ss);
}

SHEFp::SHEFp(const SHEPublicKey &pubKey, std::istream& str,
             const char *label) : sign(pubKey,0,1,true),
             exp(pubKey, 0, 1, true), mantissa(pubKey, 0, 1, true)
{
  if (label) labelHash[this]=label;
  readFromJSON(str);
}

// This needs work. reset of SHEFp is not going to be as
// cheap as reset on int because we will have to do special
// processing on overflow and underflow results
void SHEFp::reset(int expSize, int mantissaSize)
{
  // it might be better to store exp as a 2's complement number
  // and then truncate would just work (except overflow and under
  // flow).
  if (expSize < exp.getSize()) {
    exp -= mkBiasExp(exp.getSize()) - mkBiasExp(expSize);
  }
  exp.reset(expSize, true);
  if (expSize > exp.getSize()) {
    exp += mkBiasExp(expSize) - mkBiasExp(exp.getSize());
  }
  if (mantissaSize >= mantissa.getSize()) {
    mantissa <<= (mantissaSize - mantissa.getSize());
    mantissa.reset(mantissaSize, true);
    return;
  }
  mantissa >>= (mantissa.getSize() - mantissaSize);
  mantissa.reset(mantissaSize, true);
}

// do we need to reCrypt before doing more operations.
// bitCapacity uses noise to estimate how many more operations
// we can do, use it to decide if we need to reCrypt.
bool SHEFp::needRecrypt(long level) const
{
  return sign.needRecrypt() || exp.needRecrypt(level)
         || mantissa.needRecrypt(level);
}


bool SHEFp::needRecrypt(const SHEFp &a, long level) const
{
  return needRecrypt(level) || a.needRecrypt(level);
}

/* maybe we should do a 6 var packed recrypt here? */
void SHEFp::reCrypt(SHEFp &a)
{
  sign.reCrypt(a.sign);
  exp.reCrypt(a.exp);
  mantissa.reCrypt(a.mantissa);
}

/* maybe we should do a 3 var packed recrypt here? */
void SHEFp::reCrypt(void)
{
  exp.reCrypt(mantissa);
  sign.reCrypt();
}


void SHEFp::verifyArgs(SHEFp &a, long level)
{
  if (needRecrypt(a,level)) {
    reCrypt(a);
  }
}

void SHEFp::verifyArgs(long level)
{
  if (needRecrypt(level)) {
    reCrypt();
  }
}

void SHEFp::normalize(void)
{
  SHEInt shift(exp, (uint64_t)0);
  SHEBool lbreak(shift,false);

  // calculate how for to shift the mantissa. we are looking
  // for the first '1' bit in the mantissa
  for (int i=0; i < mantissa.getSize(); i++) {
    lbreak = lbreak.select(lbreak, mantissa.getBitHigh(i));
    shift += !lbreak;
  }

  // if we are shifting more than whats left in the exponent,
  // then the resulting number is denormal.
  SHEBool denormal = exp <= shift;
  // shift mantissa to accommodate the denormal number, otherwise shift it
  // to the normal place
  mantissa = denormal.select(mantissa << exp, mantissa >> shift);
  // now set the exponent, denormal exponents are zero.
  exp = denormal.select(0,exp - shift);
}

void SHEFp::denormalize(const SHEInt &targetExp)
{
  SHEInt shift(targetExp);
  shift -= exp;
  mantissa >>= shift;
  exp = targetExp;
}

///////////////////////////////////////////////////////////////////////////
//                      input/output operators.                           /
///////////////////////////////////////////////////////////////////////////
std::ostream& operator<<(std::ostream& str, const SHEFp& a)
{
  a.writeToJSON(str);
  return str;
}

std::istream& operator>>(std::istream& str, SHEFp& a)
{
  a.readFromJSON(str);
  return str;
}

std::ostream &operator<<(std::ostream& str, const SHEFpSummary &summary)
{
  long level = summary.shefp.bitCapacity();
  str << "SHEFp(" <<  summary.shefp.getLabel() << ","
      << summary.shefp.getExp().getSize() << ","
      << summary.shefp.getMantissa().getSize()
      << "," ;
  if (level == LONG_MAX) {
    str << "MAX";
  } else {
    str << level;
  }

#ifdef DEBUG
  const SHEPrivateKey *privKey = summary.getPrivateKey();
  if (privKey) {
    str << ":";
    if (summary.shefp.isCorrect()) {
      shemaxfloat_t decrypted = summary.shefp.decryptRaw(*privKey);
      str << decrypted;
    } else {
      str << "NaN-noise";
    }
  }
#endif
  str << ")";
  return str;
}

bool SHEFp::isCorrect(void) const
{
  return sign.isCorrect() || exp.isCorrect() || mantissa.isCorrect();
}

unsigned char *SHEFp::flatten(int &size, bool ascii) const
{
  std::stringstream ss;
  if (ascii) {
    writeToJSON(ss);
  } else {
    writeTo(ss);
  }
  std::string s=ss.str();
  size=s.length();
  return (unsigned char *)s.data();
}

void SHEFp::writeTo(std::ostream& str) const
{
  write_raw_int(str, SHEFpMagic); // magic to say we're a SHEFp
  sign.writeTo(str);
  exp.writeTo(str);
  mantissa.writeTo(str);
}

void SHEFp::writeToJSON(std::ostream& str) const
{
  helib::executeRedirectJsonError<void>([&]() { str << writeJSON(); });
}

helib::JsonWrapper SHEFp::writeJSON(void) const
{
  auto body = [this]() {
    json j = { {"sign", helib::unwrap(this->sign.writeJSON())},
              {"exp", helib::unwrap(this->exp.writeJSON())},
              {"mantissa", helib::unwrap(this->mantissa.writeJSON())}};

    return helib::wrap(helib::toTypedJson<SHEFp>(j));
  };
  return helib::executeRedirectJsonError<helib::JsonWrapper>(body);
}

SHEFp SHEFp::readFrom(std::istream& str, const SHEPublicKey &pubKey)
{
  SHEFp a(pubKey, 0, 1, true);
  a.read(str);
  return a;
}

SHEFp SHEFp::readFromJSON(std::istream& str, const SHEPublicKey& pubKey)
{
  return helib::executeRedirectJsonError<SHEFp>([&]() {
    json j;
    str >> j;
    return readFromJSON(helib::wrap(j), pubKey);
  });
}

SHEFp SHEFp::readFromJSON(const helib::JsonWrapper& j,
                            const SHEPublicKey& pubKey)
{
  SHEFp a(pubKey, (shemaxfloat_t)0.0, 1, true);
  a.readFromJSON(j);
  a.resetNative();
  return a;
}

void SHEFp::read(std::istream& str)
{
  long magic;

  magic = read_raw_int(str);
  helib::assertEq<helib::IOError>(magic, SHEFpMagic,
                                    "not an SHEFp on the stream");
  sign.read(str);
  exp.read(str);
  mantissa.read(str);
  resetNative();
}

void SHEFp::readFromJSON(std::istream& str)
{
  return helib::executeRedirectJsonError<void>([&]() {
    json j;
    str >> j;
    return readFromJSON(helib::wrap(j));
  });
}

void SHEFp::readFromJSON(const helib::JsonWrapper& jw)
{
  auto body = [&]() {
    json j = helib::fromTypedJson<SHEFp>(unwrap(jw));
    this->sign.readFromJSON(helib::wrap(j.at("sign")));
    this->exp.readFromJSON(helib::wrap(j.at("exp")));
    this->mantissa.readFromJSON(helib::wrap(j.at("mantissa")));
  };

  helib::executeRedirectJsonError<void>(body);
}

///////////////////////////////////////////////////////////////////////////
//                      General helpers
///////////////////////////////////////////////////////////////////////////
shemaxfloat_t SHEFp::decryptRaw(const SHEPrivateKey &privKey) const
{
  uint64_t isign = sign.decryptRaw(privKey);
  uint64_t iexp = exp.decryptRaw(privKey);
  uint64_t imantissa = mantissa.decryptRaw(privKey);
  int mantissaSize = std::min(mantissa.getSize(),
                              (int)sizeof(uint64_t)*CHAR_BIT);
  shemaxfloat_t result;

  if (iexp == mkSpecialExp(exp.getSize())) {
    if (imantissa == 0) {
      return isign ? -INFINITY : INFINITY;
    }
    if (imantissa & mkNanSignal(mantissa.getSize())) {
      return isign ? -SHEFP_SNAN : SHEFP_SNAN;
    }
    return isign ? -NAN : NAN;
  }
  result = (shemaxfloat_t) imantissa;
  result /= (shemaxfloat_t)(1 << mantissaSize);
  int64_t sexp = (int64_t)iexp - mkBiasExp(exp.getSize());
  if (sexp != 0) {
    result *= (shemaxfloat_t) shemaxfloat_pow((shemaxfloat_t)2.0,sexp);
  }
  return isign ? -result :result;
}

double SHEFp::securityLevel(void) const
{
  return sign.securityLevel();
}

///////////////////////////////////////////////////////////////////////////
//                      Mathematic helpers.                               /
///////////////////////////////////////////////////////////////////////////
// caller must ensure that the bit size of this, a, and result are all equal

SHEFp SHEFp::abs(void) const
{
   SHEFp copy(*this);
   copy.sign = SHEInt(copy.sign, (uint64_t)0);
   return copy;
}

///////////////////////////////////////////////////////////////////////////
//                      Mathematic operators.                             /
///////////////////////////////////////////////////////////////////////////

// basic addition, subtraction and negation operators. These functions
// return the values of the same size as the biggest operand
SHEFp SHEFp::operator-(void) const {
  SHEFp copy(*this);
  copy.sign ^= 1;
  return copy;
}

SHEFp SHEFp::operator+(const SHEFp &a) const {
  SHEBool swap=exp < a.exp;

  int thisMantissaSize = mantissa.getSize();
  int aMantissaSize = a.mantissa.getSize();

  // note: select will return the maximal size between big and little,
  // so both will have the same size mantissa and exponent.
  SHEFp big(select(swap, a, *this));
  SHEFp little(select(swap, *this, a));
  // add 1 bit for sign, 1 bit for overflow
  int mantissaSize = big.mantissa.getSize() + 2;

  little.denormalize(big.exp);
  big.mantissa.reset(mantissaSize, true); // extend with out sign extend
  big.mantissa.reset(mantissaSize, false); // make signed
  little.mantissa.reset(mantissaSize, true);
  big.mantissa.reset(mantissaSize, false);

  // now add the sign.
  big.mantissa = big.sign.select(-big.mantissa, big.mantissa);
  little.mantissa = little.sign.select(-little.mantissa, little.mantissa);

  big.mantissa += little.mantissa;
  big.sign = big.mantissa.isNegative();
  big.mantissa = big.sign.select(-big.mantissa,big.mantissa);
  big.mantissa.reset(mantissaSize-1, true); // back to unsigned
  SHEInt overflow = big.mantissa.getBitHigh(0);
  // handle the integer overflow case
  big.exp += overflow;
  big.mantissa = overflow.select(big.mantissa>>1, big.mantissa);
  big.mantissa.reset(mantissaSize-2, true); // back to normal
  big.normalize();

  // finally we need to handle Nan and Inf support
  // NOTE if both *this and a are special, the results
  // return whatever special value *this is. Ideally we should
  // order them. Question what should NAN() + (-NAN()) return
  // and what should INF + (-INF()) return?
  big = select(a.isSpecial(), big, a);
  big = select(isSpecial(), big, *this);
  return big;
}

SHEFp SHEFp::operator-(const SHEFp &a) const {
  SHEFp result(*this);
  result += (-a);
  return result;
}

// += and -= operators return the the same size as the 'this' pointer;
SHEFp &SHEFp::operator+=(const SHEFp &a) {
  *this = *this + a;
  return *this;
}

SHEFp &SHEFp::operator-=(const SHEFp &a) {
  *this = *this - a;
  return *this;
}

SHEFp SHEFp::operator+(shemaxfloat_t a) const {
  SHEFp aEncrypt(*this, a);
  return *this + aEncrypt;
}

SHEFp SHEFp::operator-(shemaxfloat_t a) const {
  SHEFp aEncrypt(*this, a);
  return *this - aEncrypt;
}

SHEFp &SHEFp::operator+=(shemaxfloat_t a) {
  SHEFp aEncrypt(*this, a);
  return *this = (*this) + aEncrypt;
}

SHEFp &SHEFp::operator-=(shemaxfloat_t a) {
  SHEFp aEncrypt(*this, a);
  return *this = (*this) - aEncrypt;
}

SHEFp SHEFp::operator*(const SHEFp &a) const {
  SHEFp result(*this);
  SHEInt mantissa(result.mantissa);
  int expSize = std::max(exp.getSize(), a.exp.getSize());
  int expMinSize = std::min(exp.getSize(), a.exp.getSize());

  // handle the sign
  result.sign ^= a.sign;
  SHEInt saveSign = result.sign;

  // handle the exponent
  result.exp.reset(expSize+1, true);
  result.exp += a.exp;
  // we create underflowAmount and make is signed so we can detect
  // the exponent going negative.
  SHEInt underflowAmount(result.exp);
  underflowAmount.reset(expSize+1, false);
  underflowAmount -= mkBiasExp(expMinSize);
  SHEBool overflow = result.exp >= (uint64_t)(1<< (expSize+expMinSize));
  SHEBool underflow = underflowAmount.isNegative();
  result.exp = underflowAmount;
  result.exp.reset(expSize, true);
  result.exp = underflow.select(0.0, result.exp);
  result.exp = overflow.select(mkSpecialExp(expSize), result.exp);
  underflowAmount = -underflowAmount;

  // handle the mantissa
  mantissa.reset(result.mantissa.getSize()+a.mantissa.getSize(), true);
  mantissa *= a.mantissa;
  mantissa >>= a.mantissa.getSize();
  mantissa.reset(result.mantissa.getSize(), true);
  mantissa = underflow.select(mantissa >> underflowAmount, mantissa);
  mantissa = overflow.select(0.0, mantissa);
  result.mantissa = mantissa;
  result.normalize();

  // now handle all the checks that normally happen at the beginning,
  // but in homomorphic programming, happens at the end.
  result = select(a.isNan() || isNan(),result,NAN);
  result = select(a.isInf() || isInf(),result,INFINITY);
  result = select(a.isZero() || isZero(),result,0.0);
  result.sign = saveSign;
  return result;
}

SHEFp &SHEFp::operator*=(const SHEFp &a) {
  *this = *this * a;
  return (*this);
}

// we use shifts and adds when we are multiplying with an unencrypted
// constant because that increases the error by less than a full on
// multiplication (decreasing the need for bootstraping)
SHEFp SHEFp::operator*(shemaxfloat_t a) const
{
  SHEFp aEncrypt(*this, a);
  aEncrypt = *this * aEncrypt;
  return aEncrypt;
}

SHEFp &SHEFp::operator*=(shemaxfloat_t a) {
  *this = *this * a;
  return *this;
}

SHEFp SHEFp::operator/(const SHEFp &a) const {
  SHEFp arg(a);
  SHEBool needNan = a.isZero()  && isZero();
  SHEBool needInf = a.isZero();
  SHEInt divisor(a.mantissa,1);

  arg.exp = 2*mkBiasExp(arg.exp.getSize()) - arg.exp;
  divisor.reset(a.mantissa.getSize()*2,true);
  divisor <<= a.mantissa.getSize()*2-1;
  arg.mantissa = divisor/arg.mantissa;
  arg = select(a.isInf(), arg, 0.0);
  arg = select(a.isNan(), arg, NAN);
  arg = *this * arg;
  SHEInt saveSign = arg.sign;
  arg = select(needInf, arg, INFINITY);
  arg = select(needNan, arg, NAN);
  arg.sign = saveSign;
  return arg;
}

//
// No real efficiency gain in division, just do the normal
// wrapping
//
SHEFp &SHEFp::operator/=(const SHEFp &a) {
  *this = *this / a;
  return *this;
}

SHEFp SHEFp::operator/(shemaxfloat_t a) const {
  if (a == 0.0) {
    throw helib::LogicError("divide by integer zero");
  }
  SHEFp aEncrypt(*this, a);
  return *this / aEncrypt;
}

SHEFp &SHEFp::operator++(void)
{
  *this += 1.0;
  return *this;
}

SHEFp &SHEFp::operator--(void)
{
  *this -= 1.0;
  return *this;
}

SHEFp SHEFp::operator++(int dummy)
{
  SHEFp result(*this);
  *this += 1.0;
  return result;
}

SHEFp SHEFp::operator--(int dummy)
{
  SHEFp result(*this);
  *this -= 1.0;
  return result;
}

///////////////////////////////////////////////////////////////////////////
//                      Logical operators.                                /
///////////////////////////////////////////////////////////////////////////
// note: there is recursion going on here.
// all logical operators always return bitSize == 1, isUnsigned = true,
// AKA SHEBool. They can take non-Bool inputs, with 0=0 and nonZero=1

SHEBool SHEFp::isZero(void) const
{
  return abs() == 0.0;
}

SHEBool SHEFp::isNotZero(void) const
{
  return abs() != 0.0;
}

SHEBool SHEFp::isNegative(void) const
{
  // for integers, we return 0 as false, but
  // not for float, (float has +/- 0)?
  return SHEBool(sign);
}

SHEBool SHEFp::isPositive(void) const
{
  // for integers, we return 0 as false, but
  // not for float (float has +/- 0)?
  return !SHEBool(sign);
}

SHEBool SHEFp::operator!(void) const
{
  return isNotZero();
}

SHEFp select(const SHEInt &sel, const SHEFp &a_true, const SHEFp &a_false)
{
  SHEFp r_true(a_true);
  SHEFp r_false(a_false);
  int trueMantissaSize=a_true.mantissa.getSize();
  int falseMantissaSize=a_false.mantissa.getSize();
  int mantissaSize = std::max(trueMantissaSize,falseMantissaSize);
  r_true.mantissa.reset(mantissaSize, true);
  r_true.mantissa <<= mantissaSize - trueMantissaSize;
  r_false.mantissa.reset(mantissaSize, true);
  r_false.mantissa <<= mantissaSize - falseMantissaSize;
  int expSize = std::max(r_true.exp.getSize(),r_false.exp.getSize());
  r_true.exp.reset(expSize,true);
  r_false.exp.reset(expSize,true);
  // handle Nan and Inf
  if (a_true.exp.getSize() != expSize) {
    r_true.exp = a_true.isSpecial().select(mkSpecialExp(expSize),r_true.exp);
  }
  if (a_false.exp.getSize() != expSize) {
    r_false.exp = a_false.isSpecial().select(mkSpecialExp(expSize),r_false.exp);
  }
  r_true.sign = sel.select(r_true.sign,r_false.sign);
  r_true.exp = sel.select(r_true.exp,r_false.exp);
  r_true.mantissa = sel.select(r_true.mantissa,r_false.mantissa);
  return r_true;
}

SHEFp select(const SHEInt &sel, const SHEFp &a_true,
                    shemaxfloat_t a_false)
{
  SHEFp result(a_true);
  SHEFp r_false(a_true, a_false);
  result.sign = sel.select(a_true.sign,r_false.sign);
  result.exp = sel.select(a_true.exp,r_false.exp);
  result.mantissa = sel.select(a_true.mantissa,r_false.mantissa);
  return result;
}

SHEFp select(const SHEInt &sel, shemaxfloat_t a_true,
                    const SHEFp &a_false)
{
  SHEFp result(a_false);
  SHEFp r_true(a_false, a_true);
  result.sign = sel.select(r_true.sign,a_false.sign);
  result.exp = sel.select(r_true.exp,a_false.exp);
  result.mantissa = sel.select(r_true.mantissa,a_false.mantissa);
  return result;
}

SHEFp select(const SHEInt &sel, const SHEFp &model,
                    shemaxfloat_t a_true, shemaxfloat_t a_false)
{
  SHEFp result(model);
  SHEFp r_true(model, a_true);
  SHEFp r_false(model, a_false);
  result.sign = sel.select(r_true.sign,r_false.sign);
  result.exp = sel.select(r_true.exp,r_false.exp);
  result.mantissa = sel.select(r_true.mantissa,r_false.mantissa);
  return result;
}

// return special static of the encrypted FP
SHEBool SHEFp::isSpecial(void) const
{
  return exp == mkSpecialExp(exp.getSize());
}

SHEBool SHEFp::isNan(void) const
{
  return isSpecial() && (mantissa.isNotZero());
}

SHEBool SHEFp::isInf(void) const
{
  return isSpecial() && (mantissa.isZero());
}

SHEBool SHEFp::rawGT(const SHEFp &a) const
{
  if (log) {
    (*log) << (SHEFpSummary)*this << ">" << (SHEFpSummary)a << "="
           << std::flush;
  }
  SHEBool signGt = sign > a.sign;
  SHEBool signEq = sign == a.sign;
  SHEBool expGt = signEq && (exp > a.exp);
  SHEBool mantissaGt = signEq && (exp ==  a.exp) && (mantissa > a.mantissa);
  SHEBool result = signGt || expGt || mantissaGt;

  if (log) { (*log) << (SHEIntSummary)result << std::endl; }
  return result;
}

SHEBool SHEFp::rawGE(const SHEFp &a) const
{
  if (log) {
    (*log) << (SHEFpSummary)*this << ">=" << (SHEFpSummary)a << "="
           << std::flush;
  }
  SHEBool signGt = sign > a.sign;
  SHEBool signEq = sign == a.sign;
  SHEBool expGt = signEq && (exp > a.exp);
  SHEBool mantissaGe = signEq && (exp ==  a.exp) && (mantissa >= a.mantissa);
  SHEBool result = signGt || expGt || mantissaGe;

  if (log) { (*log) << (SHEIntSummary)result << std::endl; }
  return result;
}

SHEBool SHEFp::operator>(const SHEFp &a) const
{
  SHEBool notNan = !(isNan() || a.isNan());
  return notNan && rawGT(a);
}

SHEBool SHEFp::operator<(const SHEFp &a) const
{
  SHEBool notNan = !(isNan() || a.isNan());
  return notNan && a.rawGT(*this);
}

SHEBool SHEFp::operator>=(const SHEFp &a) const
{
  SHEBool notNan = !(isNan() || a.isNan());
  return notNan && rawGE(a);
}

SHEBool SHEFp::operator<=(const SHEFp &a) const
{
  SHEBool notNan = !(isNan() || a.isNan());
  return notNan && a.rawGE(*this);
}

SHEBool SHEFp::operator!=(const SHEFp &a) const
{
  SHEBool isEitherNan = (isNan() || a.isNan());

  return isEitherNan || (sign != a.sign) ||
         (exp != a.exp) || (mantissa != a.mantissa);
}

SHEBool SHEFp::operator==(const SHEFp &a) const
{
  SHEBool notNan = !(isNan() || a.isNan());
  return notNan && (sign == a.sign)&&
         (exp == a.exp) && (mantissa == a.mantissa);
}


SHEBool SHEFp::operator<(shemaxfloat_t a) const
{
    SHEFp heA(*this, a);
    return *this < heA;
}

SHEBool SHEFp::operator>(shemaxfloat_t a) const
{
    SHEFp heA(*this, a);
    return *this > heA;
}

SHEBool SHEFp::operator<=(shemaxfloat_t a) const
{
    SHEFp heA(*this, a);
    return *this <= heA;
}

SHEBool SHEFp::operator>=(shemaxfloat_t a) const
{
    SHEFp heA(*this, a);
    return *this >= heA;
}
