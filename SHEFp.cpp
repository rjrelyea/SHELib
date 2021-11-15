//
// implement basic integer operations for Homomorphic values
//
#include <iostream>
#include "SHEFp.h"
#include "SHEInt.h"
#include "SHEKey.h"
#include "SHEUtil.h"
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
static uint64_t i_mantissa(shemaxfloat_t d, int mantissaSize, int expSize)
{
    int exp;
    int bias = mkBiasExp(expSize);
    // clamp the size to uint64_t
    if (mantissaSize > sizeof(uint64_t)*CHAR_BIT) {
      mantissaSize = sizeof(uint64_t)*CHAR_BIT;
    }
    if (std::isnan(d)) { return mkNanMantissa(mantissaSize, issignaling(d)); }
    if (std::isinf(d)) { return 0; }
    shemaxfloat_t m = shemaxfloat_frexp(d,&exp);
    exp += bias;
    if ((exp > mkSpecialExp(expSize)) || ((exp+bias) < 0)) {
       return 0;
    }
    m = shemaxfloat_abs(m);
    uint64_t mult = 1ULL << (SHE_UINT64_SHIFT);
    uint64_t mantissa = (uint64_t)(m * (shemaxfloat_t)mult); // capture
    mantissa = mantissa >> (SHE_UINT64_SHIFT - mantissaSize); // truncate
    return mantissa;
}

static uint64_t i_exp(shemaxfloat_t d, uint64_t expSize)
{
    int exp;
    int bias = mkBiasExp(expSize);
    if (d == 0.0) {
      return 0;
    }
    uint64_t special = mkSpecialExp(expSize);
    if (!std::isfinite(d)) { return special; }
    (void) shemaxfloat_frexp(d,&exp);
    exp += bias;
    if ( exp < 0) return 0;
    if (exp >= special) {
      return special;
    }
    return (uint64_t) exp;
}

SHEFp::SHEFp(const SHEPublicKey &pubKey, shemaxfloat_t myFloat,
               int expSize, int mantissaSize, const char *label) :
              sign(pubKey, std::signbit(myFloat), 1, true),
              exp(pubKey, i_exp(myFloat, expSize), expSize, true),
              mantissa(pubKey, i_mantissa(myFloat, mantissaSize, expSize),
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
                          i_mantissa(myFloat, model.mantissa.getSize(),
                                     model.exp.getSize()))
{
  if (label) labelHash[this]=label;
  // if our mantissa was too big for uint64, we need to shift the result
  // back into place
  if (model.mantissa.getSize() > sizeof(uint64_t)*CHAR_BIT) {
    mantissa <<= model.mantissa.getSize() - sizeof(uint64_t)*CHAR_BIT;
  }
}
SHEFp::SHEFp(const SHEInt &a, const char *label)
               : sign(a.isNegative()), exp(a.getPublicKey(), 0, 1, true),
                 mantissa(a.abs())
{
  if (label) labelHash[this]=label;

  // figure out how big to make exponent based on the integer size
  int expSize = log2(a.getSize()) + 3;
  exp.reset(expSize, true);
  exp = mkBiasExp(expSize)+a.getSize();

  // we've already stripped the mantissa sign, now make it unsigned
  // so that we'll normalize properly
  mantissa.reset(mantissa.getSize(),true);
  normalize();
  // we now have a floating point value that has preserved all the bits
  // of the input Integer, If this is set to a concrete FP time (like SHEFloat
  // the various componets will get properly sized.
}

SHEFp::SHEFp(const SHEFp &model, const SHEInt &a, const char *label)
               : sign(a.isNegative()), exp(a.getPublicKey(), 0, 1, true),
                 mantissa(a.abs())
{
  if (label) labelHash[this]=label;

  // set the proper bias for the exponent.
  int expSize = model.exp.getSize();
  exp.reset(expSize, true);
  exp = mkBiasExp(expSize)+model.mantissa.getSize();

  // we've already stripped the mantissa sign, now make it unsigned
  // so that we'll normalize properly
  mantissa.reset(model.mantissa.getSize(), true);
  normalize();
  // now set to the size of the model, avoiding expensive resets.
}

// caste a Floating point value to a SHEInt
SHEInt SHEFp::toSHEInt(int bitSize, bool isUnsigned) const
{
  SHEInt out(mantissa);
  SHEInt adjustedExp(exp);
  adjustedExp.reset(exp.getSize(), false);
  adjustedExp -= (mantissa.getSize() + mkBiasExp(exp.getSize()));
  // allow the caller to override our bitsize choice
  if (bitSize) out.reset(bitSize, true);
  uint64_t intmax = (1ULL << out.getSize())-1;
  SHEBool max = (this->abs() > (double)(intmax));

  // NOTE: we need to balance the cost of doing a double
  // encrypted shift on bitSize sized ints versus not having
  // enough bits to properly represent the floating point value.
  // (64 bit ints shifts are very expensive). If the caller
  // didn't specify a bitsize, we just use the current mantissa
  // size.
  out = out.leftShiftSigned(adjustedExp);
  out = max.select(intmax, out);
  if (!isUnsigned) {
    out.reset(out.getSize(), false);
    out = sign.select(-out, out);
  }
  return out;
}

// truncate the fraction, ingnore the sign
SHEFp SHEFp::trunc(void) const
{
  SHEFp result(*this);
  SHEInt firstFract = (mantissa.getSize() + mkBiasExp(exp.getSize())) - exp;

  for (int i=0; i < mantissa.getSize(); i++) {
    SHEBool clear(firstFract > (uint64_t)i);
    result.mantissa.setBit(i, clear.select(0, result.mantissa.getBit(i)));
  }
  // we either cleared all the bits, or we left the high bits in place, no need
  // to normalize, just update the exponent if everything cleared.
  result.exp = select(result.mantissa.isZero(), 0, result.exp);
  return result;
}

// trucate the integer, ignore the sign
SHEFp SHEFp::fract(void) const
{
  SHEFp result(*this);
  SHEInt firstFract = (mantissa.getSize() + mkBiasExp(exp.getSize())) - exp;

  for (int i=0; i < mantissa.getSize(); i++) {
    SHEBool clear(firstFract <= (uint64_t)i);
    result.mantissa.setBit(i, clear.select(0, result.mantissa.getBit(i)));
  }
  result.normalize();
  return result;
}

SHEBool SHEFp::hasFract(void) const
{
  SHEInt resultMantissa(this->mantissa);
  SHEInt firstFract = (mantissa.getSize() + mkBiasExp(exp.getSize())) - exp;

  for (int i=0; i < mantissa.getSize(); i++) {
    SHEBool clear(firstFract <= (uint64_t)i);
    resultMantissa.setBit(i, clear.select(0, resultMantissa.getBit(i)));
  }
  return resultMantissa.isNotZero();
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
  int oldExpSize = exp.getSize();
  int oldMantissaSize = mantissa.getSize();
  SHEBool saveSpecial(SHEBool(exp,false));

  if (expSize != oldExpSize) {
    saveSpecial = isSpecial();
  }
  if (expSize < oldExpSize) {
    exp -= mkBiasExp(oldExpSize) - mkBiasExp(expSize);
  }
  exp.reset(expSize, true);  // noop if expSize == exp.getSize()
  if (expSize > oldExpSize) {
    exp += mkBiasExp(expSize) - mkBiasExp(oldExpSize);
  }

  if (expSize != oldExpSize) {
    exp = saveSpecial.select(mkSpecialExp(expSize), exp);
  }
  if (mantissaSize == oldMantissaSize) {
    return;  // nothing more to do.
  }
  if (mantissaSize > oldMantissaSize) {
    mantissa.reset(mantissaSize, true);
    mantissa <<= (mantissaSize - oldMantissaSize);
    return;
  }
  // matissaSize < oldMantissaSize
  mantissa >>= (oldMantissaSize - mantissaSize);
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
void SHEFp::reCrypt(SHEFp &a, bool force)
{
  sign.reCrypt(a.sign, force);
  exp.reCrypt(a.exp, force);
  mantissa.reCrypt(a.mantissa, force);
}

/* maybe we should do a 3 var packed recrypt here? */
void SHEFp::reCrypt(bool force)
{
  exp.reCrypt(mantissa, force);
  sign.reCrypt(force);
}


void SHEFp::verifyArgs(SHEFp &a, long level)
{
  if (needRecrypt(a,level)) {
    reCrypt(a, false);
  }
}

void SHEFp::verifyArgs(long level)
{
  if (needRecrypt(level)) {
    reCrypt(false);
  }
}

void SHEFp::normalize(void)
{
  // this is an expensive capacity call, make sure our inputs are good
  mantissa.verifyArgs(exp, 2*SHEINT_DEFAULT_LEVEL_TRIGGER);
  SHEInt shift(exp, (uint64_t)0);
  SHEBool lbreak(shift,false);
  SHEBool saveSpecial = isSpecial();

  // calculate how for to shift the mantissa. we are looking
  // for the first '1' bit in the mantissa
  for (int i=0; i < mantissa.getSize(); i++) {
    lbreak = lbreak.select(lbreak, mantissa.getBitHigh(i));
    // add 1 if lbreak is zero without colapsing the size
    // of shift
    SHEInt addr(!lbreak);
    addr.reset(exp.getSize(), true);
    shift += addr;
  }
  // if we are shifting more than whats left in the exponent,
  // then the resulting number is denormal. exponent will go to zero
  shift = (exp < shift).select(exp, shift);
  // shift has just come down off a chain of operations and may have
  // diminished capacity, which we will bring into the expensive
  // >> operator
  shift.verifyArgs(2*SHEINT_DEFAULT_LEVEL_TRIGGER);
  mantissa = mantissa << shift;
  exp -= shift;
  exp = mantissa.isZero().select(0,exp);
  exp = saveSpecial.select(mkSpecialExp(exp.getSize()),exp);
}

void SHEFp::denormalize(const SHEInt &targetExp)
{
  SHEInt shift(targetExp);
  shift = shift - exp;
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
  std::ios_base::fmtflags saveFlags = str.flags();
  str << "SHEFp(" <<  summary.shefp.getLabel() << "," << std::dec
      << summary.shefp.getExp().getSize() << ","
      << summary.shefp.getMantissa().getSize()
      << "," ;
  if (level == LONG_MAX) {
    str << "MAX";
  } else {
    str << level;
  }
  str.flags(saveFlags);

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
  return sign.isCorrect() && exp.isCorrect() && mantissa.isCorrect();
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
  helib::executeRedirectJsonError<void>([&]() { str << writeToJSON(); });
}

helib::JsonWrapper SHEFp::writeToJSON(void) const
{
  auto body = [this]() {
    json j = { {"sign", helib::unwrap(this->sign.writeToJSON())},
              {"exp", helib::unwrap(this->exp.writeToJSON())},
              {"mantissa", helib::unwrap(this->mantissa.writeToJSON())}};

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

SHEInt SHEFp::getUnbiasedExp(void) const
{
  SHEInt exp_(exp);
  exp_.reset(exp.getSize(), false);
  return exp_ - mkBiasExp(exp.getSize());
}

void SHEFp::setUnbiasedExp(int64_t e)
{
  SHEInt exp_(exp, e + mkBiasExp(exp.getSize()));
  exp = exp_;
}

void SHEFp::setUnbiasedExp(const SHEInt &e)
{
  SHEInt exp_(e + mkBiasExp(exp.getSize()));
  exp_.reset(exp.getSize(), true);
  exp = exp_;
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

// get the maximum value that can be represented by this float.
shemaxfloat_t SHEFp::getMax() const
{
  uint64_t maxExp = (mkSpecialExp(exp.getSize()) -1) - mkBiasExp(exp.getSize());
  shemaxfloat_t mantissaFract = (shemaxfloat_t)1.0;
  shemaxfloat_t result = (shemaxfloat_t)0.0;
  for (int i=0; i < mantissa.getSize(); i++) {
    mantissaFract /= (shemaxfloat_t)2.0;
    result += mantissaFract;
  }
  result *= (shemaxfloat_t) shemaxfloat_pow((shemaxfloat_t)2.0, maxExp);
  return result;
}

// get the value closest to zero that can be represented by this float.
shemaxfloat_t SHEFp::getMin() const
{
  return (shemaxfloat_t)
          shemaxfloat_pow((shemaxfloat_t).5,
                          mantissa.getSize()+ mkBiasExp(exp.getSize()));
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
  int thisMantissaSize = mantissa.getSize();
  int aMantissaSize = a.mantissa.getSize();
  int thisExpSize = exp.getSize();
  int aExpSize = a.exp.getSize();
  int maxMantissaSize = thisMantissaSize;
  int maxExpSize = thisExpSize;
  SHEFpBool swap(SHEBool(exp, false));
  SHEFp big(*this, 0.0, "big");
  SHEFp little(a, 0.0, "little");

  if (log) {
    (*log) << (SHEFpSummary) *this << ".operator+("
           << (SHEFpSummary) a << ") = " << std::flush;
  }

  // if the mantissa or exponent sizes mismatch,
  // reset to the same size before adding.
  // we need to do this before select, because select will
  // do a reset, and may change which exponent is larger.
  if ((thisMantissaSize != aMantissaSize) ||
      (thisExpSize != aExpSize)) {
    SHEFp tThis(*this);
    SHEFp ta(a);
    maxMantissaSize = std::max(thisMantissaSize, aMantissaSize);
    maxExpSize = std::max(thisExpSize, aExpSize);
    tThis.reset(maxExpSize, maxMantissaSize);
    ta.reset(maxExpSize, maxMantissaSize);
    swap=tThis.exp < ta.exp;
    big = swap.select(ta, tThis);
    little = swap.select(tThis, ta);
  } else {
    // already the same size, dispense with the expensive
    // reset.
    swap=exp < a.exp;
    big = swap.select(a, *this);
    little = swap.select(*this, a);
  }


  big.verifyArgs(little);
  // add 1 bit for sign, 1 bit for overflow
  int mantissaSize = big.mantissa.getSize() + 2;

  little.denormalize(big.exp);
  big.mantissa.reset(mantissaSize, true); // extend with out sign extend
  big.mantissa.reset(mantissaSize, false); // make signed
  little.mantissa.reset(mantissaSize, true); // do the same for little
  little.mantissa.reset(mantissaSize, false);

  // now add the sign.
  big.mantissa = select(big.sign, -big.mantissa, big.mantissa);
  little.mantissa = select(little.sign, -little.mantissa, little.mantissa);

  big.mantissa += little.mantissa;
  big.sign = big.mantissa.isNegative();
  big.mantissa = select(big.sign,-big.mantissa,big.mantissa);
  big.mantissa.reset(mantissaSize-1, true); // back to unsigned
  SHEInt overflow = big.mantissa.getBitHigh(0);
  // handle the integer overflow case
  big.exp += overflow;
  big.mantissa = select(overflow, big.mantissa>>1, big.mantissa);
  big.mantissa.reset(mantissaSize-2, true); // back to normal
  big.normalize();

  // finally we need to handle Nan and Inf support
  // skipping this would increase capacity after this operation, but will
  // reduce correctness
  SHEBool aNan = a.isNan();
  SHEBool aInf = a.isInf();
  SHEBool thisNan = isNan();
  SHEBool thisInf = isInf();
  // -INF +INF generates a new Nan
  SHEBool gNan = thisInf && aInf && (sign ^ a.sign);
  SHEFp sNan(*this,NAN);
  SHEFp sInf(*this,INFINITY);
  // if we are returning Nan, pick it's sign
  sNan.sign = thisNan.select(sign, a.sign);
  // if w are generating the NAN, make the sign +
  sNan.sign = gNan.select(0,sNan.sign);
  sInf.sign = thisInf.select(sign,a.sign);
  big = select(thisInf || aInf, sInf, big);
  big = select(aNan || thisNan || gNan, sNan, big);
  if (log) (*log) << (SHEFpSummary) big << std::endl;
  return big;
}

SHEFp SHEFp::operator-(const SHEFp &a) const
{
  SHEFp result(*this);
  result += (-a);
  return result;
}

// += and -= operators return the the same size as the 'this' pointer;
SHEFp &SHEFp::operator+=(const SHEFp &a)
{
  *this = *this + a;
  return *this;
}

SHEFp &SHEFp::operator-=(const SHEFp &a)
{
  *this = *this - a;
  return *this;
}

SHEFp SHEFp::operator+(shemaxfloat_t a) const
{
  SHEFp aEncrypt(*this, a);
  return *this + aEncrypt;
}

SHEFp SHEFp::operator-(shemaxfloat_t a) const
{
  SHEFp aEncrypt(*this, a);
  return *this - aEncrypt;
}

SHEFp &SHEFp::operator+=(shemaxfloat_t a)
{
  SHEFp aEncrypt(*this, a);
  return *this = (*this) + aEncrypt;
}

SHEFp &SHEFp::operator-=(shemaxfloat_t a)
{
  SHEFp aEncrypt(*this, a);
  return *this = (*this) - aEncrypt;
}

SHEFp SHEFp::operator*(const SHEFp &a) const
{

  if (log) {
    (*log) << (SHEFpSummary) *this << ".operator*("
           << (SHEFpSummary) a << ") = " << std::flush;
  }
  SHEFp result(*this);
  SHEInt rmantissa(result.mantissa);
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
  SHEBool overflow = result.exp >=
                     (uint64_t) (mkSpecialExp(expSize)+mkBiasExp(expMinSize));
  SHEBool underflow = underflowAmount.isNegative();
  result.exp = underflowAmount;
  result.exp.reset(expSize, true);
  result.exp = underflow.select(0, result.exp);
  result.exp = overflow.select(mkSpecialExp(expSize), result.exp);
  // if underflow was negative, we are going to use it to shift the mantissa
  // make it positive for the shift operator.
  underflowAmount = -underflowAmount;

  // handle the mantissa
  rmantissa.reset(result.mantissa.getSize()+a.mantissa.getSize(), true);
  rmantissa *= a.mantissa; // do the multiply
  rmantissa >>= a.mantissa.getSize(); // shift back to original location
  rmantissa.reset(result.mantissa.getSize(), true);
  // overflow and underflow processing
  rmantissa = underflow.select(rmantissa >> underflowAmount, rmantissa);
  rmantissa = overflow.select(0, rmantissa);
  result.mantissa = rmantissa;
  result.normalize();

  // now handle all the checks that normally happen at the beginning,
  // but in homomorphic programming, happens at the end.
  SHEBool aInf = a.isInf();
  SHEBool thisInf = isInf();
  SHEBool aZero = a.isZero();
  SHEBool thisZero = isZero();
  result = select(a.isNan() || isNan(), NAN, result);
  result = select(aInf || thisInf, INFINITY, result);
  result = select(aZero || thisZero, 0.0, result);
  result = select((aZero && thisInf) || (aInf && thisZero), NAN, result);

  result.sign = saveSign;

  if (log) (*log) << (SHEFpSummary) result << std::endl;
  return result;
}


SHEFp &SHEFp::operator*=(const SHEFp &a)
{
  *this = *this * a;
  return (*this);
}

// we use shifts and adds when we are multiplying with an unencrypted
// constant because that increases the error by less than a full on
// multiplication (decreasing the need for bootstraping)
SHEFp SHEFp::operator*(shemaxfloat_t a) const
{
  // process special versions first since
  // we see the special versions
  if (a == 0.0 || !std::isfinite(a)) {
    SHEFp sNan(*this,std::signbit(a) ? -NAN : NAN);
    SHEFp sInf(*this,std::signbit(a) ? -INFINITY : INFINITY);
    SHEFp sZero(*this,std::signbit(a) ? -0.0 : 0.0);
    sNan.sign ^= sign;
    sInf.sign ^= sign;
    sZero.sign ^= sign;
    if (a==0.0) {
      return select(isInf(),sNan, sInf);
    } else if (std::isinf(a)) {
      return select(isZero(), sNan, sInf);
    } else { // NAN
      sNan = select(isZero(), sZero, sNan);
      return select(isInf(), sInf, sNan);
    }
  }
  SHEFp aEncrypt(*this, a);
  aEncrypt = *this * aEncrypt;
  return aEncrypt;
}

SHEFp &SHEFp::operator*=(shemaxfloat_t a) {
  *this = *this * a;
  return *this;
}

SHEFp SHEFp::operator/(const SHEFp &a) const
{
  if (log) {
    (*log) << (SHEFpSummary) *this << ".operator/("
           << (SHEFpSummary) a << ") = " << std::flush;
  }
  SHEFp result(*this);
  SHEInt rmantissa(result.mantissa);
  int expSize = std::max(exp.getSize(), a.exp.getSize());
  int expMinSize = std::min(exp.getSize(), a.exp.getSize());

  // handle the sign
  result.sign ^= a.sign;
  SHEInt saveSign = result.sign;

  // handle the exponent
  result.exp.reset(expSize+2, true);
  result.exp -=  a.exp;
  // we create underflowAmount and make is signed so we can detect
  // the exponent going negative.
  SHEInt underflowAmount(result.exp);
  underflowAmount.reset(expSize+2, false);
  underflowAmount += (mkBiasExp(a.exp.getSize()) - mkBiasExp(exp.getSize())) +
                      mkBiasExp(expSize) + 1;
  SHEBool underflow = underflowAmount.isNegative();
  result.exp = underflowAmount;
  result.exp.reset(expSize+2, true);
  // overflow is really !underflow && overflow, we handle this below
  // by handling the overflow case first, and then the underflow case
  // which will cause the latter to override
  SHEBool overflow = result.exp >= (uint64_t) mkSpecialExp(expSize);
  result.exp.reset(expSize, true);
  result.exp = overflow.select(mkSpecialExp(expSize), result.exp);
  result.exp = underflow.select(0.0, result.exp);
  // if underflow was negative, we are going to use it to shift the mantissa
  // make it positive for the shift operator.
  underflowAmount = -underflowAmount;

  // handle the mantissa
  rmantissa.reset(result.mantissa.getSize()+a.mantissa.getSize()-1, true);
  rmantissa <<= a.mantissa.getSize()-1; // shift up to capture maximal precision
  rmantissa /= a.mantissa; // do the divide
  // overflow and underflow processing
  rmantissa = overflow.select(0, rmantissa);
  // do the underflow shift before we reset..
  rmantissa = underflow.select(rmantissa >> underflowAmount, rmantissa);
  rmantissa.reset(result.mantissa.getSize(), true); // back to normal
  result.mantissa = rmantissa;
  result.normalize();

  // now handle all the checks that normally happen at the beginning,
  // but in homomorphic programming, happens at the end.
  SHEBool aInf = a.isInf();
  SHEBool thisInf = isInf();
  SHEBool aZero = a.isZero();
  SHEBool thisZero = isZero();
  result = select(a.isNan() || isNan(), NAN, result);
  result = select(aZero || thisInf, INFINITY, result);
  result = select(aInf || thisZero, 0.0, result);
  result = select(((aZero && thisZero) || (aInf && thisInf)), NAN, result);
  result.sign = saveSign;

  if (log) (*log) << (SHEFpSummary) result << std::endl;
  return result;
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
  // process special versions first since
  // we see the special versions
  if (a == 0.0 || !std::isfinite(a)) {
    SHEFp sNan(*this, std::signbit(a) ? -NAN : NAN);
    SHEFp sInf(*this, std::signbit(a) ? -INFINITY : INFINITY);
    SHEFp sZero(*this, std::signbit(a) ? -0.0 : 0.0);
    sNan.sign ^= sign;
    sInf.sign ^= sign;
    sZero.sign ^= sign;
    if (a==0.0) {
      return select(isZero(), sNan, sInf);
    } else if (std::isinf(a)) {
      return select(isInf(), sNan, sZero);
    } else { // NAN
      sNan = select(isZero(), sInf,sNan);
      return select(isInf(), sZero, sNan);
    }
  }
  // invert before we encrypt when it's cheaper...
  a = 1.0/a;
  SHEFp aEncrypt(*this, a);
  return *this * aEncrypt;
}

SHEFp &SHEFp::operator/=(shemaxfloat_t a) {
  *this = *this / a;
  return *this;
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
  return exp.isZero() && mantissa.isZero();
}

SHEBool SHEFp::isNotZero(void) const
{
  return !isZero();
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
  int mantissaSize = std::max(a_true.mantissa.getSize(),
                              a_false.mantissa.getSize());
  int expSize = std::max(r_true.exp.getSize(),r_false.exp.getSize());
  // use reset to make them the same. reset preserves
  // the underlying FP value (adjusting the exp to account for
  // changes in the mantissa).
  r_true.reset(expSize, mantissaSize);
  r_false.reset(expSize, mantissaSize);
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

inline static int getBitSize(int64_t a)
{
  int i;
  int64_t topBit = a&(1ULL<<63);
  for(i=62; i > 4; i--) {
    if (topBit != a&(1ULL<<i)) {
      return i+2;
    }
  }
  return 5; // encode at least 5 bits;
}

static inline int getExpBitSize(shemaxfloat_t d)
{
    int exp;
    if (!std::isfinite(d)) { return 5;} // something minimal
    (void) shemaxfloat_frexp(d,&exp);
    return getBitSize(exp);
}

// we probably should pick Mantissa from the precision of
// the inputed mantissa, capping it based on the exponent
static inline int guessMantissaFromExp(int expSize)
{
  if (expSize <= 5) {
    //halffloat/float16
    return 16-expSize;
  }
  if (expSize <= 8) {
    //float/float32
    return 32-expSize;
  }
  if (expSize <= 11) {
    //double/float64
    return 64-expSize;
  }
  if (expSize <= 15) {
    //long double/float128
    return 128 - expSize;
  }
  // greater than our largest known exponent,
  // This shouldn't happen, if it does, use
  // a maximal mantissa
  return 128;
}

SHEFp select(const SHEInt &sel, shemaxfloat_t a_true, shemaxfloat_t a_false)
{
  int expSize = std::max(getExpBitSize(a_true),getExpBitSize(a_false));
  int mantissaSize = guessMantissaFromExp(expSize);
  SHEFp result(sel.getPublicKey(), 0.0, expSize, mantissaSize);
  SHEFp r_true(result, a_true);
  SHEFp r_false(result, a_false);
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

SHEBool SHEFp::isFinite(void) const
{
  return !isSpecial();
}

SHEBool SHEFp::isNormal(void) const
{
  return !isSpecial() && exp.isNotZero();
}

SHEBool SHEFp::rawGT(const SHEFp &a) const
{
  if (log) {
    (*log) << (SHEFpSummary)*this << ">" << (SHEFpSummary)a << "="
           << std::flush;
  }
  SHEBool signGt = sign < a.sign; // zero is greater than 1 for sign
  SHEBool signEq = sign == a.sign;
  SHEBool expGt = signEq && (exp > a.exp);
  SHEBool mantissaGt = signEq && (exp ==  a.exp) && (mantissa > a.mantissa);
  SHEBool result = signGt || expGt || mantissaGt;
  result ^= (signEq && sign); // if we are both negative,
                              // flip the compare

  if (log) { (*log) << (SHEIntSummary)result << std::endl; }
  return result;
}

SHEBool SHEFp::rawGE(const SHEFp &a) const
{
  return !a.rawGT(*this);
}

SHEBool SHEFp::operator>(const SHEFp &a) const
{
  SHEBool notNan = !(isNan() || a.isNan());
  SHEBool bothZero = (isZero() && a.isZero());
  return notNan && !bothZero && rawGT(a);
}

SHEBool SHEFp::operator<(const SHEFp &a) const
{
  SHEBool notNan = !(isNan() || a.isNan());
  SHEBool bothZero = (isZero() && a.isZero());
  return notNan && !bothZero && a.rawGT(*this);
}

SHEBool SHEFp::operator>=(const SHEFp &a) const
{
  SHEBool notNan = !(isNan() || a.isNan());
  SHEBool bothZero = (isZero() && a.isZero());
  return bothZero || (notNan && rawGE(a));
}

SHEBool SHEFp::operator<=(const SHEFp &a) const
{
  SHEBool notNan = !(isNan() || a.isNan());
  SHEBool bothZero = (isZero() && a.isZero());
  return bothZero || (notNan && a.rawGE(*this));
}

SHEBool SHEFp::operator!=(const SHEFp &a) const
{
  SHEBool isEitherNan = (isNan() || a.isNan());
  SHEBool bothZero = (isZero() && a.isZero());

  return !bothZero && (isEitherNan || (sign != a.sign) ||
         (exp != a.exp) || (mantissa != a.mantissa));
}

SHEBool SHEFp::operator==(const SHEFp &a) const
{
  SHEBool notNan = !(isNan() || a.isNan());
  SHEBool bothZero = (isZero() && a.isZero());
  return bothZero || (notNan && (sign == a.sign) &&
         (exp == a.exp) && (mantissa == a.mantissa));
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

SHEBool SHEFp::operator!=(shemaxfloat_t a) const
{
    SHEFp heA(*this, a);
    return *this != heA;
}

SHEBool SHEFp::operator==(shemaxfloat_t a) const
{
    SHEFp heA(*this, a);
    return *this != heA;
}
