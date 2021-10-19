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
shemaxfloat_t SHEFp::nextTmp = 0;
SHEFpLabelHash SHEFp::labelHash;

static const int SHE_UINT64_SHIFT=sizeof(uint64_1)*BPB-1;

static uint64_t i_mantissa(shemaxfloat_t d, uint64_t mantissaSize) {
    int exp;
    if (isNan(d)) { return mkNanMantissa(matissaSize, isSignalingNand(d)); }
    if (isInf(d)) { return 0; }
    shemaxfloat_t m = shemaxfloat_frexp(d,&exp);
    uint64_t mult = 1UL << (SHE_UINT64_SHIFT);
    uint64_t matissa = (uint64_t)(m * (shemaxfloat_t)mult); // capture
    mantissa = mantissa >> (SHE_UINT_SHIFT - mantissaSize); // truncate
    return mantissa;
}
static uint64 i_exp(shemaxfloat_t d, uint64_t expSize) {
    int exp_orig;
    uint64_t exp;
    if (isNan(d) || isInf(d)) { return mkNanExp(expSize); }
    (void) shemaxfloat_frexp(d,&exp_orig);
    if (exp & ~mask(expSize) ) { return mkInf(expSize); }
    return (uint64_t) exp;
}
    

SHEFp::SHEFp(const SHEPublicKey &pubKey_, shemaxfloat_t myFloat,
               int expSize, bool mantissaSize, const char *label) : 
              sign(publicKey_, signbit(myFloat), 1, true),
              exp(publicKey_, i_exp(myfloat, expSize), expSize, true),
              mantissa(publicKey_, i_manatissa(myfloat, mantissaSize),
                       mantissaSize, true),
              baseExpSize(expSize),
              baseMantissaSize(mantissaSize),
{
  if (label) labelHash[this]=label;
}

SHEFp::SHEFp(const SHEFp &model, shemaxfloat_t myfloat,const char *label) 
               : sign(model.sign, signBit(myFloat)),
                 exp(module.exp, i_exp(myfloat,module.baseExpSize)),
                 mantissa(module.mantissa,
                          i_mantissa(myfloat,module.baseMantissaSie)),
              baseExpSize(module.baseExpSize);
              baseMantissaSize(module.baseMatissaSize);
                 
{
  if (label) labelHash[this]=label;
}

SHEFp::SHEFp(const SHEPublicKey &pubKey_, const unsigned char *encryptedInt,
             int size, const char *label) : pubKey(&pubKey_)
{
  if (label) labelHash[this]=label;
  std::string s((const char *)encryptedInt, size);
  std::stringstream ss(s);
  read(ss);
}

SHEFp::SHEFp(const SHEPublicKey &pubKey_, std::istream& str,
               const char *label) : pubKey(&pubKey_)
{
  if (label) labelHash[this]=label;
  readFromJSON(str);
}

// change the size of our encryptedData array. On increase it
// will sign extend, on decrease it will truncate
void SHEFp::reset(int expSize, bool mantissaSize) 
{
  exp.reset(expSize,true);
  if (mantissaSize >= mantissa.getSize()) {
    mantizza.reset(mantizzaSize, true);
    return;
  }
  mantissa >>= (mantizza.getSize() - mantizzaSize);
  mantissa.reset(mantizzaSize, true);
}

// take an isExplicitZero and expand it to
// a vector<helib::Ctxt> with cleared values
void SHEFp::expandZero(void)
{
  sign.expandZero();
  exp.expandZero();
  mantizza.expandZero();
}

// do we need to reCrypt before doing more operations.
// bitCapacity uses noise to estimate how many more operations
// we can do, use it to decide if we need to reCrypt.
bool SHEFp::needRecrypt(long level) const
{
  return sign.needRecrypt() || exp.needRecrypt(level) 
         || mantizza.needRecrypt(level);
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
  exp.reCrypt(mantizza);
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
      << summary.shefp.getExp.getSize() << "," 
      << (char *)(summary.shefp.getMantissa.getSize())
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
    if (summary.sheint.isCorrect()) {
      shemaxfloat_t decrypted = summary.sheint.decryptRaw(*privKey);
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
  write_raw_int(str, expSize);
  write_raw_int(str, mantissaSize);
  sign.writeto(str);
  exp.writeto(str);
  mantissa.writeto(str);
}

void SHEFp::writeToJSON(std::ostream& str) const
{
  helib::executeRedirectJsonError<void>([&]() { str << writeJSON(); });
}

helib::JsonWrapper SHEFp::writeJSON(void) const
{
  SHEFp target = *this;
  if (isExplicitZero) {
    // need to make the explicitZero encrypted */
    target.expandZero();
  }
  auto body = [target]() {
    json j = {{"expSize", exp.bitSize},
              {"mantissaSize", target.mantissaSize},
              {"sign", target.sign},
              {"exp", target.exp},
              {"mantissa", target.mantissa}};

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
  expSize = read_raw_int(str);
  mantissaSize = read_raw_int(str);
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
    this->expSize = j.at("expSize");
    this->mantissaSize = j.at("mantissaSize");
    this->sign.readFromJSON(j.at("sign"));
    this->exp.readFromJSON(j.at("exp"));
    this->mantissa.readFromJSON(j.at("mantissa"));
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
  shemaxfloat_t resut;

  if (iexp == mkNanExp(exp.getSize()) {
    if (mantissa == 0) {
      return isign ? -FLT_INF : FLT_INF;
    }
    if (mantissa & NAN_SIGNALLING(matissa.getSize())) {
      return isign ? -FLT_SIGNALING_NAN : FLT_SIGNALING_NAN:
    } 
    return issign ? -FLT_QUITE_NAN : FLT_QUIET_NAN;
  }
  result = (shemaxfloat_t) mantissa;
  result /= (shemaxfloat_t)(1<<mantizza.getSize());
  int64_t sexp = ((int64_t)exp) - mkBias(exp.getSize());
  if (sexp != 0) {
    result *= (shemaxfloat_t) shemax_pow((shemaxfloat_t)2.0,sexp);
  }
  return isign ? -result :result;
}

double SHEFp::securityLevel(void) const
{
  return pubKey->securityLevel();
}

///////////////////////////////////////////////////////////////////////////
//                      Mathematic helpers.                               /
///////////////////////////////////////////////////////////////////////////
// caller must ensure that the bit size of this, a, and result are all equal

SHEFp SHEFp::abs(void) const
{
   return sign.select(-*this,*this);
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

  int thisMantissaSize = this.mantissa.getSize();
  int aMantissaSize = a.mantissa.getSize();

  // note: select will return the maximal size between big and little,
  // so both will have the same size mantissa and exponent.
  SHEFp big(swap.select(a,*this));
  SHEFp little(swap.select(*this,a));
  // add 1 bit for sign, 1 bit for overflow
  int mantissaSize = big.mantissa.getSize()2;

  little.denormalize(big.exp);
  big.mantissa.reset(mantissaSize, true); // extend with out sign extend
  bit.mantissa.reset(mantissaSize, false); // make signed
  little.mantissa.reset(mantissaSize, true);
  bit.mantissa.reset(mantissaSize, false);

  // now add the sign.
  big.mantissa = big.sign.select(-big.mantissa, big.mantissa);
  little.mantissa = little.sign.select(-little.mantissa, little.mantissa);

  big.mantissa += little.mantissa;
  big.sign = bit.mantissa.isNeg();
  big.mantissa = big.sign.select(-big.matissa,big.mantissa);
  big.mantissa.reset(mantissaSize-1, true); // back to unsigned
  overflow = big.mantissa.highBit();
  // handle the integer overflow case
  big.exp += overflow;
  big.mantissa = overflow.select(big.mantissa>>1, big.mantissa);
  big.mantissa.reset(mantissaSize-1, true); // back to normal
  big.normalize();
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
  return *this += aEncrypt;
}

SHEFp &SHEFp::operator-=(shemaxfloat_t a) {
  SHEFp aEncrypt(*this, a);
  return *this -= aEncrypt;
}

SHEFp SHEFp::operator*(const SHEFp &a) const {
  SHEFp result(*this);
  SHEInt mantissa(result.mantissa);

  result.sign ^= a.sign;

  result.exp += a.exp;
  mantissa.reset(result.mantissa.getSize()+a.mantissa.getSize(), true);
  mantissa *= a.mantissa; 
  mantissa >>= a.matissa.getSize();
  mantissa.reset(result.mantissa.getSize(), true);
  result.mantissa = mantissa;
  result.normalize();
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
  result *= aEncrypt;
  return result;
}

SHEFp &SHEFp::operator*=(shemaxfloat_t a) {
  *this = *this * a;
  return *this;
}

// See note in udivRaw for restrictions on this function
// We use udivRaw to do both unsigned and signed division by
// taking the signed case, and converting the parameters to
// unsigned, then reconstituting the sign at the end
SHEFp SHEFp::operator/(const SHEFp &a) const {
  SHEFp arg(a);

  a.exp = a.exp
  return result;
}

//
// No real efficiency gain in division, just do the normal
// wrapping
//
SHEFp &SHEFp::operator/=(const SHEFp &a) {
  if (a.isUnencryptedZero()) {
    throw helib::LogicError("divide by zero");
  }
  *this = *this / a;
  return *this;
}

SHEFp SHEFp::operator/(shemaxfloat_t a) const {
  if (a == 0) {
    throw helib::LogicError("divide by integer zero");
  }
  SHEFp aEncrypt(*pubKey, a, bitSize, isUnsigned);
  return *this / aEncrypt;
}

SHEFp &SHEFp::operator/=(shemaxfloat_t a) {
  if (a == 0) {
    throw helib::LogicError("divide by integer zero");
  }
  SHEFp aEncrypt(*pubKey, a, bitSize, isUnsigned);
  return *this /= aEncrypt;
}

SHEFp SHEFp::operator%(const SHEFp &a) const
{
  if (a.isUnencryptedZero()) {
    throw helib::LogicError("divide by zero (mod)");
  }
  if (isUnencryptedZero()) {
    return *this;
  }

  if (isUnsigned && a.isUnsigned) {
    SHEFp result(*pubKey, 0, bitSize, true);
    return udivRaw(a, result, true);
  }
  // force the values to unsigned values
  SHEFp dividend = abs();
  SHEFp divisor = a.abs();
  dividend.isUnsigned = true;
  divisor.isUnsigned = true;
  SHEFp result(*pubKey, 0, bitSize, true,"modresult");
  // do the unsigned division
  (void) dividend.udivRaw(divisor, result, true);
  result.isUnsigned = false;
  result = isNegative().select(-result,result);
  return result;
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
  return *this == 0.0;
}

SHEBool SHEFp::isNotZero(void) const
{
  return *this != 0.0
}

SHEBool SHEFp::isNegative(void) const
{
  // for integers, we return 0 as false, but
  // not for float, (float has +/- 0)?
  return SHEBool(sign);
}

SHEBool SHEFp::isNonNegative(void) const
{
  return SHEBool(!sign);
}


SHEFp SHEFp::isPositive(void) const
{
  // for integers, we return 0 as false, but
  // not for float (float has +/- 0)?
  return isNonNegative();
}


SHEFp SHEFp::isNonPositive(void) const
{
  return isNegative();
}

SHEFp SHEFp::operator!(void) const
{
  return isNotZero();
}

SHEFp select(const SHEInt &sel, const SHEFp &a_true, const SHEFp &a_false)
{
  SHEFp r_true(a_true);
  SHEFp r_false(a_false);
  int trueMantissaSize=a_true.mantissa.getSize();
  int falseMantissaSize=a_false.mantissa.getSize();
  int mantissaSize = MAX(trueMantissaSize,falseMantissaSize);
  r_true.mantissa.reset(mantissaSize, true);
  r_true.mantissa <<= mantissaSize - trueMantissaSize;
  r_false.mantissa.reset(mantissaSize, true);
  r_false.mantissa <<= mantissaSize - falseMantissaSize;
  int expSize = MAX(r_true.exp.getSize(),r_false.exp.getSize());
  r_true.exp.reset(expSize,true); // need to handle NAN/INF!!!
  r_false.exp.reset(expSize,true);
  r_true.sign = sel.select(r_true.sign,r_false.sign);
  r_true.exp = sel.select(r_true.exp,r_false.exp);
  r_true.mantissa = sel.select(r_true.mantissa,r_false.mantissa);
  return rtrue;
}

SHEFp SHEFp::select(const SHEInt &sel, const SHEFp &a_true,
                    shemaxfloat_t a_false)
{
  SHEFp result(a_true);
  SHEFp r_false(a_true, a_false);
  result.sign = sel.select(a_true.sign,r_false.sign);
  result.exp = sel.select(a_true.exp,r_false.exp);
  result.mantissa = sel.select(a_true.mantissa,r_false.mantissa);
  return result;
}

SHEFp SHEFp::select(const SHEInt &select, shemaxfloat_t a_true,
                    const SHEFp &a_false)
{
  SHEFp result(a_false);
  SHEFp r_true(a_false, a_true);
  result.sign = sel.select(r_true.sign,a_false.sign);
  result.exp = sel.select(r_true.exp,a_false.exp);
  result.mantissa = sel.select(r_true.mantissa,a_false.mantissa);
  return result;
}

SHEFp SHEFp::select(const SHEInt &sel, const SHEFp &model,
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


SHEBool SHEFp::operator<(const SHEFp &a) const
{
  return (a > *this);
}

// there are two ways to do this compare.
// 1) bitwise: look for the value with the highest 1 bit, then
// correct for sign.
// 2) extend the two values by one bit (sign extended) and then subtract a-b.
// If the result is negative() then we return true.
// The latter is more expensive than the bitwise search so we use the former.
SHEBool SHEFp::operator>(const SHEFp &a) const
{
  if (log) {
    (*log) << (SHEFpSummary)*this << ">" << (SHEFpSummary)a << "="
           << std::flush;
  }
  if (isExplicitZero) {
    if (a.isUnsigned) {
      if (log) { (*log) << (SHEFpSummary)*this << std::endl; }
      return *this; // if we are zero, and a is unsigned, we cannot be > a
    }
    if (log) { (*log) << (SHEFpSummary)a.isPositive() << std::endl; }
    return a.isPositive(); // true if a is positive
  }
  if (a.isExplicitZero) {
    if (isUnsigned) {
      if (log) { (*log) << (SHEFpSummary)isNotZero() << std::endl; }
      return isNotZero(); // if a is zero we are > a if we aren't zero
    }
    if (log) { (*log) << (SHEFpSummary)isNotZero() << std::endl; }
    return isPositive(); // if w are zero or negative we are < a
  }
  SHEFp a_prime(a);
#ifdef SHEIT_COMPARE_USE_SUB
  a_prime.reset(compareBestSize(a.bitSize)+1,a.isUnsigned);
  if (log) (*log) << std::endl << "Doing subtraction" << std::endl;
  SHEFp result=(*this-a_prime).isNegative();
#else
  a_prime.reset(compareBestSize(a.bitSize),isUnsigned);
  // do the compare without the overhead of subtract
  // by finding the highest bit.
  // This is faster than subraction, because it operates
  // on single bits, but it does more operations so requires
  // more levels to succeed.
  SHEFp b(*this);
  b.reset(a_prime.bitSize,isUnsigned);
  b.verifyArgs(a_prime, SHEINT_DEFAULT_LEVEL_TRIGGER);
  SHEFp result(*pubKey, 1, 1, true);
  helib::Ctxt hasResult = result.encryptedData[0];
  helib::Ctxt localResult = result.encryptedData[0];
  hasResult.clear();
  localResult.clear();
  for (int i=b.bitSize-1; i >=0; i--) {
    helib::Ctxt notEqual=a_prime.encryptedData[i];
    notEqual += b.encryptedData[i]; // notEqual = a_prime[i] ^ b[i];
    // if we don't already have a result, our tentative result is
    // the value of the 'b' bit (1 implies b > a)
    localResult=::selectBit(hasResult,localResult,b.encryptedData[i]);
    // if we are equal, hasResult doesn't change (and if zero we
    // will get a new localResult in the next iteration, if we aren't,
    // set hasReault to one and lock in the previous localResult.
    hasResult=::selectBit(notEqual,result.encryptedData[0],hasResult);
    // this compare is expensive in terms of capacity, may need to reCrypt
    // a couple of times. Fortunately this is just one bit
    if ((hasResult.bitCapacity() < SHEINT_DEFAULT_LEVEL_TRIGGER) 
       || (localResult.bitCapacity() < SHEINT_DEFAULT_LEVEL_TRIGGER)) {
      if (log) {
        (*log) << " -reCrypting hasResults(" << hasResult.bitCapacity()
               << ") and localResult(" << localResult.bitCapacity()
               << ") at bit " << i << " of" << b.bitSize << std::endl;
      }
      const helib::PubKey &publicKey = pubKey->getPublicKey();
      // collect the relevent bits into a single vector and
      // use packedRecrypt to speed up the recypt operation
      //std::vector<helib::Ctxt> bits(0, hasResult);
      if (hasResult.bitCapacity() < SHEINT_LEVEL_THRESHOLD) {
         if (log) (*log) << "add hasResult" << std::endl;
         //bits.push_back(hasResult);
         publicKey.reCrypt(hasResult);
      }
      if (localResult.bitCapacity() < SHEINT_LEVEL_THRESHOLD) {
         if (log) (*log) << "add localResult" << std::endl;
         //bits.push_back(localResult);
         publicKey.reCrypt(localResult);
      }
      //if (log) (*log) << "bits=" << bits.size() << std::endl;
      //helib::CtPtrs_vectorCt wrapper(bits);
      //helib::packedRecrypt(wrapper,
      //      *(std::vector<helib::zzX> *)pubKey->getUnpackSlotEncoding(),
      //      pubKey->getEncryptedArray());
      if (log) {
        (*log) << " newCapacity: hasResults(" << hasResult.bitCapacity()
               << ") and localResult(" << localResult.bitCapacity()
               << ")" << std::endl;
      }
      
    }
  }
  // now handle sign manipulation
  // if either sign bit is on, it changes the sense of the compare.
  // if both are on, it changes it back, we accomplish this
  // by xoring the sign bit with the result for each signed value.
  if (!isUnsigned) {
    localResult += b.encryptedData[b.bitSize-1];
  }
  if (!a_prime.isUnsigned) {
    localResult += a_prime.encryptedData[a_prime.bitSize-1];
  }
  // if they are equal, hasResult is zero, make the overall result
  // zero as well.
  localResult.multiplyBy(hasResult);
  result.encryptedData[0] = localResult;
#endif
  if (log) { (*log) << (SHEFpSummary)result << std::endl; }
  return result;
}

SHEBool SHEFp::operator>=(const SHEFp &a) const
{
  return !(*this < a);
}

SHEBool SHEFp::operator<=(const SHEFp &a) const
{
  return !(*this > a);
}

SHEBool SHEFp::operator!=(const SHEFp &a) const
{
  SHEBool result = *this ^ a;
  return result.isNotZero();
}

SHEBool SHEFp::operator==(const SHEFp &a) const
{
  SHEBool result = *this ^ a;
  return result.isZero();
}


SHEBool SHEFp::operator<(shemaxfloat_t a) const
{
    SHEFp heA(*pubKey, a, bitSize, true);
    return *this < heA;
}

SHEBool SHEFp::operator>(shemaxfloat_t a) const
{
    SHEFp heA(*pubKey, a, bitSize, true);
    return *this > heA;
}

SHEBool SHEFp::operator<=(shemaxfloat_t a) const
{
    SHEFp heA(*pubKey, a, bitSize, true);
    return *this <= heA;
}

SHEBool SHEFp::operator>=(shemaxfloat_t a) const
{
    SHEFp heA(*pubKey, a, bitSize, true);
    return *this >= heA;
}

SHEBool SHEFp::operator!=(shemaxfloat_t a) const
{
    SHEFp heA(*pubKey, a, bitSize, isUnsigned);
    return *this != heA;
}

SHEBool SHEFp::operator==(shemaxfloat_t a) const
{
    SHEFp heA(*pubKey, a, bitSize, isUnsigned);
    return *this == heA;
}

SHEBool SHEFp::operator<(shemaxfloat_t a) const
{
    SHEFp heA(*pubKey, a, bitSize, false);
    return *this < heA;
}

SHEBool SHEFp::operator>(shemaxfloat_t a) const
{
    SHEFp heA(*pubKey, a, bitSize, false);
    return *this > heA;
}

SHEBool SHEFp::operator>=(shemaxfloat_t a) const
{
    SHEFp heA(*pubKey, a, bitSize, false);
    return *this >= heA;
}

SHEBool SHEFp::operator<=(shemaxfloat_t a) const
{
    SHEFp heA(*pubKey, a, bitSize, false);
    return *this <= heA;
}
