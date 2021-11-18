
//
// int wrapper for SHELib which operates on various integers
//
#ifndef SHEFp_H_
#define SHEFp_H_ 1
#include "SHEInt.h"
//
// this class uses the SHEInt class to implement encrypted floating
// point operations. Like SHEInt, SHEFp is a general class with
// subclasses implementing specific sizes emulation existing
// 'native' floating point implementations.

#if !defined(SHEFP_ENABLE_LONG_DOUBLE) || defined(__NO_LONG_DOUBLE_MATH)
typedef double shemaxfloat_t;
#define shemaxfloat_frexp(x,y) frexp(x,y)
#define shemaxfloat_pow(x,y) pow(x,y)
#define shemaxfloat_abs(x) fabs(x)
#define shemaxfloat_log(x) log(x)
#define shemaxfloat_sin(x) sin(x)
#define SHEFP_SNAN SNAN
#define SHEFP_USE_DOUBLE 1
#undef SHEFP_USE_LONG_DOUBLE
#else
typedef long double shemaxfloat_t;
#define shemaxfloat_frexp(x,y) frexpl(x,y)
#define shemaxfloat_pow(x,y) powl(x,y)
#define shemaxfloat_abs(x) fabsl(x)
#define shemaxfloat_log(x) logl(x)
#define shemaxfloat_sin(x) sinl(x)
#define SHEFP_SNAN SNANL
#define SHEFP_USE_LONG_DOUBLE 1
#undef SHEFP_USE_DOUBLE
#endif


class SHEFp;
typedef std::unordered_map<const SHEFp *,const char *>SHEFpLabelHash;

class SHEFp {
private:
  friend class SHEFpSummary;
#ifdef DEBUG
  static SHEPrivateKey *debugPrivKey; // set for debugging
#endif
  static std::ostream *log;
  static uint64_t nextTmp;
  static SHEFpLabelHash labelHash;
  SHEInt sign;
  SHEInt exp;
  SHEInt mantissa;
  char labelBuf[SHEINT_MAX_LABEL_SIZE];
  // helper
  // setNextLabel lies about const since it's basically a caching function
  const char *setNextLabel(void) const { uint64_t current=nextTmp++;
    snprintf((char *)&labelBuf[0], sizeof(labelBuf), "t%d",current);
    labelHash[this]=labelBuf;
    return labelBuf;
  }

protected:
  SHEFp(const SHEPublicKey &pubkey, const unsigned char *encryptedInt,
         int size, const char *label=nullptr);
  // used so the parent can reset the bit sizes to the proper native values to
  // those of the child class.
  virtual void resetNative(void) const { } // parent has no native values
  void denormalize(const SHEInt &targetexp);
  // raw GT comparison that ignores Nans
  SHEBool rawGT(const SHEFp &a) const;
  SHEBool rawGE(const SHEFp &a) const;

public:
   static constexpr std::string_view typeName = "SHEFp";
  ~SHEFp(void) { labelHash.erase(this); }
  // copy operators
  SHEFp(const SHEPublicKey &pubkey, shemaxfloat_t val,
        int expSize, int mantissaSize, const char *label=nullptr);
  SHEFp(const SHEPublicKey &pubkey) :
        sign(pubkey), exp(pubkey), mantissa(pubkey) { resetNative(); }
  SHEFp(const SHEFp &a, const char *label) :
     sign(a.sign), exp(a.exp), mantissa(a.mantissa)
  { if (label) { labelHash[this] = label; } }
  SHEFp(const SHEFp &a) :
     sign(a.sign), exp(a.exp), mantissa(a.mantissa)  {}
  SHEFp &operator=(const SHEFp &a)
  { sign = a.sign;
    exp = a.exp;
    mantissa = a.mantissa;
    resetNative();
    return *this;
  }
  // SHEInt->SHEFp casts
  SHEFp(const SHEInt &a, const char *label=nullptr);
  SHEFp(const SHEFp &model, const SHEInt &a, const char *label=nullptr);
  // this cast lets us set the Bit size we are casting to.
  SHEInt toSHEInt(int bitSize=0, bool isUnsigned=false) const;
  // Allow casting to SHEInt, but no implicit casts. Allowing explicit
  // casts could cause issues with operator overloading of select, so
  // SHEBool(x).select(SHEFp,SHEFp) would try to use
  // SHEBool(x).select(SHEInt,SHEInt), producing the wrong result.
  // with explicit the former will generate a compilier error, and the code
  // could the be changes to use SHEFpBool(x).select or
  // select(bool, SHEFp,SHEFp).
  explicit operator SHEInt() { return toSHEInt(); }
  explicit operator SHEInt64() { return toSHEInt(64); }
  explicit operator SHEInt32() { return toSHEInt(32); }
  explicit operator SHEInt16() { return toSHEInt(16); }
  explicit operator SHEInt8() { return toSHEInt(8); }
  explicit operator SHEUInt64() { return toSHEInt(64, true); }
  explicit operator SHEUInt32() { return toSHEInt(32, true); }
  explicit operator SHEUInt16() { return toSHEInt(16, true); }
  explicit operator SHEUInt8() { return toSHEInt(8, true); }
  SHEFp &operator=(shemaxfloat_t val)
  { SHEFp a(*this, val);
    *this = a;
    return *this;
  }

  // create a SHEFp using the context and size of a module SHEFp
  SHEFp(const SHEFp &model, shemaxfloat_t a, const char *label=nullptr);
  // read an int from the stream
  SHEFp(const SHEPublicKey &pubkey, std::istream &str,
         const char *label=nullptr);
  void normalize(void);
  // arithmetic operators
  SHEFp operator-(void) const;
  SHEFp abs(void) const;
  SHEFp operator+(const SHEFp &a) const;
  SHEFp operator-(const SHEFp &a) const;
  SHEFp operator*(const SHEFp &a) const;
  SHEFp operator/(const SHEFp &a) const;
  SHEFp operator+(shemaxfloat_t a) const;
  SHEFp operator-(shemaxfloat_t a) const;
  SHEFp operator*(shemaxfloat_t a) const;
  SHEFp operator/(shemaxfloat_t a) const;
  SHEFp &operator+=(const SHEFp &a);
  SHEFp &operator-=(const SHEFp &a);
  SHEFp &operator*=(const SHEFp &a);
  SHEFp &operator/=(const SHEFp &a);
  SHEFp &operator+=(shemaxfloat_t a);
  SHEFp &operator-=(shemaxfloat_t a);
  SHEFp &operator*=(shemaxfloat_t a);
  SHEFp &operator/=(shemaxfloat_t a);
  SHEFp &operator++(void);
  SHEFp &operator--(void);
  SHEFp operator++(int);
  SHEFp operator--(int);
  // logical operators
  // these return either an encrypted 1 or an encrypted 0
  // the results can't be directly checked in an if, they
  // can only affect the output a a select call.
  SHEBool operator!(void) const;
  SHEBool operator<(const SHEFp &a) const;
  SHEBool operator>(const SHEFp &a) const;
  SHEBool operator>=(const SHEFp &a) const;
  SHEBool operator<=(const SHEFp &a) const;
  SHEBool operator!=(const SHEFp &a) const;
  SHEBool operator==(const SHEFp &a) const;
  SHEBool operator<(shemaxfloat_t) const;
  SHEBool operator>(shemaxfloat_t) const;
  SHEBool operator>=(shemaxfloat_t) const;
  SHEBool operator<=(shemaxfloat_t) const;
  SHEBool operator!=(shemaxfloat_t) const;
  SHEBool operator==(shemaxfloat_t) const;
  SHEBool isZero(void) const;
  SHEBool isNotZero(void) const;
  SHEBool isNegative(void) const;
  SHEBool isPositive(void) const;
  SHEBool isSpecial(void) const;
  // use the same names as math.h
  SHEBool isNan(void) const;
  SHEBool isInf(void) const;
  SHEBool isNormal(void) const;
  SHEBool isFinite(void) const;
  // return fraction or integer parts only
  SHEFp trunc(void) const;
  SHEFp fract(void) const;
  SHEBool hasFract(void) const;

  // Operatator ? : can't be overridden,
  // so a?b:c becomes a.select(b,c)
  // handle all flavors where b and c are random mix of unencrypted
  // and encrypted values.
  friend SHEFp select(const SHEInt &b, const SHEFp &a_true,
                      const SHEFp &a_false);
  friend SHEFp select(const SHEInt &b, const SHEFp &a_true,
                      shemaxfloat_t a_false);
  friend SHEFp select(const SHEInt &b, shemaxfloat_t a_true,
                      const SHEFp &a_false);
  friend SHEFp select(const SHEInt &b, shemaxfloat_t a_true,
                      shemaxfloat_t a_false);

  // Accessor functions
  const SHEInt &getSign(void) const { return sign; }
  const SHEInt &getExp(void) const { return exp; }
  const SHEInt &getMantissa(void) const { return mantissa; }
  SHEInt getUnbiasedExp(void) const ;
  void setUnbiasedExp(int64_t);
  void setUnbiasedExp(const SHEInt &);
  void setSign(const SHEInt &sign_)
  { sign = sign_; sign.reset(1,true); }
  void setExp(const SHEInt &exp_)
  { exp = exp_; resetNative(); }
  void setMantissa(const SHEInt &mantissa_)
  { mantissa = mantissa_; resetNative(); normalize(); }
  const char *getLabel(void) const
  {const char *label = labelHash[this];
   if (label) return label;
   return setNextLabel(); }
  // switch size and signedness
  void reset(int newExpSize, int newMatissaSize);
  void clear(void) { sign.clear(); exp.clear(); mantissa.clear(); }
  // get ranges of the current fp
  // getMax() returns the larget value that can be represented by this float
  // getMin() returs the value closest to zero hat can be represented by
  // this float. both values are positive.
  shemaxfloat_t getMax() const;
  shemaxfloat_t getMin() const;

  // get the decrypted result given the private key
  shemaxfloat_t decryptRaw(const SHEPrivateKey &privKey) const;
  // bootstrapping help
  long bitCapacity(void) const
  { long capacity = sign.bitCapacity();
    capacity = std::min(capacity, exp.bitCapacity());
    return std::min(capacity, mantissa.bitCapacity());
  }
  double securityLevel(void) const;
  bool isCorrect(void) const;
  bool needRecrypt(long level=SHEINT_DEFAULT_LEVEL_TRIGGER) const;
  bool needRecrypt(const SHEFp &a,
                   long level=SHEINT_DEFAULT_LEVEL_TRIGGER) const;
  void verifyArgs(long level=SHEINT_DEFAULT_LEVEL_TRIGGER);
  void verifyArgs(SHEFp &a, long level=SHEINT_DEFAULT_LEVEL_TRIGGER);
  void reCrypt(bool force=false);
  void reCrypt(SHEFp &a, bool force=false);

#ifdef DEBUG
  static void setDebugPrivateKey(SHEPrivateKey &privKey)
    { debugPrivKey = &privKey; }
#endif
  static void setLog(std::ostream &str) { log = &str; }

  // input/output functions
  // use helib standard intput, outputs methods
  void writeTo(std::ostream& str) const;
  void writeToJSON(std::ostream& str) const;
  helib::JsonWrapper writeToJSON(void) const;
  static SHEFp readFrom(std::istream& str, const SHEPublicKey &pubKey);
  static SHEFp readFromJSON(std::istream& str, const SHEPublicKey &pubKey);
  static SHEFp readFromJSON(const helib::JsonWrapper& j, const SHEPublicKey &pubKey);
  void read(std::istream& str);
  void readFromJSON(std::istream&str);
  void readFromJSON(const helib::JsonWrapper &jw);
  void readJSON(const helib::JsonWrapper &jw) { readFromJSON(jw); }

  // give a simple import/export function as well
  unsigned char *flatten(int &size, bool ascii) const;
};

class SHEFpSummary
{
private:
   const SHEFp &shefp;
#ifdef DEBUG
   const SHEPrivateKey *getPrivateKey(void) const
         { return SHEFp::debugPrivKey; }
#endif
public:
   SHEFpSummary(const SHEFpSummary &summary) : shefp(summary.shefp) {}
   SHEFpSummary(const SHEFp &shefp_) : shefp(shefp_) {}
   friend std::ostream &operator<<(std::ostream&, const SHEFpSummary&);
};


// overload integer(unencrypted) [op] SHEFp, so we get the same results
// even if we swap the unencrypted and encrypted values. We can implent most
// of them using either communitive values, or communitive identities
inline SHEFp operator+(shemaxfloat_t a, const SHEFp &b) { return b+a; }
inline SHEFp operator-(shemaxfloat_t a, const SHEFp &b) { return (-b)+a; }
inline SHEFp operator*(shemaxfloat_t a, const SHEFp &b) { return b*a; }
inline SHEBool operator>(shemaxfloat_t a, const SHEFp &b) { return b < a; }
inline SHEBool operator<(shemaxfloat_t a, const SHEFp &b) { return b > a; }
inline SHEBool operator>=(shemaxfloat_t a, const SHEFp &b) { return b <= a; }
inline SHEBool operator<=(shemaxfloat_t a, const SHEFp &b) { return b >= a; }
inline SHEBool operator!=(shemaxfloat_t a, const SHEFp &b) { return b != a; }
inline SHEBool operator==(shemaxfloat_t a, const SHEFp &b) { return b == a; }
// these operators can't easily commute, we implement
// them by explicit casts to SHEFp
inline SHEFp operator/(shemaxfloat_t a, const SHEFp &b)
       { SHEFp heA(b, a); return heA/b; }
// io operators. uses public functions, do no need a friend declaration
std::istream&operator>>(std::istream&, SHEFp &a);
std::ostream&operator<<(std::ostream&, const SHEFp &a);
// declare where SHEFpBool can see them..
SHEFp select(const SHEInt &b, const SHEFp &a_true, const SHEFp &a_false);
SHEFp select(const SHEInt &b, const SHEFp &a_true, shemaxfloat_t a_false);
SHEFp select(const SHEInt &b, shemaxfloat_t a_true, const SHEFp &a_false);
SHEFp select(const SHEInt &b, shemaxfloat_t a_true, shemaxfloat_t a_false);
// fetch from an array based on an encrypted index
inline SHEFp getArray(const SHEFp &_default, shemaxfloat_t *a,  int size,
                      const SHEInt &index)
{
  SHEFp retVal(_default);
  for (int i=0; i < size; i++) {
    retVal = select(i == index, a[i], retVal);
  }
  return retVal;
}

inline SHEFp getVector(const SHEFp &_default,
                       const std::vector<shemaxfloat_t> &a,
                       const SHEInt &index)
{
  SHEFp retVal(_default);
  for (int i=0; i < a.size(); i++) {
    retVal = select(i == index, a[i], retVal);
  }
  return retVal;
}


// allow SHEBool.select(SHEFp, SHEFp) output
class SHEFpBool : public SHEInt {
public:
  SHEFpBool(const SHEInt &a) : SHEInt(a) {}
  SHEFpBool(const SHEBool &a) : SHEInt(a) {}
  SHEFp select(const SHEFp &a_true, const SHEFp &a_false) const
  {
    const SHEInt &narrow = *this;
    return ::select(narrow, a_true, a_false);
  }
  SHEFp select(const SHEFp &a_true, shemaxfloat_t a_false) const
  {
    const SHEInt &narrow = *this;
    return ::select(narrow, a_true, a_false);
  }
  SHEFp select(shemaxfloat_t a_true, const SHEFp &a_false) const
  {
    const SHEInt &narrow = *this;
    return ::select(narrow, a_true, a_false);
  }
  SHEFp select(shemaxfloat_t a_true, shemaxfloat_t a_false) const
  {
    const SHEInt &narrow = *this;
    return ::select(narrow, a_true, a_false);
  }
};

// now define the various native types
// would the be better as a template?
#define NEW_FP_CLASS(name, type, expSize, mantissaSize) \
class name : public SHEFp { \
protected:           \
    virtual void resetNative(void)  { reset(expSize, mantissaSize); } \
public:              \
    static constexpr std::string_view typeName = #name; \
    name(const SHEPublicKey &pubKey, const char *label_=nullptr) : \
      SHEFp(pubKey, (shemaxfloat_t)0.0, expSize, mantissaSize, label_) {} \
    name(const SHEPublicKey &pubKey, \
         const unsigned char *encryptedInt, int dataSize, \
         const char *label_=nullptr) : \
            SHEFp(pubKey, encryptedInt, dataSize, label_) { resetNative(); } \
    name(const SHEPublicKey &pubKey, type myfloat, const char *label_=nullptr):\
            SHEFp(pubKey, (shemaxfloat_t)myfloat, expSize, mantissaSize, label_) {} \
    name(const SHEFp &a, const char *label_) : SHEFp(a, label_) \
            { resetNative(); } \
    name(const SHEFp &a) : SHEFp(a) { resetNative(); } \
    name(const SHEFp &model, type a, const char *label_=nullptr) \
         : SHEFp(model, (shemaxfloat_t)a, label_) \
            { resetNative(); } \
    name &operator=(type a) \
             { SHEFp a_(*this,(shemaxfloat_t)a); return *this=a_; } \
    type decrypt(const SHEPrivateKey &privKey) const  \
            { return (type) decryptRaw(privKey); }; \
}; \
//inline name operator[](const std::vector<type> &a,  const SHEInt &index) \
//{ \
//  name retVal(index.getPublicKey(), 0.0); \
//  for (int i=0; i < a.size; i++) { \
//    retVal = select(i == index, a[i], retVal); \
//  } \
//  return retVal; \
//}

// define classes for the various float types.
// halfFlaot anb BFloat16 don't have native types,
// we return them in a full float. ExtendedFloat
// or IEEE long Double may be the native type of
// long double if supported, we return what we can
// on the platform, but the underlying type uses full
// presision of that type
#if __HAVE_FLOAT16
typedef _Float16 shefloat16_t;
# else
typedef float shefloat16_t;
#endif
#if __HAVE_BFLOAT16
typedef bfloat16 shebfloat16_t;
#else
typedef float shebfloat16_t;
#endif
#if _HAVE_FLOAT32
typedef _Float32 shefloat32_t;
#else
typedef float shefloat32_t;
#endif
#if _HAVE_FLAT64
typedef _Float64 shefloat64_t;
#else
typedef double shefloat64_t;
#endif
#if _HAVE_FLOAT128
typedef _Float128 shefloat128_t;
#else
typedef shemaxfloat_t shefloat128_t;
#endif

// NOTE: mantissa is 2 greater than the natural format.
// 1) SHEFp keeps the implicit high bit explicitly.
// The cost of recontructing it and removing it isn't
// worth the space savings.
// 2) We carry one extra bit of precision to mimic the
// internal percision of the Intel FP engin
NEW_FP_CLASS(SHEHalfFloat,     shefloat16_t,   5,  12)
NEW_FP_CLASS(SHEBFloat16,      shebfloat16_t,  8,   9)
NEW_FP_CLASS(SHEFloat,         shefloat32_t,   8,  25)
NEW_FP_CLASS(SHEDouble,        shefloat64_t,  11,  54)
NEW_FP_CLASS(SHEExtendedFloat, shefloat128_t, 15,  66)
NEW_FP_CLASS(SHELongDouble,    shefloat128_t, 15, 114)

#endif
