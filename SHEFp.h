
//
// int wrapper for SHELib which operates on various integers
//
#ifndef SHEFp_H_
#define SHEFp_H_ 1
#include "SHEInt.h"
//
// this class uses the SHEInt class to implement encrypted floating
// point operations. Like SHEInt, SHEFp is a general class with
// subclasses implementing specific sizes
//
//
//

#ifdef __NO_LONG_DOUBLE_MATH
typdef double shemaxfloat_t;
#define shemaxfloat_frexp(x,y) frexp(x,y)
#define shemaxfloat_pow(x,y) pow(x,y)
#else
typdef long double shemaxfloat_t;
#define shemaxfloat_frexp(x,y) frexpl(x,y)
#define shemaxfloat_pow(x,y) powl(x,y)
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
  int baseExpSize;
  int baseMantissaSize;
  char labelBuf[SHEINT_MAX_LABEL_SIZE];
  // helper
  // setNextLabel lies about const since it's basically a caching function
  const char *setNextLabel(void) const { uint64_t current=nextTmp++;
    snprintf((char *)&labelBuf[0], sizeof(labelBuf), "t%d",current);
    labelHash[this]=labelBuf;
    return labelBuf;
  }

protected:
  SHEFp(const SHEPublicKey &pubkey, shemaxfloat_t val,
        int expSize, int mantissaSize, const char *lable=nullptr);
  SHEFp(const SHEPublicKey &pubkey, const unsigned char *encryptedInt,
         int size, const char *label=nullptr);
  // used so the parent can reset the bit sizes to the proper native values to
  // those of the child class.
  virtual void resetNative(void) const { } // parent has no native values
  normalize(int expSize, int mantissaSize);

public:
   static constexpr std::string_view typeName = "SHEFp";
  ~SHEFp(void) { labelHash.erase(this); }
  // copy operators
  SHEFp(const SHEFp &a, const char *label) :
     sign(a.sign), exp(a.exp), mantissa(a.mantissa) 
  { if (label) { labelHash[this] = label; } }
  SHEFp(const SHEFp &a) :
     sign(a.sign), exp(a.exp), mantissa(a.mantissa)  {}
  SHEInt &operator=(const SHEFp &a)
  { sign = a.sign;
    exp = a.exp;
    mantissa = a.mantissa;
    resetNative();
    return *this;
  }
   
  // create a SHEInt using the context and size of a module SHEInt 
  SHEFp(const SHEFp &model, shemaxfloat_t a, const char *label=nullptr);
  SHEFp(const SHEInt &a, const char *label=nullptr);
  // read an int from the stream
  SHEFp(const SHEPublicKey &pubkey,std::istream &str,
         const char *label=nullptr);
  // arithmetic operators
  SHEFp operator-(void) const;
  SHEFp abs(void) const;
  SHEFp operator+(const SHEFp &a) const;
  SHEFp operator-(const SHEFp &a) const;
  SHEFp operator*(const SHEFp &a) const;
  SHEFp operator/(const SHEFp &a) const;
  SHEfp operator+(long shemaxfloat_t a) const;
  SHEfp operator-(long shemaxfloat_t a) const;
  SHEfp operator*(long shemaxfloat_t a) const;
  SHEfp operator/(long shemaxfloat_t a) const;
  SHEfp &operator+=(const SHEInt &a);
  SHEfp &operator-=(const SHEInt &a);
  SHEfp &operator*=(const SHEInt &a);
  SHEfp &operator/=(const SHEInt &a);
  SHEfp &operator+=(uint64_t a);
  SHEfp &operator-=(uint64_t a);
  SHEfp &operator*=(uint64_t a);
  SHEfp &operator/=(uint64_t a);
  SHEfp &operator++(void);
  SHEfp &operator--(void);
  SHEfp operator++(int);
  SHEfp operator--(int);
  // logical operators
  // these return either an encrypted 1 or an encrypted 0
  // the results can't be directly checked in an if, they
  // can only affect the output a a select call.
  SHEBool operator(void) const;
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
  SHEBool isNonNegative(void) const;
  SHEBool isPositive(void) const;
  SHEBool isNonPositive(void) const;
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
  friend SHEFp select(const SHEInt &b, const SHEFp &model,
                      shemaxfloat_t a_true, shemaxfloat_t a_false);
  // Accessor functions
  const SHEInt &getSign(void) const { return sign; }
  const SHEInt &getExp(void) const { return exp; }
  const SHEInt &getMantissa(void) const { return mantissa; }
  const char *getLabel(void) const 
  {const char *label = labelHash[this];
   if (label) return label;
   return setNextLabel(); }
  // switch size and signedness
  void reset(int newExpSize, int newMatissaSize);
  // get the decrypted result given the private key
  shemaxfloat_t decryptRaw(const SHEPrivateKey &privKey) const;
  // bootstrapping help
  long bitCapacity(void) const;
  double securityLevel(void) const;
  bool isCorrect(void) const;
  bool needRecrypt(long level=SHEINT_DEFAULT_LEVEL_TRIGGER) const;
  bool needRecrypt(const SHEInt &a,
                   long level=SHEINT_DEFAULT_LEVEL_TRIGGER) const;
  void verifyArgs(long level=SHEINT_DEFAULT_LEVEL_TRIGGER);
  void verifyArgs(SHEInt &a, long level=SHEINT_DEFAULT_LEVEL_TRIGGER);
  void reCrypt(void);
  void reCrypt(SHEInt &a);

#ifdef DEBUG
  static void setDebugPrivateKey(SHEPrivateKey &privKey) 
    { debugPrivKey = &privKey; }
#endif
  static void setLog(std::ostream &str) { log = &str; }

  // input/output functions
  // use helib standard intput, outputs methods
  void writeTo(std::ostream& str) const;
  void writeToJSON(std::ostream& str) const;
  helib::JsonWrapper writeJSON(void) const;
  static SHEFp readFrom(std::istream& str, const SHEPublicKey &pubKey);
  static SHEFp readFromJSON(std::istream& str, const SHEPublicKey &pubKey);
  static SHEFp readFromJSON(const helib::JsonWrapper& j, const SHEPublicKey &pubKey);
  void read(std::istream& str);
  void readFromJSON(std::istream&str);
  void readFromJSON(const helib::JsonWrapper &jw);

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
   SHEFpSummary(const SHEfp &shefp_) : shefp(shefp_) {}
   friend std::ostream &operator<<(std::ostream&, const SHEFpSummary&);
};


// overload integer(unencrypted) [op] SHEInt, so we get the same results
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

// now define the various native types
// would the be better as a template?
#define NEW_FP_CLASS(name, type, expSize, mantissaSize) \
class name : public SHEFp { \
protected:           \
    virtual void resetNative(void)  { reset(expSize, mantissaSize); } \
public:              \
    static constexpr std::string_view typeName = #name; \
    name(const SHEPublicKey &pubKey, const char *label_=nullptr) : \
      SHEFp(pubKey, (shemaxfloat_t)0.0, expSize, mattissaSize, label_) {} \
    name(const SHEPublicKey &pubKey, \
         const unsigned char *encryptedInt, int dataSize, \
         const char *label_=nullptr) : \
            SHEFp(pubKey, encryptedInt, dataSize, label_) { resetNative(); } \
    name(const SHEPublicKey &pubKey, type myfloat, const char *label_=nullptr):\
            SHEFp(pubKey, (shemaxfloat_t)myfloat, expSize, mattissaSize, label_) {} \
    name(const SHEFp &a, const char *label_) : SHEFp(a, label_) \
            { resetNative(); } \
    name(const SHEFp &a) : SHEFp(a) { resetNative(); } \
    name(const SHEFp &model, type a, const char *label_=nullptr) \
         : SHEFp(model, (shemaxfloat_t)a, label_) \
            { resetNative(); } \
    name &operator=(type a) \
             { SHEFp a_(*this,(shemaxfloat_t)a); return *this=a_; } \
    type decrypt(SHEPrivateKey &privKey)  \
            { return (type) decryptRaw(privKey); }; \
};

// define classes for the various float types.
// halfFlaot anb BFloat16 don't have native types,
// we return them in a full float. ExtendedFloat
// or IEEE long Double may be the native type of
// long double if supported, we return what we can
// on the platform, but the underlying type uses full
// presision of that type
#ifdef __HAVE_FLOAT16
typedef _Float16 shefloat16_t;
# else
typedef float shefloat16_1;
#endif
#ifdef __HAVE_BFLOAT16
typedef bfloat16 shebfloat16_t;
#else
typedef _float16 shebfloat16_t;
#endif
#ifdef _HAVE_FLOAT32
typedef _Float32 shefloat32_t;
#else
typedef float shefloat32_t;
#endif
#ifdef _HAVE_FLAT64
typedef _Float64 shefloat64_t
#else
typedef double shefloat64_t
#endif
#ifdef _HAVE-FLOAT128
typedef _Float128 shefloat128_t
#else
typedef shemaxfloat_t shefloat128_t
#endif

NEW_FP_CLASS(SHEHalfFloat,     shefloat16,     5,  10)
NEW_FP_CLASS(SHEBFloat16,      shebfloat16,    8,   7)
NEW_FP_CLASS(SHEFloat,         shefloat32_t,   8,  23)
NEW_FP_CLASS(SHEDouble,        shefloat64_t,  11,  52)
NEW_FP_CLASS(SHEExtendedFloat, shefloat128_t, 15,  64)
NEW_FP_CLASS(SHELongDouble,    shefloat128_t, 15, 112)
#endif
