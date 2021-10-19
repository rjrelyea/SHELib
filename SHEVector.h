//
// handle vector functions where the index
// is encrypted
//
#ifndef SHEVector_H_
#define SHEVector_H_ 1
#include <cstdint>
#include <iostream>
#include <helib/helib.h>
#include "SHEInt.h"

// T can be any class that is a target or source of a select
// function (SHEInt and subclasses, SHEString and subclasses, SHEFp and
// subclasses, etc.) 
template<class T>
class SHEVector : public std::vector<T>
{
private:
  T model;
public:
  SHEVector(const T &model_, const std::vector<T> &v) : vector(v),
            model(model_) { example.clear(); }
  SHEVector(const T &model_, int size) : vector(size), model(model_) 
           { model.clear(); }
  SHEVector(const <SHEVector> &a) : vector(a.vector), model(a.model) 
           { model.clear(); }
  // unlike the normal operator[], we can't return the reference
  // because we don't know it. This will trigger errors in programs
  // the try to set arrays. To add an element @ location you need to
  // use assign. NOTE: the normal in operator[](int) is still valid
  T operator[](const SHEInt &index) {
    return this->at(index);
  }
  // these functions to 'natural' bounds checking, in that we'll return
  // the value in the given slot, or an encrypted zero. Since the index and
  // the return value is encrypted, we don't know (only the user who later
  // decrypts the result will know
  T at(const SHEInt &index) {
    RT retVal(model);
    for (int i=0; i < this.size(); i++) {
      retVal = select((i == index),(*this)[i],retVal);
    }
    return retVal;
  }
  // if index is out of range, this will return none
  void assign(const SHEInt &index, const T &value)
  {
    for (int i=0; i < this.size(); i++) {
      (*this)[i] = (i == index).select(value, (*this)[i]);
    }
    return;
  }
};
    
  
  


//
// this class uses the helib binaryArthm interface to implement various
// homomorphic encrypted integer types. These classes create operators
// which allow you do your homomorphic operations as simple c++ operators.
//
// Each of the types, SHEInt64, SHEUint32, etc defines unsigned and signed
// fixed length integers. They are operated on using a generalized parent
// class, which can use any length integers (including greater than 64 bits).
//
// The encrypted data is made up of individually encrypted bits which either
// store an unsigned value, or a twos complement signed value. As such the
// underlying structure is visible to the implementor, so individual bits can
// be manipulated, whoever, except in conditions where our manipulation has
// explicitly cleared bits, the actual bit value of each encrypted bit is
// opaque to us. We can use those values to affect a new value which we output
// but can't examine the value itself directly.
//
// Logical operations return SHEBool values. SHEBool is an encrypted conditional
// result. We can use the select function on an SHEBool to choose between
// two results, but even if the input results are in the clear, the final
// result will be encrypted. This means we can't do things like:
//
//  SHEInt64 a(...)
//
//  if (a>5) {
//     printf("a>5"\n);
//  }
//  we can only logically do b=(a>5).select(1,2); which will asigned b to
//  SHEInt(a,1) if a>5 or SHEInt(a,2) if a <= 5; The only way to get an in the
//  clear result is to use the decrypt function, supplying the private key
//  (which isn most cases is unavailable).
//
//

class SHEInt;
typedef std::unordered_map<const SHEInt *,const char *>SHEIntLabelHash;

class SHEInt {
private:
  friend class SHEIntSummary;
#ifdef DEBUG
  static SHEPrivateKey *debugPrivKey; // set for debugging
#endif
  static std::ostream *log;
  static uint64_t nextTmp;
  static SHEIntLabelHash labelHash;
  const SHEPublicKey *pubKey;
  int bitSize;              // how may bits in our int
  bool isUnsigned;          // treat this as a 2's complement binary value
  bool isExplicitZero;      // is this zero (encryptedData not allocated)
  std::vector<helib::Ctxt> encryptedData;
  char labelBuf[SHEINT_MAX_LABEL_SIZE];
  // helper
  helib::Ctxt selectBit(const helib::Ctxt &trueBit,
                        const helib::Ctxt &falseBit) const;
  helib::Ctxt selectArrayBit(const SHEInt index,
                             const helib::Ctxt &defaultBit) const;
  int compareBestSize(int size) const;
  // math
  SHEInt &addRaw(const SHEInt &a, SHEInt &result) const;
  SHEInt &subRaw(const SHEInt &a, SHEInt &result) const;
  SHEInt &mulRaw(const SHEInt &a, SHEInt &result) const;
  SHEInt &udivRaw(const SHEInt &a, SHEInt &result, bool mod) const;
  // shifts
  void leftShift(uint64_t shift);
  void rightShift(uint64_t shift);
  SHEInt &leftShift(const SHEInt &shift, SHEInt &result) const;
  SHEInt &rightShift(const SHEInt &shift, SHEInt &result) const;
  uint64_t decryptBit(const SHEPrivateKey &privKey, helib::Ctxt &ctxt) const;
  // setNextLabel lies about const since it's basically a caching function
  const char *setNextLabel(void) const { uint64_t current=nextTmp++;
    snprintf((char *)&labelBuf[0], sizeof(labelBuf), "t%d",current);
    labelHash[this]=labelBuf;
    return labelBuf;
  }

protected:
  SHEInt(const SHEPublicKey &pubkey, uint64_t myInt,
         int bitSize, bool isUnsigned, const char *label=nullptr);
  SHEInt(const SHEPublicKey &pubkey, const unsigned char *encryptedInt,
         int size, const char *label=nullptr);
  // used so the parent can reset the bit sizes to the proper native values to
  // those of the child class.
  virtual void resetNative(void) const { } // parent has no native values

public:
   static constexpr std::string_view typeName = "SHEInt";
  ~SHEInt(void) { labelHash.erase(this); }
  // copy operators
  SHEInt(const SHEInt &a, const char *label) :
     pubKey(a.pubKey), isUnsigned(a.isUnsigned),
     bitSize(a.bitSize), isExplicitZero(a.isExplicitZero)
  { if (label) { labelHash[this] = label; }
    if (!isExplicitZero) encryptedData = a.encryptedData; }
  SHEInt(const SHEInt &a) :
     pubKey(a.pubKey), isUnsigned(a.isUnsigned), bitSize(a.bitSize),
     isExplicitZero(a.isExplicitZero)
  { if (!isExplicitZero) encryptedData = a.encryptedData; }
  SHEInt &operator=(const SHEInt &a)
  { pubKey=a.pubKey;
    isUnsigned = a.isUnsigned;
    bitSize = a.bitSize;
    isExplicitZero = a.isExplicitZero;
    if (!isExplicitZero) encryptedData = a.encryptedData;
    return *this;
  }
   
  // create a SHEInt using the context and size of a module SHEInt 
  SHEInt(const SHEInt &model, uint64_t a, const char *label=nullptr);
  // read an int from the stream
  SHEInt(const SHEPublicKey &pubkey,std::istream &str,
         const char *label=nullptr);
  // arithmetic operators
  SHEInt operator-(void) const;
  SHEInt abs(void) const;
  SHEInt operator+(const SHEInt &a) const;
  SHEInt operator-(const SHEInt &a) const;
  SHEInt operator*(const SHEInt &a) const;
  SHEInt operator/(const SHEInt &a) const;
  SHEInt operator%(const SHEInt &a) const;
  SHEInt operator<<(const SHEInt &a) const;
  SHEInt operator>>(const SHEInt &a) const;
  SHEInt operator+(uint64_t) const;
  SHEInt operator-(uint64_t a) const;
  SHEInt operator*(uint64_t a) const;
  SHEInt operator/(uint64_t a) const;
  SHEInt operator%(uint64_t a) const;
  SHEInt operator<<(uint64_t a) const;
  SHEInt operator>>(uint64_t a) const;
  SHEInt &operator+=(const SHEInt &a);
  SHEInt &operator-=(const SHEInt &a);
  SHEInt &operator*=(const SHEInt &a);
  SHEInt &operator/=(const SHEInt &a);
  SHEInt &operator%=(const SHEInt &a);
  SHEInt &operator<<=(const SHEInt &a);
  SHEInt &operator>>=(const SHEInt &a);
  SHEInt &operator+=(uint64_t a);
  SHEInt &operator-=(uint64_t a);
  SHEInt &operator*=(uint64_t a);
  SHEInt &operator/=(uint64_t a);
  SHEInt &operator%=(uint64_t a);
  SHEInt &operator<<=(uint64_t a);
  SHEInt &operator>>=(uint64_t a);
  SHEInt &operator++(void);
  SHEInt &operator--(void);
  SHEInt operator++(int);
  SHEInt operator--(int);
  // bitwise operators
  SHEInt operator~(void) const;
  SHEInt operator^(const SHEInt &a) const;
  SHEInt operator&(const SHEInt &a) const;
  SHEInt operator|(const SHEInt &a) const;
  SHEInt operator^(uint64_t a) const;
  SHEInt operator&(uint64_t a) const;
  SHEInt operator|(uint64_t a) const;
  SHEInt &operator^=(const SHEInt &a);
  SHEInt &operator&=(const SHEInt &a);
  SHEInt &operator|=(const SHEInt &a);
  SHEInt &operator^=(uint64_t a);
  SHEInt &operator&=(uint64_t a);
  SHEInt &operator|=(uint64_t a);
  void bitNot(void);
  // logical operators
  // these return either an encrypted 1 or an encrypted 0
  // the results can't be directly checked in an if, they
  // can only affect the output a a select call.
  SHEInt operator!(void) const;
  SHEInt operator&&(const SHEInt &a) const;
  SHEInt operator||(const SHEInt &a) const;
  SHEInt operator<(const SHEInt &a) const;
  SHEInt operator>(const SHEInt &a) const;
  SHEInt operator>=(const SHEInt &a) const;
  SHEInt operator<=(const SHEInt &a) const;
  SHEInt operator!=(const SHEInt &a) const;
  SHEInt operator==(const SHEInt &a) const;
  SHEInt operator&&(bool) const;
  SHEInt operator||(bool) const;
  SHEInt operator<(uint64_t) const;
  SHEInt operator>(uint64_t) const;
  SHEInt operator>=(uint64_t) const;
  SHEInt operator<=(uint64_t) const;
  SHEInt operator!=(uint64_t) const;
  SHEInt operator==(uint64_t) const;
  SHEInt operator<(int64_t) const;
  SHEInt operator>(int64_t) const;
  SHEInt operator>=(int64_t) const;
  SHEInt operator<=(int64_t) const;
  void logicNot(void);
  SHEInt isZero(void) const;
  SHEInt isNotZero(void) const;
  SHEInt isNegative(void) const;
  SHEInt isNonNegative(void) const;
  SHEInt isPositive(void) const;
  SHEInt isNonPositive(void) const;
  bool isUnencryptedZero(void) const;
  // Operatator ? : can't be overridden,
  // so a?b:c becomes a.select(b,c)
  // handle all flavors where b and c are random mix of unencrypted
  // and encrypted values.
  SHEInt select(const SHEInt &a_true, const SHEInt &a_false) const;
  SHEInt select(const SHEInt &a_true,       uint64_t a_false) const;
  SHEInt select(      uint64_t a_true, const SHEInt &a_false) const;
  SHEInt select(      uint64_t a_true,       uint64_t a_false) const;
  // Accessor functions
  std::vector<helib::Ctxt> getCtxt(void) const {return encryptedData;}
  int getSize(void) const { return bitSize; }
  bool getUnsigned(void) const { return isUnsigned; };
  bool getExplicitZero(void) const { return isExplicitZero; }
  const char *getLabel(void) const 
  {const char *label = labelHash[this];
   if (label) return label;
   return setNextLabel(); }
  // switch size and signedness
  void reset(int newBitSize, bool newIsUnsigned);
  // get the decrypted result given the private key
  uint64_t decryptRaw(const SHEPrivateKey &privKey) const;
  void expandZero(void);
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
  static SHEInt readFrom(std::istream& str, const SHEPublicKey &pubKey);
  static SHEInt readFromJSON(std::istream& str, const SHEPublicKey &pubKey);
  static SHEInt readFromJSON(const helib::JsonWrapper& j, const SHEPublicKey &pubKey);
  void read(std::istream& str);
  void readFromJSON(std::istream&str);
  void readFromJSON(const helib::JsonWrapper &jw);

  // give a simple import/export function as well
  unsigned char *flatten(int &size, bool ascii) const;
};

class SHEIntSummary
{
private:
   const SHEInt &sheint;
#ifdef DEBUG
   const SHEPrivateKey *getPrivateKey(void) const
         { return SHEInt::debugPrivKey; }
#endif
public:
   SHEIntSummary(const SHEIntSummary &summary) : sheint(summary.sheint) {}
   SHEIntSummary(const SHEInt &sheint_) : sheint(sheint_) {}
   friend std::ostream &operator<<(std::ostream&, const SHEIntSummary&);
};

// overload integer(unencrypted) [op] SHEInt, so we get the same results
// even if we swap the unencrypted and encrypted values. We can implent most 
// of them using either communitive values, or communitive identities
inline SHEInt operator+(uint64_t a, const SHEInt &b) { return b+a; }
inline SHEInt operator-(uint64_t a, const SHEInt &b) { return (-b)+a; }
inline SHEInt operator*(uint64_t a, const SHEInt &b) { return b*a; }
inline SHEInt operator^(uint64_t a, const SHEInt &b) { return b^a; }
inline SHEInt operator&(uint64_t a, const SHEInt &b) { return b&a; }
inline SHEInt operator|(uint64_t a, const SHEInt &b) { return b|a; }
inline SHEInt operator>(uint64_t a, const SHEInt &b) { return b < a; }
inline SHEInt operator<(uint64_t a, const SHEInt &b) { return b > a; }
inline SHEInt operator>=(uint64_t a, const SHEInt &b) { return b <= a; }
inline SHEInt operator<=(uint64_t a, const SHEInt &b) { return b >= a; }
inline SHEInt operator!=(uint64_t a, const SHEInt &b) { return b != a; }
inline SHEInt operator==(uint64_t a, const SHEInt &b) { return b == a; }
inline SHEInt operator>(int64_t a, const SHEInt &b) { return b < a; }
inline SHEInt operator<(int64_t a, const SHEInt &b) { return b > a; }
inline SHEInt operator>=(int64_t a, const SHEInt &b) { return b <= a; }
inline SHEInt operator<=(int64_t a, const SHEInt &b) { return b >= a; }
// these operators can't easily commute, we implement
// them by explicit casts to SHEInt
inline SHEInt operator/(uint64_t a, const SHEInt &b) 
       { SHEInt heA(b, a); return heA/b; }
inline SHEInt operator%(uint64_t a, const SHEInt &b) 
       { SHEInt heA(b, a); return heA%b; }
inline SHEInt operator<<(uint64_t a, const SHEInt &b) 
       { SHEInt heA(b, a); return heA<<b; }
inline SHEInt operator>>(uint64_t a, const SHEInt &b) 
       { SHEInt heA(b, a); return heA>>b; }
// io operators. uses public functions, do no need a friend declaration
std::istream&operator>>(std::istream&, SHEInt &a);
std::ostream&operator<<(std::ostream&, const SHEInt &a);

// now define the various native types
// would the be better as a template?
#define NEW_INT_CLASS(name, type, size, typeIsUnsigned) \
class name : public SHEInt { \
protected:           \
    virtual void resetNative(void)  { reset(size,typeIsUnsigned); } \
public:              \
    static constexpr std::string_view typeName = #name; \
    name(const SHEPublicKey &pubKey, const char *label_=nullptr) : \
      SHEInt(pubKey, (uint64_t)0, size, typeIsUnsigned, label_) {} \
    name(const SHEPublicKey &pubKey, \
         const unsigned char *encryptedInt, int dataSize, \
         const char *label_=nullptr) : \
            SHEInt(pubKey, encryptedInt, dataSize, label_) { resetNative(); } \
    name(const SHEPublicKey &pubKey, type myInt, const char *label_=nullptr):\
            SHEInt(pubKey, (uint64_t)myInt, size, typeIsUnsigned, label_) {} \
    name(const SHEInt &a, const char *label_) : SHEInt(a, label_) \
            { resetNative(); } \
    name(const SHEInt &a) : SHEInt(a) { resetNative(); } \
    name(const SHEInt &model, type a, const char *label_=nullptr) \
         : SHEInt(model, (uint64_t)a, label_) \
            { resetNative(); } \
    name &operator=(type a) \
             { SHEInt a_(*this,(uint64_t)a); return *this=a_; } \
    type decrypt(SHEPrivateKey &privKey)  \
            { return (type) decryptRaw(privKey); }; \
};

#define SHEINT_LOG2_64 6
NEW_INT_CLASS(SHEInt8,     int8_t,  8, false)
NEW_INT_CLASS(SHEInt16,   int16_t, 16, false)
NEW_INT_CLASS(SHEInt32,   int32_t, 32, false)
NEW_INT_CLASS(SHEInt64,   int64_t, 64, false)
NEW_INT_CLASS(SHEUInt8,   uint8_t,  8, true)
NEW_INT_CLASS(SHEUInt16, uint16_t, 16, true)
NEW_INT_CLASS(SHEUInt32, uint32_t, 32, true)
NEW_INT_CLASS(SHEUInt64, uint64_t, 64, true)

// cast to bool is different, it returns !zero rather than truncate
// this maintains the standard C++ semantic for bools.
class SHEBool : public SHEInt {
protected:           
  virtual void resetNative(void) { 
    if (getSize() != 1) {
      *this = isNotZero();
    }
    reset(1,true);
  }
public:
  static constexpr std::string_view typeName = "SHEBool";
  SHEBool(const SHEPublicKey &pubKey, const char *label_=nullptr) 
    : SHEInt(pubKey, (uint64_t)0, 1, true, label_) {}
  SHEBool(const SHEPublicKey &pubKey, 
          const unsigned char *encryptedInt, int dataSize,
          const char *label_=nullptr) :
    SHEInt(pubKey, encryptedInt, dataSize, label_) { resetNative(); }
  SHEBool(const SHEPublicKey &pubKey, bool myBool, const char *label_=nullptr) :
    SHEInt(pubKey, myBool, 1, true, label_) {}
  SHEBool(const SHEInt &a, const char *label_) : SHEInt(a.isNotZero(),label_) {}
  SHEBool(const SHEInt &a) : SHEInt(a.isNotZero()) {}
  SHEBool(const SHEInt &model, bool a, const char *label_=nullptr) 
    : SHEInt(model,(uint64_t) a) 
    { resetNative(); }
  SHEBool &operator=(bool a) 
             { SHEInt a_(*this,(uint64_t)a); return *this=a_; } 
  bool decrypt(SHEPrivateKey &privKey) { return (bool) decryptRaw(privKey); }
};
#endif
