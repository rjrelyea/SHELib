//
// implement basic integer operations for Homomorphic values
//
#include <iostream>
#include "SHEInt.h"
#include "SHEKey.h"
#include "SHEUtil.h"
#include "SHEMagic.h"
#include <helib/helib.h>
#include <helib/binaryArith.h>
#include <helib/binaryCompare.h>
#include <helib/intraSlot.h>
#include "helibio.h"

#ifdef DEBUG
SHEPrivateKey *SHEInt::debugPrivKey = nullptr;
#endif

std::ostream *SHEInt::log = nullptr;
uint64_t SHEInt::nextTmp = 0;
SHEIntLabelHash SHEInt::labelHash;
SHERecryptCounters SHEInt::recryptCounters = { 0 };

static std::vector<helib::Ctxt> &
sheInt_Encrypt(const SHEPublicKey &pubKey,
              std::vector<helib::Ctxt> &encryptedData,
              uint64_t myint, int bitSize)
{
  const helib::PubKey &helibPubKey = pubKey.getPublicKey();
  helib::Ctxt ctxtTemplate(helibPubKey);
  const helib::EncryptedArray &ea = pubKey.getEncryptedArray();

  encryptedData = std::vector<helib::Ctxt>(bitSize,ctxtTemplate);
  for (int i=0; i < bitSize; i++) {
    std::vector<long> vec(ea.size());
    for (auto& slot: vec) {
      slot = (myint >> i) & 1;
    }
    ea.encrypt(encryptedData[i], helibPubKey, vec);
  }
  return encryptedData;
}

SHEInt::SHEInt(const SHEPublicKey &pubKey_, uint64_t myInt,
               int bitSize_, bool isUnsigned_, const char *label) :
              pubKey(&pubKey_), bitSize(bitSize_),
              isUnsigned(isUnsigned_)
{
  if (label) labelHash[this]=label;
  isExplicitZero = !myInt;
  // if myInt is zero, delay creating the encrypted data. The rest of the
  // functions will recognize an isExplicitZero
  if (myInt) {
    sheInt_Encrypt(*pubKey, encryptedData, myInt, bitSize);
  }
}

SHEInt::SHEInt(const SHEInt &model, uint64_t myInt,const char *label)
               : pubKey(model.pubKey)
{
  if (label) labelHash[this]=label;
  bitSize = model.bitSize;
  isUnsigned = model.isUnsigned;
  isExplicitZero = !myInt;
  // if myInt is zero, delay creating the encrypted data. The rest of the
  // functions will recognize an isExplicitZero
  if (myInt) {
    sheInt_Encrypt(*pubKey, encryptedData, myInt, bitSize);
  }
}

SHEInt::SHEInt(const SHEPublicKey &pubKey_, const unsigned char *encryptedInt,
             int size, const char *label) : pubKey(&pubKey_)
{
  if (label) labelHash[this]=label;
  std::string s((const char *)encryptedInt, size);
  std::stringstream ss(s);
  read(ss);
}

SHEInt::SHEInt(const SHEPublicKey &pubKey_, std::istream& str,
               const char *label) : pubKey(&pubKey_)
{
  if (label) labelHash[this]=label;
  readFromJSON(str);
}

// change the size of our encryptedData array. On increase it
// will sign extend, on decrease it will truncate
void SHEInt::reset(int newBitSize, bool newIsUnsigned)
{
  isUnsigned = newIsUnsigned;
  if (newBitSize == bitSize) {
    return;
  }
  // explicitZero has no encrypted data, just set the bit size
  if (isExplicitZero) {
    bitSize = newBitSize;
    return;
  }

  // For unsigned, we extend zeros, for signed
  // we extend the sign bit. truncation looses
  // the high bits.
  helib::Ctxt ctxtTemplate(pubKey->getPublicKey());
  if (isUnsigned) {
    ctxtTemplate.clear();
  } else {
    ctxtTemplate = encryptedData[bitSize-1];
  }
  encryptedData.resize(newBitSize, ctxtTemplate);
  bitSize = newBitSize;
}

// take an isExplicitZero and expand it to
// a vector<helib::Ctxt> with cleared values
void SHEInt::expandZero(void)
{
  if (!isExplicitZero) {
    return;
  }
  helib::Ctxt ctxtTemplate(pubKey->getPublicKey());
  ctxtTemplate.clear();
  encryptedData.resize(bitSize, ctxtTemplate);
  isExplicitZero=false;
}

// do we need to reCrypt before doing more operations.
// bitCapacity uses noise to estimate how many more operations
// we can do, use it to decide if we need to reCrypt.
bool SHEInt::needRecrypt(long level) const
{
  // if we are explicit zero, nothing to reencrypt
  if (isExplicitZero) {
    return false;
  }

  // first check by level
  return level > bitCapacity();
}

// needRecrypt returns true of any of the passed in ints falls below a given
// level
bool SHEInt::needRecrypt(const SHEInt &a, long level) const
{
  return needRecrypt(level) || a.needRecrypt(level);
}

bool SHEInt::needRecrypt(const SHEInt &a, const SHEInt &b, long level) const
{
  return needRecrypt(level) || a.needRecrypt(level) || b.needRecrypt(level) ;
}

bool SHEInt::needRecrypt(const SHEInt &a, const SHEInt &b, const SHEInt &c,
                         long level) const
{
  return needRecrypt(a, level) || b.needRecrypt(c, level);
}
bool SHEInt::needRecrypt(const SHEInt &a, const SHEInt &b, const SHEInt &c,
                         const SHEInt &d, long level) const
{
  return needRecrypt(a, b, level) || c.needRecrypt(d, level);
}

bool SHEInt::needRecrypt(const SHEInt &a, const SHEInt &b, const SHEInt &c,
                         const SHEInt &d, const SHEInt &e, long level) const
{
  return needRecrypt(a, b, level) || c.needRecrypt(d, e, level);
}

// reCrypt performs a simultaneous bootstrap on all the given integers.
// we skip integers which appear to have a higher capacity then the expected
// result of the bootstrap itself. 'force' overrides this behavior and we
// will unconditionally recrypt everything.

// build a CtPtrs container that holds all the CtrPtrs we wish
// Recrypt
struct CtPtrs_array : helib::CtPtrs
{
  // sigh I would prefer to use std::vector, but trying to get the
  // allocator right for helib::CtPtrs is non-trivial.
  const helib::CtPtrs *a[10];
  int nElements;
  CtPtrs_array(void)  {
    for (int i=0; i < 10; i++)
      a[i] = nullptr;
    nElements=0;
  }
  void addEntry(const helib::CtPtrs& a_) { a[nElements++] = &a_; }
  long size() const override {
    long tsize = 0;
    for (int i=0; i < nElements; i++) {
      tsize += lsize(*a[i]);
    }
    return tsize;
  }
  helib::Ctxt *operator[](long i) const override
  {
    long tsize = 0;
    for (int element=0; element < nElements; element++) {
      long _lsize = lsize(*a[element]);
      long offset = i - tsize;
      if (offset < _lsize) {
        return (*a[element])[offset];
      }
      tsize += _lsize;
    }
    return nullptr; // shouldn't happen
  }
};

void SHEInt::reCrypt(SHEInt &a, SHEInt &b, SHEInt &c, SHEInt &d, SHEInt &e,
                     bool force)
{
  if (!force) {
    if ((isExplicitZero) || (bitCapacity() > SHEINT_LEVEL_THRESHOLD)) {
      a.reCrypt(b, c, d, e, false);
      return;
    }
    if ((a.isExplicitZero) || (a.bitCapacity() > SHEINT_LEVEL_THRESHOLD)) {
      reCrypt(b, c, d, e, false);
      return;
    }
    if ((b.isExplicitZero) || (b.bitCapacity() > SHEINT_LEVEL_THRESHOLD)) {
      reCrypt(a, c, d, e, false);
      return;
    }
    if ((c.isExplicitZero) || (c.bitCapacity() > SHEINT_LEVEL_THRESHOLD)) {
      reCrypt(a, b, d, e, false);
      return;
    }
    if ((d.isExplicitZero) || (d.bitCapacity() > SHEINT_LEVEL_THRESHOLD)) {
      reCrypt(a, b, c, e, false);
      return;
    }
    if ((e.isExplicitZero) || (e.bitCapacity() > SHEINT_LEVEL_THRESHOLD)) {
      reCrypt(a, b, c, d, false);
      return;
    }
  }
  if (log) {
    (*log) << "[Recrypt(" << (SHEIntSummary)*this << ","
           << (SHEIntSummary) a << ")->" << std::flush;
  }
  helib::CtPtrs_vectorCt wrapper(encryptedData);
  helib::CtPtrs_vectorCt wrapperA(a.encryptedData);
  helib::CtPtrs_vectorCt wrapperB(b.encryptedData);
  helib::CtPtrs_vectorCt wrapperC(c.encryptedData);
  helib::CtPtrs_vectorCt wrapperD(d.encryptedData);
  helib::CtPtrs_vectorCt wrapperE(e.encryptedData);
  CtPtrs_array matrix;
  matrix.addEntry(wrapper);
  matrix.addEntry(wrapperA);
  matrix.addEntry(wrapperB);
  matrix.addEntry(wrapperC);
  matrix.addEntry(wrapperD);
  matrix.addEntry(wrapperE);
  helib::packedRecrypt(matrix,
            *(std::vector<helib::zzX> *)pubKey->getUnpackSlotEncoding(),
            pubKey->getEncryptedArray());
  reCryptSextupleCounter();
}

void SHEInt::reCrypt(SHEInt &a, SHEInt &b, SHEInt &c, SHEInt &d, bool force)
{
  if (!force) {
    if ((isExplicitZero) || (bitCapacity() > SHEINT_LEVEL_THRESHOLD)) {
      a.reCrypt(b, c, d, false);
      return;
    }
    if ((a.isExplicitZero) || (a.bitCapacity() > SHEINT_LEVEL_THRESHOLD)) {
      reCrypt(b, c, d, false);
      return;
    }
    if ((b.isExplicitZero) || (b.bitCapacity() > SHEINT_LEVEL_THRESHOLD)) {
      reCrypt(a, c, d, false);
      return;
    }
    if ((c.isExplicitZero) || (c.bitCapacity() > SHEINT_LEVEL_THRESHOLD)) {
      reCrypt(a, b, d, false);
      return;
    }
    if ((d.isExplicitZero) || (d.bitCapacity() > SHEINT_LEVEL_THRESHOLD)) {
      reCrypt(a, b, c, false);
      return;
    }
  }
  if (log) {
    (*log) << "[Recrypt(" << (SHEIntSummary)*this << ","
           << (SHEIntSummary) a << ")->" << std::flush;
  }
  helib::CtPtrs_vectorCt wrapper(encryptedData);
  helib::CtPtrs_vectorCt wrapperA(a.encryptedData);
  helib::CtPtrs_vectorCt wrapperB(b.encryptedData);
  helib::CtPtrs_vectorCt wrapperC(c.encryptedData);
  helib::CtPtrs_vectorCt wrapperD(d.encryptedData);
  CtPtrs_array matrix;
  matrix.addEntry(wrapper);
  matrix.addEntry(wrapperA);
  matrix.addEntry(wrapperB);
  matrix.addEntry(wrapperC);
  matrix.addEntry(wrapperD);
  helib::packedRecrypt(matrix,
            *(std::vector<helib::zzX> *)pubKey->getUnpackSlotEncoding(),
            pubKey->getEncryptedArray());
  reCryptQuintupleCounter();
}

void SHEInt::reCrypt(SHEInt &a, SHEInt &b, SHEInt &c, bool force)
{
  if (!force) {
    if ((isExplicitZero) || (bitCapacity() > SHEINT_LEVEL_THRESHOLD)) {
      a.reCrypt(b, c, false);
      return;
    }
    if ((a.isExplicitZero) || (a.bitCapacity() > SHEINT_LEVEL_THRESHOLD)) {
      reCrypt(b, c, false);
      return;
    }
    if ((b.isExplicitZero) || (b.bitCapacity() > SHEINT_LEVEL_THRESHOLD)) {
      reCrypt(a, c, false);
      return;
    }
    if ((c.isExplicitZero) || (c.bitCapacity() > SHEINT_LEVEL_THRESHOLD)) {
      reCrypt(a, b, false);
      return;
    }
  }
  if (log) {
    (*log) << "[Recrypt(" << (SHEIntSummary)*this << ","
           << (SHEIntSummary) a << ")->" << std::flush;
  }
  helib::CtPtrs_vectorCt wrapper(encryptedData);
  helib::CtPtrs_vectorCt wrapperA(a.encryptedData);
  helib::CtPtrs_vectorCt wrapperB(b.encryptedData);
  helib::CtPtrs_vectorCt wrapperC(c.encryptedData);
  CtPtrs_array matrix;
  matrix.addEntry(wrapper);
  matrix.addEntry(wrapperA);
  matrix.addEntry(wrapperB);
  matrix.addEntry(wrapperC);
  helib::packedRecrypt(matrix,
            *(std::vector<helib::zzX> *)pubKey->getUnpackSlotEncoding(),
            pubKey->getEncryptedArray());
  reCryptQuadrupleCounter();
}

void SHEInt::reCrypt(SHEInt &a, SHEInt &b, bool force)
{
  if (!force) {
    if ((isExplicitZero) || (bitCapacity() > SHEINT_LEVEL_THRESHOLD)) {
      a.reCrypt(b, false);
      return;
    }
    if ((a.isExplicitZero) || (a.bitCapacity() > SHEINT_LEVEL_THRESHOLD)) {
      reCrypt(b, false);
      return;
    }
    if ((b.isExplicitZero) || (b.bitCapacity() > SHEINT_LEVEL_THRESHOLD)) {
      reCrypt(a, false);
      return;
    }
  }
  if (log) {
    (*log) << "[Recrypt(" << (SHEIntSummary)*this << ","
           << (SHEIntSummary) a << ")->" << std::flush;
  }
  helib::CtPtrs_vectorCt wrapper(encryptedData);
  helib::CtPtrs_vectorCt wrapperA(a.encryptedData);
  helib::CtPtrs_vectorCt wrapperB(b.encryptedData);
  CtPtrs_array matrix;
  matrix.addEntry(wrapper);
  matrix.addEntry(wrapperA);
  matrix.addEntry(wrapperB);
  helib::packedRecrypt(matrix,
            *(std::vector<helib::zzX> *)pubKey->getUnpackSlotEncoding(),
            pubKey->getEncryptedArray());
  reCryptTripleCounter();
}

void SHEInt::reCrypt(SHEInt &a, bool force)
{
  if (!force) {
    if ((isExplicitZero) || (bitCapacity() > SHEINT_LEVEL_THRESHOLD)) {
      a.reCrypt(false);
      return;
    }
    if ((a.isExplicitZero) || (a.bitCapacity() > SHEINT_LEVEL_THRESHOLD)) {
      reCrypt(false);
      return;
    }
  }
  if (log) {
    (*log) << "[Recrypt(" << (SHEIntSummary)*this << ","
           << (SHEIntSummary) a << ")->" << std::flush;
  }
  helib::CtPtrs_vectorCt wrapper(encryptedData);
  helib::CtPtrs_vectorCt wrapperA(a.encryptedData);
  helib::packedRecrypt(wrapper, wrapperA,
            (std::vector<helib::zzX> *)pubKey->getUnpackSlotEncoding());
  reCryptDoubleCounter();
  if (log) {
    (*log) << "<" << (SHEIntSummary)*this << ","
           << (SHEIntSummary) a << ">]" << std::flush;
  }
}


void SHEInt::reCrypt(bool force)
{
  // don't check threshold here. If we wound up here with a greater threshold
  // it means we have been specifically requested to bootstrap
  if (!force && isExplicitZero) {
    return;
  }
  helib::CtPtrs_vectorCt wrapper(encryptedData);
  if (log) {
    (*log) << "[Recrypt(" << (SHEIntSummary)*this << ")->" << std::flush;
  }
  helib::packedRecrypt(wrapper,
            *(std::vector<helib::zzX> *)pubKey->getUnpackSlotEncoding(),
            pubKey->getEncryptedArray());
  reCryptCounter();
  if (log) {
    (*log) << (SHEIntSummary)*this << "]" << std::flush;
  }
}

// verifyArgs can be used before various calls to bring a set of variables up
// to a given level at once.
void SHEInt::verifyArgs(SHEInt &a, SHEInt &b, SHEInt &c, SHEInt &d, SHEInt &e,
                        long level)
{
  if (needRecrypt(a, b, c, d, e, level)) {
    reCrypt(a, b, c, d, e, false);
  }
}

void SHEInt::verifyArgs(SHEInt &a, SHEInt &b, SHEInt &c, SHEInt &d, long level)
{
  if (needRecrypt(a, b, c, d, level)) {
    reCrypt(a, b, c, d, false);
  }
}

void SHEInt::verifyArgs(SHEInt &a, SHEInt &b, SHEInt &c, long level)
{
  if (needRecrypt(a, b, c, level)) {
    reCrypt(a, b, c, false);
  }
}

void SHEInt::verifyArgs(SHEInt &a, SHEInt &b, long level)
{
  if (needRecrypt(a, b, level)) {
    reCrypt(a, b, false);
  }
}

void SHEInt::verifyArgs(SHEInt &a, long level)
{
  if (needRecrypt(a, level)) {
    reCrypt(a, false);
  }
}

void SHEInt::verifyArgs(long level)
{
  if (needRecrypt(level)) {
    reCrypt(false);
  }
}

///////////////////////////////////////////////////////////////////////////
//                      input/output operators.                           /
///////////////////////////////////////////////////////////////////////////
std::ostream& operator<<(std::ostream& str, const SHEInt& a)
{
  a.writeToJSON(str);
  return str;
}

std::istream& operator>>(std::istream& str, SHEInt& a)
{
  a.readFromJSON(str);
  return str;
}

std::ostream &operator<<(std::ostream& str, const SHEIntSummary &summary)
{
  long level = summary.sheint.bitCapacity();
  std::ios_base::fmtflags saveFlags = str.flags();
  str << "SHEInt(" <<  summary.sheint.getLabel() << "," << std::dec
      << summary.sheint.getSize() << ","
      << (char *)(summary.sheint.getUnsigned() ? "U" : "S") << ","
      << (char *)(summary.sheint.getExplicitZero() ? "Z" : "E")
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
    if (summary.sheint.isCorrect()) {
      uint64_t decrypted = summary.sheint.decryptRaw(*privKey);
      if (summary.sheint.getUnsigned()) {
        str << decrypted;
      } else {
        str << (int64_t)decrypted;
      }
    } else {
      str << "NaN";
    }
  }
#endif
  str << ")";
  return str;
}

bool SHEInt::isCorrect(void) const
{
  if (isExplicitZero) {
    return true;
  }
  for (int i=0; i < bitSize; i++) {
    if (!encryptedData[i].isCorrect()) {
      return false;
    }
  }
  return true;
}

unsigned char *SHEInt::flatten(int &size, bool ascii) const
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

void SHEInt::writeTo(std::ostream& str) const
{
  write_raw_int(str, SHEIntMagic); // magic to say we're a SHEInt
  write_raw_int(str, bitSize);
  write_raw_int(str, isUnsigned);
  // make our explicit zero encrypted now
  if (isExplicitZero) {
    helib::Ctxt zero_Ctxt(pubKey->getPublicKey());
    zero_Ctxt.clear();
    for(int i=0; i < bitSize; i++) {
      zero_Ctxt.writeTo(str);
    }
    return;
  }
  for (int i=0; i <bitSize; i++) {
    encryptedData[i].writeTo(str);
  }
}

void SHEInt::writeToJSON(std::ostream& str) const
{
  helib::executeRedirectJsonError<void>([&]() { str << writeToJSON(); });
}

helib::JsonWrapper SHEInt::writeToJSON(void) const
{
  SHEInt target = *this;
  if (isExplicitZero) {
    // need to make the explicitZero encrypted */
    target.expandZero();
  }
  auto body = [target]() {
    json j = {{"bitSize", target.bitSize},
              {"isUnsigned", target.isUnsigned},
              {"encryptedData", helib::writeVectorToJSON(target.encryptedData)}};

    return helib::wrap(helib::toTypedJson<SHEInt>(j));
  };
  return helib::executeRedirectJsonError<helib::JsonWrapper>(body);
}

SHEInt SHEInt::readFrom(std::istream& str, const SHEPublicKey &pubKey)
{
  SHEInt a(pubKey, 0, 1, true);
  a.read(str);
  return a;
}

SHEInt SHEInt::readFromJSON(std::istream& str, const SHEPublicKey& pubKey)
{
  return helib::executeRedirectJsonError<SHEInt>([&]() {
    json j;
    str >> j;
    return readFromJSON(helib::wrap(j), pubKey);
  });
}

SHEInt SHEInt::readFromJSON(const helib::JsonWrapper& j,
                            const SHEPublicKey& pubKey)
{
  SHEInt a(pubKey, (uint64_t)0, 1, true);
  a.readFromJSON(j);
  a.resetNative();
  return a;
}

void SHEInt::read(std::istream& str)
{
  long magic;

  magic = read_raw_int(str);
  helib::assertEq<helib::IOError>(magic, SHEIntMagic,
                                    "not an SHEInt on the stream");
  bitSize = read_raw_int(str);
  isUnsigned = read_raw_int(str);
  helib::Ctxt ctxtTemplate(pubKey->getPublicKey());
  encryptedData = std::vector<helib::Ctxt>(bitSize,ctxtTemplate);
  for (int i=0; i < bitSize; i++) {
    encryptedData[i].read(str);
  }
  isExplicitZero = false;
  resetNative();
}

void SHEInt::readFromJSON(std::istream& str)
{
  return helib::executeRedirectJsonError<void>([&]() {
    json j;
    str >> j;
    return readFromJSON(helib::wrap(j));
  });
}

void SHEInt::readFromJSON(const helib::JsonWrapper& jw)
{
  auto body = [&]() {
    json j = helib::fromTypedJson<SHEInt>(unwrap(jw));
    this->bitSize = j.at("bitSize");
    this->isUnsigned = j.at("isUnsigned");
    // Using inplace parts deserialization as read_raw_vector will do a
    // resize, then reads the parts in-place, so may re-use memory.
    const helib::PubKey &helibPubKey = pubKey->getPublicKey();
    helib::Ctxt templateCtxt(helibPubKey);
    helib::readVectorFromJSON(j.at("encryptedData"),
                              this->encryptedData, templateCtxt);
    this->isExplicitZero = false;
    // sanity-check
    helib::assertEq(this->bitSize, (int) this->encryptedData.size(),
       "bitSize and the size of the encryptedData does not match");
  };

  helib::executeRedirectJsonError<void>(body);
}

///////////////////////////////////////////////////////////////////////////
//                      General helpers
///////////////////////////////////////////////////////////////////////////
uint64_t SHEInt::decryptRaw(const SHEPrivateKey &privKey) const
{
  if (isExplicitZero) {
    return 0;
  }
  uint64_t result;
  std::vector<long> decrypted_result;
  helib::CtPtrs_vectorCt wrapper((std::vector<helib::Ctxt>&)encryptedData);

  helib::decryptBinaryNums(decrypted_result, wrapper, privKey.getPrivateKey(),
                           pubKey->getEncryptedArray());
  result = decrypted_result.back();
  if (!isUnsigned) {
    // sign extend for signed values
    uint64_t sign=(result >> (bitSize-1)) & 1;
    for (int i=bitSize; i < 64; i++) {
      result |= (sign << i);
    }
  }
  return result;
}

uint64_t SHEInt::decryptBit(const SHEPrivateKey &privKey, helib::Ctxt &ctxt) const
{
   std::vector<long> slots;
   const helib::EncryptedArray& ea=pubKey->getEncryptedArray();

   ea.decrypt(ctxt,privKey.getPrivateKey(), slots);
   return slots[ea.sizeOfDimension(ea.dimension()-1)];
}

long SHEInt::bitCapacity(void) const
{
  if (isExplicitZero) {
    return LONG_MAX;
  }
  helib::CtPtrs_vectorCt wrapper((std::vector<helib::Ctxt>&)encryptedData);
  return helib::findMinBitCapacity(wrapper);
}

double SHEInt::securityLevel(void) const
{
  return pubKey->securityLevel();
}

///////////////////////////////////////////////////////////////////////////
//                      Single bit helpers                                /
///////////////////////////////////////////////////////////////////////////
//
// select a singe bit (Ctxt) based on the this logical operator (this is
// the bit equivalent of select, except on Ctxt values).

static helib::Ctxt selectBit(const helib::Ctxt &sel,
                             const helib::Ctxt &trueBit,
                             const helib::Ctxt &falseBit)
{
   helib::Ctxt negate_cond(sel);
   negate_cond.addConstant(NTL::ZZX(1L));
   helib::Ctxt result(trueBit);
   helib::Ctxt result_(falseBit);
   result.multiplyBy(sel);
   result_.multiplyBy(negate_cond);
   result += result_;
   return result;
}

helib::Ctxt SHEInt::selectBit(const helib::Ctxt &trueBit,
                              const helib::Ctxt &falseBit) const
{
  return ::selectBit(encryptedData[0], trueBit, falseBit);
}

//
// return the bit indexed by and encrypted 'index+offset'. This is equivalent to
// encryptedArray[i], except 'i' is encrypted. The use of the unencrypted
// offset allows the caller to use offset as the loop variable rather than
// the encrypted index. This allows us to not need to update the encrypted
// offset every step of the loop which saves time and capacity.
// If the array index is outside 0..biSize-1 then defaultBit is returned
//
helib::Ctxt SHEInt::selectArrayBit(const SHEInt &index, int offset,
                                   int direction,
                                   const helib::Ctxt &defaultBit) const
{
  SHEInt thisBit(*pubKey, 0, 1, true);
  helib::Ctxt selectedBit = defaultBit;
  for (int i=0; i < bitSize; i++) {
    int cmpIndex= direction?offset-i:i-offset;
    if (selectedBit.bitCapacity() < SHEINT_DEFAULT_LEVEL_TRIGGER) {
      // it's posible we hit the capacity mid loop, recrypt if necessary
      const helib::PubKey &publicKey = pubKey->getPublicKey();
      if (log) {
        (*log) << " -reCrypting selectedBit(" << selectedBit.bitCapacity()
               << ") at bit " << i << " of" << bitSize << std::endl;
      }
      publicKey.reCrypt(selectedBit);
      reCryptBitCounter();
    }
    selectedBit = (index == cmpIndex).selectBit(encryptedData[i],
                                                  selectedBit);
  }
  return selectedBit;
}

///////////////////////////////////////////////////////////////////////////
//                      Mathematic helpers.                               /
///////////////////////////////////////////////////////////////////////////
// caller must ensure that the bit size of this, a, and result are all equal
SHEInt &SHEInt::addRaw(const SHEInt &a, SHEInt &result) const
{
  helib::CtPtrs_vectorCt wrapper(result.encryptedData);

  if (log) {
    (*log) << (SHEIntSummary)*this << ".addRaw(" << (SHEIntSummary) a << ","
        << (SHEIntSummary)result << ")=" << std::flush;
  }
  helib::addTwoNumbers(wrapper,
            helib::CtPtrs_vectorCt((std::vector<helib::Ctxt>&)encryptedData),
            helib::CtPtrs_vectorCt((std::vector<helib::Ctxt>&)a.encryptedData),
            result.bitSize,
            (std::vector<helib::zzX> *)pubKey->getUnpackSlotEncoding());
   //result.encryptedData is now set
   result.isExplicitZero = false;
   if (log) (*log) << (SHEIntSummary)result << std::endl;
   return result;
}

SHEInt &SHEInt::cmpRaw(const SHEInt &a, SHEInt &gt, SHEInt &lt) const
{
  if (log) {
    (*log) << (SHEIntSummary)*this << ".cmpRaw(" << (SHEIntSummary) a << ","
        << (SHEIntSummary)gt << "," << (SHEIntSummary)lt << ") ->" << std::flush;
  }
  helib::compareTwoNumbers(gt.encryptedData[0], lt.encryptedData[0],
            helib::CtPtrs_vectorCt((std::vector<helib::Ctxt>&)encryptedData),
            helib::CtPtrs_vectorCt((std::vector<helib::Ctxt>&)a.encryptedData),
            !isUnsigned,
            (std::vector<helib::zzX> *)pubKey->getUnpackSlotEncoding());
   if (log) (*log) << "gt=" <<(SHEIntSummary)gt << "lt=" << (SHEIntSummary)lt << std::endl;
   return gt;
}

// caller must ensure that the bit size of this, a, and result are all equal
SHEInt &SHEInt::subRaw(const SHEInt &a, SHEInt &result) const
{
  helib::CtPtrs_vectorCt wrapper(result.encryptedData);
  if (log) {
    (*log) << (SHEIntSummary)*this << ".subRaw(" << (SHEIntSummary) a << ","
        << (SHEIntSummary)result << ")=" << std::flush;
  }
  helib::subtractBinary(wrapper,
            helib::CtPtrs_vectorCt((std::vector<helib::Ctxt>&)encryptedData),
            helib::CtPtrs_vectorCt((std::vector<helib::Ctxt>&)a.encryptedData),
            (std::vector<helib::zzX> *)pubKey->getUnpackSlotEncoding());
   //result.encryptedData is now set
   result.isExplicitZero = false;
   if (log) (*log) << (SHEIntSummary)result << std::endl;
   return result;
}

// no need to have a & b =, result must be = MAX(bitsize, a.bitSize);
SHEInt &SHEInt::mulRaw(const SHEInt &a, SHEInt &result) const
{
  helib::CtPtrs_vectorCt wrapper(result.encryptedData);

  if (isUnsigned == a.isUnsigned) {
      // If the input values are both unsigned or both signed,
      // multTwoNumbers can handle the result
      result.isUnsigned = isUnsigned;
      if (log) {
        (*log) << (SHEIntSummary)*this << ".mulRaw(" << (SHEIntSummary) a <<
               "," << (SHEIntSummary)result << ")=" << std::flush;
      }
      helib::multTwoNumbers(wrapper,
            helib::CtPtrs_vectorCt((std::vector<helib::Ctxt>&)encryptedData),
            helib::CtPtrs_vectorCt((std::vector<helib::Ctxt>&)a.encryptedData),
            !isUnsigned,
            result.bitSize,
            (std::vector<helib::zzX> *)pubKey->getUnpackSlotEncoding());
      if (log) (*log) << (SHEIntSummary)result << std::endl;
      //result.encryptedData is now set
   } else {
      SHEInt m1(*this);
      SHEInt m2(a);
      // One operand is unsigned, the other is signed
      // extending the values by 1 puts a zero in the high bit
      // for unsigned operands, and signed extends for signed operands.
      // we can then safely use multTwoNumbers for signed operations
      // and get the correct result (which will be signed)
      m1.reset(bitSize+1,isUnsigned);
      m2.reset(a.bitSize+1,isUnsigned);
      result.isUnsigned = false;
      if (log) {
        (*log) << (SHEIntSummary)*this << ".mulRaw-mixed("
               << (SHEIntSummary) a << ","
               << (SHEIntSummary)result << ")=" << std::flush;
      }
      helib::multTwoNumbers(wrapper,
            helib::CtPtrs_vectorCt((std::vector<helib::Ctxt>&)encryptedData),
            helib::CtPtrs_vectorCt((std::vector<helib::Ctxt>&)a.encryptedData),
            true,
            result.bitSize,
            (std::vector<helib::zzX> *)pubKey->getUnpackSlotEncoding());
      if (log) (*log) << (SHEIntSummary)result << std::endl;
      //result.encryptedData is now set
   }
   result.isExplicitZero = false;
   return result;
}

// we do the shift by hand rather than use the binaryArithm library here
// because we want to implement shift in place. NOTE: shifts using an
// integer are relatively fast (no Homomorphic operations) and does not
// reduce capacity!
void SHEInt::leftShift(uint64_t shift)
{
  // shift of zero is a noop
  if (isExplicitZero) {
    return;
  }
  // allow in place shift, first targets should be the lost bits
  for (int i=bitSize-1; i >= shift ; i--) {
    encryptedData[i] = encryptedData[i - shift];
  }
  for (int i=0; i < shift; i++) {
    encryptedData[i].clear();
  }
}

// the binaryArithm library doesn't have a right shift
void SHEInt::rightShift(uint64_t shift)
{
  // shift of zero is a noop
  if (isExplicitZero) {
    return;
  }
  // allow in place shift, first targets should be the lost bits
  for (int i=0; i < bitSize - shift; i++) {
    encryptedData[i] = encryptedData[i+shift];
  }
  if (!isUnsigned) {
    // arithmetic shift, preserving the sign bit
    for (int i=bitSize-shift; i < bitSize-1; i++) {
      encryptedData[i] = encryptedData[bitSize-1];
    }
  } else {
    for (int i=bitSize-shift; i < bitSize; i++) {
      encryptedData[i].clear();
    }
  }
}


//
// Shift by an encrypted shift index requires logical operaters.
// Note: unlike integer shifts, these are more expensive in both time
// (O(bitSize^2) single bit multiplies and a xor) and capacity.
SHEInt &SHEInt::leftShift(const SHEInt &shift, SHEInt &result) const
{
  // walk down the possible shifts and return the one that matches
  result = SHEInt(*this, (uint64_t)0);

  for (int i=0; i < bitSize; i++) {
    result = (i==shift).select(*this << i, result);
  }
  return result;
}

SHEInt &SHEInt::rightShift(const SHEInt &shift, SHEInt &result) const
{
  // walk down the possible shifts and return the one that matches
  result = SHEInt(*this, (uint64_t)0);
  if (!isUnsigned) {
    result=isNegative().select(-1,result);
  }

  for (int i=0; i < bitSize; i++) {
    result = (i==shift).select(*this >> i, result);
  }
  return result;
}

// this shift takes in account of the sign of shift and reverses
// fields if it's negative.
SHEInt SHEInt::rightShiftSigned(const SHEInt &shift) const
{
  // walk down the possible shifts and return the one that matches
  // if none matches, the result is zero
  SHEInt result(*this, (uint64_t)0);

  // If shift is unsigned, reduce to just a normal rightShift
  if (shift.isUnsigned) {
    return rightShift(shift,result);
  }
  // If this is signed and negative, default result of a right
  // shift (shift is positive) is -1, not zero.
  if (!isUnsigned) {
    result=(isNegative() & !shift.isNegative()).select(-1,result);
  }

  // handle the no shift case first
  result = shift.isZero().select(*this, result);
  // now check each positive an negative shift up to bitsize
  for (int i=1; i < bitSize; i++) {
    result = (i==shift).select(*this >> i, result);
    result = (-i==shift).select(*this << i, result);
  }
  return result;
}

// this shift takes in account of the sign of shift and reverses
// fields if it's negative.
SHEInt SHEInt::leftShiftSigned(const SHEInt &shift) const
{
  // walk down the possible shifts and return the one that matches
  // if none matches, the result is zero
  SHEInt result(*this, (uint64_t)0);
  // If shift is unsigned, reduce to just a normal leftShift
  if (shift.isUnsigned) {
    return leftShift(shift,result);
  }
  // If this is signed and negative, default result of a right
  // shift (shift is negative) is -1, not zero.
  if (!isUnsigned) {
    result=(isNegative() & shift.isNegative()).select(-1,result);
  }

  // handle the no shift case first
  result = shift.isZero().select(*this, result);
  // now check each positive an negative shift up to bitsize
  for (int i=1; i < bitSize; i++) {
    result = (i==shift).select(*this << i, result);
    result = (-i==shift).select(*this >> i, result);
  }
  return result;
}

SHEInt SHEInt::abs(void) const
{
  // save the capacity of the single multiply
  // if we already know *this isn't negative
  // from unencrypted information
  if (isUnsigned || isExplicitZero) {
    return *this;
  }
  return isNegative().select(-*this,*this);
}

//
// NOTE: divide requires logical operations, so make sure we don't
// call divide in any of the logical operation code.
//
// Also Note if divisor is an encrypted zero, we can't detect that case,
// so it will return incorrect results (quotient=0, remainder=0). Callers are
// responsible for detecting and dealing with that case on their own.

SHEInt &SHEInt::udivRaw(const SHEInt &div, SHEInt *result, SHEInt *mod) const
{
  SHEInt dividend(*this,"dividend");
  SHEInt divisor(div,"divisor");
  if (log) {
    (*log) << (SHEIntSummary) *this << ".udivRaw("
          << (SHEIntSummary) divisor << ",";
    if (result) {
      (*log) << (SHEIntSummary) *result << ",";
    }else {
      (*log) << "NULL,";
    }
    if (mod) {
      (*log) << (SHEIntSummary) *mod << "";
    }else {
      (*log) << "NULL";
    }
    (*log) << "=" << std::endl;
  }
  // for our math case, make sure the dividend has at least as many
  // bits as the divisor
  dividend.verifyArgs(divisor, SHEINT_DEFAULT_LEVEL_TRIGGER*2);
  if ( bitSize < divisor.bitSize) {
    dividend.reset(divisor.bitSize, true);
  }
  // below we keep a couple of versions, one that will record the final
  // result of the loop, and one that continues to shift/decrement through the
  // whole loop, We'll use encrypted select to decide when to stop updating
  // the result version
  SHEInt remainder(dividend, 0, "remainder");
  SHEInt quotient(dividend, 0, "quotient");
  SHEInt quotientShift(dividend, 0, "quotientShift");
  SHEInt t(dividend, 0, "t");
  SHEInt sel(*pubKey, 1, 1, true, "sel");

  // this is logically 'while remainder < dividend'. We don't know when
  // we hit this condition because sel is encrypted, so we loop over the full
  // length if the dividend, but stop updating once sel is true
  for (int i=0; i < dividend.bitSize; i++) {
    SHEInt bit = dividend.getBitHigh(0);
    remainder.leftShift(1);
    remainder.setBit(0,bit);
    // precheck bootstrapping on deep use variables
    sel.verifyArgs(remainder, quotient, quotientShift,
                   SHEINT_DEFAULT_LEVEL_TRIGGER*2);
    sel = sel && remainder < divisor;
    dividend.leftShift(1);
    t = remainder - divisor;
    SHEInt q = t.getBitHigh(0);
    quotientShift = quotient << 1;
    // quotient |= !q
    quotientShift.setBit(0,!q);
    quotient = sel.select(quotient,quotientShift);
    remainder = (q || sel).select(remainder, t);
  }
  if (result) {
    *result = quotient;
    if (log) (*log) << "udivRaw.result=" << (SHEIntSummary) *result
                    << std::endl;
  }
  if (mod) {
    *mod = remainder;
    if (log) (*log) << "udivRaw.mod=" << (SHEIntSummary) *mod
                    << std::endl;
  }
   return result ? *result : *mod;
}


///////////////////////////////////////////////////////////////////////////
//                      Mathematic operators.                             /
///////////////////////////////////////////////////////////////////////////

// basic addition, subtraction and negation operators. These functions
// return the values of the same size as the biggest operand
SHEInt SHEInt::operator-(void) const {
  if (isExplicitZero) {
    return *this;
  }
  SHEInt copy(*this);
  SHEInt result(*this,(uint64_t)0);
  result.expandZero(); // unlike addition and multiplication, negation
                       // result needs to be preallocated
  helib::CtPtrs_vectorCt wrapper(result.encryptedData);
  if (log) (*log) << (SHEIntSummary)*this << ".operator-()=" << std::flush;
  copy.verifyArgs();
  negateBinary(wrapper, helib::CtPtrs_vectorCt(copy.encryptedData));
  result.isExplicitZero = false;
  if (log) { (*log) << (SHEIntSummary)result << std::endl; }
  return result;
}

SHEInt SHEInt::operator+(const SHEInt &a) const {
  if (a.isExplicitZero) {
    return *this;
  }
  if (isExplicitZero) {
    return a;
  }
  if (a.bitSize == bitSize) {
     SHEInt result(*this, (uint64_t)0);
    return SHEInt(this->addRaw(a, result));
  }
  if (a.bitSize < bitSize) {
    SHEInt result(*this, (uint64_t)0);
    SHEInt add2(a);
    add2.reset(bitSize, a.isUnsigned);
    return this->addRaw(add2, result);
  }

  SHEInt result(*pubKey, 0, a.bitSize, isUnsigned);
  SHEInt add1(*this);
  add1.reset(a.bitSize, isUnsigned);
  return add1.addRaw(a, result);
}

SHEInt SHEInt::operator-(const SHEInt &a) const {
  if (a.isExplicitZero) {
    return *this;
  }
  if (isExplicitZero) {
   return -a;
  }
  SHEInt result(*this, (uint64_t)0);
  result.expandZero(); // unlike addition and multiplication, subtraction
                       // needs expanded vectors
  if (a.bitSize == bitSize) {
    return this->subRaw(a, result);
  }
  if (a.bitSize < bitSize) {
    SHEInt sub2(a);
    sub2.reset(bitSize, a.isUnsigned);
    return this->subRaw(sub2, result);
  }

  SHEInt sub1(*this);
  sub1.reset(a.bitSize, isUnsigned);
  result.reset(a.bitSize, isUnsigned);
  return sub1.subRaw(a, result);
}

// += and -= operators return the the same size as the 'this' pointer;
SHEInt &SHEInt::operator+=(const SHEInt &a) {
  // addRaw doesn't work if the target and the source is the same
  // value, so do it noarmally with a copy;
  *this = *this + a;
  return *this;
}

SHEInt &SHEInt::operator-=(const SHEInt &a) {
  // subRaw doesn't work if the target and the source is the same
  // value, so do it noarmally with a copy;
  *this = *this -a;
  return *this;
}

SHEInt SHEInt::operator+(uint64_t a) const {
    SHEInt aEncrypt(*pubKey, a, bitSize, isUnsigned);
    return *this + aEncrypt;
}

SHEInt SHEInt::operator-(uint64_t a) const {
    SHEInt aEncrypt(*pubKey, a, bitSize, isUnsigned);
    return *this - aEncrypt;
}

SHEInt &SHEInt::operator+=(uint64_t a) {
    SHEInt aEncrypt(*pubKey, a, bitSize, isUnsigned);
    return *this += aEncrypt;
}

SHEInt &SHEInt::operator-=(uint64_t a) {
    SHEInt aEncrypt(*pubKey, a, bitSize, isUnsigned);
    return *this -= aEncrypt;
}

SHEInt SHEInt::operator*(const SHEInt &a) const {
  if (a.isExplicitZero) {
    return a;
  }
  if (isExplicitZero) {
    return *this;
  }
  SHEInt result(*this, (uint64_t)0);
  if (bitSize < a.bitSize) {
    result.reset(a.bitSize,isUnsigned);
  }
  return this->mulRaw(a, result);
}

SHEInt &SHEInt::operator*=(const SHEInt &a) {
  if (a.isExplicitZero) {
    *this = a;
    return *this;
  }
  if (isExplicitZero) {
    return *this;
  }
  return this->mulRaw(a, *this);
}

// we use shifts and adds when we are multiplying with an unencrypted
// constant because that increases the error by less than a full on
// multiplication (decreasing the need for bootstraping)
SHEInt SHEInt::operator*(uint64_t a) const
{
  SHEInt result(*this, (uint64_t)0);

  // handle some quite options here
  if (a == 0) {
    return result;
  }

  if (isExplicitZero) {
    return result;
  }

  // find top bit in our unencrypted multiplier
  // note: topBit is declared outside the scope of
  // the 'for' loop so we can reference it later.
  int topBit;
  for (topBit=64; topBit > 0; topBit--) {
    if (a & (1<<(topBit-1))) {
      break;
    }
  }

  SHEInt current(*this);
  if (topBit > bitSize) {
    result.reset(topBit, isUnsigned);
    current.reset(topBit, isUnsigned);
  }
  for (int i=0; i < topBit; i++) {
    if (a & (1<<i)) {
      result += current;
    }
    current.leftShift(1);
  }
  return result;
}

SHEInt &SHEInt::operator*=(uint64_t a)
{
  *this = *this * a;
  return *this;
}

// See note in udivRaw for restrictions on this function
// We use udivRaw to do both unsigned and signed division by
// taking the signed case, and converting the parameters to
// unsigned, then reconstituting the sign at the end
SHEInt &SHEInt::divmod(const SHEInt &a, SHEInt *result, SHEInt *mod) const
{
  // if we can tell we are dividing by zero, return an error
  // if a is actually an encrypted 'zero' we can't tell that here.
  // currently we have to signalling for NaN like floating point, but none
  // for integers
  helib::assertTrue(result || mod, "either result or mod must be supplied");
  if (a.isUnencryptedZero()) {
    throw helib::LogicError("divide by zero");
  }
  if (isUnencryptedZero()) {
    if (result) *result = *this;
    if (mod) *mod = a;
    return result ? *result : * mod;
  }

  if (isUnsigned && a.isUnsigned) {
    return udivRaw(a, result, mod);
  }
  // force the values to unsigned values
  SHEInt dividend = abs();
  SHEInt divisor = a.abs();
  dividend.isUnsigned = true;
  divisor.isUnsigned = true;
  // do the unsigned division
  (void) dividend.udivRaw(divisor, result, mod);
  // udivRaw can be brutal on our levels, levelup before
  // we drop into select.
  if (result) {
    if (mod) {
      result->verifyArgs(*mod);
    } else {
      result->verifyArgs();
    }
  } else {
    mod->verifyArgs();
  }
  if (result) {
    result->isUnsigned = false;
    // set the final sign appropriately
    *result = (this->isNegative() ^ a.isNegative()).
              select(-(*result),*result);
  }
  if (mod) {
    mod->isUnsigned = false;
    *mod = isNegative().select(-(*mod),*mod);
  }
  return result ? *result : *mod;
}

SHEInt SHEInt::operator/(const SHEInt &a) const
{
  SHEInt result(*pubKey, 0, bitSize, true);
  return divmod(a, &result, nullptr);
}

SHEInt &SHEInt::divmod(const SHEInt &a, SHEInt &result, SHEInt &mod) const
{
  return divmod(a, &result, &mod);
}

//
// No real efficiency gain in division, just do the normal
// wrapping
//
SHEInt &SHEInt::operator/=(const SHEInt &a) {
  if (a.isUnencryptedZero()) {
    throw helib::LogicError("divide by zero");
  }
  *this = *this / a;
  return *this;
}

SHEInt SHEInt::operator/(uint64_t a) const {
  if (a == 0) {
    throw helib::LogicError("divide by integer zero");
  }
  SHEInt aEncrypt(*pubKey, a, bitSize, isUnsigned);
  return *this / aEncrypt;
}

SHEInt &SHEInt::operator/=(uint64_t a) {
  if (a == 0) {
    throw helib::LogicError("divide by integer zero");
  }
  SHEInt aEncrypt(*pubKey, a, bitSize, isUnsigned);
  return *this /= aEncrypt;
}

SHEInt SHEInt::operator%(const SHEInt &a) const
{
  SHEInt result(*pubKey, 0, bitSize, true);
  return divmod(a, nullptr, &result);
}

//
// No real efficiency gain in modulus, just do the normal
// wrapping
//
SHEInt &SHEInt::operator%=(const SHEInt &a) {
  *this = *this % a;
  return *this;
}

SHEInt SHEInt::operator%(uint64_t a) const {
  if (a == 0) {
    throw helib::LogicError("divide by integer zero (mod)");
  }
  SHEInt aEncrypt(*pubKey, a, bitSize, isUnsigned);
  return *this % aEncrypt;
}

SHEInt &SHEInt::operator%=(uint64_t a) {
  if (a == 0) {
    throw helib::LogicError("divide by integer zero (mod)");
  }
  SHEInt aEncrypt(*pubKey, a, bitSize, isUnsigned);
  return *this %= aEncrypt;
}

SHEInt SHEInt::operator>>(const SHEInt &a) const
{
  if (a.isExplicitZero) {
    return *this;
  }
  if (isExplicitZero) {
    return *this;
  }
  SHEInt result(*this, (uint64_t)0);
  if (log) {
    (*log) << (SHEIntSummary) *this << ">>" << (SHEIntSummary) a << "="
           << std::flush;
  }
  if (needRecrypt(a,160)) {
    SHEInt this_copy(*this);
    SHEInt a_copy(a);
    this_copy.verifyArgs(a_copy,160);
    this_copy.rightShift(a_copy, result);
    if (log) (*log) << (SHEIntSummary) result << std::endl;
    return result;
  }
  rightShift(a, result);
  if (log) (*log) << (SHEIntSummary) result << std::endl;
  return result;
}

SHEInt SHEInt::operator<<(const SHEInt &a) const
{
  if (a.isExplicitZero) {
    return *this;
  }
  if (isExplicitZero) {
    return *this;
  }
  SHEInt result(*this, (uint64_t)0);
  if (log) {
    (*log) << (SHEIntSummary) *this << "<<" << (SHEIntSummary) a << "="
           << std::flush;
  }
  if (needRecrypt(a,160)) {
    SHEInt this_copy(*this);
    SHEInt a_copy(a);
    this_copy.verifyArgs(a_copy,160);
    this_copy.leftShift(a_copy, result);
    if (log) (*log) << (SHEIntSummary) result << std::endl;
    return result;
  }
  leftShift(a,result);
  if (log) (*log) << (SHEIntSummary) result << std::endl;
  return result;
}

SHEInt &SHEInt::operator>>=(const SHEInt &a)
{
  *this = *this >> a;
  return *this;
}

SHEInt &SHEInt::operator<<=(const SHEInt &a)
{
  *this = *this << a;
  return *this;
}

SHEInt SHEInt::operator>>(uint64_t a) const
{
  if (a == 0) {
    return *this;
  }
  if (isExplicitZero) {
    return *this;
  }
  SHEInt result(*this);
  result.rightShift(a);
  return result;
}

SHEInt SHEInt::operator<<(uint64_t a) const
{
  if (a == 0) {
    return *this;
  }
  if (isExplicitZero) {
    return *this;
  }
  SHEInt result(*this);
  result.leftShift(a);
  return result;
}

SHEInt &SHEInt::operator>>=(uint64_t a)
{
  if (a == 0) {
    return *this;
  }
  if (isExplicitZero) {
    return *this;
  }
  rightShift(a);
  return *this;
}

SHEInt &SHEInt::operator<<=(uint64_t a)
{
  if (a == 0) {
    return *this;
  }
  if (isExplicitZero) {
    return *this;
  }
  leftShift(a);
  return *this;
}

SHEInt &SHEInt::operator++(void)
{
  *this += 1;
  return *this;
}

SHEInt &SHEInt::operator--(void)
{
  *this -= 1;
  return *this;
}

SHEInt SHEInt::operator++(int dummy)
{
  SHEInt result(*this);
  *this += 1;
  return result;
}

SHEInt SHEInt::operator--(int dummy)
{
  SHEInt result(*this);
  *this -= 1;
  return result;
}

///////////////////////////////////////////////////////////////////////////
//                      Bitwise operators.                                /
///////////////////////////////////////////////////////////////////////////
void SHEInt::bitNot(void)
{
  if (isExplicitZero) {
    *this = SHEInt(*pubKey,-1LL,bitSize,isUnsigned);
    return;
  }
  if (log) (*log) << (SHEIntSummary) *this << ".bitwiseNot=" << std::flush;
  verifyArgs(SHEINT_DEFAULT_LEVEL_TRIGGER/2);
  helib::CtPtrs_vectorCt wrapper(encryptedData);
  helib::bitwiseNot(wrapper, wrapper);
  if (log) (*log) << (SHEIntSummary) *this << std::endl;
}

SHEInt SHEInt::operator~(void) const
{
  if (isExplicitZero) {
    return SHEInt(*this,-1LL);
  }
  SHEInt result(*this);
  result.bitNot();
  return result;
}


SHEInt SHEInt::operator^(const SHEInt &a) const
{
  if (a.isExplicitZero) {
    return *this;
  }
  if (isExplicitZero) {
    return a;
  }

  SHEInt result(*this);
  // make sure they are all the same size, resize the to the larget
  SHEInt target(a);
  if (a.bitSize < result.bitSize) {
    target.reset(result.bitSize,a.isUnsigned);
  } else if (a.bitSize > result.bitSize) {
    result.reset(a.bitSize, isUnsigned);
  }
  result.verifyArgs(target);
  helib::CtPtrs_vectorCt wrapper(result.encryptedData);
  if (log) {
    (*log) << (SHEIntSummary)*this << ".bitwiseXOR(" << (SHEIntSummary) a << ","
        << (SHEIntSummary)result << ")=" << std::flush;
  }
  helib::bitwiseXOR(wrapper, wrapper,
                    helib::CtPtrs_vectorCt(target.encryptedData));
  if (log) (*log) << (SHEIntSummary)result << std::endl;
  return result;
}

SHEInt SHEInt::operator&(const SHEInt &a) const
{
  if (a.isExplicitZero) {
    return a;
  }
  if (isExplicitZero) {
    return *this;
  }
  SHEInt result(*this);
  // make sure they are all the same size, resize the to the larget
  SHEInt target(a);
  if (a.bitSize < result.bitSize) {
    target.reset(result.bitSize,a.isUnsigned);
  } else if (a.bitSize > result.bitSize) {
    result.reset(a.bitSize, isUnsigned);
  }
  helib::CtPtrs_vectorCt wrapper(result.encryptedData);
  if (log) {
    (*log) << (SHEIntSummary)*this << ".bitwiseAnd(" << (SHEIntSummary) a << ","
        << (SHEIntSummary)result << ")=" << std::flush;
  }
  result.verifyArgs(target);
  helib::bitwiseAnd(wrapper, wrapper,
                    helib::CtPtrs_vectorCt(target.encryptedData));
  if (log) (*log) << (SHEIntSummary)result << std::endl;
  return result;
}

SHEInt SHEInt::operator|(const SHEInt &a) const
{
  if (a.isExplicitZero) {
    return *this;
  }
  if (isExplicitZero) {
    return a;
  }
  SHEInt result(*this);
  // make sure they are all the same size, resize the to the larget
  SHEInt target(a);
  if (a.bitSize < result.bitSize) {
    target.reset(result.bitSize,a.isUnsigned);
  } else if (a.bitSize > result.bitSize) {
    result.reset(a.bitSize, isUnsigned);
  }
  result.verifyArgs(target);
  // bitwiseOr can't handle input and output buffers being the same
  std::vector<helib::Ctxt> lhs = result.encryptedData;
  helib::CtPtrs_vectorCt wrapper(result.encryptedData);
  if (log) {
    (*log) << (SHEIntSummary)*this << ".bitwiseOr(" << (SHEIntSummary) a << ","
        << (SHEIntSummary)result << ")=" << std::flush;
  }
  helib::bitwiseOr(wrapper,helib::CtPtrs_vectorCt(lhs),
                   helib::CtPtrs_vectorCt(target.encryptedData));
  if (log) (*log) << (SHEIntSummary)result << std::endl;
  return result;
}

SHEInt &SHEInt::operator^=(const SHEInt &a)
{
  if (a.isExplicitZero) {
    return *this;
  }
  if (isExplicitZero) {
    *this = a;
    return *this;
  }

  // make sure they are all the same size, resize the to the larget
  SHEInt target(a);
  if (a.bitSize < bitSize) {
    target.reset(bitSize,a.isUnsigned);
  } else if (a.bitSize > bitSize) {
    reset(a.bitSize, isUnsigned);
  }
  verifyArgs(target);
  helib::CtPtrs_vectorCt wrapper(encryptedData);
  helib::bitwiseXOR(wrapper, wrapper,
                    helib::CtPtrs_vectorCt(target.encryptedData));
  return *this;
}

SHEInt &SHEInt::operator&=(const SHEInt &a)
{
  if (a.isExplicitZero) {
    *this = a;
    return *this;
  }
  if (isExplicitZero) {
    return *this;
  }
  // make sure they are all the same size, resize the to the larget
  SHEInt target(a);
  if (a.bitSize < bitSize) {
    target.reset(bitSize,a.isUnsigned);
  } else if (a.bitSize > bitSize) {
    reset(a.bitSize, isUnsigned);
  }
  verifyArgs(target);
  helib::CtPtrs_vectorCt wrapper(encryptedData);
  helib::bitwiseAnd(wrapper, wrapper,
                    helib::CtPtrs_vectorCt(target.encryptedData));
  return *this;
}

SHEInt &SHEInt::operator|=(const SHEInt &a)
{
  if (a.isExplicitZero) {
    return *this;
  }
  if (isExplicitZero) {
    *this=a;
    return *this;
  }
  // make sure they are all the same size, resize the to the larget
  SHEInt target(a);
  if (a.bitSize < bitSize) {
    target.reset(bitSize,a.isUnsigned);
  } else if (a.bitSize > bitSize) {
    reset(a.bitSize, isUnsigned);
  }
  verifyArgs(target);
  // bitwiseOr can't handle overlapped buffers
  std::vector<helib::Ctxt> lhs = encryptedData;
  helib::CtPtrs_vectorCt wrapper(encryptedData);
  helib::bitwiseOr(wrapper,helib::CtPtrs_vectorCt(lhs),
                   helib::CtPtrs_vectorCt(target.encryptedData));
  return *this;
}

SHEInt SHEInt::operator^(uint64_t a) const
{
  if (a == 0) {
    return *this;
  }
  if (isExplicitZero) {
    return SHEInt(*this, a);
  }

  SHEInt result(*this);
  // make sure they are all the same size, resize the to the larget
  result ^= a;
  return result;
}

SHEInt SHEInt::operator&(uint64_t a) const
{
  if (a == 0) {
    return SHEInt(*this, (uint64_t)0);
  }
  if (isExplicitZero) {
    return *this;
  }
  SHEInt result(*this);
  result &= a;
  return result;
}

SHEInt SHEInt::operator|(uint64_t a) const
{
  if (a == 0) {
    return *this;
  }
  if (isExplicitZero) {
    return SHEInt(*this, a);
  }
  SHEInt result(*this);
  result |= a;
  return result;
}

SHEInt &SHEInt::operator^=(uint64_t a)
{
  if (a == 0) {
    return *this;
  }
  if (isExplicitZero) {
    SHEInt result(*this, a);
    *this = result;
    return *this;
  }

  for (int i=0; i < bitSize; i++) {
    if (a & (1<<i)) {
      encryptedData[i].addConstant(NTL::ZZX(1L));
    }
  }
  return *this;
}

SHEInt &SHEInt::operator&=(uint64_t a)
{
  if (a == 0) {
    isExplicitZero = true;
    return *this;
  }
  if (isExplicitZero) {
    return *this;
  }
  for (int i=0; i < bitSize; i++) {
    if ((a & (1<<i)) == 0) {
      encryptedData[i].clear();
    }
  }
  return *this;
}

SHEInt &SHEInt::operator|=(uint64_t a)
{
  if (a == 0) {
    return *this;
  }
  if (isExplicitZero) {
    *this= SHEInt(*this, a);
    return *this;
  }
  SHEInt one(*pubKey, 1, 1, true);
  for (int i=0; i < bitSize; i++) {
    if (a & (1<<i)) {
      encryptedData[i] = one.encryptedData[0];
    }
  }
  return *this;
}


///////////////////////////////////////////////////////////////////////////
//                      Logical operators.                                /
///////////////////////////////////////////////////////////////////////////
// note: there is recursion going on here.
// all logical operators always return bitSize == 1, isUnsigned = true,
// AKA SHEBool. They can take non-Bool inputs, with 0=0 and nonZero=1

// unlike isZero, this function tells us that the underlying SHEInt is
// known to be an unencrypted zero. This can be used in a normal if
// statement
bool SHEInt::isUnencryptedZero(void) const
{
  if (isExplicitZero) {
    return true;
  }
  for (int i=0; i< bitSize; i++) {
    if (!encryptedData[i].isEmpty()) {
      return false;
    }
  }
  return true;
}

void SHEInt::logicNot(void)
{
  if (bitSize != 1) {
    // isZero will call logicNot again, but with a bitSize of 1, so
    // we don't loop forever
    *this = isZero();
    return;
  }
  bitNot();
}

SHEInt SHEInt::isZero(void) const
{
  if (isExplicitZero)  {
    return SHEInt(*pubKey, 1, 1, true);
  }
  return !isNotZero();
}

SHEInt SHEInt::isNotZero(void) const
{
  if (isExplicitZero)  {
    return SHEInt(*pubKey, (uint64_t)0, 1, true);
  }
  if (bitSize == 1) {
    return *this;
  }
  return isNegative() || isPositive();
}

SHEInt SHEInt::isNegative(void) const
{
  SHEInt isNeg(*pubKey, 1, 1, true);
  if (isUnsigned || isExplicitZero) {
    isNeg.encryptedData.clear();
    isNeg.isExplicitZero=true;
    return isNeg;
  }
  isNeg.encryptedData[0] = encryptedData[bitSize-1];
  return isNeg;
}

SHEInt SHEInt::isNonNegative(void) const
{
  SHEInt isNonNeg = isNegative();
  isNonNeg.logicNot();
  return isNonNeg;
}


SHEInt SHEInt::isPositive(void) const
{
  if (isExplicitZero)  {
    return SHEInt(*pubKey, (uint64_t)0, 1, true);
  }
  if (isUnsigned) {
    SHEInt forceSigned(*this);
    // extend to the high bit is zero
    forceSigned.reset(bitSize+1,true);
    forceSigned.isUnsigned = false;
    return (-forceSigned).isNegative();
  }
  SHEInt thisNeg = -*this;
  return thisNeg.isNegative();
}


SHEInt SHEInt::isNonPositive(void) const
{
  SHEInt isNonPos = isPositive();
  isNonPos.logicNot();
  return isNonPos;
}

// handle the case where the sign is different, in this case
// expand the unsigned value to get a leading zero and do a signed
// compare.
void SHEInt::docmp(const SHEInt &a, SHEInt &gt, SHEInt &lt) const
{
  if (isUnsigned != a.isUnsigned) {
    if (isUnsigned) {
      SHEInt thiscmp(*this);
      thiscmp.reset(getSize()+1,true);
      thiscmp.reset(getSize()+1,false);
      thiscmp.cmpRaw(a, gt, lt);
    } else {
      SHEInt acmp(a);
      acmp.reset(getSize()+1,true);
      acmp.reset(getSize()+1,false);
      cmpRaw(acmp, gt, lt);
    }
  } else {
    // signs are the same, just do a normal compare
    cmpRaw(a, gt, lt);
  }
}

SHEInt SHEInt::bitgt(const SHEInt &a) const
{
  SHEInt a_prime(a);
  a_prime.reset(compareBestSize(a.bitSize),isUnsigned);
  // do the compare without the overhead of subtract
  // by finding the highest bit.
  // This is faster than subraction, because it operates
  // on single bits, but it does more operations so requires
  // more levels to succeed.
  SHEInt b(*this);
  b.reset(a_prime.bitSize,isUnsigned);
  b.verifyArgs(a_prime, SHEINT_DEFAULT_LEVEL_TRIGGER);
  SHEInt result(*pubKey, 1, 1, true);
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
         reCryptBitCounter();
      }
      if (localResult.bitCapacity() < SHEINT_LEVEL_THRESHOLD) {
         if (log) (*log) << "add localResult" << std::endl;
         //bits.push_back(localResult);
         publicKey.reCrypt(localResult);
         reCryptBitCounter();
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
  return result;
}

SHEInt SHEInt::isgt(const SHEInt &a) const
{
  SHEInt gt(*pubKey, 1, 1, true);
  SHEInt lt(*pubKey, 1, 1, true);

  docmp(a, gt, lt);
  return gt;
}

SHEInt SHEInt::islt(const SHEInt &a) const
{
  SHEInt gt(*pubKey, 1, 1, true);
  SHEInt lt(*pubKey, 1, 1, true);

  docmp(a, gt, lt);
  return lt;
}

// presumes input is signed, return 1 if input is positive, -1 if input is
// negative, and zero if input is zero
SHEInt SHEInt::reduce(void) const
{
  SHEInt result(*pubKey, 1, 2, false);
  result.setBitHigh(0,getBitHigh(0));
  result.setBit(0,isZero());
  return result;
}

// testing only
SHEInt SHEInt::_bitgt(const SHEInt &a) const
{
  if (isExplicitZero) {
    if (a.isUnsigned) {
      return *this;
    }
    return a.isPositive();
  }
  if (a.isExplicitZero) {
    if (isUnsigned) {
      return isNotZero();
    }
    return isPositive();
  }
  return bitgt(a);
}

// returns 0 if this == a, -1 if this < a and 1 if this > a
SHEInt SHEInt::cmp(const SHEInt &a) const
{
  SHEInt _isGt(*pubKey, 1, 2, false);
  SHEInt _isLt(*pubKey, -1, 2, false);
  SHEInt _isZero(*pubKey, (uint64_t)0, 2, false);

  if (isExplicitZero) {
    if (a.isExplicitZero) {
      return _isZero;
    }
    if (a.isUnsigned) {
      return a.isZero().select(_isZero,_isLt);
    }
    return a.reduce();
  }
  if (a.isExplicitZero) {
    if (isUnsigned) {
      return isNotZero().select(_isGt, _isZero);
    }
    return reduce();
  }
  SHEInt gt(*pubKey, 1, 1, true);
  SHEInt lt(*pubKey, 1, 1, false);

  docmp(a, gt, lt);
  lt.reset(2,false); // 1 -> -1 (11 = 3), 0 -> 0
  gt.reset(2,true);  // 1 ->  1 (01 = 1), 0 -> 0
  gt.reset(2,false); // make gt_ signed so the final result is signed
  return lt ^ gt;    // xor is the most efficent way of combing
                     // lt_ and gt_, in the problematic case where
                     // they are both 1 (an error in cmpRaw), then it
                     // will return a unique 2 (or -2)
}

SHEInt SHEInt::operator!(void) const
{
  SHEInt result(*this);
  result.logicNot();
  return result;
}

SHEInt SHEInt::select(const SHEInt &a_true, const SHEInt &a_false) const
{
  if (isExplicitZero) {
    return a_false;
  }
  if (bitSize != 1) {
    return isNotZero().select(a_true, a_false);
  }
  SHEInt mask(*this);
  if (mask.needRecrypt(a_true,a_false)) {
  // if we need to handle preemptive recrypt, do the copy now
    SHEInt r_true(a_true), r_false(a_false);
    mask.verifyArgs(r_true, r_false);
    mask.reset(std::max(a_true.bitSize,a_false.bitSize), false);
    mask.isUnsigned = a_true.isUnsigned || a_false.isUnsigned;
    return (mask&r_true) ^ ((~mask)&r_false);
  }
  mask.reset(std::max(a_true.bitSize,a_false.bitSize), false);
  mask.isUnsigned = a_true.isUnsigned || a_false.isUnsigned;
  return (mask&a_true) ^ ((~mask)&a_false);
}

SHEInt SHEInt::select(const SHEInt &a_true, uint64_t a_false) const
{
  if (isExplicitZero) {
    return SHEInt(a_true,a_false);
  }
  if (bitSize != 1) {
    return isNotZero().select(a_true, a_false);
  }
  SHEInt mask(*this);
  if (mask.needRecrypt(a_true)) {
    SHEInt r_true(a_true);
    mask.verifyArgs(r_true);
    mask.reset(a_true.bitSize, false);
    mask.isUnsigned = a_true.isUnsigned;
    return (mask&r_true) ^ ((~mask)&a_false);
  }
  mask.reset(a_true.bitSize, false);
  mask.isUnsigned = a_true.isUnsigned;
  // xor is cheaper than or, and it's safe because
  // one side is guarrenteed to be zero
  return (mask&a_true) ^ ((~mask)&a_false);
}

SHEInt SHEInt::select(uint64_t a_true, const SHEInt &a_false) const
{
  if (isExplicitZero) {
    return a_false;
  }
  if (bitSize != 1) {
    return isNotZero().select(a_true, a_false);
  }
  SHEInt mask(*this);
  if (mask.needRecrypt(a_false)) {
    SHEInt r_false(a_false);
    mask.verifyArgs(r_false);
    mask.reset(a_false.bitSize, false);
    mask.isUnsigned = a_false.isUnsigned;
    return (mask&a_true) ^ ((~mask)&r_false);
  }
  mask.reset(a_false.bitSize, false);
  mask.isUnsigned = a_false.isUnsigned;
  return (mask&a_true) ^ ((~mask)&a_false);
}

inline static int getBitSize(int64_t a)
{
  int i;
  int64_t topBit = a&(1ULL<<63);
  for(i=62; i > 0; i--) {
    if (topBit != a&(1ULL<<i)) {
      return i+2;
    }
  }
  return 1; // encode at least 1 bit;
}

SHEInt SHEInt::select(uint64_t a_true, uint64_t a_false) const
{
  int size = std::max(getBitSize(a_true), getBitSize(a_false));
  if (isExplicitZero) {
    // we probably need versions of this that handle other int type
    return SHEInt(*pubKey, a_false, size, false);
  }
  if (bitSize != 1) {
    return isNotZero().select(a_true, a_false);
  }
  SHEInt mask(*this);
  mask.verifyArgs();
  mask.reset(size, false); // reset sign extends
  return (mask&a_true) ^ ((~mask)&a_false);
}


// && and || call themselves again if bitSize != 1 to reduce
// down to a logical bit. Then we can do a bitwize &
SHEInt SHEInt::operator&&(const SHEInt &a) const
{
  if (isExplicitZero || a.isExplicitZero) {
    return SHEInt(*pubKey, (uint64_t)0, 1, true);
  }
  // first handle non-logical values
  if (a.bitSize != 1) {
    return *this && a.isNotZero();
  }
  if (bitSize != 1) {
    return a && isNotZero();
  }
  // we only have logical bits now
  return *this & a;
}

SHEInt SHEInt::operator||(const SHEInt &a) const
{
  if (isExplicitZero && a.isExplicitZero) {
    return SHEInt(*pubKey, (uint64_t)0, 1, true);
  }
  // first handle non-logical values
  if (a.bitSize != 1) {
    return *this || a.isNotZero();
  }
  if (bitSize != 1) {
    return a || isNotZero();
  }
  // we only have logical bits now
  return *this | a;
}

// for comparison operations, we increase the number of bits to prevent
// Overflow conditions
int SHEInt::compareBestSize(int size) const
{
  // find the largest of the sizes
  if (bitSize > size) {
    size = bitSize;
  }
  return size;
}

SHEInt SHEInt::operator<(const SHEInt &a) const
{
  return (a > *this);
}

// there are two ways to do this compare.
// 1) bitwise: look for the value with the highest 1 bit, then
// correct for sign.
// 2) extend the two values by one bit (sign extended) and then subtract a-b.
// If the result is negative() then we return true.
// The latter is more expensive than the bitwise search so we use the former.
SHEInt SHEInt::operator>(const SHEInt &a) const
{
  if (log) {
    (*log) << (SHEIntSummary)*this << ">" << (SHEIntSummary)a << "="
           << std::flush;
  }
  if (isExplicitZero) {
    if (a.isUnsigned) {
      if (log) { (*log) << (SHEIntSummary)*this << std::endl; }
      return *this; // if we are zero, and a is unsigned, we cannot be > a
    }
    if (log) { (*log) << (SHEIntSummary)a.isPositive() << std::endl; }
    return a.isPositive(); // true if a is positive
  }
  if (a.isExplicitZero) {
    if (isUnsigned) {
      if (log) { (*log) << (SHEIntSummary)isNotZero() << std::endl; }
      return isNotZero(); // if a is zero we are > a if we aren't zero
    }
    if (log) { (*log) << (SHEIntSummary)isNotZero() << std::endl; }
    return isPositive(); // if w are zero or negative we are < a
  }
#if SHEINT_COMPARE == SHEINT_USE_SUB
  SHEInt a_prime(a);
  a_prime.reset(compareBestSize(a.bitSize)+1,a.isUnsigned);
  if (log) (*log) << std::endl << "Doing subtraction" << std::endl;
  SHEInt result = (*this-a_prime).getBitHigh(0);
#elif SHEINT_COMPARE == SHEINT_USE_BITS
  SHEInt result = bitgt(a);
#else
  SHEInt result = isgt(a);
#endif
  if (log) { (*log) << (SHEIntSummary)result << std::endl; }
  return result;
}

SHEInt SHEInt::operator>=(const SHEInt &a) const
{
  return !(*this < a);
}

SHEInt SHEInt::operator<=(const SHEInt &a) const
{
  return !(*this > a);
}

SHEInt SHEInt::operator!=(const SHEInt &a) const
{
  SHEInt result = *this ^ a;
  return result.isNotZero();
}

SHEInt SHEInt::operator==(const SHEInt &a) const
{
  SHEInt result = *this ^ a;
  return result.isZero();
}

SHEInt SHEInt::operator&&(bool a) const
{
  if (a) {
    return this->isNotZero();
  }
  return SHEInt(*pubKey, (uint64_t)0, 1, true);
}

SHEInt SHEInt::operator||(bool a) const
{
  if (!a) {
    return this->isNotZero();
  }
  return SHEInt(*pubKey, 1, 1, true);
}

SHEInt SHEInt::operator<(uint64_t a) const
{
    SHEInt heA(*pubKey, a, bitSize, true);
    return *this < heA;
}

SHEInt SHEInt::operator>(uint64_t a) const
{
    SHEInt heA(*pubKey, a, bitSize, true);
    return *this > heA;
}

SHEInt SHEInt::operator<=(uint64_t a) const
{
    SHEInt heA(*pubKey, a, bitSize, true);
    return *this <= heA;
}

SHEInt SHEInt::operator>=(uint64_t a) const
{
    SHEInt heA(*pubKey, a, bitSize, true);
    return *this >= heA;
}

SHEInt SHEInt::operator!=(uint64_t a) const
{
    SHEInt heA(*pubKey, a, bitSize, isUnsigned);
    return *this != heA;
}

SHEInt SHEInt::operator==(uint64_t a) const
{
    SHEInt heA(*pubKey, a, bitSize, isUnsigned);
    return *this == heA;
}

SHEInt SHEInt::operator<(int64_t a) const
{
    SHEInt heA(*pubKey, a, bitSize, false);
    return *this < heA;
}

SHEInt SHEInt::operator>(int64_t a) const
{
    SHEInt heA(*pubKey, a, bitSize, false);
    return *this > heA;
}

SHEInt SHEInt::operator>=(int64_t a) const
{
    SHEInt heA(*pubKey, a, bitSize, false);
    return *this >= heA;
}

SHEInt SHEInt::operator<=(int64_t a) const
{
    SHEInt heA(*pubKey, a, bitSize, false);
    return *this <= heA;
}
