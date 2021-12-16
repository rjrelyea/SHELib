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
#include "SHEUtil.h"
#include "SHEMagic.h"
#include "helibio.h"

// T can be any class that is a target or source of a select(SHEInt, T, T),
// a void T::clear(void), and a full set of reCrypt methods.
// function (SHEInt and subclasses, SHEString and subclasses, SHEFp and
// subclasses, etc.)
template<class T>
class SHEVector : public std::vector<T>
{
private:
  T model;
public:
  static constexpr std::string_view typeName = "SHEVector";
  SHEVector(const SHEPublicKey &pubKey) :
             std::vector<T>(0,T(pubKey)), model(pubKey) { model.clear(); }
  SHEVector(const T &model_, const std::vector<T> &v) :
            std::vector<T>(v,model_), model(model_) { model.clear(); }
  SHEVector(const T &model_, int size) : std::vector<T>(size, model_),
            model(model_) { model.clear(); }
  SHEVector(const SHEVector<T> &a) : std::vector<T>(a), model(a.model)
           { model.clear(); }
  // unlike the normal operator[], we can't return the reference
  // because we don't know it. This will trigger errors in programs
  // the try to set arrays. To add an element @ location you need to
  // use assign. NOTE: the normal in operator[](int) is still valid
  T operator[](const SHEInt &index) const {
    return this->at(index);
  }
  T &operator[](int i) {
    std::vector<T> &narrow= *this;
    return narrow[i];
  }
  const T &operator[](int i) const {
    const std::vector<T> &narrow= *this;
    return narrow[i];
  }
  // these functions to 'natural' bounds checking, in that we'll return
  // the value in the given slot, or an encrypted zero. Since the index and
  // the return value is encrypted, we don't know (only the user who later
  // decrypts the result will know if we returned the zero.
  T at(const SHEInt &index) const {
    T retVal(model);
    const std::vector<T> &narrow = *this;
    for (int i=0; i < narrow.size(); i++) {
      retVal = select(i == index, narrow.at(i), retVal);
    }
    return retVal;
  }
  const T &at(size_t i) const {
    const std::vector<T> &narrow = *this;
    return narrow.at(i);
  }
  T &at(size_t i) {
    std::vector<T> &narrow = *this;
    return narrow.at(i);
  }
  // if index is out of range, this will return none
  void assign(const SHEInt &index, const T &value)
  {
    std::vector<T> &narrow = *this;
    for (int i=0; i < narrow.size(); i++) {
      narrow[i] = select(i == index, value, narrow[i]);
    }
    return;
  }
  void assign(size_t i, const T &value)
  {
    std::vector<T> &narrow = *this;
    narrow.assign(i, value);
  }
  // override the base class resize to pass the model
  void resize(size_t n)
  {
    std::vector<T> &narrow = *this;
    narrow.resize(n, model);
  }
  void resize(size_t n, const T &val)
  {
    std::vector<T> &narrow = *this;
    narrow.resize(n, val);
  }

  // to decrypt, we would need to add the unencrypted type to the template
  long bitCapacity(void) const
  {
    const std::vector<T> &narrow = *this;
    long capacity = LONG_MAX;
    for (auto element : narrow) {
      capacity = std::min(capacity,element.bitCapacity());
    }
    return capacity;
  }
  bool isCorrect(void) const
  {
    const std::vector<T> &narrow = *this;
    for (auto element : narrow) {
      if (!element.isCorrect()) {
        return false;
      }
    }
    return true;
  }

  double securityLevel(void) const { return model.securityLevel(); }
  bool needRecrypt(long level=SHEINT_DEFAULT_LEVEL_TRIGGER) const
  {
    const std::vector<T> &narrow = *this;
    for (auto element : narrow) {
      if (element.needRecrypt(level)) return true;
    }
    return false;
  }
  void verifyArgs(long level=SHEINT_DEFAULT_LEVEL_TRIGGER)
  {
    if (needRecrypt(level)) reCrypt();
  }
  void reCrypt(void)
  {
    std::vector<T> &narrow = *this;
    int i;
    // lump together up to 6 elements to take advantage of
    // packed recrypt.
    for (int i=5; i < narrow.size(); i+=6) {
      narrow[i].reCrypt(narrow[i-1],narrow[i-2],narrow[i-3],
                        narrow[i-4],narrow[i-5]);
    }
    switch (i - narrow.size()) {
    case 5:
      narrow[i].reCrypt(narrow[i-4], narrow[i-3], narrow[i-2], narrow[i-1]);
      break;
    case 4:
      narrow[i].reCrypt(narrow[i-3], narrow[i-2], narrow[i-1]);
      break;
    case 3:
      narrow[i].reCrypt(narrow[i-2], narrow[i-1]);
      break;
    case 2:
      narrow[i].reCrypt(narrow[i-1]);
      break;
    case 1:
      narrow[i].reCrypt();
      break;
    case 0:
      break;
    }
  }
  void writeTo(std::ostream& str) const
  {
    const std::vector<T> &narrow = *this;
    write_raw_int(str, SHEVectorMagic); // magic to say we're a SHEVector
    write_raw_int(str, narrow.size());
    model.writeTo(str);
    for (auto elem : narrow) {
      elem.writeTo(str);
    }
  }

  void writeToJSON(std::ostream& str) const
  { helib::executeRedirectJsonError<void>([&]() { str << writeToJSON(); }); }

  helib::JsonWrapper writeToJSON(void) const
  {
    auto body = [*this]() {
      const std::vector<T> &narrow = *this;
      json j = {{"model", helib::unwrap(this->model.writeToJSON())},
                {"vector", helib::writeVectorToJSON(narrow)}};
      return helib::wrap(helib::toTypedJson<SHEVector<T>>(j));
    };
    return helib::executeRedirectJsonError<helib::JsonWrapper>(body);
  }
  static SHEVector<T> readFrom(std::istream& str,
                               const SHEPublicKey &pubKey)
  {
   SHEVector<T> a(pubKey);
   a.read(str);
   return a;
  }
  static SHEVector<T> readFromJSON(std::istream& str,
                                   const SHEPublicKey &pubKey)
  {
    return helib::executeRedirectJsonError<SHEVector<T>>([&]() {
      json j;
      str >> j;
      return readFromJSON(helib::wrap(j), pubKey);
    });
  }

  static SHEVector<T> readFromJSON(const helib::JsonWrapper& j,
                                   const SHEPublicKey &pubKey)
  {
    SHEVector<T> a(pubKey);
    a.readFromJSON(j);
    return a;
  }

  void read(std::istream& str)
  {
    long magic;
    size_t len;
    std::vector<T> &narrow = *this;

    magic = read_raw_int(str);
    helib::assertEq<helib::IOError>(magic, SHEVectorMagic,
                                    "not an SHEVector on the stream");
    len = read_raw_int(str);
    model.read(str);
    narrow.resize(len);
    for (int i=0; i < len; i++) {
      narrow[i].read(str);
    }
  }

  void readFromJSON(std::istream&str)
  {
    return helib::executeRedirectJsonError<void>([&]() {
      json j;
      str >> j;
      return readFromJSON(helib::wrap(j));
    });
  }

  void readFromJSON(const helib::JsonWrapper &jw)
  {
    std::vector<T> &narrow = *this;
    auto body = [&]() {
      json j = helib::fromTypedJson<SHEVector<T>>(unwrap(jw));
      this->model.readFromJSON(helib::wrap(j.at("model")));
      helib::readVectorFromJSON(j.at("vector"), narrow, this->model);
    };

    helib::executeRedirectJsonError<void>(body);
  }

  void readJSON(const helib::JsonWrapper &jw) { readFromJSON(jw); }

  // give a simple import/export function as well
  unsigned char *flatten(int &size, bool ascii) const
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
};

// access an unencrypted array with an encrypted index
// Unencrypted must match an Encrypted select function
//  example: SHEFp and shemaxfloat_t, or SHEInt and uint64_t
template<class Encrypted, class Unencrypted>
inline Encrypted getArray(const Encrypted &_default, Unencrypted *a,  size_t size,
                          const SHEInt &index)
{
  Encrypted retVal(_default);
  for (uint64_t i=0; i < size; i++) {
    retVal = select(i == index, a[i], retVal);
  }
  return retVal;
}


// access an unencrypted vector with an encrypted index
// Unencrypted must match an Encrypted select function
//  example: SHEFp and shemaxfloat_t, or SHEInt and uint64_t
template<class Encrypted, class Unencrypted>
inline Encrypted getVector(const Encrypted &_default,
                          const std::vector<Unencrypted> &a,
                          const SHEInt &index)
{
  Encrypted retVal(_default);
  for (int i=0; i < a.size(); i++) {
    retVal = select(i == index, a[i], retVal);
  }
  return retVal;
}

// access an unencrypted map with an encrypted key.
// Unencrypted must match an Encrypted select function
//  example: SHEFp and shemaxfloat_t, or SHEInt and uint64_t
// UnencryptedKey must match an Encrypted operator== function
//  example: SHEFp and shemaxfloat_t, or SHEInt and uint64_t
template<class EncryptedKey,   class EncryptedValue,
         class UnencryptedKey, class UnencryptedValue>
inline EncryptedValue getMap(const EncryptedValue &_default,
                             const std::unordered_map<UnencryptedKey,
                                                      UnencryptedValue> &a,
                             const EncryptedKey &searchKey)
{
  EncryptedValue retVal(_default);
  for (const auto& [key,value] : a) {
    retVal = select(searchKey == key, value, retVal);
  }
  return retVal;
}

#endif
