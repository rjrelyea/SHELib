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
#include "SHEio.h"
#include "SHEMagic.h"
#include "helibio.h"

// T can be any class that is a target or source of a select(SHEInt, T, T)
// and has a void T::clear(void) method.
// function (SHEInt and subclasses, SHEString and subclasses, SHEFp and
// subclasses, etc.)
template<class T>
class SHEVector : public std::vector<T>
{
private:
  T model;
public:
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
  T operator[](const SHEInt &index) {
    return this->at(index);
  }
  T &operator[](int i) {
    std::vector<T> &narrow= *this;
    return narrow[i];
  }
  // these functions to 'natural' bounds checking, in that we'll return
  // the value in the given slot, or an encrypted zero. Since the index and
  // the return value is encrypted, we don't know (only the user who later
  // decrypts the result will know
  T at(const SHEInt &index) {
    T retVal(model);
    std::vector<T> &narrow = *this;
    for (int i=0; i < narrow.size(); i++) {
      retVal = select(i == index, narrow.at(i), retVal);
    }
    return retVal;
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
  // to decrypt, we would need to add the unencrypted type to the template
  long bitCapacity(void) const {
    std::vector<T> &narrow = *this;
    long capacity = LONG_MAX;
    for (auto element : narrow) {
      capacity = std::min(capacity,element.bitCapacity());
    }
    return capacity;
  }
  double securityLevel(void) const { return model.securityLevel(); }
  bool needRecrypt(long level=SHEINT_DEFAULT_LEVEL_TRIGGER) const {
    std::vector<T> &narrow = *this;
    for (auto element : narrow) {
      if (element.needRecrypt(level)) return true;
    }
    return false;
  }
  void verifyArgs(long level=SHEINT_DEFAULT_LEVEL_TRIGGER) {
    if (needRecrypt(level)) reCrypt();
  }
  void reCrypt(void) {
    std::vector<T> &narrow = *this;
    for (int i=1; i < narrow.size(); i+=2) {
      narrow[i].reCrypt(narrow[i-1]);
    }
    if (narrow.size() & 1) {
      narrow.back().reCrypt();
    }
  }
  void writeTo(std::ostream& str) const
  {
    std::vector<T> &narrow = *this;
    write_raw_int(str, SHEVectorMagic); // magic to say we're a SHEVector
    write_raw_int(str, narrow.size());
    model.writeTo(str);
    for (auto elem : narrow) {
      elem.writeTo(str);
    }
  }

  void writeToJSON(std::ostream& str) const
  { helib::executeRedirectJsonError<void>([&]() { str << writeJSON(); }); }
  
  helib::JsonWrapper writeJSON(void) const
  { 
    auto body = [*this]() {
      std::vector<T> &narrow = *this;
      json j = {{"model", this->model},
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
      this->model = j.at("model");
      narrow = j.at("vector");
      this->alloc = SHEInt8(this->eLen, 0);
    };

    helib::executeRedirectJsonError<void>(body);
  }

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
#endif
