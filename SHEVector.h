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
};
#endif
