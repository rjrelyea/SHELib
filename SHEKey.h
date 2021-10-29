//
// create a hormorphic key to do Mathematic operations. Keys store
// 1 bit per slot, and use BGV_Binary_aritmetic
//
#ifndef SHEkey_H
#define SHEkey_H 1
#include <iostream>
#include <helib/helib.h>
#include <helib/intraSlot.h>
#include "SHEContext.h"

class SHEPublicKey {
private:
  static std::ostream *log;
  bool empty;
  helib::PubKey *publicKey;
  bool hasEncoding;
  SHEContextType type;
  long contextSecurityLevel;
  long contextCapacity;
  std::vector<helib::zzX> unpackSlotEncoding;
public:
  static constexpr std::string_view typeName = "SHEPublicKey";
  ~SHEPublicKey() {}
  SHEPublicKey(): empty(true), publicKey(nullptr), hasEncoding(false) {}
  SHEPublicKey(helib::PubKey *pubKey, SHEContextType type_, long sl, long cap):
    empty(false), publicKey(nullptr), hasEncoding(false), type(type_),
    contextSecurityLevel(sl), contextCapacity(cap)
    { publicKey = pubKey; }
  SHEPublicKey &operator=(const SHEPublicKey &pubKey) {
    empty = pubKey.empty;
    publicKey = nullptr;
    // We have two ways to handle this:
    //  1) copy the encoding if we have it, or
    //  2) always mark hasEncoding to false and regenerate it as necessary.
    // Option 2 assume regenerating is expensive. We still have 'fast' copies
    // of publicKeys before we get an encoding, so it's probably the best
    // option.
    hasEncoding = pubKey.hasEncoding;
    if (hasEncoding) {
      unpackSlotEncoding = pubKey.unpackSlotEncoding;
    }
    if (!empty) {
      type = pubKey.type;
      contextSecurityLevel = pubKey.contextSecurityLevel;
      contextCapacity = pubKey.contextCapacity;
      publicKey = pubKey.publicKey;
    }
    return *this;
  }
  SHEPublicKey(const SHEPublicKey &pubKey) { *this = pubKey; }
  SHEPublicKey(unsigned char *data, int size);
  const helib::PubKey &getPublicKey(void) const {
        helib::assertFalse(empty, "attempt to use an empty SHEPublicKey");
        return *publicKey;
  }
  const helib::Context &getHEContext(void) const
        { return getPublicKey().getContext(); }
  const helib::EncryptedArray &getEncryptedArray(void) const
        { return getHEContext().getEA(); }
  const std::vector<helib::zzX> *getUnpackSlotEncoding(void) const {
        if (!hasEncoding) {
          // we are updating the cache, so we treat this as a logical
          // const (we aren't changing anything, we are just remembering
          // our calculated value for the future)
          // cast away the consts to allow that to happen.
          helib::buildUnpackSlotEncoding(
                  (std::vector<helib::zzX> &)unpackSlotEncoding,
                  getEncryptedArray());
          *((bool *)&hasEncoding) = true;
        }
        return &unpackSlotEncoding;
  }
  double securityLevel(void) const
    { return getHEContext().securityLevel(); }
  static void setLog(std::ostream& str) { log = &str; }
  static std::ostream *getLog(void) { return log; }
  // io functions
  // use helib standard intput, outputs methods

  void writeTo(std::ostream& str) const;
  void writeToJSON(std::ostream& str) const;
  helib::JsonWrapper writeToJSON(void) const;
  void readFrom(std::istream& str);
  void readFromJSON(std::istream& str);
  void readFromJSON(const helib::JsonWrapper& jw);
  void clear(void) {
    if (empty) return;
    empty = true;
    delete publicKey;
    publicKey = nullptr;
  }
  // give a simple import/export function as well
  unsigned char *flatten(int &size, bool ascii) const;
};

class SHEPrivateKey {
private:
  static std::ostream *log;
  bool empty;
  helib::SecKey *privateKey;
  SHEContextType type;
  long contextSecurityLevel;
  long contextCapacity;
public:
 static constexpr std::string_view typeName = "SHEPrivateKey";
  ~SHEPrivateKey() { }
  SHEPrivateKey(): empty(true), privateKey(nullptr) {}
  SHEPrivateKey(helib::SecKey *secKey, SHEContextType type_, long sl, long cap):
    empty(false), privateKey(nullptr) , type(type_), contextSecurityLevel(sl),
    contextCapacity(cap)
    { privateKey = secKey; }
  SHEPrivateKey &operator=(const SHEPrivateKey &privKey) {
    empty = privKey.empty;
    privateKey = nullptr;
    if (!empty) {
      type = privKey.type;
      contextSecurityLevel = privKey.contextSecurityLevel;
      contextCapacity = privKey.contextCapacity;
      privateKey = privKey.privateKey;
    }
    return *this;
  }
  SHEPrivateKey(const SHEPrivateKey &pubKey) { *this = pubKey; }
  SHEPrivateKey(unsigned char *data, int size);
  const helib::SecKey &getPrivateKey(void) const {
        helib::assertFalse(empty, "attempt to use an empty SHEPrivateKey");
        return *privateKey; }
  static void setLog(std::ostream& str) { log = &str; }
  static std::ostream *getLog(void) { return log; }
  double securityLevel(void) const
    { return getPrivateKey().getContext().securityLevel(); }
  void writeTo(std::ostream& str) const;
  void writeToJSON(std::ostream& str) const;
  helib::JsonWrapper writeToJSON(void) const;
  void readFrom(std::istream& str);
  void readFromJSON(std::istream& str);
  void readFromJSON(const helib::JsonWrapper& jw);
  void clear(void) {
    if (empty) return;
    empty = true;
    delete privateKey;
    privateKey = nullptr;
  }

  // give a simple import/export function as well
  unsigned char *flatten(int &size, bool ascii) const;
};

// io operators. uses public functions, do no need a friend declaration
std::istream&operator>>(std::istream&, SHEPublicKey &pubKey);
std::ostream&operator<<(std::ostream&, const SHEPublicKey &pubKey);
std::istream&operator>>(std::istream&, SHEPrivateKey &pubKey);
std::ostream&operator<<(std::ostream&, const SHEPrivateKey &pubKey);

void SHEGenerate_BinaryKey(SHEPrivateKey &privKey, SHEPublicKey &pubKey,
                           long securityLevel=80,
                           long capacity=SHE_CONTEXT_CAPACITY_ANY);
#endif
