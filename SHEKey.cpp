//
// create a hormorphic key to do Mathematic operations. Keys store
// 1 bit per slot, and use BGV_Binary_aritmetic
//
#include "SHEKey.h"
#include "SHEMagic.h"
#include "SHEio.h"
#include "helibio.h"

std::ostream *SHEPublicKey::log = nullptr;
std::ostream *SHEPrivateKey::log = nullptr;

// this function generates a binary key, that is a key where each bit
// is separately encrypted and operated on. securityLevel is a bit
// security equivalent (to symetric encryption. nOps is the
// number of operations we want to be able to do before we need
// to bootstrap again). All these keys are bootstrappable.
void SHEGenerate_BinaryKey(SHEPrivateKey &privKey, SHEPublicKey &pubKey,
                           long securityLevel, long operationLevel)
{
  std::ostream *log = nullptr;
  if (SHEPrivateKey::getLog()) {
    log = SHEPrivateKey::getLog();
  } else if (SHEPublicKey::getLog()) {
    log = SHEPublicKey::getLog();
  }
  helib::Context *context =
                    SHEContext::GetContext(SHEContextBinary, securityLevel,
                                           operationLevel);

  helib::assertNeq(context, (helib::Context *)nullptr,
                   "Can't get a binary context by security level");

  // now the code to generate a key
  helib::SecKey *secretKey = new helib::SecKey(*context);
  if (log)  (*log) << "Generating BinaryKey secretKey.."
                   << (void *) secretKey << std::endl;
  secretKey->GenSecKey();
  if (log) (*log) << "Generating 1DMatrices.." << std::endl;
  helib::addSome1DMatrices(*secretKey);
  if (log) (*log) << "Generating FrbMatrices.." << std::endl;
  helib::addFrbMatrices(*secretKey);
  if (log) (*log) << "Generating Recrypt Data.." << std::endl;
  secretKey->genRecryptData();


  // now return them
  if (log) (*log) << "Building SHEPrivateKey.." << std::endl;
  privKey = SHEPrivateKey(secretKey, SHEContextBinary, securityLevel,
                          operationLevel);
  pubKey = SHEPublicKey(secretKey, SHEContextBinary, securityLevel,
                        operationLevel);
  std::cout << "SHEGenerate_BinaryKey complete! " << std::endl;
}

//
// IO functions for keys
//

std::ostream& operator<<(std::ostream& str, const SHEPublicKey& pubKey)
{
  pubKey.writeToJSON(str);
  return str;
}

std::istream& operator>>(std::istream& str, SHEPublicKey& pubKey)
{
  pubKey.readFromJSON(str);
  return str;
}

unsigned char *SHEPublicKey::flatten(int &size, bool ascii) const
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


void SHEPublicKey::writeTo(std::ostream& str) const
{
  helib::assertFalse(empty, "attempt to use an empty SHEPublicKey");
  if (log) (*log) << "outputting SHEPublicKey" << std::endl;
  long typeValue = SHEContext::GetContextTypeValue(type);
  write_raw_int(str, SHEPublicKeyMagic); // magic to say we're a SHEPublicKey
  write_raw_int(str, typeValue);
  write_raw_int(str, contextSecurityLevel);
  write_raw_int(str, contextCapacity);
  publicKey->writeTo(str);
  if (log) (*log) << "...done" << std::endl;
}

void SHEPublicKey::writeToJSON(std::ostream& str) const
{
  helib::assertFalse(empty, "attempt to use an empty SHEPublicKey");
  if (log) (*log) << "outputting JSON SHEPublicKey" << std::endl;
  helib::executeRedirectJsonError<void>([&]() { str << writeToJSON(); });
  if (log) (*log) << "...done" << std::endl;
}

helib::JsonWrapper SHEPublicKey::writeToJSON(void) const
{
  helib::assertFalse(empty, "attempt to use an empty SHEPublicKey");
  auto body = [this]() {
    json j = {{"contextType", this->type },
              {"securityLevel", this->contextSecurityLevel },
              {"capacity", this->contextCapacity },
              {"publicKey", unwrap(this->publicKey->writeToJSON())}};
    return helib::wrap(helib::toTypedJson<SHEPublicKey>(j));
  };
  return helib::executeRedirectJsonError<helib::JsonWrapper>(body);
}

void SHEPublicKey::readFrom(std::istream& str)
{
  long magic = read_raw_int(str);
  if (log) (*log) << "inputting SHEPublicKey:" << magic << std::endl;
  helib::assertEq<helib::IOError>(magic, SHEPublicKeyMagic,
                                  "not an SHEPublicKey on the stream");
  long typeValue = read_raw_int(str);
  type = SHEContext::GetContextType(typeValue);
  contextSecurityLevel = read_raw_int(str);
  contextCapacity = read_raw_int(str);
  helib::Context *context = SHEContext::GetContext(type, contextSecurityLevel,
                                                   contextCapacity);
  helib::assertNeq<helib::IOError>(context, (helib::Context *)nullptr,
                                  "Can't find context by type & level");
  publicKey = new helib::PubKey(helib::PubKey::readFrom(str, *context));
  empty = false;
  hasEncoding = false;
  if (log) (*log) << "...done" << std::endl;
}

void SHEPublicKey::readFromJSON(std::istream& str)
{
  if (log) (*log) << "inputting JSON SHEPublicKey" << std::endl;
  return helib::executeRedirectJsonError<void>([&]() {
    json j;
    str >> j;
    return readFromJSON(helib::wrap(j));
  });
}

void SHEPublicKey::readFromJSON(const helib::JsonWrapper &jw)
{
 auto body = [&]() {
    json j = helib::fromTypedJson<SHEPublicKey>(unwrap(jw));

    this->type = j.at("contextType");
    this->contextSecurityLevel = j.at("securityLevel");
    this->contextCapacity = j.at("capacity");
    helib::Context *context = SHEContext::GetContext(this->type,
                                                     this->contextSecurityLevel,
                                                     this->contextCapacity);
    this->publicKey = new helib::PubKey(*context);
    this->publicKey->readJSON(helib::wrap(j.at("publicKey")));
    this->empty = false;
    this->hasEncoding = false;
  };

  helib::executeRedirectJsonError<void>(body);
}

std::ostream& operator<<(std::ostream& str, const SHEPrivateKey& privKey)
{
  privKey.writeToJSON(str);
  return str;
}

std::istream& operator>>(std::istream& str, SHEPrivateKey& privKey)
{
  privKey.readFromJSON(str);
  return str;
}

unsigned char *SHEPrivateKey::flatten(int &size, bool ascii) const
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


void SHEPrivateKey::writeTo(std::ostream& str) const
{
  helib::assertFalse(empty, "attempt to use an empty SHEPrivateKey");
  if (log) (*log) << "outputting SHEPrivateKey..." << std::endl;
  long typeValue = SHEContext::GetContextTypeValue(type);
  write_raw_int(str, SHEPrivateKeyMagic); // magic to say we're a SHEPrivateKey
  write_raw_int(str, typeValue);
  write_raw_int(str, contextSecurityLevel);
  write_raw_int(str, contextCapacity);
  privateKey->writeTo(str);
  if (log) (*log) << "...done" << std::endl;
}

void SHEPrivateKey::writeToJSON(std::ostream& str) const
{
  helib::assertFalse(empty, "attempt to use an empty SHEPrivateKey");
  if (log) (*log) << "outputting JSON SHEPrivateKey" << std::endl;
  helib::executeRedirectJsonError<void>([&]() { str << writeToJSON(); });
  if (log) (*log) << "...done" << std::endl;
}

helib::JsonWrapper SHEPrivateKey::writeToJSON(void) const
{
  helib::assertFalse(empty, "attempt to use an empty SHEPrivateKey");
  auto body = [this]() {
    json j = {{"contextType", this->type },
              {"securityLevel", this->contextSecurityLevel },
              {"capacity", this->contextCapacity },
              {"privateKey", unwrap(this->privateKey->writeToJSON())}};
    return helib::wrap(helib::toTypedJson<SHEPrivateKey>(j));
  };
  return helib::executeRedirectJsonError<helib::JsonWrapper>(body);
}

void SHEPrivateKey::readFrom(std::istream& str)
{
  long magic = read_raw_int(str);
  if (log) (*log) << "inputting SHEPrivateKey:" << magic << std::endl;
  helib::assertEq<helib::IOError>(magic, SHEPrivateKeyMagic,
                                  "not an SHEPrivateKey on the stream");
  long typeValue = read_raw_int(str);
  type = SHEContext::GetContextType(typeValue);
  contextSecurityLevel = read_raw_int(str);
  contextCapacity = read_raw_int(str);
  helib::Context *context = SHEContext::GetContext(type, contextSecurityLevel,
                                                   contextCapacity);
  helib::assertNeq<helib::IOError>(context, (helib::Context *)nullptr,
                                  "Can't find context by type & level");
  privateKey = new helib::SecKey(helib::SecKey::readFrom(str, *context));
  empty = false;
  if (log) (*log) << "...done" << std::endl;
}

void SHEPrivateKey::readFromJSON(std::istream& str)
{
  if (log) (*log) << "inputting JSON SHEPrivateKey" << std::endl;
  return helib::executeRedirectJsonError<void>([&]() {
    json j;
    str >> j;
    return readFromJSON(helib::wrap(j));
  });
}

void SHEPrivateKey::readFromJSON(const helib::JsonWrapper &jw)
{
 auto body = [&]() {
    json j = helib::fromTypedJson<SHEPrivateKey>(unwrap(jw));

    this->type = j.at("contextType");
    this->contextSecurityLevel = j.at("securityLevel");
    this->contextCapacity = j.at("capacity");
    helib::Context *context = SHEContext::GetContext(this->type,
                                                     this->contextSecurityLevel,
                                                     this->contextCapacity);
    this->privateKey = new helib::SecKey(*context);
    this->privateKey->readJSON(helib::wrap(j.at("privateKey")));
    this->empty = false;
  };

  helib::executeRedirectJsonError<void>(body);

}
