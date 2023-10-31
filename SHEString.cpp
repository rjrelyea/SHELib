//
// Handle encrypted strings. This mimics functions found in std::string
//
#include "SHEString.h"
#include "SHEInt.h"
#include "SHEKey.h"
#include "SHEVector.h"
//#include "SHEUtil.h"
#include "helibio.h"

#ifdef DEBUG
SHEPrivateKey *SHEString::debugPrivKey = nullptr; // set for debugging
#endif
std::ostream *SHEString::log = nullptr;
uint64_t SHEString::nextTmp = 0;
SHEStringLabelHash SHEString::labelHash;
const size_t SHEString::npos;
const size_t SHEString::maxEncryptStringSize;
size_t SHEString::maxStringSize = 32;
bool SHEString::hasFixedSize = true;




// 'default' constructor, needs a public key
// construct from c strings and c++ strings
SHEString::SHEString(const SHEPublicKey &pubKey, const char *string_,
                     bool hasEncryptedLength_, const char *label) :
                     model(pubKey, (uint8_t)0), string(model, 0),
                     eLen(pubKey, (uint8_t)0),
                     hasEncryptedLength(hasEncryptedLength_)
{
  if (label) labelHash[this] = label;
  size_t len = strlen(string_);
  string.resize(len);
  for (size_t i=0; i < len ; i++) {
    string[i] = string_[i];
  }
  if (hasEncryptedLength) {
    encryptLength(true);
  }
}
SHEString::SHEString(const SHEPublicKey &pubKey, const std::string &string_,
                     bool hasEncryptedLength_, const char *label) :
                     model(pubKey, (uint8_t)0), string(model, 0),
                     eLen(pubKey, (uint8_t)0),
                     hasEncryptedLength(hasEncryptedLength_)
{
  if (label) labelHash[this] = label;
  size_t len = string_.size();
  string.resize(len);
  for (size_t i=0; i < len ; i++) {
    string[i] = string_[i];
  }
  if (hasEncryptedLength) {
    encryptLength(true);
  }
}

SHEString::SHEString(const SHEString &model_, const char *string_,
                     bool hasEncryptedLength_, const char *label) :
                     model(model_.model, (uint8_t)0), string(model, 0),
                     eLen(model_.eLen, (uint8_t)0),
                     hasEncryptedLength(hasEncryptedLength_)
{
  if (label) labelHash[this] = label;
  size_t len = strlen(string_);
  string.resize(len);
  for (size_t i=0; i < len ; i++) {
    string[i] = string_[i];
  }
  if (hasEncryptedLength) {
    encryptLength(true);
  }
}

SHEString::SHEString(const SHEString &model_, const char *string_, size_t n,
                     bool hasEncryptedLength_, const char *label) :
                     model(model_.model, (uint8_t)0), string(model, 0),
                     eLen(model_.eLen, (uint8_t)0),
                     hasEncryptedLength(hasEncryptedLength_)
{
  if (label) labelHash[this] = label;
  string.resize(n);
  for (size_t i=0; i < n ; i++) {
    string[i] = string_[i];
  }
  if (hasEncryptedLength) {
    encryptLength(true);
  }
}

SHEString::SHEString(const SHEString &model_, const std::string &string_,
                     bool hasEncryptedLength_, const char *label) :
                     model(model_.model, (uint8_t)0), string(model, 0),
                     eLen(model_.eLen, (uint8_t)0),
                     hasEncryptedLength(hasEncryptedLength_)
{
  if (label) labelHash[this] = label;
  size_t len = string_.size();
  string.resize(len);
  for (size_t i=0; i < len ; i++) {
    string[i] = string_[i];
  }
  if (hasEncryptedLength) {
    encryptLength(true);
  }
}

// from single chars
SHEString::SHEString(size_t n, const SHEChar &c, bool hasEncryptedLength_,
                     const char *label) :
                     model(c, (uint8_t)0), string(model, 0),
                     eLen(c, (uint8_t)0),
                     hasEncryptedLength(hasEncryptedLength_)
{
  if (label) labelHash[this] = label;
  string.resize(n, c);
  if (hasEncryptedLength) {
    encryptLength(true);
  }
}

SHEString::SHEString(const SHEInt &n, const SHEChar &c,
                     const char *label) :
                     model(c, (uint8_t)0), string(model, 0),
                     eLen(c, (uint8_t)0),
                     hasEncryptedLength(true)
{
  if (label) labelHash[this] = label;
  size_t maxSize = hasFixedSize ? maxStringSize : maxEncryptStringSize;
  string.resize(maxSize, c);
  eLen = SHEMIN(n,maxSize);
}

SHEString::SHEString(const SHEChar &model_, size_t n, char c,
                     bool hasEncryptedLength_, const char *label) :
                     model(model_, (uint8_t)0), string(model, 0),
                     eLen(model_, (uint8_t)0),
                     hasEncryptedLength(hasEncryptedLength_)
{
  if (label) labelHash[this] = label;
  string.resize(n, SHEChar(model, c));
  if (hasEncryptedLength) {
    encryptLength(true);
  }
}

SHEString::SHEString(const SHEInt &n, char c, const char *label) :
                     model(n, (uint8_t)0), string(model, 0),
                     eLen(n, (uint8_t)0),
                     hasEncryptedLength(true)
{
  if (label) labelHash[this] = label;
  size_t maxSize = hasFixedSize ? maxStringSize : maxEncryptStringSize;
  string.resize(maxSize, SHEChar(model, c));
  eLen = SHEMIN(n,maxSize);
}


// resize functions. The unencrypted length versions
// will convert hasEncryptedLength strings to
// !hasEncryptedLength strings
void SHEString::resize(size_t n)
{
  if (!hasEncryptedLength) {
    string.resize(n);
    return;
  }
  string.resize(n);
  for (uint64_t i=0; i < n; i++) {
    string[i] = (i>eLen).select(0,string[i]);
  }
  hasEncryptedLength = false;
}

void SHEString::resize(size_t n, const SHEChar &c)
{
  if (!hasEncryptedLength) {
    string.resize(n, c);
    return;
  }
  string.resize(n, c);
  for (uint64_t i=0; i < n; i++) {
    string[i] = (i>eLen).select(c,string[i]);
  }
  hasEncryptedLength = false;
}

void SHEString::resize(size_t n, char c) {
  if (!hasEncryptedLength) {
    string.resize(n, SHEChar(model,c));
    return;
  }
  for (uint64_t i=0; i < n; i++) {
    string[i] = (i>eLen).select(c,string[i]);
  }
  hasEncryptedLength = false;
}

// these will force length to be encrypted
void SHEString::resize(const SHEInt &n) {
  resize(n, 0);
}

void SHEString::resize(const SHEInt &n, char c) {
  resize(n,SHEChar(model, c));
}

void SHEString::resize(const SHEInt &n, const SHEChar &c) {
  if (!hasEncryptedLength) {
    encryptLength();
  }
  for (uint64_t i=0; i < size(); i++) {
    string[i] = (i>eLen).select(c,string[i]);
  }
  encryptLengthReset(n);
}

SHEString &SHEString::operator+=(const SHEString &str)
{
  // both strings have unencrypted lengths
  if (!hasEncryptedLength && !str.hasEncryptedLength) {
    for (size_t i=0; i < str.size(); i++) {
      string.push_back(str[i]);
    }
    return *this;
  }
  // *this has unencrytped length, but str has an encrypted length
  if (!hasEncryptedLength && str.hasEncryptedLength) {
    size_t tsize = size();
    // just concatentate the set the new encrypted length
    for (size_t i=0; i < str.size(); i++) {
      string.push_back(str[i]);
    }
    encryptLengthReset(tsize+SHEUInt16(str.eLen));
    return *this;
  }
  string.resize(size()+str.size());
  SHEUInt16 lLen(eLen);
  // use assign to insert the target string since we know
  // we only need to do this for str.size() lengths.
  for (int64_t i=0; i < str.size(); i++) {
    string.assign(lLen++, str[i]);
  }
  encryptLengthReset(eLen+str.length());
  return *this;
}

SHEString SHEString::operator+(const SHEString &str) const
{
  SHEString result(*this);

  result += str;
  return result;
}

SHEString &SHEString::operator+=(const SHEChar &c)
{
  if (!hasEncryptedLength) {
    string.push_back(c);
    return *this;
  }
  size_t tsize=size()+1;
  string.resize(tsize);
  for (uint64_t i=0; i < tsize; i++) {
    string[i] = (i>eLen).select(c,string[i]);
  }
  encryptLengthReset(SHEUInt16(eLen)+1);
  return *this;
}

SHEString SHEString::operator+(const SHEChar &c) const
{
  SHEString result(*this);
  result += c;
  return result;
}

SHEString &SHEString::insert(size_t pos, const SHEString &str)
{
  size_t tsize = string.size();
  size_t insertSize = str.size();
  if (pos > string.size()) {
    throw std::out_of_range("SHEString::insert, pos larger than size");
  }
  string.resize(tsize+insertSize);
  SHEVector<SHEChar> origString = string;
  for (size_t i=0; i < insertSize; i++) {
    string[i+pos] = str[i];
  }
  if (!hasEncryptedLength && !str.hasEncryptedLength) {
    for (size_t i=pos; i < tsize; i++) {
      string[i+insertSize] = origString[i];
    }
    return *this;
  }
  SHEUInt16 insertNext = str.eLen;
  insertNext += pos;
  for (size_t i=pos; i < tsize; i++) {
    string.assign(insertNext++, origString[i]);
  }
  encryptLengthReset(SHEUInt16(eLen)+str.eLen);
  return *this;
}

SHEString &SHEString::insert(const SHEInt &pos, const SHEString &str)
{
  SHEString insertStr(str);
  if (!hasEncryptedLength)  {
    encryptLength();
  }
  if (!str.hasEncryptedLength) {
    insertStr.encryptLength();
  }
  SHEVector<SHEChar> origString(string);
  SHEUInt16 insertLast = insertStr.eLen;
  insertLast += pos;
  size_t tsize = size() + insertStr.size();
  size_t osize = origString.size();
  string.resize(tsize);
  for (uint64_t i=0; i < tsize; i++) {
    SHEChar current = (i>=pos).select(insertStr.string[i-pos],
                                      origString[i<osize?i:0]);
    string[i] = (i>=insertLast).select(origString[i-insertStr.eLen],current);
  }
  encryptLengthReset(SHEUInt16(eLen)+insertStr.eLen);
  return *this;
}

SHEString &SHEString::erase(size_t pos, size_t len)
{
  size_t size= string.size();
  if (pos > size) {
    throw std::out_of_range("SHEString::erase, pos larger than size");
  }
  size_t offset = std::min(len,size);
  size_t last = size - offset;
  // copy out the end of the string
  // over the removed portions
  for (size_t i=pos; i < last; i++) {
    string[i] = string[i+offset];
  }
  // reset the size;
  if (!hasEncryptedLength) {
    string.resize(last);
  } else {
    SHEUInt16 rmLen = SHEMIN(len,length());
    encryptLengthReset(eLen-rmLen);
  }
  return *this;

}

SHEString &SHEString::erase(const SHEInt &pos, const SHEInt &len)
{
  if (!hasEncryptedLength) {
    encryptLength();
  }
  SHEUInt16 offset = SHEMIN(len,eLen);
  // copy out the end of the string
  // over the removed portions
  for (uint64_t i=0; i < size(); i++) {
    string[i] = (i>=pos).select(string[i+offset],string[i]);
  }
  // reset the size;
  encryptLengthReset(eLen-offset);
  return *this;

}

SHEString &SHEString::replace(size_t pos, size_t len, const SHEString &str)
{
  erase(pos, len);
  insert(pos, str);
  return *this;
}

SHEString &SHEString::replace(const SHEInt &pos, const SHEInt &len,
                              const SHEString &str)
{
  erase(pos,len);
  insert(pos, str);
  return *this;
}

void SHEString::swap(SHEString &str)
{
  // just do the simple basic operation
  SHEString save(*this);
  *this = str;
  str = save;
}

SHEInt SHEString::copy(SHEVector<SHEChar> &s, size_t len, size_t pos)
{
  if (hasEncryptedLength) {
    return copy(s, SHEStringLength(len), SHEStringLength(pos));
  }
  if (pos != 0) {
    SHEString subString(substr(pos,len));
    s = subString.string;
    return subString.length();
  }
  s = string;
  if (len < s.size()) {
     s.resize(len);
  }
  return SHEInt16(model, s.size());
}

SHEInt SHEString::copy(SHEVector<SHEChar> &s, const SHEInt &len,
                       const SHEInt &pos)
{
  SHEString subString(substr(pos,len)); // guarrenteed to have encrypted len
  s = subString.string;
  return subString.length();
}

SHEInt SHEString::find(const SHEChar &c, size_t pos) const
{
  SHEUInt16 foundPos(model, npos);
  SHEBool found(model, false);

  for (size_t i=pos; i < string.size(); i++) {
    SHEBool match = (string[i] == c);
    foundPos = (!found && match).select(i, foundPos);
    if (hasEncryptedLength) {
      found = found || match || (i == eLen);
    } else {
      found = found || match;
    }
  }
  return foundPos;
}

SHEInt SHEString::find(const SHEChar &c, const SHEInt &pos) const
{
  SHEUInt16 foundPos(model, npos);
  SHEBool found(model, false);

  for (uint64_t i=0; i < string.size(); i++) {
    SHEBool match = (string[i] == c) && (i >= pos);
    foundPos = (!found && match).select(i, foundPos);
    if (hasEncryptedLength) {
      found = found || match || (i == eLen);
    } else {
      found = found || match;
    }
  }
  return foundPos;
}

SHEInt SHEString::find(const SHEString &str, size_t pos ) const
{
  SHEUInt16 foundPos(model, npos);
  SHEUInt16 matchNext(model,(uint16_t)0);
  SHEBool found(model,false);

  for (uint64_t i=pos; i < string.size(); i++) {
    matchNext = (string[i] == str[matchNext]).select(matchNext+1,
                (string[i] == str[0]).select(1,0));
    SHEBool match = matchNext == str.length();
    foundPos = (!found && match).select(i-matchNext, foundPos);
    if (hasEncryptedLength) {
      found = found || match || (i == eLen);
    } else {
      found = found || match;
    }
  }
  return foundPos;
}

SHEInt SHEString::find(const SHEString &str, const SHEInt &pos ) const
{
  SHEUInt16 foundPos(model,npos);
  SHEUInt16 matchNext(model,(uint16_t)0);
  SHEBool found(model,false);

  for (uint64_t i=0; i < string.size(); i++) {
    matchNext = (string[i] == str[matchNext]).select(matchNext+1,
                (string[i] == str[0]).select(1,0));
    matchNext = (i < pos).select(0, matchNext);
    SHEBool match = matchNext == str.length();
    foundPos = (!found && match).select(i-matchNext, foundPos);
    if (hasEncryptedLength) {
      found = found || match || (i == eLen);
    } else {
      found = found || match;
    }
  }
  return foundPos;
}

SHEString SHEString::reverse(void) const
{
  SHEString result(*this);
  size_t size = result.size();

  if (!hasEncryptedLength) {
    for (size_t i=0; i < size; i++) {
      result.string[i] = string[size-i-1];
    }
    return result;
  }
  // encrypted length
  for (size_t i=0; i < size; i++) {
    result.string[i] = string[eLen-i-1];
  }
  return result;
}

SHEInt SHEString::rfind(const SHEChar &c, size_t pos) const
{
  SHEUInt16 foundPos(model,npos);
  SHEBool found(model,false);

  for (size_t i=string.size(); i <= pos; i--) {
    SHEBool match = (string[i] == c);
    foundPos = (!found && match).select(i, foundPos);
    if (hasEncryptedLength) {
      found = found || match || (i == eLen);
    } else {
      found = found || match;
    }
  }
  return foundPos;
}

SHEInt SHEString::rfind(const SHEString &str, size_t pos) const
{
  if (hasEncryptedLength) {
    SHEInt foundPos = reverse().find(str.reverse(), eLen - pos);
    return (foundPos == npos).select(npos, eLen - foundPos);
  }
  SHEInt foundPos = reverse().find(str.reverse(), string.size() - pos);
  return (foundPos == npos).select(npos, eLen - foundPos);
}

SHEInt SHEString::rfind(const SHEChar &c, const SHEInt &pos) const
{
  SHEUInt16 foundPos(model,npos);
  SHEBool found(model,false);

  for (uint64_t i=string.size(); i <= 0; i--) {
    SHEBool match = (string[i] == c) && (i <= pos);
    foundPos = (!found && match).select(i, foundPos);
    if (hasEncryptedLength) {
      found = found || match || (i == eLen);
    } else {
      found = found || match;
    }
  }
  return foundPos;
}

SHEInt SHEString::rfind(const SHEString &str, const SHEInt &pos) const
{
  SHEInt foundPos = reverse().find(str.reverse(), length() - pos);
  return (foundPos == npos).select(npos, eLen - foundPos);
}

SHEString SHEString::substr(size_t pos, size_t len) const
{
  size_t size = string.size();
  if (pos > size) {
    throw std::out_of_range("SHEString::substr, pos larger than size");
  }
  SHEString result(*this);
  if (hasEncryptedLength) {
    for (size_t i=0; i < (size-pos); i++) {
      result.string[i] = string[i+pos];
    }
    result.eLen = SHEMIN(eLen, len);
  } else {
    if (pos+len > size) {
      len = size - pos;
    }
    for (size_t i=0; i < len; i++) {
      result.string[i] = string[i+pos];
    }
    result.string.resize(len);
  }
  return result;
}

SHEString SHEString::substr(const SHEInt &pos, const SHEInt &len) const
{
  SHEString result(*this);
  if (!result.hasEncryptedLength) {
    result.encryptLength();
  }
  for (size_t i=0; i < result.size(); i++) {
    result.string[i] = string[i+pos];
  }
  SHEInt maxLen = (pos > result.eLen).select(0, result.eLen - pos);
  result.eLen = (len > maxLen).select(maxLen,len);
  return result;
}

SHEInt SHEString::compare(const SHEString &str) const
{
  SHEInt8 result(eLen, (int8_t)0);
  SHEBool isgreater(eLen, false);
  SHEBool isequal(eLen, true);
  size_t loopLen = std::min(string.size(),str.string.size());
  if (!hasEncryptedLength && !str.hasEncryptedLength) {
    // if they are both unencrypted, we can do the check more quickly
    for (size_t i=0; i < loopLen; i++) {
      isgreater = isequal.select(string[i] > str.string[i], isgreater);
      isequal = isequal && (string[i] == str.string[i]);
    }
    isgreater = isequal.select(string.size() > str.string.size(), isgreater);
    isequal = isequal && (string.size() == str.string.size());
  } else {
    // one or both are encrypted, check the entire
    SHEBool done(eLen, false);
    SHEInt thisLen = length();
    SHEInt sLen = str.length();
    SHEBool lenGreater = thisLen > sLen;
    SHEInt len = lenGreater.select(sLen, thisLen);
    for (uint64_t i=0; i < loopLen; i++) {
      done = i > len;
      isgreater = (!done && isequal).select(string[i] > str.string[i],
                                            isgreater);
      isequal = isequal && (done || (string[i] == str.string[i]));
    }
    isgreater = isequal.select(lenGreater, isgreater);
    isequal = isequal && (thisLen == sLen);
  }
  result = isgreater.select(1,SHEInt8(eLen,-1));
  result = isequal.select(0, result);
  return result;
}

SHEString SHEString::selectHelper(const SHEInt &sel, const SHEString &a_false) const
{
  SHEString result(*this);
  // if both this and a_false have unencrypted lengths and
  // are the same size, the result can have an unencrypted
  // length as well..
  if (!hasEncryptedLength && !a_false.hasEncryptedLength &&
      (size() == a_false.size())) {
    for (size_t i=0; i < size(); i++) {
      result.string[i]=sel.select(result.string[i],a_false.string[i]);
    }
    return result;
  }
  // othersize we need to move to an encrypted length string
  if (!hasEncryptedLength) {
    result.encryptLength();
  }
  SHEString s_false(a_false);
  if (!s_false.hasEncryptedLength) {
    s_false.encryptLength();
  }
  size_t rsize = std::max(result.size(),s_false.size());
  result.string.resize(rsize);
  s_false.string.resize(rsize);
  // select the length
  result.eLen = sel.select(result.eLen, s_false.eLen);
  // select the string;
  for (size_t i=0; i < rsize; i++) {
    result.string[i] = sel.select(result.string[i], s_false.string[i]);
  }
  return result;
}


// get the decrypted raw string given the private key
// caller owns the memory and must free it in the end
// with delete[]
char *SHEString::decryptRaw(const SHEPrivateKey &privKey, size_t *lenp) const
{
  size_t len = hasEncryptedLength ? eLen.decrypt(privKey) : string.size();
  char *out = new char[len+1];
  *lenp = 0;
  if (out == NULL) { return NULL; }
  for (size_t i=0; i < len; i++) {
    out[i] = string[i].decrypt(privKey);
  }
  out[len] = 0;
  *lenp = len;
  return out;
}

// get the decrypted string given the private key
std::string SHEString::decrypt(const SHEPrivateKey &privKey) const
{
  size_t len = hasEncryptedLength ? eLen.decrypt(privKey) : string.size();
  std::string out;
  out.resize(len);
  for (size_t i=0; i < len; i++) {
    out[i] = string[i].decrypt(privKey);
  }
  return out;
}

// bootstrapping help
long SHEString::bitCapacity(void) const
{
  long capacity=std::min(eLen.bitCapacity(),model.bitCapacity());
  return std::min(capacity,string.bitCapacity());
}

double SHEString::securityLevel(void) const
{ return model.securityLevel(); }

bool SHEString::isCorrect(void) const
{
  return eLen.isCorrect() && model.isCorrect() && string.isCorrect();
}

bool SHEString::needRecrypt(long level) const
{
  return (bool)(bitCapacity() <= level);
}

bool SHEString::needRecrypt(const SHEString &a, long level) const
{
  return needRecrypt(level) || a.needRecrypt(level);
}

void SHEString::verifyArgs(long level)
{
  if (needRecrypt(level)) reCrypt();
}

void SHEString::verifyArgs(SHEString &a, long level)
{
  if (needRecrypt(a,level)) reCrypt(a);
}

void SHEString::reCrypt(void)
{
  model.reCrypt(eLen);
  string.reCrypt();
}

void SHEString::reCrypt(SHEString &a)
{
  model.reCrypt(eLen, a.model, a.eLen);
  string.reCrypt();
  a.string.reCrypt();
}

// input/output functions
// use helib standard intput, outputs methods
void SHEString::writeTo(std::ostream& str) const
{
  write_raw_int(str, SHEStringMagic); // magic to say we're a SHEString
  write_raw_int(str, hasEncryptedLength);
  eLen.writeTo(str);
  string.writeTo(str);
}

void SHEString::writeToJSON(std::ostream& str) const
{
  helib::executeRedirectJsonError<void>([&]() { str << writeToJSON(); });
}

helib::JsonWrapper SHEString::writeToJSON(void) const
{
  auto body = [this]() {
    json j = {{"hasEncryptedLength", this->hasEncryptedLength},
              {"encryptedLength", helib::unwrap(this->eLen.writeToJSON())},
              {"string", helib::unwrap(this->string.writeToJSON())}};

    return helib::wrap(helib::toTypedJson<SHEString>(j));
  };
  return helib::executeRedirectJsonError<helib::JsonWrapper>(body);
}

SHEString SHEString::readFrom(std::istream& str, const SHEPublicKey &pubKey)
{
   SHEString a(pubKey,"");
   a.read(str);
   return a;
}

SHEString SHEString::readFromJSON(std::istream& str, const SHEPublicKey &pubKey)
{
  return helib::executeRedirectJsonError<SHEString>([&]() {
    json j;
    str >> j;
    return readFromJSON(helib::wrap(j), pubKey);
  });
}

SHEString SHEString::readFromJSON(const helib::JsonWrapper& j,
                                  const SHEPublicKey &pubKey)
{
  SHEString a(pubKey, "");
  a.readFromJSON(j);
  return a;
}

void SHEString::read(std::istream& str)
{
  long magic;

  magic = read_raw_int(str);
  helib::assertEq<helib::IOError>(magic, SHEStringMagic,
                                    "not an SHEString on the stream");
  hasEncryptedLength = read_raw_int(str);
  eLen.read(str);
  //string.read(str);
}

void SHEString::readFromJSON(std::istream&str)
{
  return helib::executeRedirectJsonError<void>([&]() {
    json j;
    str >> j;
    return readFromJSON(helib::wrap(j));
  });
}

void SHEString::readFromJSON(const helib::JsonWrapper &jw)
{
  auto body = [&]() {
    json j = helib::fromTypedJson<SHEString>(unwrap(jw));
    this->hasEncryptedLength = j.at("hasEncryptedLength");
    this->eLen.readFromJSON(helib::wrap(j.at("encryptedLength")));
    this->model = SHEUInt8(this->eLen, (uint8_t)0);
    // Using inplace parts deserialization as read_raw_vector will do a
    // resize, then reads the parts in-place, so may re-use memory.
    this->string.readFromJSON(helib::wrap(j.at("string")));
  };

  helib::executeRedirectJsonError<void>(body);
}

// give a simple import/export function as well
unsigned char *SHEString::flatten(size_t &size, bool ascii) const
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

std::ostream &operator<<(std::ostream &str, const SHEStringSummary &summary)
{
  long level = summary.shestring.bitCapacity();
  std::ios_base::fmtflags saveFlags = str.flags();
  str << "SHEString(" <<  summary.shestring.getLabel() << ","
      << (char *)(summary.shestring.lengthIsEncrypted() ? "El" : "Ul")
      << "," << summary.shestring.size() << ",";
  if (level == LONG_MAX) {
    str << "MAX";
  } else {
    str << std::dec << level;
  }

#ifdef DEBUG
  const SHEPrivateKey *privKey = summary.getPrivateKey();
  if (privKey) {
    str << ":\"";
    if (summary.shestring.isCorrect()) {
      str << summary.shestring.decrypt(*privKey) << "\"";
    } else {
      str << "NaS";
    }
  }
#endif
  str << ")";
  str.flags(saveFlags);
  return str;
}
