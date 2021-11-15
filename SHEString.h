//
// Handle encrypted strings. This mimics functions found in std::string
//
#ifndef SHEString_H_
#define SHEString_H_ 1
#include "SHEVector.h"
#include "SHEInt.h"
#include "SHEKey.h"
//#include "SHEUtil.h"

// use unsigned char for encrypted char because
// unsigned char usually has less overhead in the library.
typedef SHEUInt8 SHEChar;

class SHEString;
typedef std::unordered_map<const SHEString *,const char *>SHEStringLabelHash;

class SHEString {
private:
  friend class SHEStringSummary;
#ifdef DEBUG
  static SHEPrivateKey *debugPrivKey; // set for debugging
#endif
  static std::ostream *log;
  static uint64_t nextTmp;
  static SHEStringLabelHash labelHash;
  static const size_t npos = (1<<16)-1;
  static const size_t maxEncryptStringSize = 255;
  static size_t maxStringSize;
  static bool hasFixedSize;
  SHEChar   model;
  SHEVector<SHEChar> string;
  SHEUInt8   eLen;
  bool       hasEncryptedLength;
  char labelBuf[SHEINT_MAX_LABEL_SIZE];
  static size_t getBestSize(size_t len) { return log2i(len)+1; }
  void encryptLengthReset(const SHEInt &len)
  {
    if (hasFixedSize) {
      eLen = SHEMIN(len, maxStringSize);
      string.resize(maxStringSize);
    } else {
      eLen = SHEMIN(len,maxEncryptStringSize);
      if (size() > maxEncryptStringSize) {
        string.resize(maxEncryptStringSize);
      }
    }
    hasEncryptedLength=true;
  }

  // setNextLabel lies about const since it's basically a caching function
  const char *setNextLabel(void) const
  {
    uint64_t current=nextTmp++;
    snprintf((char *)&labelBuf[0], sizeof(labelBuf), "t%d",current);
    labelHash[this]=labelBuf;
    return labelBuf;
  }
public:
  static constexpr std::string_view typeName = "SHEString";
  ~SHEString(void) { labelHash.erase(this); }
  // 'default' constructor, needs a public key
  explicit SHEString(const SHEPublicKey &pubKey, bool hasEncryptedLength=false,
                     const char *label=nullptr) :
                     model(pubKey,(uint8_t)0), string(model, 0),
                     eLen(pubKey,(uint8_t)0),
                     hasEncryptedLength(hasEncryptedLength)
  { if (label) labelHash[this] = label; }
  // copy constructer
  SHEString(const SHEString &s) :
            model(s.model), string(s.string),
            eLen(s.eLen), hasEncryptedLength(s.hasEncryptedLength) { }
  // copy with label
  SHEString(const SHEString &s, int dummy, const char *label) :
            model(s.model), string(s.string),
            eLen(s.eLen), hasEncryptedLength(s.hasEncryptedLength)
  { labelHash[this] = label; }
  SHEString &operator=(const SHEString &s) {
    model = s.model; string = s.string; eLen= s.eLen;
    hasEncryptedLength = s.hasEncryptedLength;
    return *this;
  }
  // assigment from std::string and cstrings (char *)
  SHEString &operator=(std::string s) {
    *this = SHEString(*this, s);
    return *this;
  }
  SHEString &operator=(char *s) {
    *this = SHEString(*this, s);
    return *this;
  }
  // construct from c strings and c++ strings
  SHEString(const SHEPublicKey &pubKey, const char *string_,
            bool hasEncryptedLength=false, const char *label=nullptr);
  SHEString(const SHEPublicKey &pubKey, const std::string &string_,
            bool hasEncryptedLength=false, const char *label=nullptr);
  SHEString(const SHEString &model, const char *string_,
            bool hasEncryptedLength=false, const char *label=nullptr);
  SHEString(const SHEString &model, const std::string &string_,
            bool hasEncryptedLength=false, const char *label=nullptr);
  // buffers
  SHEString(const SHEPublicKey &pubKey, const char *string_, size_t len,
            bool hasEncryptedLength=false, const char *label=nullptr);
  SHEString(const SHEString &model, const char *string_, size_t len,
            bool hasEncryptedLength=false, const char *label=nullptr);

  // from single chars
  SHEString(size_t n, const SHEChar &c, bool hasEncryptedLength=false,
            const char *label=nullptr);
  SHEString(const SHEInt &n, const SHEChar &c, const char *label=nullptr);
  SHEString(const SHEChar &model, size_t n, char c,
            bool hasEncryptedLength=false, const char *label=nullptr);
  SHEString(const SHEInt &n, char c, const char *label=nullptr);

  // map and unencrypted length or pos to an encrypted value
  SHEInt SHEStringLength(size_t len) const {
   len = std::min(len,maxEncryptStringSize);
   return SHEInt(model, len);
  }
  const char *getLabel(void) const
  {
    const char *label = labelHash[this];
    if (label) return label;
    return setNextLabel();
  }
  // control the behavior of encrypted length strings.
  static void setFixedSize(bool hasFixedSize_, size_t maxSize)
  {
    hasFixedSize = hasFixedSize_;
    maxStringSize = maxSize;
  }
  static size_t getFixedSize(void) { return maxStringSize; }
  static bool getHasFixedSize(void) { return hasFixedSize; }
  // force a string to have an encrypted length
  void encryptLength(bool force=false)
  {
    if (!force && hasEncryptedLength) return;
    size_t len = size();
    if (hasFixedSize) {
      eLen = std::min(len, maxStringSize);
      string.resize(maxStringSize);
    } else {
      eLen = std::min(len, maxEncryptStringSize);
      if (len > maxEncryptStringSize) {
        string.resize(maxEncryptStringSize);
      }
    }
    hasEncryptedLength=true;
  }
  // skip iterators for now
  // size will return the unencrypted size. If Size is encrypted,
  // it returns the max size allowed
  size_t size(void) const { return string.size(); }
  // length returns the encrypted size, whether it's stored encrypted
  // or not.
  SHEInt length(void) const {
    if (hasEncryptedLength) return eLen;
    size_t len = string.size();
    SHEInt neLen(model, (uint64_t)0);
    if (len > maxEncryptStringSize) {
      neLen.reset(getBestSize(len), true);
    }
    neLen = len;
    return neLen;
  }
  size_t max_size(void) const {
    return hasEncryptedLength ? maxEncryptStringSize : npos;
  }
  size_t capacity(void) const { return string.capacity(); }
  void reserve(size_t n=0) { string.reserve(n); }
  void shrink_to_fit(void) { }
  // clear works on both encrypted and unencrypted length strings
  void clear(void) {
    if (!hasEncryptedLength) { string.clear(); return; }
    eLen.clear(); // if the length was encrypted, clear it
  }
  // empty only works on unencrypted length, or recently cleared() strings
  bool empty(void) {
    if (hasEncryptedLength) return eLen.isUnencryptedZero();
    return string.empty();
  }
  // empty(0) works on encrypted length strings, but the result is encrypted
  SHEBool empty(int dummy) {
    if (hasEncryptedLength) return eLen.isZero();
    return SHEBool(model,string.empty());
  }
  void resize(size_t n);
  void resize(size_t n, const SHEChar &c);
  void resize(size_t n, char c);
  // these will force length to be encrypted
  void resize(const SHEInt &n);
  void resize(const SHEInt &n, const SHEChar &c);
  void resize(const SHEInt &n, char c);
  SHEString reverse(void) const;
  SHEChar &operator[] (size_t pos) { return string[pos]; }
  const SHEChar &operator[] (size_t pos) const { return string[pos]; }
  SHEChar operator[] (const SHEInt &pos) const { return string[pos]; }
  SHEChar at(size_t pos) const {
    return hasEncryptedLength? (SHEChar)(pos>=eLen).select(0,string.at(pos))
           : string.at(pos); }
  SHEChar at(const SHEInt &pos) const {
    return hasEncryptedLength? (SHEChar)(pos>=eLen).select(0,string.at(pos))
           : string.at(pos); }
  SHEString &operator+=(const SHEString &str);
  SHEString operator+(const SHEString &str) const;
  SHEString &operator+=(const SHEChar &c);
  SHEString operator+(const SHEChar &c) const;
  SHEString &operator+=(const std::string &str)
    { return *this += SHEString(*this,str); }
  SHEString operator+(const std::string &str) const
    { return *this + SHEString(*this,str); }
  SHEString &operator+=(const char *str)
    { return *this += SHEString(*this,str); }
  SHEString operator+(const char *str) const
    { return *this + SHEString(*this,str); }
  SHEString &operator+=(char c)
    { return *this += SHEChar(model,c); }
  SHEString operator+(char c) const
    { return *this + SHEChar(model,c); }
  SHEString &append(const SHEString &str)
    { return *this += str; }
  SHEString &append(const SHEString &str, size_t subpos, size_t sublen)
    { return *this += str.substr(subpos,sublen); }
  SHEString &append(const SHEString &str, const SHEInt &subpos,
                    const SHEInt &sublen)
    { return *this += str.substr(subpos,sublen); }
  SHEString &append(const std::string &str)
    { return *this += str; }
  SHEString &append(size_t n, const SHEChar &c)
    { return *this += SHEString(n, c); }
  SHEString &append(const SHEInt &n, const SHEChar &c)
    { return *this += SHEString(n, c); }
  SHEString &append(const std::string &str, size_t subpos, size_t sublen)
    { return *this += str.substr(subpos, sublen); }
  SHEString &append(const std::string &str, const SHEInt &subpos,
                    const SHEInt &sublen)
    { return append(SHEString(*this, str), subpos, sublen); }
  SHEString &append(const char *str)
    { return *this += str; }
  SHEString &append(const char *str, size_t subpos, size_t sublen)
    { return append(SHEString(*this, str), subpos, sublen); }
  SHEString &append(const char *str, const SHEInt &subpos, const SHEInt &sublen)
    { return append(SHEString(*this, str), subpos, sublen); }
  SHEString &append(size_t n, char c) { return append(n,SHEChar(model,c)); }
  SHEString &append(const SHEInt &n, char c)
    { return append(n,SHEChar(model, c)); }
  void push_back(const SHEChar &c) { *this += c; }
  void push_back(char c) { *this += c; }
  SHEString &assign(const SHEString &str)
    { return *this = str; }
  SHEString &assign(const SHEString &str, size_t subpos, size_t sublen)
    { return *this = str.substr(subpos, sublen); }
  SHEString &assign(const SHEString &str, const SHEInt &subpos,
                    const SHEInt &sublen)
    { return *this = str.substr(subpos, sublen); }
  SHEString &assign(const std::string &str)
    { return *this = SHEString(*this, str); }
  SHEString &assign(const std::string &str, size_t subpos, size_t sublen)
    { return *this = SHEString(*this, str.substr(subpos, sublen)); }
  SHEString &assign(const std::string &str, const SHEInt &subpos,
                    const SHEInt &sublen)
    { return *this = SHEString(*this,str).substr(subpos, sublen); }
  SHEString &assign(const char *str)
    { return *this = SHEString(*this, str); }
  SHEString &assign(const char *str, size_t n)
    { return *this = SHEString(*this, str, n); }
  SHEString &assign(size_t n, char c)
    { return *this = SHEString(model, n, c); }
  SHEString &assign(const SHEInt &n, char c)
    { return *this = SHEString(n, c); }
  SHEString &assign(size_t n, const SHEChar &c)
    { return *this = SHEString(n, c); }
  SHEString &assign(const SHEInt &n, const SHEChar &c)
    { return *this = SHEString(n, c); }
  SHEString &insert(size_t pos, const SHEString &str);
  SHEString &insert(const SHEInt &pos, const SHEString &str);
  SHEString &insert(size_t pos, const std::string &str)
    { return insert(pos, SHEString(*this, str)); }
  SHEString &insert(const SHEInt &pos, const std::string &str)
    { return insert(pos, SHEString(*this, str)); }
  SHEString &insert(size_t pos, const SHEString &str, size_t subpos,
                    size_t sublen)
    { return insert(pos, str.substr(subpos,sublen)); }
  SHEString &insert(const SHEInt &pos, const SHEString &str,
                    const SHEInt &subpos, const SHEInt &sublen)
    { return insert(pos, str.substr(subpos, sublen)); }
  SHEString &insert(size_t pos, const std::string &str, size_t subpos,
                    size_t sublen)
    { return insert(pos, SHEString(*this, str.substr(subpos, sublen))); }
  SHEString &insert(size_t pos, const char *str)
    { return insert(pos, SHEString(*this, str)); }
  SHEString &insert(const SHEInt &pos, const char *str)
    { return insert(pos, SHEString(*this, str)); }
  SHEString &insert(size_t pos, const char *str, size_t n)
    { return insert(pos, SHEString(*this, str, n)); }
  SHEString &insert(const SHEInt &pos, const char *str, size_t n)
    { return insert(pos, SHEString(*this, str, n)); }
  SHEString &insert(size_t pos, size_t n, const SHEChar &c)
    { return insert(pos, SHEString(n, c)); }
  SHEString &insert(const SHEInt& pos, const SHEInt &n, const SHEChar &c)
    { return insert(pos, SHEString(n, c)); }
  SHEString &insert(size_t pos, const SHEInt &n, const SHEChar &c)
    { return insert(pos, SHEString(n, c)); }
  SHEString &insert(const SHEInt& pos, size_t n, const SHEChar &c)
    { return insert(pos, SHEString(n, c)); }
  SHEString &insert(size_t pos, size_t n, char c)
    { return insert(pos, SHEString(model, n, c)); }
  SHEString &insert(const SHEInt& pos, const SHEInt &n, char c)
    { return insert(pos, SHEString(n, c)); }
  SHEString &insert(size_t pos, const SHEInt &n, char c)
    { return insert(pos, SHEString(n, c)); }
  SHEString &insert(const SHEInt& pos, size_t n, char c)
    { return insert(pos, SHEString(model, n, c)); }
  SHEString &erase(size_t pos=0, size_t len=npos);
  SHEString &erase(const SHEInt &pos, const SHEInt &len);
  SHEString &erase(const SHEInt &pos, size_t len=npos)
    { return erase(pos, SHEStringLength(len)); }
  SHEString &erase(size_t pos, const SHEInt &len)
    { return erase(SHEStringLength(pos), len); }
  SHEString &replace(size_t pos, size_t len, const SHEString &str);
  SHEString &replace(const SHEInt &pos, const SHEInt &len,
                     const SHEString &str);
  SHEString &replace(size_t pos, size_t len, const std::string &str)
    { return replace(pos, len, SHEString(*this, str)); }
  SHEString &replace(const SHEInt &pos, size_t len, const std::string &str)
    { return replace(pos, SHEStringLength(len), SHEString(*this, str)); }
  SHEString &replace(const SHEInt &pos, size_t len, const char *str)
    { return replace(pos, SHEStringLength(len), SHEString(*this, str)); }
  SHEString &replace(const SHEInt &pos, size_t len, const SHEString &str)
    { return replace(pos, SHEStringLength(len), str); }
  SHEString &replace(size_t pos, const SHEInt &len, const std::string &str)
    { return replace(SHEStringLength(pos), len, SHEString(*this, str)); }
  SHEString &replace(size_t pos, const SHEInt &len, const char *str)
    { return replace(SHEStringLength(pos), len, SHEString(*this, str)); }
  SHEString &replace(size_t pos, const SHEInt &len, const SHEString &str)
    { return replace(SHEStringLength(pos), len, str); }
  SHEString &replace(const SHEInt &pos, const SHEInt &len,
                     const std::string &str)
    { return replace(pos, len, SHEString(*this, str)); }
  SHEString &replace(const SHEInt &pos, const SHEInt &len, const char *str)
    { return replace(pos, len, SHEString(*this, str)); }
  SHEString &replace(size_t pos, size_t len, const std::string &str,
                     size_t subpos, size_t sublen)
    { return replace(pos, len, SHEString(*this, str.substr(subpos,sublen))); }
  SHEString &replace(const SHEInt &pos, size_t len, const std::string &str,
                     size_t subpos, size_t sublen)
    { return replace(pos, SHEStringLength(len),
                     SHEString(*this, str.substr(subpos,sublen))); }
  SHEString &replace(size_t pos, const SHEInt &len, const std::string &str,
                     size_t subpos, size_t sublen)
    { return replace(SHEStringLength(pos), len,
                     SHEString(*this, str.substr(subpos,sublen))); }
  SHEString &replace(const SHEInt &pos, const SHEInt &len,
                     const std::string &str, size_t subpos, size_t sublen)
    { return replace(pos, len, SHEString(*this, str.substr(subpos,sublen))); }
  SHEString &replace(size_t pos, size_t len, const SHEString &str,
                     size_t subpos, size_t sublen)
    { return replace(pos, len, str.substr(subpos,sublen)); }
  SHEString &replace(size_t pos, size_t len, const SHEString &str,
                     size_t subpos, const SHEInt &sublen)
    { return replace(pos, len, str.substr(subpos,sublen)); }
  SHEString &replace(const SHEInt &pos, size_t len, const SHEString &str,
                     size_t subpos, size_t sublen)
    { return replace(pos, SHEStringLength(len), str.substr(subpos,sublen)); }
  SHEString &replace(const SHEInt &pos, size_t len, const SHEString &str,
                     const SHEInt &subpos, size_t sublen)
    { return replace(pos, SHEStringLength(len), str.substr(subpos,sublen)); }
  SHEString &replace(const SHEInt &pos, size_t len, const SHEString &str,
                     size_t subpos, const SHEInt &sublen)
    { return replace(pos, SHEStringLength(len), str.substr(subpos,sublen)); }
  SHEString &replace(size_t pos, const SHEInt &len, const SHEString &str,
                     size_t subpos, size_t sublen)
    { return replace(SHEStringLength(pos), len, str.substr(subpos,sublen)); }
  SHEString &replace(size_t pos, const SHEInt &len, const SHEString &str,
                     const SHEInt &subpos, size_t sublen)
    { return replace(SHEStringLength(pos), len, str.substr(subpos,sublen)); }
  SHEString &replace(const SHEInt &pos, const SHEInt &len, const SHEString &str,
                     size_t subpos, size_t sublen)
    { return replace(pos, len, str.substr(subpos,sublen)); }
  SHEString &replace(const SHEInt &pos, const SHEInt &len, const SHEString &str,
                     const SHEInt &subpos, size_t sublen)
    { return replace(pos, len, str.substr(subpos,sublen)); }
  SHEString &replace(size_t pos, size_t len, const char *s,
                     size_t n)
    { return replace(pos, len, SHEString(*this, s, n)); }
  SHEString &replace(const SHEInt &pos, size_t len, const char *s,
                     size_t n)
    { return replace(pos, SHEStringLength(len), SHEString(*this, s, n)); }
  SHEString &replace(size_t pos, const SHEInt &len, const char *s,
                     size_t n)
    { return replace(SHEStringLength(pos), len, SHEString(*this, s, n)); }
  SHEString &replace(const SHEInt &pos, const SHEInt &len, const char *s,
                     size_t n)
    { return replace(pos, len, SHEString(*this, s, n)); }
  SHEString &replace(size_t pos, size_t len, char c, size_t n)
    { return replace(pos, len, SHEString(model, n, c)); }
  SHEString &replace(size_t pos, size_t len, char c, const SHEInt &n)
    { return replace(pos, len, SHEString(n, c)); }
  SHEString &replace(size_t pos, size_t len, const SHEChar &c,
                     size_t n)
    { return replace(pos, len, SHEString(n, c)); }
  SHEString &replace(size_t pos, size_t len, const SHEChar &c,
                     const SHEInt &n)
    { return replace(pos, len, SHEString(n, c)); }
  SHEString &replace(const SHEInt &pos, size_t len, char c, size_t n)
    { return replace(pos, SHEStringLength(len), SHEString(model, n, c)); }
  SHEString &replace(const SHEInt &pos, size_t len, char c, const SHEInt &n)
    { return replace(pos, SHEStringLength(len), SHEString(n, c)); }
  SHEString &replace(const SHEInt &pos, size_t len, const SHEChar &c,
                     size_t n)
    { return replace(pos, SHEStringLength(len), SHEString(n, c)); }
  SHEString &replace(const SHEInt &pos, size_t len, const SHEChar &c,
                     const SHEInt &n)
    { return replace(pos, SHEStringLength(len), SHEString(n, c)); }
  SHEString &replace(size_t pos, const SHEInt &len, char c, size_t n)
    { return replace(SHEStringLength(pos), len, SHEString(model, n, c)); }
  SHEString &replace(size_t pos, const SHEInt &len, char c, const SHEInt &n)
    { return replace(SHEStringLength(pos), len, SHEString(n, c)); }
  SHEString &replace(size_t pos, const SHEInt &len, const SHEChar &c,
                     size_t n)
    { return replace(SHEStringLength(pos), len, SHEString(n, c)); }
  SHEString &replace(size_t pos, const SHEInt &len, const SHEChar &c,
                     const SHEInt &n)
    { return replace(SHEStringLength(pos), len, SHEString(n, c)); }
  SHEString &replace(const SHEInt &pos, const SHEInt &len, char c, size_t n)
    { return replace(pos, len, SHEString(model, n, c)); }
  SHEString &replace(const SHEInt &pos, const SHEInt &len, char c,
                     const SHEInt &n)
    { return replace(pos, len, SHEString(n, c)); }
  SHEString &replace(const SHEInt &pos, const SHEInt &len, const SHEChar &c,
                     size_t n)
    { return replace(pos, len, SHEString(n, c)); }
  SHEString &replace(const SHEInt &pos, const SHEInt &len, const SHEChar &c,
                     const SHEInt &n)
    { return replace(pos, len, SHEString(n, c)); }
  void swap(SHEString &str);
  void pop_back(void) {
    if (hasEncryptedLength) {
      eLen = eLen.isZero().select(0,eLen-1);
    } else {
      string.pop_back();
    }
  }
  SHEInt copy(SHEVector<SHEChar> &s, size_t len, size_t pos=0);
  SHEInt copy(SHEVector<SHEChar> &s, const SHEInt &len, const SHEInt &pos);
  SHEInt copy(SHEVector<SHEChar> &s, const SHEInt &len, size_t pos=0)
    { return copy(s, len, SHEStringLength(pos)); }
  SHEInt copy(SHEVector<SHEChar> &s, size_t len, const SHEInt &pos)
    { return copy(s, SHEStringLength(len), pos); }
  SHEInt find(const SHEString &str, size_t pos = 0) const;
  SHEInt find(const SHEChar &c, size_t pos) const;
  SHEInt find(const SHEChar &c, const SHEInt &pos) const;
  SHEInt find(const SHEString &str, const SHEInt &pos) const;
  SHEInt find(const std::string &str, size_t pos = 0) const
    { return find(SHEString(*this,str),pos); }
  SHEInt find(const char *s, size_t pos = 0) const
    { return find(SHEString(*this,s),pos); }
  SHEInt find(const char *s, size_t pos, size_t n) const
    { return find(SHEString(*this,s,n),pos); }
  SHEInt find(const char c, size_t pos) const
    { return find(SHEChar(model,c),pos); }
  SHEInt find(const std::string &str, const SHEInt &pos) const
    { return find(SHEString(*this,str),pos); }
  SHEInt find(const char *s, const SHEInt &pos) const
    { return find(SHEString(*this,s),pos); }
  SHEInt find(const char *s, const SHEInt &pos, size_t n) const
    { return find(SHEString(*this,s,n),pos); }
  SHEInt find(const char c, const SHEInt &pos) const
    { return find(SHEChar(model,c),pos); }
  SHEInt rfind(const SHEChar &c, size_t pos) const;
  SHEInt rfind(const SHEString &str, size_t pos = 0) const;
  SHEInt rfind(const SHEChar &c, const SHEInt &pos) const;
  SHEInt rfind(const SHEString &str, const SHEInt &pos) const;
  SHEInt rfind(const std::string &str, size_t pos = 0) const
    { return rfind(SHEString(*this,str), pos); }
  SHEInt rfind(const char *s, size_t pos = 0) const
    { return rfind(SHEString(*this,s), pos); }
  SHEInt rfind(const char *s, size_t pos, size_t n) const
    { return rfind(SHEString(*this,s,n), pos); }
  SHEInt rfind(const char c, size_t pos) const
    { return rfind(SHEChar(model,c), pos); }
  SHEInt rfind(const std::string &str, const SHEInt &pos) const
    { return rfind(SHEString(*this,str), pos); }
  SHEInt rfind(const char *s, const SHEInt &pos) const
    { return rfind(SHEString(*this,s), pos); }
  SHEInt rfind(const char *s, const SHEInt &pos, size_t n) const
    { return rfind(SHEString(*this,s,n), pos); }
  SHEInt rfind(const char c, const SHEInt &pos) const
    { return rfind(SHEChar(model,c), pos); }

  SHEString substr(size_t pos = 0, size_t len=npos) const;
  SHEString substr(const SHEInt &pos, size_t len=npos) const
    { return substr(pos, SHEStringLength(len)); }
  SHEString substr(size_t pos, const SHEInt &len) const
    { return substr(SHEStringLength(pos), len); }
  SHEString substr(const SHEInt &pos, const SHEInt &len) const;
  SHEInt compare(const SHEString &s) const;
  SHEInt compare(const std::string &s) const
    { return compare(SHEString(*this,s)); }
  SHEInt compare(size_t pos, size_t len, const std::string &s) const
    { return substr(pos,len).compare(SHEString(*this,s)); }
  SHEInt compare(size_t pos, size_t len, const std::string &s,
                   size_t subpos, size_t subLen) const
    { return substr(pos,len).compare(SHEString(*this,
                                     s.substr(subpos,subLen))); }
  SHEInt compare(const char *s) const
    { return compare(SHEString(*this,s)); }
  SHEInt compare(size_t pos, size_t len, const char *s) const
    { return substr(pos,len).compare(SHEString(*this,s)); }
  SHEInt compare(size_t pos, size_t len, const char *s,
                  size_t subpos, size_t subLen) const;
  SHEInt compare(size_t pos, size_t len, const SHEString&s) const
    { return substr(pos,len).compare(s); }
  SHEInt compare(size_t pos, size_t len, const SHEString&s,
                  size_t subpos, size_t subLen) const
    { return substr(pos,len).compare(s.substr(subpos,subLen)); }
  SHEInt compare(size_t pos, const SHEInt &len, const SHEString&s) const
    { return substr(pos,len).compare(s); }
  SHEInt compare(size_t pos, const SHEInt &len, const SHEString&s,
                  size_t subpos, size_t subLen) const
    { return substr(pos,len).compare(s.substr(subpos,subLen)); }
  SHEInt compare(const SHEInt &pos, size_t len, const SHEString&s) const
    { return substr(pos,len).compare(s); }
  SHEInt compare(const SHEInt &pos, size_t len, const SHEString&s,
                  size_t subpos, size_t subLen) const
    { return substr(pos,len).compare(s.substr(subpos,subLen)); }
  SHEInt compare(const SHEInt &pos, const SHEInt &len,
                  const SHEString&s) const
    { return substr(pos,len).compare(s); }
  SHEInt compare(const SHEInt &pos, const SHEInt &len, const SHEString&s,
                  size_t subpos, size_t subLen) const
    { return substr(pos,len).compare(s.substr(subpos,subLen)); }
  SHEInt compare(const SHEInt &pos, const SHEInt &len, const SHEString&s,
                  const SHEInt &subpos, const SHEInt &subLen) const
    { return substr(pos,len).compare(s.substr(subpos,subLen)); }
  SHEInt compare(const SHEInt &pos, const SHEInt &len, const char *s) const
    { return substr(pos,len),compare(SHEString(*this,s)); }
  SHEBool operator==(const SHEString&s) const
    { return compare(s).isZero(); }
  SHEBool operator!=(const SHEString &s) const
    { return compare(s).isNotZero(); }
  SHEBool operator<(const SHEString &s) const
    { return compare(s).isNegative(); }
  SHEBool operator<=(const SHEString &s) const
    { return compare(s).isNonPositive(); }
  SHEBool operator>(const SHEString &s) const
    { return compare(s).isPositive(); }
  SHEBool operator>=(const SHEString &s) const
    { return compare(s).isNonNegative(); }
  SHEBool operator==(const std::string &s) const
    { return compare(s).isZero(); }
  SHEBool operator!=(const std::string &s) const
    { return compare(s).isNotZero(); }
  SHEBool operator<(const std::string &s) const
    { return compare(s).isNegative(); }
  SHEBool operator<=(const std::string &s) const
    { return compare(s).isNonPositive(); }
  SHEBool operator>(const std::string &s) const
    { return compare(s).isPositive(); }
  SHEBool operator>=(const std::string &s) const
    { return compare(s).isNonNegative(); }
  SHEBool operator==(const char *s) const
    { return compare(s).isZero(); }
  SHEBool operator!=(const char *s) const
    { return compare(s).isNotZero(); }
  SHEBool operator<(const char *s) const
    { return compare(s).isNegative(); }
  SHEBool operator<=(const char *s) const
    { return compare(s).isNonPositive(); }
  SHEBool operator>(const char *s) const
    { return compare(s).isPositive(); }
  SHEBool operator>=(const char *s) const
    { return compare(s).isNonNegative(); }
  // this plays the role of a_true
  SHEString selectHelper(const SHEInt &sel, const SHEString &a_false) const;

  // get the decrypted result given the private key
  char *decryptRaw(const SHEPrivateKey &privKey, size_t *len) const;
  std::string decrypt(const SHEPrivateKey &privKey) const;
  // bootstrapping help
  long bitCapacity(void) const;
  double securityLevel(void) const;
  bool isCorrect(void) const;
  bool needRecrypt(long level=SHEINT_DEFAULT_LEVEL_TRIGGER) const;
  bool needRecrypt(const SHEString &a,
                   long level=SHEINT_DEFAULT_LEVEL_TRIGGER) const;
  void verifyArgs(long level=SHEINT_DEFAULT_LEVEL_TRIGGER);
  void verifyArgs(SHEString &a, long level=SHEINT_DEFAULT_LEVEL_TRIGGER);
  void reCrypt(void);
  void reCrypt(SHEString &a);

#ifdef DEBUG
  static void setDebugPrivateKey(SHEPrivateKey &privKey)
    { debugPrivKey = &privKey; }
#endif
  static void setLog(std::ostream &str) { log = &str; }

  bool lengthIsEncrypted(void) const { return hasEncryptedLength; }

  // input/output functions
  // use helib standard intput, outputs methods
  void writeTo(std::ostream& str) const;
  void writeToJSON(std::ostream& str) const;
  helib::JsonWrapper writeToJSON(void) const;
  static SHEString readFrom(std::istream& str, const SHEPublicKey &pubKey);
  static SHEString readFromJSON(std::istream& str, const SHEPublicKey &pubKey);
  static SHEString readFromJSON(const helib::JsonWrapper& j,
                                const SHEPublicKey &pubKey);
  void read(std::istream& str);
  void readFromJSON(std::istream&str);
  void readFromJSON(const helib::JsonWrapper &jw);
  void readJSON(const helib::JsonWrapper &jw) { readFromJSON(jw); }

  // give a simple import/export function as well
  unsigned char *flatten(size_t &size, bool ascii) const;
};

class SHEStringSummary
{
private:
   const SHEString &shestring;
#ifdef DEBUG
   const SHEPrivateKey *getPrivateKey(void) const
         { return SHEString::debugPrivKey; }
#endif
public:
   SHEStringSummary(const SHEStringSummary &summary) :
                    shestring(summary.shestring) {}
   SHEStringSummary(const SHEString &shestring_) : shestring(shestring_) {}
   friend std::ostream &operator<<(std::ostream&, const SHEStringSummary&);
};

// overload integer(unencrypted) [op] SHEInt, so we get the same results
// even if we swap the unencrypted and encrypted values. We can implent most
// of them using either communitive values, or communitive identities
inline SHEBool operator>(const std::string &a, const SHEString &b)
  { return b < a; }
inline SHEBool operator<(const std::string &a, const SHEString &b)
  { return b > a; }
inline SHEBool operator>=(const std::string &a, const SHEString &b)
  { return b <= a; }
inline SHEBool operator<=(const std::string &a, const SHEString &b)
  { return b >= a; }
inline SHEBool operator!=(const std::string &a, const SHEString &b)
  { return b != a; }
inline SHEBool operator==(const std::string &a, const SHEString &b)
  { return b == a; }
inline SHEBool operator>(const char *a, const SHEString &b) { return b < a; }
inline SHEBool operator<(const char *a, const SHEString &b) { return b > a; }
inline SHEBool operator>=(const char *a, const SHEString &b) { return b <= a; }
inline SHEBool operator<=(const char *a, const SHEString &b) { return b >= a; }
inline  SHEString select(const SHEInt &sel, const SHEString &a_true,
                         const SHEString &a_false)
  { return a_true.selectHelper(sel, a_false); }
inline  SHEString select(const SHEInt &sel, const SHEString &a_true,
                         const std::string &a_false)
  { return a_true.selectHelper(sel, SHEString(a_true,a_false)); }
inline  SHEString select(const SHEInt &sel, const std::string &a_true,
                         const SHEString &a_false)
  { return SHEString(a_false, a_true).selectHelper(sel, a_false); }
inline  SHEString select(const SHEInt &sel, const std::string &a_true,
                         const std::string &a_false)
  { return SHEString(sel.getPublicKey(), a_true).selectHelper(sel,
           SHEString(sel.getPublicKey(),a_false)); }
inline  SHEString select(const SHEInt &sel, const SHEString &a_true,
                         const char *a_false)
  { return a_true.selectHelper(sel, SHEString(a_true,a_false)); }
inline  SHEString select(const SHEInt &sel, const char *a_true,
                         const SHEString &a_false)
  { return SHEString(a_false, a_true).selectHelper(sel, a_false); }
inline  SHEString select(const SHEInt &sel, const char *a_true,
                         const char *a_false)
  { return SHEString(sel.getPublicKey(), a_true).selectHelper(sel,
           SHEString(sel.getPublicKey(),a_false)); }

// io operators. uses public functions, do no need a friend declaration
std::istream&operator>>(std::istream&, SHEString &a);
std::ostream&operator<<(std::ostream&, const SHEString &a);

// allow SHEBool.select(SHEFp, SHEFp) output
class SHEStringBool : public SHEInt {
public:
  SHEStringBool(const SHEInt &a) : SHEInt(a) {}
  SHEStringBool(const SHEBool &a) : SHEInt(a) {}
  SHEString select(const SHEString &a_true, const SHEString &a_false) const
  {
    const SHEInt &narrow = *this;
    return ::select(narrow, a_true, a_false);
  }
  SHEString select(const SHEString &a_true, const std::string &a_false) const
  {
    const SHEInt &narrow = *this;
    return ::select(narrow, a_true, a_false);
  }
  SHEString select(const std::string &a_true, const SHEString &a_false) const
  {
    const SHEInt &narrow = *this;
    return ::select(narrow, a_true, a_false);
  }
  SHEString select(const std::string &a_true, const std::string &a_false) const
  {
    const SHEInt &narrow = *this;
    return ::select(narrow, a_true, a_false);
  }
  SHEString select(const SHEString &a_true, const char *a_false) const
  {
    const SHEInt &narrow = *this;
    return ::select(narrow, a_true, a_false);
  }
  SHEString select(const char *a_true, const SHEString &a_false) const
  {
    const SHEInt &narrow = *this;
    return ::select(narrow, a_true, a_false);
  }
  SHEString select(const char *a_true, const char *a_false) const
  {
    const SHEInt &narrow = *this;
    return ::select(narrow, a_true, a_false);
  }
};
#endif
