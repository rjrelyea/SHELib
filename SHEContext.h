//
// Build standard context sets. helib does not allow contexts to be copied
//  and it's difficult to serialize them. It really assumes that all contexts
//  will be generated once in the application and just used everywhere.
//  We handle this by having sets of well known contexts and keeping them in
//  a global hash list.
//
#ifndef SHEContext_H
#define SHEContext_H 1
#include <unordered_map>
#include <helib/helib.h>
#include "SHEConfig.h"

// we keep 3 types of contexts: Binary for binary arithmetic,
// strings for encrypted strings (used for encrypted searches), and
// Vectors, used for simultaneous vector math.
typedef enum {
  SHEContextBinary,
  SHEContextBGV,
  SHEContextCVV
} SHEContextType;

typedef std::unordered_map<long,helib::Context *>SHEContextHash;

#define SHE_CONTEXT_CAPACITY_ANY  0
#define SHE_CONTEXT_CAPACITY_LOW   600
#define SHE_CONTEXT_CAPACITY_HIGH  900

class SHEContext
{
private:
  static std::ostream *log;
  static  SHEContextHash binaryDatabase;
  static  SHEContextHash bgvDatabase;
  static  SHEContextHash cvvDatabase;
  static SHEContextHash *GetContextHash(SHEContextType type);
  static helib::Context *GetNewGenericContext(long prime, long securityLevel,
                                              long capacity);
  static helib::Context *GetNewBGVContext(long &securityLevel,
                                          long &capacity);
  static helib::Context *GetNewCVVContext(long &securityLevel,
                                          long &capacity);
  static helib::Context *GetNewBinaryContext(long &securityLevel,
                                             long &capacity);
  static helib::Context *BuildBootstrappableContext(long p, long m,
                                       long securityLevel,
                                       long levels, long r, long c,
                                       const std::vector<long> &mvec,
                                       std::vector<long> &ords,
                                       std::vector<long> &gens);
public:
  static constexpr std::string_view typeName = "SHEContext";
  static helib::Context *GetContext(SHEContextType type,
                                    long &securityLevel, long &capacity);
  static const char *GetContextTypeLabel(SHEContextType type);
  static long GetContextTypeValue(SHEContextType type);
  static SHEContextType GetContextType(long value);
  static SHEContextType GetContextType(char *value);
  static void FreeContext(SHEContextType type, long securityLevel,
                          long capacity=SHE_CONTEXT_CAPACITY_ANY);
  static void setLog(std::ostream &str) { log = &str; }
};
#endif
