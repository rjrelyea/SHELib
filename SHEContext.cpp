//
// Build standard context sets. helib does not allow contexts to be copied
//  and it's difficult to serialize them. It really assumes that all contexts
//  will be generated once in the application and just used everywhere.
//  We handle this by having sets of well known contexts and keeping them in
//  a global hash list.
//
#include <iostream>
#include <unordered_map>
#include <helib/helib.h>
#include "SHEContext.h"

SHEContextHash SHEContext::binaryDatabase;// = {0};
SHEContextHash SHEContext::bgvDatabase;// = {0};
SHEContextHash SHEContext::cvvDatabase;// = {0};
std::ostream *SHEContext::log = nullptr;

static const struct {
  SHEContextType type;
  long typeValue;
  const char *name;
} contextTypeTable[] = {
  { SHEContextBinary, 1, "SHEContextBinary" },
  { SHEContextBGV, 2, "SHEContextBGV" },
  { SHEContextCVV, 3, "SHEContextCVV" }
};

static const int contextTypeTableSize=sizeof(contextTypeTable)/
                                      sizeof(contextTypeTable[0]);
#define SHE_ARRAY_SIZE(t) (sizeof(t)/sizeof(t[0]))

struct SHEContextParams {
  long p;
  long L;
  long r;
  long c;
  long m;
  long gens[SHECONTEXT_MAX_GEN_SIZE];
  long ords[SHECONTEXT_MAX_ORD_SIZE];
  long securityLevel; // security level context
};

#ifdef COMMENT
// same context settings from the bootstrapping tests in GTestBootstrapping.cpp
// these were used as the initial input into the table below:
//{ p, phi(m),  m,    d, m1,  m2, m3,   g1,    g2,    g3,ord1,ord2,ord3, c_m}
{  2,    48,   105, 12,  3,  35,  0,    71,    76,    0,    2,   2,   0, 200},
{  2,   600,  1023, 10, 11,  93,  0,   838,   584,    0,   10,   6,   0, 100}, // m=(3)*11*{31} m/phim(m)=1.7    C=24  D=2 E=1
{  2,  1200,  1705, 20, 11, 155,  0,   156,   936,    0,   10,   6,   0, 100}, // m=(5)*11*{31} m/phim(m)=1.42   C=34  D=2 E=2
{  2,  1728,  4095, 12,  7,  5, 117,  2341,  3277, 3641,    6,   4,   6, 100}, // m=(3^2)*5*7*{13} m/phim(m)=2.36 C=26 D=3 E=2
{  2,  2304,  4641, 24,  7,  3, 221,  3979,  3095, 3760,    6,   2,  -8, 300}, // m=3*7*(13)*{17} :-( m/phim(m)=2.01 C=45 D=4 E=3
{  2,  4096,  4369, 16, 17, 257,  0,   258,  4115,    0,   16, -16,   0, 100}, // m=17*(257) :-( m/phim(m)=1.06 C=61 D=3 E=4
{  2, 12800, 17425, 40, 41, 425,  0,  5951,  8078,    0,   40,  -8,   0, 100}, // m=(5^2)*{17}*41 m/phim(m)=1.36 C=93  D=3 E=3
{  2, 15004, 15709, 22, 23, 683,  0,  4099, 13663,    0,   22,  31,   0, 100}, // m=23*(683) m/phim(m)=1.04      C=73  D=2 E=1
{  2, 16384, 21845, 16, 17,   5,257,  8996, 17477,21591,   16,   4, -16, 200}, // m=5*17*(257) :-( m/phim(m)=1.33 C=65 D=4 E=4
{  2, 18000, 18631, 25, 31, 601,  0, 15627,  1334,    0,   30,  24,   0, 100}, // m=31*(601) m/phim(m)=1.03      C=77  D=2 E=0
{  2, 18816, 24295, 28, 43, 565,  0, 16386, 16427,    0,   42,  16,   0, 100}, // m=(5)*43*{113} m/phim(m)=1.29  C=84  D=2 E=2
{  2, 21168, 27305, 28, 43, 635,  0, 10796, 26059,    0,   42,  18,   0, 100}, // m=(5)*43*{127} m/phim(m)=1.28  C=86  D=2 E=2
{  2, 23040, 28679, 24, 17,  7, 241, 15184,  4098,28204,   16,   6, -10, 200}, // m=7*17*(241) m/phim(m)=1.24    C=63  D=4 E=3
{  2, 24000, 31775, 20, 41, 775,  0,  6976, 24806,    0,   40,  30,   0, 100}, // m=(5^2)*{31}*41 m/phim(m)=1.32 C=88  D=2 E=2
{  2, 26400, 27311, 55, 31, 881,  0, 21145,  1830,    0,   30,  16,   0, 100}, // m=31*(881) m/phim(m)=1.03      C=99  D=2 E=0
{  2, 27000, 32767, 15, 31,  7, 151, 11628, 28087,25824,   30,   6, -10, 200},
{  2, 31104, 35113, 36, 37, 949,  0, 16134,  8548,    0,   36,  24,   0, 200}, // m=(13)*37*{73} m/phim(m)=1.12  C=94  D=2 E=2
{  2, 34848, 45655, 44, 23, 1985, 0, 33746, 27831,    0,   22,  36,   0, 100}, // m=(5)*23*{397} m/phim(m)=1.31  C=100 D=2 E=2
{  2, 42336, 42799, 21, 127, 337, 0, 25276, 40133,    0,  126,  16,   0, 200}, // m=127*(337) m/phim(m)=1.01     C=161 D=2 E=0
{  2, 45360, 46063, 45, 73, 631,  0, 35337, 20222,    0,   72,  14,   0, 100}, // m=73*(631) m/phim(m)=1.01      C=129 D=2 E=0
{  2, 46080, 53261, 24, 17, 13, 241, 43863, 28680,15913,   16,  12, -10, 100}, // m=13*17*(241) m/phim(m)=1.15   C=69  D=4 E=3
{  2, 49500, 49981, 30, 151, 331, 0,  6952, 28540,    0,  150,  11,   0, 100}, // m=151*(331) m/phim(m)=1        C=189 D=2 E=1
{  2, 54000, 55831, 25, 31, 1801, 0, 19812, 50593,    0,   30,  72,   0, 100}, // m=31*(1801) m/phim(m)=1.03     C=125 D=2 E=0
{  2, 60016, 60787, 22, 89, 683,  0,  2050, 58741,    0,   88,  31,   0, 200}, // m=89*(683) m/phim(m)=1.01      C=139 D=2 E=1
#endif
struct SHEContextParams binaryContextParams[] = {
//{ p, L,    r, c,     m,   g[0],  g[1],  g[2],ord[0],ord[1],ord[2], sl}
  { 2,  600, 1, 3,   105, {   71,    76,    0}, {   2,    2,   0},  19},//final
  { 2,  900, 1, 3,  1023, {  838,   584,    0}, {  10,    6,   0},  20},//final
  { 2,  600, 1, 3,  1705, {  156,   936,    0}, {  10,    6,   0},  21},//final
  { 2,  900, 1, 2,  4095, { 2341,  3277, 3641}, {   6,    4,   6},  22},//final
  { 2,  900, 1, 2,  4641, { 3979,  3095, 3760}, {   6,    2,  -8},  23},//final
  { 2,  600, 1, 2,  4095, { 2341,  3277,  911}, {   6,    4,   6},  24},//final
  { 2,  600, 1, 2,  4641, { 3979,  3095, 3760}, {   6,    2,  -8},  25},//final
  { 2,  900, 1, 2,  4369, {  258,  4115,    0}, {  16,  -16,   0},  26},//final
  { 2,  600, 1, 2,  4369, {  258,  4115,    0}, {  16,  -16,   0},  29},//final
  { 2,  900, 1, 2, 17425, { 5951,  8078,    0}, {  40,   -8,   0},  41},//final
  { 2,  900, 1, 2, 15709, { 4099, 13663,    0}, {  22,   31,   0},  45},//final
  { 2,  900, 1, 2, 21845, { 8996, 17477,21591}, {  16,    4, -16},  47},//final
  { 2,  900, 1, 2, 18631, {15627,  1334,    0}, {  30,   24,   0},  50},//final
  { 2,  900, 1, 2, 24295, {16386, 16427,    0}, {  42,   16,   0},  51},//final
  { 2,  600, 1, 2, 17425, { 5951,  8078,    0}, {  40,   -8,   0},  52},//final
  { 2,  900, 1, 2, 27305, {10796, 26059,    0}, {  42,   18,   0},  56},//final
  { 2,  600, 1, 2, 15709, { 4099, 13663,    0}, {  22,   31,   0},  57},//final
  { 2,  900, 1, 2, 28679, {15184,  4098,28204}, {  16,    6, -10},  59},//final
  { 2,  900, 1, 2, 31775, { 6976, 24806,    0}, {  40,   30,   0},  60},//final
  { 2,  600, 1, 2, 21845, { 8996, 17477,21591}, {  16,    4, -16},  61},//final
  { 2,  600, 1, 2, 18631, {15627,  1334,    0}, {  30,   24,   0},  64},//final
  { 2,  900, 1, 2, 27311, {21145,  1830,    0}, {  30,   16,   0},  65},//final
  { 2,  900, 1, 2, 32767, {11628, 28087,25824}, {  30,    6, -10},  66},//final
  { 2,  600, 1, 2, 24295, {16386, 16427,    0}, {  42,   16,   0},  67},//final
  { 2,  900, 1, 2, 35113, {16134,  8548,    0}, {  36,   24,   0},  72},//final
  { 2,  600, 1, 2, 27305, {10796, 26059,    0}, {  42,   18,   0},  73},//final
  { 2,  600, 1, 2, 28679, {15184,  4098,28204}, {  16,    6, -10},  78},//final
  { 2,  600, 1, 2, 31775, { 6976, 24806,    0}, {  40,   30,   0},  80},//final
  { 2,  900, 1, 3, 45655, {33746, 27831,    0}, {  22,   36,   0},  85},//final
  { 2,  600, 1, 2, 27311, {21145,  1830,    0}, {  30,   16,   0},  86},//final
  { 2,  600, 1, 2, 32767, {11628, 28087,25824}, {  30,    6, -10},  88},//final
  { 2,  600, 1, 2, 35113, {16134,  8548,    0}, {  36,   24,   0},  97},//final
  { 2,  900, 1, 2, 46063, {35337, 20222,    0}, {  72,   14,   0},  98},//final
  { 2,  900, 1, 2, 53261, {43863, 28680,15913}, {  16,   12, -10},  99},//final
  { 2,  900, 1, 3, 42799, {25276, 40133,    0}, { 126,   16,   0}, 100},//final
  { 2,  900, 1, 2, 49981, { 6952, 28540,    0}, { 150,   11,   0}, 105},//final
  { 2,  600, 1, 3, 45655, {33746, 27831,    0}, {  22,   36,   0}, 120},//final
  { 2,  900, 1, 3, 55831, {19812, 50593,    0}, {  30,   72,   0}, 122},//final
  { 2,  900, 1, 3, 60787, { 2050, 58741,    0}, {  88,   31,   0}, 133},//final
  { 2,  600, 1, 2, 46063, {35337, 20222,    0}, {  72,   14,   0}, 135},//final
  { 2,  600, 1, 2, 53261, {43863, 28680,15913}, {  16,   12, -10}, 137},//final
  { 2,  600, 1, 3, 42799, {25276, 40133,    0}, { 126,   16,   0}, 142},//final
  { 2,  600, 1, 2, 49981, { 6952, 28540,    0}, { 150,   11,   0}, 146},//final
  { 2,  600, 1, 3, 55831, {19812, 50593,    0}, {  30,   72,   0}, 175},//final
  { 2,  600, 1, 3, 60787, { 2050, 58741,    0}, {  88,   31,   0}, 193},//final
};

const int binaryContextParamsTableSize = SHE_ARRAY_SIZE(binaryContextParams);


//  ----------------------- utilities
//  to help generate context parameters.

// output a vector<long> in a pretty format
std::ostream &operator<<(std::ostream &s,std::vector<long> v)
{
  s << "{ ";
  for (auto vi = v.begin(); vi != v.end(); vi++) {
    s << *vi << " ";
  }
  s << "}";
  return s;
}

#include "SHEprimetable.h"
// create the factors of m. The returned factors will be of the form
// p1^n1,p2^n2,p3^n3... and sorted by size.
// we use a brute force method of trying every prime < 32bits. This
// allows us to factor up to 64 bit 'm' values
static std::vector<long>
factorize(long m)
{
  bool needsort = false;
  std::vector<long> factors;
  if ((m == 0)  || (m == 1)) {
    factors.push_back(m);
    return factors;
  }

  /* trial divide by all the primes < 32 bits */
  for (int i=0; i< primeTableSize; i++) {
    // we found the last prime
    if (m == primeTable[i]) {
      break;
    }
    // while the prime divides m, add it to the table
    if ((m % primeTable[i]) == 0) {
      long collect=primeTable[i];

      m /= primeTable[i];
      // handle factors prime^n
      while ((m % primeTable[i]) == 0) {
        needsort = true; // if we have prime1^n, it will likely be larger
                         // than the follow prime2, so we need to resort the
                         // list when we are done.
        collect *= primeTable[i];
        m /= primeTable[i];
      }
      // handle the case where the last factor was prime^n
      if (m == 1) {
        m = collect;
        break;
      }
      factors.push_back(collect);
    }
  }
  // what is left over is either the last prime, or the original
  // 64 bit number, which we now know is prime, add it to the factors
  // list
  factors.push_back(m);

  if (needsort) {
    std::sort(factors.begin(),factors.end());
  }
  return factors;
}

// assumes m is p^n, otherwise it returns the smallest prime factor of m
static long
getPrime(long m)
{
  bool needsort = false;
  if ((m == 0)  || (m == 1)) {
    return 1;
  }

  /* trial divide by all the primes < 32 bits */
  for (int i=0; i< primeTableSize; i++) {
    // we found the  prime
    if (m == primeTable[i]) {
      break;
    }
    if ((m % primeTable[i]) == 0) {
      return primeTable[i];
    }
  }
  return m;
}

// some simple gdc expMod and multiplicitve order functions
static long
gcd(long a, long b, long &r)
{
  if (a < 0) a=-a;
  if (b < 0) b=-b;
  while (b != 0) {
    r = b;
    b = a % b;
    a = r;
  }
  return a;
}

static long
expMod(long a, long e, long mod)
{
  long result = 1;
  a = a % mod;

  for (;e; e >>=1) {
    if (e&1) { result = (result * a) % mod; }
    a = (a * a) % mod;
  }
  return result;
}

static long
multOrd(long p, long m)
{
  long ord = 1;
  long val = p;
  long tmp = 0;
  if (gcd(p,m,tmp) != 1) {
    return 0;
  }
  p = p % m;
  while (val != 1) {
    ord++;
    val = (val * p) % m;
  }
  return ord;
}

static long
getGen(long m, long ord)
{
  std::vector<long> logP(m);
  long candidate;
  long ordCandidate=1;
  long ordInv=1;

  // first build our log table
  for (candidate=2; candidate < m ;candidate++) {
    ordCandidate = multOrd(candidate,m);
    if (ordCandidate == ord) {
       // success, we've found one already!
      std::cout << "found generator directly=" <<  candidate
                << " ordCandidate=" << ordCandidate
                << " ord=" << ord << std::endl;
       return candidate;
    }
    // find a candidate generator to calculate or designated generator
    if (gcd(ord,ordCandidate,ordInv) == 1) {
      break;
    }
  }
  helib::assertNeq(ordInv, (long)1,
                  "couldn't find candidate for order");
  long gen = expMod(candidate,ordInv,m);
  std::cout << "ord=" << ord << " candidate=" << candidate
            << " ordInv=" << ordInv << " gen=" << gen
            << " ord(gen)=" << multOrd(gen,m) << std::endl;
  helib::assertEq(multOrd(gen, m), ord,
                  "Caclulating generator with for order failed");
  return gen;
}

// return the euler order of 'n'
static long
phi(long n)
{
  std::vector<long> factors=factorize(n);
  long phi = 1;

  for (auto pN : factors) {
    long p = getPrime(pN);
    phi *= (p-1)*(pN/p);
  }
  return phi;
}

// check if this mvec map is suitable for bootstrapping
static bool
checkEvalMap(long p, std::vector<long> mvec, const std::vector<long> *ords)
{
  long mvecSize = mvec.size();

  // 1.  make sure we pass inertPrefix check
  long dprod = 1;
  std::vector<long> dvec(mvecSize);
  for (int i=mvecSize-1; i >= 0; i--) {
    dvec[i] = multOrd(expMod(p, dprod, mvec[i]), mvec[i]);
    if ((i != mvecSize-1) && dvec[i] != 1) {
      return false;
    }
    dprod *= dvec[i];
  }

  // 2. make sure we pass the signature size check
  //    we use this if we already have ords
  if (ords) {
    for (int i=0; i < mvecSize; i++) {
      long ord = i >= ords->size() ? 1 : abs((*ords)[i]);
      if (ord != phi(mvec[i])/dvec[i]) {
        return false;
      }
    }
  }

  return true;
}

// make ords that will pass the eval check
static std::vector<long>
makeOrds(long p, std::vector<long> mvec)
{
  long mvecSize = mvec.size();
  std::vector<long> ords(0);
  std::cout << "make ords from mvec=" << mvec << std::endl;
  for (auto mv : mvec) {
    std::cout << " mv=" << mv << "->" << getPrime(mv) << std::endl;
  }

  // calculate d: this assumes that mvec has already passed
  // checkEvalMap and dvec is < 1, 1, 1...., d>
  long d = multOrd(p, mvec.back());
  std::cout << "... d=" << d << std::endl;

  // calculate an ord that will pass the signature check
  for (int i=0; i < mvecSize-1; i++) {
    ords.push_back(phi(mvec[i]));
  }
  // last one is skipped if it's == 1
  long ord = phi(mvec.back())/d;
  if (ord != 1) {
    ords.push_back(ord);
  }
  return ords;
}

static int
getPrevEntry(const std::vector<long> &vec, long entry, int start, int end)
{
  for (int i=end-1; i >= start; i++) {
    if (vec[i] == entry) { return i; }
  }
  return end;
}

// make ords that will pass the eval check
static std::vector<long>
makeGens(long m, std::vector<long> ords)
{
  std::cout << " makeGens from ord=" << ords << " m=" << m << std::endl;
  std::vector<long> gens(0);
  for (int i=0; i < ords.size(); i++) {
    long ord=ords[i];
    std::cout << "looking up gen[" << i << "] for ord=" << ord << std::endl;
    // we want unique generators even for the
    // same order. Check if we have already
    // used this order. 'j' is the most recent
    // instance of the requested order.
    int j=getPrevEntry(ords, ord, 0, i);
    if (j==i ) {
      gens.push_back(getGen(m, ord));
    } else {
      // use the old generator to calculate a new one
      long gen=(gens[j]*gens[j])%m;
      // gen^k mod n will have the same or less order of gen, so
      // find a candidate along this path
      while (gen != 1 && multOrd(gen,m) != ord) {
        gen = (gen*gens[j])%m;
      }
      helib::assertNeq(gen, (long)1, "couldn't find alternate generator");
      gens.push_back(gen);
    }
  }
  return gens;
}

// format a candidate mvec map
static std::vector<long>
mvecFormat(std::vector<long> mvec)
{
  std::sort(mvec.begin(),mvec.end());
  // if there are more than two factors, swap the first two factors.
  // don't know why, but this seems to be required for boostrapping.
  if (mvec.size() > 2) {
    long tmp = mvec[0];
    mvec[0] = mvec[1];
    mvec[1] = tmp;
  }
  return mvec;
}

// given a p and m, create a set of products of m that will enable
// bootstrapping in a domain of plain text p.
static std::vector<long>
getMvec(long p, long m, const std::vector<long> *ords)
{
  // first get the list of factors and format it.
  std::vector<long> factors=mvecFormat(factorize(m));
  int factorSize = factors.size();

  // if the base set of factors is fine, return it.
  if (checkEvalMap(p, factors, ords)) {
    return factors;
  }

  // try colapsing pairs of factors and return the first
  // one that works.
  for (int i=factorSize-1; i >=0; i--) {
    for (int j=i-1; j >=0; j--) {
      std::vector<long> newFactors = factors;
      newFactors[j] = newFactors[j] * newFactors[i];
      newFactors.erase(newFactors.begin()+i);
      newFactors = mvecFormat(newFactors);
      if (checkEvalMap(p, newFactors, ords)) {
        return newFactors;
      }
    }
  }

  // if factors <= 3 we've done all we can, factors > 3 are rare for
  // our chosen m
  helib::assertTrue((bool)0, "can't find suitable mvec for m");
  return factors;
}

static std::vector<long>
buildVector(const long *m, int count)
{
  std::vector<long> vectors;
  /* trial divide by all the primes < 32 bits */
  for (int i=0; i < count; i++) {
    if (m[i] == 0) {
      break;
    }
    vectors.push_back(m[i]);
  }
  return vectors;
}


SHEContextHash *
SHEContext::GetContextHash(SHEContextType type)
{
  switch(type) {
  case SHEContextBinary:
    return &binaryDatabase;
  case SHEContextBGV:
    return &bgvDatabase;
  case SHEContextCVV:
    return &cvvDatabase;
  // don't add default so the compiler will warn is when SHEContextType
  // is expanded
  };
  return nullptr;
}

const char *
SHEContext::GetContextTypeLabel(SHEContextType type)
{
  for (int i=0; i < contextTypeTableSize; i++) {
    if (contextTypeTable[i].type == type) {
      return contextTypeTable[i].name;
    }
  }
  return nullptr;
}

long
SHEContext::GetContextTypeValue(SHEContextType type)
{
  for (int i=0; i < contextTypeTableSize; i++) {
    if (contextTypeTable[i].type == type) {
      return contextTypeTable[i].typeValue;
    }
  }
  return 0;
}

SHEContextType
SHEContext::GetContextType(long value)
{
  for (int i=0; i < contextTypeTableSize; i++) {
    if (contextTypeTable[i].typeValue == value) {
      return contextTypeTable[i].type;
    }
  }
  return (SHEContextType)-1;
}

SHEContextType
SHEContext::GetContextType(char *value)
{
  for (int i=0; i < contextTypeTableSize; i++) {
    if (strcmp(contextTypeTable[i].name,value) == 0) {
      return contextTypeTable[i].type;
    }
  }
  return (SHEContextType)-1;
}

helib::Context *
SHEContext::BuildBootstrappableContext(long p, long m, long securityLevel,
                                       long levels, long r, long c,
                                       const std::vector<long> &mvec,
                                       std::vector<long> &ords,
                                       std::vector<long> &gens)
{
  NTL::Vec<long> ntlMvec;

  // convert std::vector<> to NTL:Vec<> vector
  for (auto mv : mvec) {
    ntlMvec.append(mv);
  }

  if (log) {
    (*log) << "Building Context with securityLevel=" << securityLevel
           << " m=" << m <<" mvec=" << mvec << " bits=" << levels
           << " ords=" << ords << " gens=" << gens<< "...." << std::endl;
  }
  helib::ContextBuilder builder = helib::ContextBuilder<helib::BGV>().m(m)
                                  .p(p).r(r).gens(gens).ords(ords) ;
  if (log) (*log) << "Context builder: " << builder << std::endl;

  helib::Context *context = builder.buildModChain(false).buildPtr();
  if(log) {
    (*log) << "Context no mod chain:" << std::endl;
  }

  context->buildModChain(levels, c, true, 0);
  if (log) {
    (*log) << "Context mod chain:" << std::endl;
    context->printout(*log);
    (*log) << std::endl << "mvec=" << mvec << std::endl;
  }
  context->enableBootStrapping(ntlMvec, 0);

  if (log) {
    (*log) << "Context: " << std::endl;
    context->printout(*log);
    (*log) << "... complete building context" << std::endl;
  }
  return context;
}

helib::Context *
SHEContext::GetNewGenericContext(long prime, long securityLevel,
                                 long capacity)
{
  // find an appropriate M with the given security level and operation
  // levels, and a prime we use 2 columns, and we need 128 slots to handle
  // recrypt of two 64 bit values
  long c = 2;
  long r = 1;
  long m = helib::FindM(securityLevel+200, capacity,
                        c, prime, 1, 128, 0);

  // sigh, getMvec doesn't know how to split p^N values in order to
  // match up ords. currently all the higher order m's produce such values
  // making it hard to then find appropriate generators.
  // find a suitable mvec based on m and prime
  std::vector<long> mvec = getMvec(prime, m, nullptr);
  // once we have an mvec, that determines our ords
  std::vector<long> ords = makeOrds(prime, mvec);
  std::vector<long> gens = makeGens(m, ords);

  return BuildBootstrappableContext(prime, m, securityLevel, capacity,
                                    r, c, mvec, ords, gens);
}

helib::Context *
SHEContext::GetNewBGVContext(long &securityLevel, long &capacity)
{
  helib::assertTrue(false,"non binary BGV Context not implemented");
  return nullptr;
}

helib::Context *
SHEContext::GetNewCVVContext(long &securityLevel, long &capacity)
{
  helib::assertTrue(false,"CVV Context not implemented");
  return nullptr;
}

static const struct SHEContextParams *
findBinaryParams(long securityLevel, long capacity)
{
  struct SHEContextParams &params=
                       binaryContextParams[binaryContextParamsTableSize-1];

  // we currently only support 2 binary operation levels, 600 and 900.
  // 600 is the smallest practical level.
  if (capacity != SHE_CONTEXT_CAPACITY_ANY) {
    if (capacity  <= SHE_CONTEXT_CAPACITY_LOW) {
      capacity == SHE_CONTEXT_CAPACITY_LOW;
    } else {
      capacity == SHE_CONTEXT_CAPACITY_HIGH;
    }
  }

  for (int i=0; i < binaryContextParamsTableSize; i++) {
    if ((binaryContextParams[i].securityLevel >= securityLevel)
       && ((capacity == SHE_CONTEXT_CAPACITY_ANY)  ||
            binaryContextParams[i].L == capacity)) {
      return &binaryContextParams[i];
      break;
    }
  }
  return &binaryContextParams[binaryContextParamsTableSize-1];
}


helib::Context *
SHEContext::GetNewBinaryContext(long &securityLevel, long &capacity)
{
#ifdef SHECONTEXT_USE_TABLE
  const struct SHEContextParams *params= findBinaryParams(securityLevel,
                                                          capacity);
  securityLevel = params->securityLevel;
  capacity = params->L;

  long m = params->m;
  // binary params have the same next parameters
  long p = params->p; //using binary polynomials
  long r = params->r; // Hansel listing
  long c = params->c; // key switching columns
  long levels= params->L; // bits of modulus, related to the number of levels we can
                    // do. This should be bigenough to get through one loop
                    // of the udivRaw loop after a bootstrap.
  // helib::FindM(securityLevel, levels, c, p, d, s, 0, true);// 4095;
  // build gens and ords from the table
  // ideally we would like to auto generate them at some point
  std::vector<long> gens = buildVector(params->gens,
                                       SHE_ARRAY_SIZE(params->ords));
  std::vector<long> ords = buildVector(params->ords,
                                       SHE_ARRAY_SIZE(params->ords));
  // we get hve the smarts to build the mvec on the fly
  std::vector<long> mvec = getMvec(p, m, &ords);

#else
  // The hard part of generating the key is setting up
  // all the parameters. Since we are doing a binary key, p is set to 2
  // we set r, c, s, and bits to values in the binary sample code.
  // We use FindM to find the cyclotomic polynomial (m). From those
  // parameters and the security level. We let the builder find the
  // generators, their orders, and the factorization of m.

  // generating bootsrappable contexts from first principles is difficult
  // we often fail in basic steps below.. for now we use the magic parameters
  // supplied in the sample so we can test the rest of our code.
  long p = 2; //using binary polynomials
  long levels=600; // bits of modulus, related to the number of levels we can do
  long r = 1; // Hansel listing
  long c = 2; // key switching columns
  long m = 4095;
  // these parameters appear to be magic. we can calculate the factors of m
  // but only this order seems to work. likewise, builder can calculate gens
  // but only these gens seem to work.
  std::vector<long> mvec = {7, 5, 9, 13 };
  std::vector<long> gens = {2341, 3277, 911}; //Zm* group generators
  // orders of the above generators.
  std::vector<long> ords = { 6, 4, 6 };
#endif

  return BuildBootstrappableContext(p, m, securityLevel, levels, r, c,
                                    mvec, ords, gens);
}

static long
makeIndex(SHEContextType type, long securityLevel, long capacity)
{
  switch (type) {
  case SHEContextBinary:
  {
     const struct SHEContextParams *params= findBinaryParams(securityLevel,
                                                             capacity);
     return (params->L << 16) | (params->securityLevel);
  }
  case SHEContextBGV:
  case SHEContextCVV:
  default:
     break;
  }
  return 0;
}

void
SHEContext::FreeContext(SHEContextType type, long securityLevel, long capacity)
{
  SHEContextHash *hash = SHEContext::GetContextHash(type);
  helib::Context *context;

  long index=makeIndex(type, securityLevel, capacity);
  context = (*hash)[index];
  (*hash)[index] = nullptr;
  if (context != nullptr) {
    delete context;
  }
}

helib::Context *
SHEContext::GetContext(SHEContextType type, long &securityLevel, long &capacity)
{
  SHEContextHash *hash = SHEContext::GetContextHash(type);
  helib::Context *context;

  if (hash == nullptr) {
    helib::assertTrue(false,"Unknown ContextType");
    return nullptr;
  }
  long index = makeIndex(type, securityLevel, capacity);
  context = (*hash)[index];
  if (context != nullptr) {
    return context;
  }

  switch (type) {
  case SHEContextBinary:
    context = GetNewBinaryContext(securityLevel, capacity);
    (*hash)[index] = context;
    return context;
  case SHEContextBGV:
    context = GetNewBGVContext(securityLevel, capacity);
    (*hash)[index] = context;
    return context;
  case SHEContextCVV:
    context = GetNewCVVContext(securityLevel, capacity);
    (*hash)[index] = context;
    return context;
  }
  helib::assertTrue(false,"Unknown ContextType");
  return nullptr;
}
