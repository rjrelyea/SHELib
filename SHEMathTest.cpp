//
// Test program for Simple Homomorphic Encryption
//
#include <iostream>
#include "SHEKey.h"
#include "SHEInt.h"
#include "SHETime.h"
#include "SHEVector.h"
#include "SHEFp.h"
#include "SHEMath.h"
#include "getopt.h"

#define NUM_TESTS 15
#define FLOAT_TESTS 57


static struct option longOptions[] =
{
   // options
   { "security-level", required_argument, 0, 's' },
   { "capacity", required_argument, 0, 'c' },
   { 0, 0, 0, 0 }
};

uint32_t ftohex(float a) { uint32_t *ap = (uint32_t*)&a; return *ap; }
uint64_t ftohex(double a) { uint64_t *ap = (uint64_t*)&a; return *ap; }

#define FLOATDUMP(a,b)   std::hex << ftohex(a) << " " \
                         << ftohex(b) << " " << std::dec
#define FLOAT_CMP_EQ(f,g) ((f != g) ? std::cout << FLOATDUMP(f,g) \
                           << fabs(((f)-(g))/(g)) << " " : std::cout, \
                           ((std::isnan(f) && std::isnan(g)) || \
                           (std::isinf(f) && std::isinf(g)) || \
                           (fabs(g) < F_epsilon ? fabs(f) < F_epsilon : \
                            fabs(((f)-(g))/(g)) < F_epsilon)))

#define RUN_TEST_ALIAS(target, expected, test, ptest) \
  std::cout << " calculating "#ptest \
             << std:: endl; \
  SHEInt::resetRecryptCounters(); \
  timer.start(); \
  test ; \
  timer.stop(); \
  std::cout << " "#target" time = " \
            << (PrintTime) timer.elapsedMilliseconds() \
            << " bootstraps = " << SHEInt::getRecryptCounters() << std::endl; \
  std::cout << " "#target" " << expected << "=?" << target.decrypt(privkey) \
            << std::endl;

#define RUN_TEST(target, expected, test) \
        RUN_TEST_ALIAS(target, expected, test, test)

void
do_tests(const SHEPublicKey &pubkey, SHEPrivateKey &privkey,
         int16_t a, float fa, float fb, float fc, int &failed, int &tests)
{
  int16_t r[NUM_TESTS];
  float fr[FLOAT_TESTS];
  Timer timer;


  std::cout << "------------------------ encrypting" << std::endl;
  timer.start();
  SHEInt16 ea(pubkey,a,"a");
#ifdef SHE_USE_HALF_FLOAT
  SHEHalfFloat efa(pubkey,fa,"fa");
  SHEHalfFloat efb(pubkey,fb,"fb");
  SHEHalfFloat efc(pubkey,fc,"fc");
#else
  SHEFloat efa(pubkey,fa,"fa");
  SHEFloat efb(pubkey,fb,"fb");
  SHEFloat efc(pubkey,fc,"fc");
#endif
  SHEVector<SHEInt16> er(ea,NUM_TESTS);
#ifdef SHE_USE_HALF_FLOAT
  SHEVector<SHEHalfFloat> efr(efa,FLOAT_TESTS);
#else
  SHEVector<SHEFloat> efr(efa,FLOAT_TESTS);
#endif
  timer.stop();
  std::cout << " encrypt time = " << timer.elapsedMilliseconds()
            << " ms" << std::endl;

  int16_t da;
  int result;
  float dfa,dfb,dfc;
  timer.start();
  std::cout << "------------------------ decrypting"  << std::endl;
  da = ea.decrypt(privkey);
  dfa = efa.decrypt(privkey);
  dfb = efb.decrypt(privkey);
  dfc = efc.decrypt(privkey);
  timer.stop();
  std::cout << " decrypt time = " << timer.elapsedMilliseconds()
            << " ms" << std::endl;

  std::cout << "-------------decrypted inputs\n" << std::endl;
  std::cout << "a=" << a << " da=" << da << " ";
  if (a != da) { failed++; std::cout << "FAILED"; }
  tests++; std::cout << std::endl;
  std::cout << "fa=" << fa << " dfa=" << dfa << " ";
  if (!FLOAT_CMP_EQ(fa, dfa)) { failed++; std::cout << "FAILED"; }
  tests++; std::cout << std::endl;
  std::cout << "fb=" << fb << " dfb=" << dfb << " ";
  if (!FLOAT_CMP_EQ(fb, dfb)) { failed++; std::cout << "FAILED"; }
  tests++; std::cout << std::endl;

  // integer returning functions
  r[0] = std::isinf(fa);
  r[1] = std::isnan(fa);
  r[2] = std::fpclassify(fa);
  r[3] = std::isnormal(fa);
  r[4] = std::signbit(fa);
  r[5] = std::isgreater(fa, fb);
  r[6] = std::isgreaterequal(fa, fb);
  r[7] = std::isless(fa, fb);
  r[8] = std::islessequal(fa, fb);
  r[9] = std::islessgreater(fa, fb);
  r[10] = ilogbf(fa);
  r[11] = lrintf(fa);
  r[12] = lroundf(fa);

  // floating point operations
  fr[0] = acosf(fa);
  fr[1] = acoshf(fa);
  fr[2] = asinf(fa);
  fr[3] = asinhf(fa);
  fr[4] = atanf(fa);
  fr[5] = atan2f(fa, fb);
  fr[6] = atanhf(fa);
  fr[7] = cbrtf(fa);
  fr[8] = ceilf(fa);
  fr[9] = copysignf(fa, fb);
  fr[10] = cosf(fa);
  fr[11] = coshf(fa);
  fr[12] = erff(fa);
  fr[13] = erfcf(fa);
  fr[14] = expf(fa);
  fr[15] = exp2f(fa);
  fr[16] = expm1f(fa);
  fr[17] = fabsf(fa);
  fr[18] = fdimf(fa, fb);
  fr[19] = floorf(fa);
  fr[20] = fmaf(fa, fb, fc);
  fr[21] = fmaxf(fa, fb);
  fr[22] = fminf(fa, fb);
  fr[23] = fmodf(fa, fb);
  fr[24] = frexpf(fa, &result);
  r[13] = result;
  fr[25] = hypotf(fa, fb);
  fr[26] = j0f(fa);
  fr[27] = j1f(fa);
  fr[28] = jnf(a, fa);
  fr[29] = ldexpf(fa, a);
  fr[30] = lgammaf(fa);
  fr[31] = logf(fa);
  fr[32] = log10f(fa);
  fr[33] = log1pf(fa);
  fr[34] = log2f(fa);
  fr[35] = logbf(fa);
  fr[36] = modff(fa, &fr[56]);
  fr[37] = nearbyintf(fa);
  fr[38] = nextafterf(fa, fb);
  fr[39] = nexttowardf(fa, fb);
  fr[40] = powf(fa, fb);
  fr[41] = remainderf(fa, fb);
  fr[42] = remquof(fa, fb, &result);
  r[14] = result;
  fr[43] = rintf(fa);
  fr[44] = roundf(fa);
  fr[45] = scalbnf(fa, a);
  fr[46] = sinf(fa);
  fr[47] = sinhf(fa);
  fr[48] = sqrtf(fa);
  fr[49] = tanf(fa);
  fr[50] = tanhf(fa);
  fr[51] = tgammaf(fa);
  fr[52] = truncf(fa);
  fr[53] = y0f(fa);
  fr[54] = y1f(fa);
  fr[55] = ynf(a, fa);
  //Time the encrypted operations
  std::cout << "-------------- encrypted math tests"  << std::endl;
  std::cout << "..sign ints"  << std::endl;
  RUN_TEST(er[0], r[0], er[0] = (SHEUInt16) isinf(efa))
  RUN_TEST(er[1], r[1], er[1] = (SHEUInt16) isnan(efa))
  RUN_TEST(er[2], r[2], er[2] = fpclassify(efa))
  RUN_TEST(er[3], r[3], er[3] = (SHEUInt16) isnormal(efa))
  RUN_TEST(er[4], r[4], er[4] = (SHEUInt16) signbit(efa))
  RUN_TEST(er[5], r[5], er[5] = (SHEUInt16) isgreater(efa, efb))
  RUN_TEST(er[6], r[6], er[6] = (SHEUInt16) isgreaterequal(efa, efb))
  RUN_TEST(er[7], r[7], er[7] = (SHEUInt16) isless(efa, efb))
  RUN_TEST(er[8], r[8], er[8] = (SHEUInt16) islessequal(efa, efb))
  RUN_TEST(er[9], r[9], er[9] = (SHEUInt16) islessgreater(efa, efb))
  RUN_TEST(er[10], r[10], er[10] = ilogb(efa))
  RUN_TEST(er[11], r[11], er[11] = lrint(efa))
  RUN_TEST(er[12], r[12], er[12] = lround(efa))
  RUN_TEST(efr[0], fr[0], efr[0] = acos(efa))
  RUN_TEST(efr[1], fr[1], efr[1] = acosh(efa))
  RUN_TEST(efr[2], fr[2], efr[2] = asin(efa))
#ifdef notdefdd
  RUN_TEST(efr[3], fr[3], efr[3] = asinh(efa))
  RUN_TEST(efr[4], fr[4], efr[4] = atan(efa))
  RUN_TEST(efr[5], fr[5], efr[5] = atan2(efa, efb))
  RUN_TEST(efr[6], fr[6], efr[6] = atanh(efa))
  RUN_TEST(efr[7], fr[7], efr[7] = cbrt(efa))
  RUN_TEST(efr[8], fr[8], efr[8] = ceil(efa))
  RUN_TEST(efr[9], fr[9], efr[9] = copysign(efa, efb))
  RUN_TEST(efr[10], fr[10], efr[10] = cos(efa))
  RUN_TEST(efr[11], fr[11], efr[11] = cosh(efa))
  RUN_TEST(efr[12], fr[12], efr[12] = erf(efa))
  RUN_TEST(efr[13], fr[13], efr[13] = erfc(efa))
  RUN_TEST(efr[14], fr[14], efr[14] = exp(efa))
  RUN_TEST(efr[15], fr[15], efr[15] = exp2(efa))
  RUN_TEST(efr[16], fr[16], efr[16] = expm1(efa))
  RUN_TEST(efr[17], fr[17], efr[17] = fabs(efa))
  RUN_TEST(efr[18], fr[18], efr[18] = fdim(efa, efb))
  RUN_TEST(efr[19], fr[19], efr[19] = floor(efa))
  RUN_TEST(efr[20], fr[20], efr[20] = fma(efa, efb, efc))
  RUN_TEST(efr[21], fr[21], efr[21] = fmax(efa, efb))
  RUN_TEST(efr[22], fr[22], efr[22] = fmin(efa, efb))
  RUN_TEST(efr[23], fr[23], efr[23] = fmod(efa, efb))
  RUN_TEST(efr[24], fr[24], efr[24] = frexp(efa, er[13]))
  RUN_TEST(efr[25], fr[25], efr[25] = hypot(efa, efb))
  RUN_TEST(efr[26], fr[26], efr[26] = j0(efa))
  RUN_TEST(efr[27], fr[27], efr[27] = j1(efa))
  RUN_TEST(efr[28], fr[28], efr[28] = jn(ea, efa))
#endif
  RUN_TEST(efr[29], fr[29], efr[29] = ldexp(efa, ea))
#ifdef notdef
  RUN_TEST(efr[30], fr[30], efr[30] = lgamma(efa))
  RUN_TEST(efr[31], fr[31], efr[31] = log(efa))
  RUN_TEST(efr[32], fr[32], efr[32] = log10(efa))
  RUN_TEST(efr[33], fr[33], efr[33] = log1p(efa))
  RUN_TEST(efr[34], fr[34], efr[34] = log2(efa))
#endif
  RUN_TEST(efr[35], fr[35], efr[35] = logb(efa))
#ifdef notdef
  RUN_TEST(efr[36], fr[36], efr[36] = modf(efa, efr[56]))
  RUN_TEST(efr[37], fr[37], efr[37] = nearbyint(efa))
  RUN_TEST(efr[38], fr[38], efr[38] = nextafter(efa, efb))
  RUN_TEST(efr[39], fr[39], efr[39] = nexttoward(efa, efb))
  RUN_TEST(efr[40], fr[40], efr[40] = pow(efa, efb))
#endif
  RUN_TEST(efr[41], fr[41], efr[41] = remainder(efa, efb))
  RUN_TEST(efr[42], fr[42], efr[42] = remquo(efa, efb, er[14]))
  RUN_TEST(efr[43], fr[43], efr[43] = rint(efa))
  RUN_TEST(efr[44], fr[44], efr[44] = round(efa))
  RUN_TEST(efr[45], fr[45], efr[45] = scalbn(efa, ea))
  RUN_TEST(efr[46], fr[46], efr[46] = sin(efa))
  RUN_TEST(efr[47], fr[47], efr[47] = sinh(efa))
  RUN_TEST(efr[48], fr[48], efr[48] = sqrt(efa))
  RUN_TEST(efr[49], fr[49], efr[49] = tan(efa))
  RUN_TEST(efr[50], fr[50], efr[50] = tanh(efa))
  RUN_TEST(efr[51], fr[51], efr[51] = tgamma(efa))
  RUN_TEST(efr[52], fr[52], efr[52] = trunc(efa))
  RUN_TEST(efr[53], fr[53], efr[53] = y0(efa))
  RUN_TEST(efr[54], fr[54], efr[54] = y1(efa))
  RUN_TEST(efr[55], fr[55], efr[55] = yn(ea, efa))

  int16_t dr[NUM_TESTS];
  float dfr[FLOAT_TESTS];

  std::cout << "-----------------------------decrypting results" << std::endl;
  timer.start();
  for (int i = 0; i < er.size(); i++) {
    std::cout << "er[" << i << "].bitCapacity: " << er[i].bitCapacity()
              << std::endl;
    dr[i] = er[i].decrypt(privkey);
  }
  for (int i = 0; i < efr.size(); i++) {
    std::cout << "efr[" << i << "].bitCapacity: " << efr[i].bitCapacity()
              << std::endl;
    dfr[i] = efr[i].decrypt(privkey);
  }
  timer.stop();
  std::cout << " decrypt time = "
            << (PrintTime) timer.elapsedMilliseconds() << std::endl;

  std::cout << "-------------decrypted outputs verse originals\n" << std::endl;
  for (int i = 0; i < NUM_TESTS; i++) {
    std::cout << "r[" << i << "]=" << r[i] << " dr[" << i << "]=" << dr[i]
              << " ";
    if (r[i] == dr[i]) {
      std::cout << "PASS";
    } else {
      failed++; std::cout << "FAIL";
    }
    tests++; std::cout << std::endl;
  }
  for (int i = 0; i < FLOAT_TESTS; i++) {
    std::cout << "fr[" << i << "]=" << fr[i] << " dfr[" << i << "]="
              << dfr[i] << " ";
    if (FLOAT_CMP_EQ(fr[i],dfr[i])) {
      std::cout << "PASS";
    } else {
      failed++; std::cout <<"FAIL";
    }
    tests++; std::cout << std::endl;
  }
}


int main(int argc, char **argv)
{
  SHEPublicKey pubkey;
  SHEPrivateKey privkey;
  Timer timer;
  int failed = 0;
  int tests = 0;
  long securityLevel = 19;
  long capacity = SHE_CONTEXT_CAPACITY_ANY;
  const char *argString="s:c:";

  int carg;

  while(1) {
    int optionIndex=0;
    carg = getopt_long(argc, argv, argString,
                       longOptions, &optionIndex);
    if (carg == -1) break;
    switch (carg) {
    case 's':
      securityLevel = atoi(optarg);
      break;
    case 'c':
      capacity = atoi(optarg);
      break;
    default:
      break;
    }
  }
  if (optind > argc) {
    securityLevel = atoi(argv[optind++]);
  }
  if (optind > argc) {
    capacity = atoi(argv[optind++]);
  }

  // add logging to the options list in the future...
#ifdef notdef
  // logging options
  SHEContext::setLog(std::cout);
  SHEPublicKey::setLog(std::cout);
  SHEPrivateKey::setLog(std::cout);
  SHEInt::setLog(std::cout);
  SHEFp::setLog(std::cout);
#endif
  SHEMathSetLog(std::cout);

  SHEGenerate_BinaryKey(privkey, pubkey, securityLevel, capacity);
#ifdef DEBUG
  SHEInt::setDebugPrivateKey(privkey);
  SHEFp::setDebugPrivateKey(privkey);
#endif

  int16_t a,b;
  float fa,fb,fc;
  int8_t i;

  // smoke test numbers
  a = 2;
  fa = 1.0;
  fb = 1.3;
  fc = 1.23;

  do_tests(pubkey, privkey, a, fa, fb, fc, failed, tests);

  std::cout << failed << " test" << (char *)((failed == 1) ? "" : "s")
            << " failed out of " << tests << " tests." << std::endl;
  if (failed) {
    std::cout << "FAILED" << std::endl;
  } else {
    std::cout << "PASSED" << std::endl;
  }
  return failed;
}
