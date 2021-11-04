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

#define NUM_TESTS 22
#define FLOAT_TESTS 24

// config options now just set the defaults
// (except SHE_USE_HALF_FLOAT)
#ifdef SHE_SKIP_FLOAT
int doFloat = false;
#else
int doFloat = true;
#endif
#ifdef SHE_SKIP_DIV
int doDiv = false;
#else
int doDiv = true;
#endif
#ifdef SHE_SKIP_TRIG
int doTrig = false;
#else
int doTrig = true;
#endif
#ifdef SHE_SKIP_LOG
int doLog = false;
#else
int doLog = true;
#endif

static struct option longOptions[] =
{
   // options
   { "trig", no_argument, &doTrig, true },
   { "no-trig", no_argument, &doTrig, false },
   { "div", no_argument, &doDiv, true },
   { "no-div", no_argument, &doDiv, false },
   { "float", no_argument, &doFloat, true },
   { "no-float", no_argument, &doFloat, false },
   { "log", no_argument, &doLog, true },
   { "no-log", no_argument, &doLog, false },
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
  SHEInt::resetReccryptCounters(); \
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
         int16_t a, int16_t b, int16_t c, int16_t d, int16_t z, int8_t i,
         float fa, float fb, float fc, float fd, float fz,
         int &failed, int &tests)
{
  int16_t r[NUM_TESTS];
  uint16_t ua,ub,uc,ud,uz;
  uint16_t ur[NUM_TESTS];
  uint8_t ui;
  float fr[FLOAT_TESTS];
  Timer timer;

  ua = (uint16_t)a;
  ub = (uint16_t)b;
  uc = (uint16_t)c;
  ud = (uint16_t)d;
  uz = (uint16_t)z;
  ui = (uint8_t)i;

  std::cout << "------------------------ encrypting" << std::endl;
  timer.start();
  SHEInt16 ea(pubkey,a,"a");
  SHEInt16 eb(pubkey,b,"b");
  SHEInt16 ec(pubkey,c,"c");
  SHEInt16 ed(pubkey,d,"d");
  SHEInt16 ez(pubkey,z,"z");
  SHEInt8  ei(pubkey,i,"i");
  SHEUInt16 eua(pubkey,ua,"ua");
  SHEUInt16 eub(pubkey,ub,"ub");
  SHEUInt16 euc(pubkey,uc,"uc");
  SHEUInt16 eud(pubkey,ud,"ud");
  SHEUInt16 euz(pubkey,uz,"uz");
  SHEUInt8  eui(pubkey,ui,"ui");
#ifdef SHE_USE_HALF_FLOAT
  SHEHalfFloat efa(pubkey,fa,"fa");
  SHEHalfFloat efb(pubkey,fb,"fb");
  SHEHalfFloat efc(pubkey,fc,"fc");
  SHEHalfFloat efd(pubkey,fd,"fd");
  SHEHalfFloat efz(pubkey,fz,"fd");
#else
  SHEFloat efa(pubkey,fa,"fa");
  SHEFloat efb(pubkey,fb,"fb");
  SHEFloat efc(pubkey,fc,"fc");
  SHEFloat efd(pubkey,fd,"fd");
  SHEFloat efz(pubkey,fz,"fd");
#endif
  SHEVector<SHEInt16> er(ez,NUM_TESTS);
  SHEVector<SHEUInt16> eur(euz,NUM_TESTS);
#ifdef SHE_USE_HALF_FLOAT
  SHEVector<SHEHalfFloat> efr(efz,FLOAT_TESTS);
#else
  SHEVector<SHEFloat> efr(efz,FLOAT_TESTS);
#endif
  timer.stop();
  std::cout << " encrypt time = " << timer.elapsedMilliseconds()
            << " ms" << std::endl;

  int16_t da,db,dc,dd,dz;
  int8_t di;
  uint16_t dua,dub,duc,dud,duz;
  uint8_t dui;
  float dfa,dfb,dfc,dfd,dfz;
  timer.start();
  std::cout << "------------------------ decrypting"  << std::endl;
  da = ea.decrypt(privkey);
  db = eb.decrypt(privkey);
  dc = ec.decrypt(privkey);
  dd = ed.decrypt(privkey);
  dz = ez.decrypt(privkey);
  di = ei.decrypt(privkey);
  dua = eua.decrypt(privkey);
  dub = eub.decrypt(privkey);
  duc = euc.decrypt(privkey);
  dud = eud.decrypt(privkey);
  duz = euz.decrypt(privkey);
  dui = eui.decrypt(privkey);
  dfa = efa.decrypt(privkey);
  dfb = efb.decrypt(privkey);
  dfc = efc.decrypt(privkey);
  dfd = efd.decrypt(privkey);
  dfz = efz.decrypt(privkey);
  timer.stop();
  std::cout << " decrypt time = " << timer.elapsedMilliseconds()
            << " ms" << std::endl;

  std::cout << "-------------decrypted inputs\n" << std::endl;
  std::cout << "a=" << a << " da=" << da << " ";
  if (a != da) { failed++; std::cout << "FAILED"; }
  tests++; std::cout << std::endl;
  std::cout << "b=" << b << " db=" << db << " ";
  if (b != db) { failed++; std::cout << "FAILED"; }
  tests++; std::cout << std::endl;
  std::cout << "c=" << c << " dc=" << dc << " ";
  if (c != dc) { failed++; std::cout << "FAILED"; }
  tests++; std::cout << std::endl;
  std::cout << "d=" << d << " dd=" << dd << " ";
  if (d != dd) { failed++; std::cout << "FAILED"; }
  tests++; std::cout << std::endl;
  std::cout << "z=" << z << " dz=" << dz << " ";
  if (z != dz) { failed++; std::cout << "FAILED"; }
  tests++; std::cout << std::endl;
  std::cout << "i=" << (int)i << " di=" << (int)di << " ";
  if (i != di) { failed++; std::cout << "FAILED"; }
  tests++; std::cout << std::endl;
  std::cout << "ua=" << ua << " dua=" << dua << " ";
  if (ua != dua) { failed++; std::cout << "FAILED"; }
  tests++; std::cout << std::endl;
  std::cout << "ub=" << ub << " dub=" << dub << " ";
  if (ub != dub) { failed++; std::cout << "FAILED"; }
  tests++; std::cout << std::endl;
  std::cout << "uc=" << uc << " duc=" << duc << " ";
  if (uc != duc) { failed++; std::cout << "FAILED"; }
  tests++; std::cout << std::endl;
  std::cout << "ud=" << ud << " dud=" << dud << " ";
  if (ud != dud) { failed++; std::cout << "FAILED"; }
  tests++; std::cout << std::endl;
  std::cout << "uz=" << uz << " duz=" << duz << " ";
  if (uz != duz) { failed++; std::cout << "FAILED"; }
  tests++; std::cout << std::endl;
  std::cout << "ui=" << (unsigned) ui << " dui=" << (unsigned) dui << " ";
  if (ui != dui) { failed++; std::cout << "FAILED"; }
  tests++; std::cout << std::endl;
  std::cout << "fa=" << fa << " dfa=" << dfa << " ";
  if (!FLOAT_CMP_EQ(fa, dfa)) { failed++; std::cout << "FAILED"; }
  tests++; std::cout << std::endl;
  std::cout << "fb=" << fb << " dfb=" << dfb << " ";
  if (!FLOAT_CMP_EQ(fb, dfb)) { failed++; std::cout << "FAILED"; }
  tests++; std::cout << std::endl;
  std::cout << "fc=" << fc << " dfc=" << dfc << " ";
  if (!FLOAT_CMP_EQ(fc, dfc)) { failed++; std::cout << "FAILED"; }
  tests++; std::cout << std::endl;
  std::cout << "fd=" << fd << " dfd=" << dfd << " ";
  if (!FLOAT_CMP_EQ(fd, dfd)) { failed++; std::cout << "FAILED"; }
  tests++; std::cout << std::endl;
  std::cout << "fz=" << fz << " dfz=" << dfz << " ";
  if (fz != dfz) { failed++; std::cout << " FAILED"; }
  tests++; std::cout << std::endl;

  // basic add, subtract & multiply

  r[z] = b;
  r[1] = a + b*c - d;
  r[2] = a*b - c*d;
  // basic bitwise operations
  r[3] = a & b | c ^ d;
  // shifts
  r[4] = a << 5;
  r[5] = b << 4;
  r[6] = c >> 6;
  r[7] = d >> 3;
  // logical operations
  r[8] = (a > b) && (c < d) ? a : b;
  r[9] = (a == b) || (c != d) ? a : b;
  r[10] = (a == a) && (c == c) ? c : d;
  r[11] = (a == b) || (c == d) ? c : d;
  // division and mod
  if (doDiv) {
    r[12] = a / b;
    r[13] = d % c;
  } else {
    r[12] = a + b;
    r[13] = d - c;
  }
  // variable access array
  r[14] = r[i];
  // encrypted index shift
  r[15] = a >> i;
  r[16] = a;
  r[16] >>= i;
  r[17] = a << i;
  r[18] = d;
  r[18] <<= i;
  r[19] = (int16_t) fb;
  r[20] = (bool)(fa > fb);
  r[21] = (bool)(fc < fd);

  // unsigned equivalences
  ur[z] = ub;
  ur[1] = ua + ub*uc - ud;
  ur[2] = ua*ub - uc*ud;
  ur[3] = ua & ub | uc ^ ud;
  ur[4] = ua << 5;
  ur[5] = ub << 4;
  ur[6] = uc >> 6;
  ur[7] = ud >> 3;
  ur[8] = (ua > ub) && (uc < ud) ? ua : ub;
  ur[9] = (ua == ub) || (uc != ud) ? ua : ub;
  ur[10] = (ua == ua) && (uc == uc) ? uc : ud;
  ur[11] = (ua == ub) || (uc == ud) ? uc : ud;
  if (doDiv) {
    ur[12] = ua / ub;
    ur[13] = ud % uc;
  } else {
    ur[12] = ua + ub;
    ur[13] = ud - uc;
  }
  ur[14] = ur[ui];
  ur[15] = ua >> ui;
  ur[16] = ua;
  ur[16] >>= ui;
  ur[17] = ua << ui;
  ur[18] = ud;
  ur[18] <<= ui;
  ur[19] = (uint16_t) fb;
  ur[20] = (bool)(fa > fb);
  ur[21] = (bool)(fc < fd);

  if (doFloat) {
    // floating point operations
    fr[z] = fb;
    fr[1] = fa * fb;
    fr[2] = fa + fb;
    fr[3] = fa - fb;
    fr[4] = (fa > fb) && (fc < fd) ? fa : fb;
    if (doDiv) {
      fr[5] = fa/fb;
      fr[6] = fc/fd;
    } else {
      fr[5] = fc+fd;
      fr[6] = fc*fd;
    }
    fr[7] = fa*fb - fc*fd;
    fr[8] = fr[i];
    fr[9] = (float) b;
    if (doTrig) {
      fr[10] = sinf(fb);
      fr[11] = cosf(fb);
      fr[12] = expf(fb);
      fr[13] = tanf(fb);
    } else {
      fr[10] = fb;
      fr[11] = fb;
      fr[12] = fb;
      fr[13] = fb;
    }
    if (doLog) {
      fr[14] = logf(fa);
      fr[15] = log2f(fa);
      fr[16] = log10f(fa);
    } else {
      fr[14] = fa;
      fr[15] = fa;
      fr[16] = fa;
    }
    if (doDiv) {
      fr[17] = remainderf(fa,fb);
    } else {
      fr[17] = fa;
    }
    fr[18] = roundf(fb);
    fr[19] = ceilf(fb);
    fr[20] = floorf(fb);
    fr[21] = truncf(fa);
    fr[22] = modff(fb,&fr[23]);
  }

  //Time the encrypted operations
  std::cout << "-------------- encrypted math tests"  << std::endl;
  std::cout << "..sign ints"  << std::endl;
  RUN_TEST_ALIAS(er[ez], r[z], er.assign(ez,eb), er[ez] = eb)
  RUN_TEST(er[1], r[1], er[1] = ea + eb * ec -ed)
  RUN_TEST(er[2], r[2], er[2] = ea * eb - ec * ed)
  RUN_TEST(er[3], r[3], er[3] = ea & eb | ec ^ ed)
  RUN_TEST(er[4], r[4], er[4] = ea << 5)
  RUN_TEST(er[5], r[5], er[5] = eb << 4)
  RUN_TEST(er[6], r[6], er[6] = ec >> 6)
  RUN_TEST(er[7], r[7], er[7] = ed >> 3)
  RUN_TEST_ALIAS(er[8], r[8],
                 er[8] = ((ea > eb) && (ec < ed)).select(ea,eb),
                 er[9] = ((ea > eb) && (ec < ed)) ? ea : eb)
  RUN_TEST_ALIAS(er[9], r[9],
                 er[9] = ((ea == eb) || (ec != ed)).select(ea,eb),
                 er[9] = ((ea == eb) || (ec != ed)) ? ea : eb)
  RUN_TEST_ALIAS(er[10], r[10],
                 er[10] = ((ea == ea) && (ec == ec)).select(ec,ed),
                 er[10] = ((ea == ea) && (ec == ec)) ? ec : ed)
  RUN_TEST_ALIAS(er[11], r[11],
                 er[11] = ((ea == eb) || (ec == ed)).select(ec,ed),
                 er[11] = ((ea == eb) || (ec == ed)) ? ec : ed)
  if (doDiv) {
    RUN_TEST(er[12], r[12], er[12] = ea / eb)
    RUN_TEST(er[13], r[13], er[13] = ed % ec)
  } else {
    RUN_TEST(er[12], r[12], er[12] = ea + eb)
    RUN_TEST(er[13], r[13], er[13] = ed - ec)
  }
  RUN_TEST(er[14], r[14], er[14] = er[ei])
  RUN_TEST(er[15], r[15], er[15] = ea >> ei)
  er[16] = ea;
  RUN_TEST(er[16], r[16], er[16] >>= ei)
  RUN_TEST(er[17], r[17], er[17] = ea << ei)
  er[18] = ed;
  RUN_TEST(er[18], r[18], er[18] <<= ei)
  RUN_TEST_ALIAS(er[19], r[19], er[19] = (SHEInt16) efb.toSHEInt(),
                 eur[19] = (SHEUInt16) efb)
  RUN_TEST(er[20], r[20], er[20] = (SHEUInt16) (efa > efb))
  RUN_TEST(er[21], r[21], er[21] = (SHEUInt16) (efc < efd))

  std::cout << "..unsign ints"  << std::endl;
  RUN_TEST_ALIAS(eur[euz], ur[z], eur.assign(euz,eub), eur[euz] = eub)
  RUN_TEST(eur[1], ur[1], eur[1] = eua + eub * euc -eud)
  RUN_TEST(eur[2], ur[2], eur[2] = eua * eub - euc * eud)
  RUN_TEST(eur[3], ur[3], eur[3] = eua & eub | euc ^ eud)
  RUN_TEST(eur[4], ur[4], eur[4] = eua << 5)
  RUN_TEST(eur[5], ur[5], eur[5] = eub << 4)
  RUN_TEST(eur[6], ur[6], eur[6] = euc >> 6)
  RUN_TEST(eur[7], ur[7], eur[7] = eud >> 3)
  RUN_TEST_ALIAS(eur[8], ur[8],
                 eur[8] = ((eua > eub) && (euc < eud)).select(eua,eub),
                 eur[8] = ((eua > eub) && (euc < eud)) ? eua : eub)
  RUN_TEST_ALIAS(eur[9], ur[9],
                 eur[9] = ((eua == eub) || (euc != eud)).select(eua,eub),
                 eur[9] = ((eua == eub) || (euc != eud)) ? eua : eub)
  RUN_TEST_ALIAS(eur[10], ur[10],
                 eur[10] = ((eua == eua) && (euc == euc)).select(euc,eud),
                 eur[10] = ((eua == eua) && (euc == euc)) ? euc : eud)
  RUN_TEST_ALIAS(eur[11], ur[11],
                 eur[11] = ((eua == eub) || (euc == eud)).select(euc,eud),
                 eur[11] = ((eua == eub) || (euc == eud)) ? euc : eud)
  if (doDiv) {
    RUN_TEST(eur[12], ur[12], eur[12] = eua / eub)
    RUN_TEST(eur[13], ur[13], eur[13] = eud % euc)
  } else {
    RUN_TEST(eur[12], ur[12], eur[12] = eua + eub)
    RUN_TEST(eur[13], ur[13], eur[13] = eud - euc)
  }
  RUN_TEST(eur[14], ur[14], eur[14] = eur[eui])
  RUN_TEST(eur[15], ur[15], eur[15] = eua >> eui)
  eur[16] = eua;
  RUN_TEST(eur[16], ur[16], eur[16] >>= eui)
  RUN_TEST(eur[17], ur[17], eur[17] = eua << eui)
  eur[18] = eud;
  RUN_TEST(eur[18], ur[18], eur[18] <<= eui)
  RUN_TEST_ALIAS(eur[19], ur[19], eur[19] = (SHEUInt16) efb.toSHEInt(),
                 eur[19] = (SHEUInt16) efb)
  RUN_TEST(eur[20], ur[20], eur[20] = efa > efb)
  RUN_TEST(eur[21], ur[21], eur[21] = efc < efd)

  if (doFloat) {
    std::cout << "..floats "  << std::endl;
    RUN_TEST_ALIAS(efr[euz], fr[z], efr.assign(ez,efb), efr[ez] = efb)
    RUN_TEST(efr[1], fr[1], efr[1] = efa * efb)
    RUN_TEST(efr[1], fr[1], efr[2] = efa + efb)
    RUN_TEST(efr[1], fr[1], efr[3] = efa - efb)
    RUN_TEST_ALIAS(efr[4], fr[4],
                   efr[4] = select((efa > efb) && (efc < efd), efa ,efb),
                   efr[4] = (efa > efb) && (efc < efd) ? efa : efb)
    if (doDiv) {
      RUN_TEST(efr[5], fr[5], efr[5] = efa / efb)
      RUN_TEST(efr[6], fr[6], efr[6] = efc / efd)
    } else {
      RUN_TEST(efr[5], fr[5], efr[5] = efc + efd)
      RUN_TEST(efr[6], fr[6], efr[6] = efc * efd)
    }
    RUN_TEST(efr[7], fr[7], efr[7] = efa*efb - efc*efd)
    RUN_TEST(efr[8], fr[8], efr[8] = efr[ei])
#ifdef SHE_USE_HALF_FLOAT
    RUN_TEST(efr[9], fr[9], efr[9] = (SHEHalfFloat)eb)
#else
    RUN_TEST(efr[9], fr[9], efr[9] = (SHEFloat)eb)
#endif
    if (doTrig) {
      RUN_TEST(efr[10], fr[10], efr[10] = sin(efb))
      RUN_TEST(efr[11], fr[11], efr[11] = cos(efb))
      RUN_TEST(efr[12], fr[12], efr[12] = exp(efb))
      RUN_TEST(efr[13], fr[13], efr[13] = tan(efb))
    } else {
      RUN_TEST(efr[10], fr[10], efr[10] = efb)
      RUN_TEST(efr[11], fr[11], efr[11] = efb)
      RUN_TEST(efr[12], fr[12], efr[12] = efb)
      RUN_TEST(efr[13], fr[13], efr[13] = efb)
    }
    if (doLog) {
      RUN_TEST(efr[14], fr[14], efr[14] = log(efa))
      RUN_TEST(efr[15], fr[15], efr[15] = log2(efa))
      RUN_TEST(efr[16], fr[16], efr[16] = log10(efa))
    } else {
      RUN_TEST(efr[14], fr[14], efr[14] = efa)
      RUN_TEST(efr[15], fr[15], efr[15] = efa)
      RUN_TEST(efr[16], fr[16], efr[16] = efa)
    }
    if (doDiv) {
      RUN_TEST(efr[17], fr[17], efr[17] = remainder(efa,efb))
    } else {
      RUN_TEST(efr[17], fr[17], efr[17] = efa)
    }
    RUN_TEST(efr[18], fr[18], efr[18] = round(efb))
    RUN_TEST(efr[19], fr[19], efr[19] = ceil(efb))
    RUN_TEST(efr[20], fr[20], efr[20] = floor(efb))
    RUN_TEST(efr[21], fr[21], efr[21] = trunc(efa))
    RUN_TEST(efr[22], fr[22], efr[22] = modf(efb,efr[23]))
  }

  int16_t dr[NUM_TESTS];
  uint16_t dur[NUM_TESTS];
  float dfr[FLOAT_TESTS];

  std::cout << "-----------------------------decrypting results" << std::endl;
  timer.start();
  for (int i = 0; i < er.size(); i++) {
    std::cout << "er[" << i << "].bitCapacity: " << er[i].bitCapacity()
              << std::endl;
    dr[i] = er[i].decrypt(privkey);
  }
  for (int i = 0; i < eur.size(); i++) {
    std::cout << "eur[" << i << "].bitCapacity: " << eur[i].bitCapacity()
              << std::endl;
    dur[i] = eur[i].decrypt(privkey);
  }
#ifndef SHE_SKIP_FLOAT
  for (int i = 0; i < efr.size(); i++) {
    std::cout << "efr[" << i << "].bitCapacity: " << efr[i].bitCapacity()
              << std::endl;
    dfr[i] = efr[i].decrypt(privkey);
  }
#endif
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
  for (int i = 0; i < NUM_TESTS; i++) {
    std::cout << "ur[" << i << "]=" << ur[i] << " dur[" << i << "]="
              << dur[i] << " ";
    if (ur[i] == dur[i]) {
      std::cout << "PASS";
    } else {
      failed++; std::cout << "FAIL";
    }
    tests++; std::cout << std::endl;
  }
#ifndef SHE_SKIP_FLOAT
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
#endif
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
  const char *argString="TtDdFfLls:c:";

  int carg;

  while(1) {
    int optionIndex=0;
    carg = getopt_long(argc, argv, argString,
                       longOptions, &optionIndex);
    if (carg == -1) break;
    switch (carg) {
    case 'F':
      doFloat = true;
      break;
    case 'f':
      doFloat = false;
      break;
    case 'L':
      doLog = true;
      break;
    case 'l':
      doLog = false;
      break;
    case 'D':
      doDiv = true;
      break;
    case 'd':
      doDiv = false;
      break;
    case 'T':
      doTrig = true;
      break;
    case 't':
      doTrig = false;
      break;
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

  int16_t a,b,c,d,z;
  float fa,fb,fc,fd,fz;
  int8_t i;

  a = -14;
  b = 7;
  c = 25;
  d = -5;
  z = 0;
  i = 7;
  fa = -14.0;
  fb = M_PI_4;
  fc = 1.4e-3;
  fd = 2.5e3;
  fz = 0.0;

  SHEInt16 ea(pubkey,a,"a");
  int16_t da = ea.decrypt(privkey);

  // check the streaming interface for saving and restoring keys and ints
  std::fstream save;
  std::fstream restore;

  timer.start();
  // save and restore to binary
  std::cout << "------------------------ saving keys: binary"  << std::endl;
  timer.start();
  save.open("keytest.bin",std::fstream::out|std::fstream::binary|std::fstream::trunc);

  pubkey.writeTo(save);
  privkey.writeTo(save);
  ea.writeTo(save);
  save.close();
  timer.stop();
  std::cout << "key save time (binary)= "
            << (PrintTime) timer.elapsedMilliseconds() << std::endl;

  SHEPublicKey restorePubKey;
  SHEPrivateKey restorePrivKey;

  std::cout << "------------------------ restoring keys: binary"  << std::endl;
  restore.open("keytest.bin",std::fstream::in|std::fstream::binary);
  restorePubKey.readFrom(restore);
  restorePrivKey.readFrom(restore);
  SHEInt16 restoreA(restorePubKey,"restoreA");
  restoreA.read(restore);
  restore.close();
  timer.stop();
  std::cout << "key restore time (binary)= "
            << (PrintTime) timer.elapsedMilliseconds() << std::endl;

  // save and restore from json;
  std::fstream sjson,spub,spriv,sdata;
  std::fstream rpub,rpriv,rdata;

  std::cout << "------------------------ saving keys: json"  << std::endl;
  timer.start();
  sjson.open("keytest.json",std::fstream::out|std::fstream::trunc);
  sjson << "{\"pubkey\":" << pubkey << "," << std::endl;
  sjson << "\"privkey\":" << privkey << "," << std::endl;
  sjson << "\"encryptedInt\":" <<ea << "}" << std::endl;
  sjson.close();
  timer.stop();
  std::cout << "key save time (json1)= "
            << (PrintTime) timer.elapsedMilliseconds() << std::endl;

  timer.start();
  spub.open("pubKey.json",std::fstream::out|std::fstream::trunc);
  spriv.open("privKey.json",std::fstream::out|std::fstream::trunc);
  sdata.open("edata.json",std::fstream::out|std::fstream::trunc);
  spub << pubkey << std::endl;
  spub.close();
  spriv << privkey << std::endl;
  spriv.close();
  sdata << ea << std::endl;
  sdata.close();
  std::cout << "key save time (json2)= "
            << (PrintTime) timer.elapsedMilliseconds() << std::endl;

  SHEPublicKey jrestorePubKey;
  SHEPrivateKey jrestorePrivKey;
  std::cout << "------------------------ restoring keys: json"  << std::endl;
  rpub.open("pubKey.json",std::fstream::in);
  rpriv.open("privKey.json",std::fstream::in);
  rdata.open("edata.json",std::fstream::in);

  rpub >> jrestorePubKey;
  rpub.close();
  rpriv >> jrestorePrivKey;
  rpriv.close();
  std::cout << "key restore time (json)= "
            << (PrintTime) timer.elapsedMilliseconds() << std::endl;

  SHEInt16 jrestoreA(jrestorePubKey,"jrestoreA");
  rdata >> jrestoreA;
  rdata.close();

  std::cout << "------------------------ verify restored data"  << std::endl;
  int16_t da2, dja, drestoreA, djrestoreA;
  da2 = ea.decrypt(restorePrivKey);
  dja = ea.decrypt(jrestorePrivKey);
  drestoreA= restoreA.decrypt(restorePrivKey);
  djrestoreA= jrestoreA.decrypt(jrestorePrivKey);

  std::cout << "------------- restored results" << std::endl;
  std::cout << "a=" << a << " da=" << da <<" dja=" << dja << " drestoreA="
            << drestoreA << " djrestore=" << djrestoreA << std::endl;

  std::cout << "Save/Restore: ";
  if ((a == da) && (a == dja) && (a==drestoreA) && (a == djrestoreA)) {
    std::cout << "PASS";
  } else {
    failed++; std::cout << "FAIL";
  }
  tests++; std::cout << std::endl;

  std::cout << "------------- restored public key against previous priv key"
            << std::endl;
  int e = 303;
  SHEInt16 ef(restorePubKey,e,"e");

  std::cout << "e=" << e << " ef=" << ef.decrypt(privkey) << " ";
  if (e == ef.decrypt(privkey)) {
    std::cout << "PASS";
  } else {
    failed++; std::cout << "FAIL";
  }
  tests++; std::cout << std::endl;

  //a = -14;
  //b = 7;
  //c = 25;
  //d = -5;
  //z = 0;
  //i = 7;

  //fa = -14.0;
  //fb = 7.7;
  //fc = 1.4e-3;
  //fd = 2.5e3;
  //fz = 0.0;
  //fb = M_PI_4;
  //fc = 1.4e-3;
  //fd = 2.5e3;

  do_tests(pubkey, privkey, a, b, c, d, z, i, fa, fb, fc, fd,  fz,
           failed, tests);
  do_tests(pubkey, privkey, INT16_MAX, INT16_MAX, -INT16_MAX, -INT16_MAX, z, 4,
                8.4, 3*fb, 2.5e6, 1.4e7,  fz, failed, tests);
  do_tests(pubkey, privkey, 1000, -89, -8, 8, z, 4,
                8.4e-7, 5*fb, 2.5e-6, 1.4e-7,  fz, failed, tests);
  do_tests(pubkey, privkey, 1000, -89, -18, 8, z, 2,
                M_E, M_PI_2, 2.5e-6, 1.4e-7,  fz, failed, tests);
  do_tests(pubkey, privkey, 1000, -89, -8, 18, z, 7,
                M_E*M_E, 2.5e5, 2.5e-6, 1.4e-7,  fz, failed, tests);
  do_tests(pubkey, privkey, 1000, -89, -8, 28, z, 5,
                1.001, 2.5e-6, 2.5e-6, 1.4e+5,  fz, failed, tests);
  do_tests(pubkey, privkey, 2000, -89, -28, 8, z, 1,
                1.001, 1.0, 2.5e-6, 1.4e+4,  fz, failed, tests);
  do_tests(pubkey, privkey, 2000, -89, -28, 8, z, 6,
                1.001, M_PI/3.0, 2.5e-6, 1.4e+4,  fz, failed, tests);
  do_tests(pubkey, privkey, 2000, -89, -28, 8, z, 3,
                1.001, M_PI/6.0+10*M_PI, 2.5e-6, 1.4e+4,  fz, failed, tests);

  std::cout << failed << " test" << (char *)((failed == 1) ? "" : "s")
            << " failed out of " << tests << " tests." << std::endl;
  if (failed) {
    std::cout << "FAILED" << std::endl;
  } else {
    std::cout << "PASSED" << std::endl;
  }
  return failed;
}
