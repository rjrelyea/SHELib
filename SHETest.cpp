//
// Test program for Simple Homomorphic Encryption
//
#include <iostream>
#include "SHEKey.h"
#include "SHEInt.h"
#include "SHETime.h"
#include "SHEVector.h"
#include "SHEFp.h"

#define NUM_TESTS 19
#define FLOAT_TESTS 9

#ifdef SHE_FLOAT_MISMATCHED_PRECISION
#define F_epsilon .003   // mult and divide amplify errors
#define FLOAT_CMP_EQ(f,g) ( fabs(g) < F_epsilon ? fabs(f) < F_epsilon : \
                            fabs(((f)-(g))/(g)) < F_epsilon )
#else
#define FLOAT_CMP_EQ(f,g) ((f) == (g))
#endif
int main(int argc, char **argv)
{
  SHEPublicKey pubkey;
  SHEPrivateKey privkey;
  Timer timer;
  int failed = 0;
  int tests = 0;

#ifdef notdef
  // logging options
  SHEContext::setLog(std::cout);
  SHEPublicKey::setLog(std::cout);
  SHEPrivateKey::setLog(std::cout);
  SHEInt::setLog(std::cout);
  SHEFp::setLog(std::cout);
#endif


  SHEGenerate_BinaryKey(privkey, pubkey, 19);
#ifdef DEBUG
  SHEInt::setDebugPrivateKey(privkey);
  SHEFp::setDebugPrivateKey(privkey);
#endif

  int16_t a,b,c,d,z;
  int8_t i;
  int16_t r[NUM_TESTS];
  uint16_t ua,ub,uc,ud,uz;
  uint16_t ur[NUM_TESTS];
  uint8_t ui;
  float fa,fb,fc,fd,fz;
  float fr[FLOAT_TESTS];

  a = -14;
  b = 7;
  c = 25;
  d = -5;
  z = 0;
  i = 7;
  ua = (uint16_t)a;
  ub = (uint16_t)b;
  uc = (uint16_t)c;
  ud = (uint16_t)d;
  uz = (uint16_t)z;
  ui = (uint8_t)i;
  fa = -14.0;
  fb = 7.7;
  fc = 1.4e-3;
  fd = 2.5e3;
  fz = 0.0;

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
  std::cout << "a=" << a << " da=" << da ;
  if (a != da) { failed++; std::cout << " FAILED"; }
  tests++; std::cout << std::endl;
  std::cout << "b=" << b << " db=" << db;
  if (b != db) { failed++; std::cout << " FAILED"; }
  tests++; std::cout << std::endl;
  std::cout << "c=" << c << " dc=" << dc;
  if (c != dc) { failed++; std::cout << " FAILED"; }
  tests++; std::cout << std::endl;
  std::cout << "d=" << d << " dd=" << dd;
  if (d != dd) { failed++; std::cout << " FAILED"; }
  tests++; std::cout << std::endl;
  std::cout << "z=" << z << " dz=" << dz;
  if (z != dz) { failed++; std::cout << " FAILED"; }
  tests++; std::cout << std::endl;
  std::cout << "i=" << (int)i << " di=" << (int)di;
  if (i != di) { failed++; std::cout << " FAILED"; }
  tests++; std::cout << std::endl;
  std::cout << "ua=" << ua << " dua=" << dua;
  if (ua != dua) { failed++; std::cout << " FAILED"; }
  tests++; std::cout << std::endl;
  std::cout << "ub=" << ub << " dub=" << dub;
  if (ub != dub) { failed++; std::cout << " FAILED"; }
  tests++; std::cout << std::endl;
  std::cout << "uc=" << uc << " duc=" << duc;
  if (uc != duc) { failed++; std::cout << " FAILED"; }
  tests++; std::cout << std::endl;
  std::cout << "ud=" << ud << " dud=" << dud;
  if (ud != dud) { failed++; std::cout << " FAILED"; }
  tests++; std::cout << std::endl;
  std::cout << "uz=" << uz << " duz=" << duz;
  if (uz != duz) { failed++; std::cout << " FAILED"; }
  tests++; std::cout << std::endl;
  std::cout << "ui=" << (unsigned) ui << " dui=" << (unsigned) dui;
  if (ui != dui) { failed++; std::cout << " FAILED"; }
  tests++; std::cout << std::endl;
  std::cout << "fa=" << fa << " dfa=" << dfa;
  if (!FLOAT_CMP_EQ(fa, dfa)) { failed++; std::cout << " FAILED"; }
  tests++; std::cout << std::endl;
  std::cout << "fb=" << fb << " dfb=" << dfb;
  if (!FLOAT_CMP_EQ(fb, dfb)) { failed++; std::cout << " FAILED"; }
  tests++; std::cout << std::endl;
  std::cout << "fc=" << fc << " dfc=" << dfc;
  if (!FLOAT_CMP_EQ(fc, dfc)) { failed++; std::cout << " FAILED"; }
  tests++; std::cout << std::endl;
  std::cout << "fd=" << fd << " dfd=" << dfd;
  if (!FLOAT_CMP_EQ(fd, dfd)) { failed++; std::cout << " FAILED"; }
  tests++; std::cout << std::endl;
  std::cout << "fz=" << fz << " dfz=" << dfz;
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
#ifndef SHE_SKIP_DIV
  r[12] = a / b;
  r[13] = d % c;
#else
  r[12] = a + b;
  r[13] = d - c;
#endif
  // variable access array
  r[14] = r[i];
  // encrypted index shift
  r[15] = a >> i;
  r[16] = a;
  r[16] >>= i;
  r[17] = a << i;
  r[18] = d;
  r[18] <<= i;

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
#ifndef SHE_SKIP_DIV
  ur[12] = ua / ub;
  ur[13] = ud % uc;
#else
  ur[12] = ua + ub;
  ur[13] = ud - uc;
#endif
  ur[14] = ur[ui];
  ur[15] = ua >> ui;
  ur[16] = ua;
  ur[16] >>= ui;
  ur[17] = ua << ui;
  ur[18] = ud;
  ur[18] <<= ui;

  // floating point operations
  fr[z] = fb;
  fr[1] = fa * fb;
  fr[2] = fa + fb;
  fr[3] = fa - fb;
  fr[4] = (fa > fb) && (fc < fd) ? fa : fb;
#ifndef SHE_SKIP_DIV
  fr[5] = fa/fb;
  fr[6] = fc/fd;
#else
  fr[5] = fc+fd;
  fr[6] = fc*fd;
#endif
  fr[7] = fa*fb - fc*fd;
  fr[8] = fr[b];

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

  //Time the encrypted operations
  std::cout << "-------------- encrypted math tests"  << std::endl;
  std::cout << " calculating er[ez] =  eb" << std:: endl;
  timer.start();
  er.assign(ez,eb);
  timer.stop();
  std::cout << " er[ez] (array assign) time = "
            << (PrintTime) timer.elapsedMilliseconds()
            << std::endl;
  std::cout << " er[ez] (array assign) " << r[z]<< "=?"
            << er[ez].decrypt(privkey) << std::endl;
  std::cout << " calculating er[1] = ea + eb * ec - ed" << std:: endl;
  timer.start();
  er[1] = ea + eb * ec -ed;
  timer.stop();
  std::cout << " er[1] (add) time = "
            << (PrintTime) timer.elapsedMilliseconds()
            << std::endl;
  std::cout << " er[1] (add) " << r[1]<< "=?" << er[1].decrypt(privkey)
            << std::endl;
  std::cout << " calculating er[2] = ea * eb - ec * ed" << std:: endl;
  timer.start();
  er[2] = ea*eb - ec*ed;
  timer.stop();
  std::cout << " er[2] (mul) time = "
            << (PrintTime) timer.elapsedMilliseconds()
            << std::endl;
  std::cout << " er[2] (mul) " << r[2] << "=?" << er[2].decrypt(privkey)
            << std::endl;
  std::cout << " calculating er[3] = ea & eb | ec ^ ed" << std:: endl;
  timer.start();
  er[3] = ea & eb | ec^ ed;
  timer.stop();
  std::cout << " er[3] (bitwise) time = " << timer.elapsedMilliseconds()
            << " ms" << std::endl;
  std::cout << " er[3] (bitwise) " << r[3] << "=?" << er[3].decrypt(privkey)
            << std::endl;
  std::cout << " calculating er[4] = ea << 5" << std:: endl;
  timer.start();
  er[4] = ea << 5;
  timer.stop();
  std::cout << " er[4] (shift left) time = " << timer.elapsedMilliseconds()
            << " ms" << std::endl;
  std::cout << " er[4] (shift left) " << r[4] << "=?" << er[4].decrypt(privkey)
            << std::endl;
  std::cout << " calculating er[5] = eb << 4" << std:: endl;
  timer.start();
  er[5] = eb << 4;
  timer.stop();
  std::cout << " er[5] (shift left) time = "
            << (PrintTime) timer.elapsedMilliseconds() << std::endl;
  std::cout << " er[5] (shift left) " << r[5] << "=?" << er[5].decrypt(privkey)
            << std::endl;
  std::cout << " calculating er[6] = ec >> 6" << std:: endl;
  timer.start();
  er[6] = ec >> 6;
  timer.stop();
  std::cout << " er[6] (shift right) time = "
            << (PrintTime) timer.elapsedMilliseconds() << std::endl;
  std::cout << " er[6] (shift right) " << r[6] << "=?" << er[6].decrypt(privkey)
            << std::endl;
  std::cout << " calculating er[7] = ed >> 3" << std:: endl;
  timer.start();
  er[7] = ed >> 3;
  timer.stop();
  std::cout << " er[7] (shift right) time = "
            << (PrintTime) timer.elapsedMilliseconds() << std::endl;
  std::cout << " er[7] (shift right) " << r[7] << "=?" << er[7].decrypt(privkey)
            << std::endl;
  std::cout << " calculating er[8] = ((ea > eb) && (ec < ed)) ? ea : eb"
             << std:: endl;
  timer.start();
  er[8] = ((ea > eb) && (ec < ed)).select(ea,eb);
  timer.stop();
  std::cout << " er[8] (inequal &&) time = "
            << (PrintTime) timer.elapsedMilliseconds() << std::endl;
  std::cout << " er[8] (inequal &&) " << r[8] << "=?" << er[8].decrypt(privkey)
            << std::endl;
  std::cout << " calculating er[9] = ((ea == eb) || (ec != ed)) ? ea : eb"
             << std:: endl;
  timer.start();
  er[9] = ((ea == eb) || (ec != ed)).select(ea,eb);
  timer.stop();
  std::cout << " er[9] (inequal ||) time = "
            << (PrintTime) timer.elapsedMilliseconds() << std::endl;
  std::cout << " er[9] (inequal ||) " << r[9] << "=?" << er[9].decrypt(privkey)
            << std::endl;
  std::cout << " calculating er[10] = ((ea == eb) && (ec == ed)) ? ec : ed"
             << std:: endl;
  timer.start();
  er[10] = ((ea == ea) && (ec == ec)).select(ec,ed);
  timer.stop();
  std::cout << " er[10] (equality &&) time = "
            << (PrintTime) timer.elapsedMilliseconds() << std::endl;
  std::cout << " er[10] (equality &&) " << r[10] << "=?"
            << er[10].decrypt(privkey) << std::endl;
  std::cout << " calculating er[11] = ((ea == eb) && (ec == ed)) ? ec : ed"
             << std:: endl;
  timer.start();
  er[11] = ((ea == eb) || (ec == ed)).select(ec,ed);
  timer.stop();
  std::cout << " er[11] (equality ||) time = "
            << (PrintTime) timer.elapsedMilliseconds() << std::endl;
  std::cout << " er[11] (equality ||) " << r[11] << "=?"
            << er[11].decrypt(privkey) << std::endl;
#ifndef SHE_SKIP_DIV
  std::cout << " calculating er[12] = ea / eb" << std:: endl;
#else
  std::cout << " calculating er[12] = ea + eb" << std:: endl;
#endif
  timer.start();
#ifndef SHE_SKIP_DIV
  er[12] = ea / eb;
#else
  er[12] = ea + eb;
#endif
  timer.stop();
  std::cout << " er[12] (div) time = "
            << (PrintTime) timer.elapsedMilliseconds() << std::endl;
  std::cout << " er[12] (div) " << r[12] << "=?" << er[12].decrypt(privkey)
            << std::endl;
#ifndef SHE_SKIP_DIV
  std::cout << " calculating er[13] = ed % ec" << std:: endl;
#else
  std::cout << " calculating er[13] = ed - ec" << std:: endl;
#endif
  timer.start();
#ifndef SHE_SKIP_DIV
  er[13] = ed % ec;
#else
  er[13] = ed - ec;
#endif
  std::cout << " er[13] (mod) time = "
            << (PrintTime) timer.elapsedMilliseconds() << std::endl;
  std::cout << " er[13] (mod) " << r[13] << "=?" << er[13].decrypt(privkey)
            << std::endl;
  std::cout << " calculating er[14] = er[ei]" << std:: endl;
  timer.start();
  er[14] = er[ei];
  std::cout << " er[14] (array access) time = "
            << (PrintTime) timer.elapsedMilliseconds() << std::endl;
  std::cout << " er[14] (array access) " << r[14] << "=?"
            << er[14].decrypt(privkey)
            << std::endl;
  std::cout << " calculating er[15] = ea >> ei" << std:: endl;
  timer.start();
  er[15] = ea >> ei;
  timer.stop();
  std::cout << " er[15] (encrypted shift) time = "
            << (PrintTime) timer.elapsedMilliseconds() << std::endl;
  std::cout << " er[15] (encrypted shift) " << std::hex << r[15] << "=?"
            << er[15].decrypt(privkey) << std::dec << std::endl;
  std::cout << " calculating er[16] >>= eb" << std:: endl;
  timer.start();
  er[16] = ea;
  er[16] >>=  ei;
  timer.stop();
  std::cout << " er[16] (encrypted shift) time = "
            << (PrintTime) timer.elapsedMilliseconds() << std::endl;
  std::cout << " er[16] (encrypted shift) " << std::hex << r[16] << "=?"
            << er[16].decrypt(privkey) << std::dec << std::endl;
  std::cout << " calculating er[17] = ea << ei" << std:: endl;
  timer.start();
  er[17] = ea << ei;
  timer.stop();
  std::cout << " er[17] (encrypted shift) time = "
            << (PrintTime) timer.elapsedMilliseconds() << std::endl;
  std::cout << " er[17] (encrypted shift) " << std::hex << r[17] << "=?"
            << er[17].decrypt(privkey) << std::dec << std::endl;
  std::cout << " calculating er[18] <<= ei" << std:: endl;
  timer.start();
  er[18] = ed;
  er[18] <<=  ei;
  timer.stop();
  std::cout << " er[18] (encrypted shift) time = "
            << (PrintTime) timer.elapsedMilliseconds() << std::endl;
  std::cout << " er[18] (encrypted shift) " << std::hex << r[18] << "=?"
            << er[18].decrypt(privkey) << std::dec << std::endl;

  std::cout << " calculating eur[euz] =  eub" << std:: endl;
  timer.start();
  eur.assign(euz,eub);
  timer.stop();
  std::cout << " eur[euz] (array assign) time = "
            << (PrintTime) timer.elapsedMilliseconds()
            << std::endl;
  std::cout << " eur[euz] (array asign) " << r[z]<< "=?"
            << er[euz].decrypt(privkey) << std::endl;
  std::cout << " calculating eur[1] = eua + eub * euc -eud" << std:: endl;
  timer.start();
  eur[1] = eua + eub * euc - eud;
  timer.stop();
  std::cout << " eur[1] (add) time = "
            << (PrintTime) timer.elapsedMilliseconds() << std::endl;
  std::cout << " eur[1] (add) " << r[1] << "=?" << eur[1].decrypt(privkey)
            << std::endl;
  std::cout << " calculating eur[2] = eua * eub - euc * eud" << std:: endl;
  timer.start();
  eur[2] = eua*eub - euc*eud;
  timer.stop();
  std::cout << " eur[2] (mul) time = "
            << (PrintTime) timer.elapsedMilliseconds() << std::endl;
  std::cout << " eur[2] (mul) " << r[2] << "=?" << eur[2].decrypt(privkey)
            << std::endl;
  std::cout << " calculating eur[3] = eua & eub | euc ^ eud" << std:: endl;
  timer.start();
  eur[3] = eua & eub | euc^ eud;
  timer.stop();
  std::cout << " eur[3] (bitwise) time = "
            << (PrintTime ) timer.elapsedMilliseconds() << std::endl;
  std::cout << " eur[3] (bitwise) " << ur[3] << "=?"
            << eur[3].decrypt(privkey) << std::endl;
  std::cout << " calculating eur[4] = eua << 5" << std:: endl;
  timer.start();
  eur[4] = eua << 5;
  timer.stop();
  std::cout << " eur[4] (shift left) time = "
            << (PrintTime) timer.elapsedMilliseconds() << std::endl;
  std::cout << " eur[4] (shift left) " << ur[4] << "=?"
            << eur[4].decrypt(privkey) << std::endl;
  std::cout << " calculating eur[5] = eub << 4" << std:: endl;
  timer.start();
  eur[5] = eub << 4;
  timer.stop();
  std::cout << " eur[5] (shift left) time = "
            << (PrintTime) timer.elapsedMilliseconds() << std::endl;
  std::cout << " eur[5] (shift left) " << ur[5] << "=?"
            << eur[5].decrypt(privkey) << std::endl;
  std::cout << " calculating eur[6] = euc >> 6" << std:: endl;
  timer.start();
  eur[6] = euc >> 6;
  timer.stop();
  std::cout << " eur[6] (shift right) time = "
            << (PrintTime) timer.elapsedMilliseconds() << std::endl;
  std::cout << " eur[6] (shift right) " << ur[6] << "=?"
            << eur[6].decrypt(privkey) << std::endl;
  std::cout << " calculating eur[7] = eud >> 3" << std:: endl;
  timer.start();
  eur[7] = eud >> 3;
  timer.stop();
  std::cout << " eur[7] (shift right) time = "
            << (PrintTime) timer.elapsedMilliseconds() << std::endl;
  std::cout << " eur[7] (shift right) " << ur[7] << "=?"
            << eur[7].decrypt(privkey) << std::endl;
  std::cout << " calculating eur[8] = (eua > eub) && (euc < eud) ? eua:eub"
            << std:: endl;
  timer.start();
  eur[8] = ((eua > eub) && (euc < eud)).select(eua,eub);
  timer.stop();
  std::cout << " eur[8] (inequal &&) time = "
            << (PrintTime) timer.elapsedMilliseconds() << std::endl;
  std::cout << " eur[8] (inequal &&) " << ur[8] << "=?"
            << eur[8].decrypt(privkey) << std::endl;
  std::cout << " calculating eur[9] = (eua == eub) || (euc == eud) ? eua:eub"
            << std:: endl;
  timer.start();
  eur[9] = ((eua == eub) || (euc != eud)).select(eua,eub);
  timer.stop();
  std::cout << " eur[9] (inequal ||) time = "
            << (PrintTime) timer.elapsedMilliseconds() << std::endl;
  std::cout << " eur[9] (inequal ||) " << ur[9] << "=?"
            << eur[9].decrypt(privkey) << std::endl;
  std::cout << " calculating eur[10] = (eua == eua) || (euc == euc) ? euc:eud"
            << std:: endl;
  timer.start();
  eur[10] = ((eua == eua) && (euc == euc)).select(euc,eud);
  timer.stop();
  std::cout << " eur[10] (equality &&) time = "
            << (PrintTime) timer.elapsedMilliseconds() << std::endl;
  std::cout << " eur[10] (equality &&) " << ur[10] << "=?"
            << eur[10].decrypt(privkey) << std::endl;
  std::cout << " calculating eur[11] = (eua == eub) || (euc == eud) ? euc:eud"
            << std:: endl;
  timer.start();
  eur[11] = ((eua == eub) || (euc == eud)).select(euc,eud);
  timer.stop();
  std::cout << " eur[11] (equality ||) time = "
            << (PrintTime) timer.elapsedMilliseconds() << std::endl;
  std::cout << " eur[11] (equality ||) " << ur[11] << "=?"
            << eur[11].decrypt(privkey) << std::endl;
#ifndef SHE_SKIP_DIV
  std::cout << " calculating eur[12] = eua / eub" << std:: endl;
#else
  std::cout << " calculating eur[12] = eua + eub" << std:: endl;
#endif
  timer.start();
#ifndef SHE_SKIP_DIV
  eur[12] = eua / eub;
#else
  eur[12] = eua + eub;
#endif
  timer.stop();
  std::cout << " eur[12] (div) time = "
            << (PrintTime) timer.elapsedMilliseconds() << std::endl;
  std::cout << " eur[12] (div) " << ur[12] << "=?" << eur[12].decrypt(privkey)
            << std::endl;
#ifndef SHE_SKIP_DIV
  std::cout << " calculating eur[13] = eud % euc" << std:: endl;
#else
  std::cout << " calculating eur[13] = eud - euc" << std:: endl;
#endif
  timer.start();
#ifndef SHE_SKIP_DIV
  eur[13] = eud % euc;
#else
  eur[13] = eud - euc;
#endif
  timer.stop();
  std::cout << " eur[13] (mod) time = "
            << (PrintTime) timer.elapsedMilliseconds() << std::endl;
  std::cout << " eur[13] (mod) " << ur[13] << "=?" << eur[13].decrypt(privkey)
            << std::endl;
  std::cout << " calculating eur[14] = eur[eui]" << std:: endl;
  timer.start();
  eur[14] = eur[eui];
  timer.stop();
  std::cout << " eur[14] (array access) time = "
            << (PrintTime) timer.elapsedMilliseconds() << std::endl;
  std::cout << " eur[14] (array access) " << ur[14] << "=?"
            << eur[14].decrypt(privkey) << std::endl;
  std::cout << " calculating eur[15] = eua >> eui" << std:: endl;
  timer.start();
  eur[15] = eua >> eui;
  timer.stop();
  std::cout << " eur[15] (encrypted shift) time = "
            << (PrintTime) timer.elapsedMilliseconds() << std::endl;
  std::cout << " eur[15] (encrypted shift) " << std::hex << ur[15] << "=?"
            << eur[15].decrypt(privkey) << std::dec << std::endl;
  std::cout << " calculating eur[16] >>= eui" << std:: endl;
  timer.start();
  eur[16] = eua;
  eur[16] >>=  eui;
  timer.stop();
  std::cout << " eur[16] (encrypted shift) time = "
            << (PrintTime) timer.elapsedMilliseconds() << std::endl;
  std::cout << " eur[16] (encrypted shift) " << std::hex << ur[16] << "=?"
            << eur[16].decrypt(privkey) << std::dec << std::endl;
  std::cout << " calculating eur[17] = eua << eui" << std:: endl;
  timer.start();
  eur[17] = eua << eui;
  timer.stop();
  std::cout << " eur[17] (encrypted shift) time = "
            << (PrintTime) timer.elapsedMilliseconds() << std::endl;
  std::cout << " eur[17] (encrypted shift) " << std::hex << ur[17] << "=?"
            << eur[17].decrypt(privkey) << std::dec << std::endl;
  std::cout << " calculating eur[18] <<= ei" << std:: endl;
  timer.start();
  eur[18] = ed;
  eur[18] <<=  ei;
  timer.stop();
  std::cout << " eur[18] (encrypted shift) time = "
            << (PrintTime) timer.elapsedMilliseconds() << std::endl;
  std::cout << " eur[18] (encrypted shift) " << std::hex << ur[18] << "=?"
            << eur[18].decrypt(privkey) << std::dec << std::endl;

  std::cout << " calculating efr[ez] = efb" << std:: endl;
  timer.start();
  efr.assign(ez,efb);
  timer.stop();
  std::cout << " efr[ez] (array set) time = "
            << (PrintTime) timer.elapsedMilliseconds() << std::endl;
  std::cout << " efr[ez] (array set) " << fr[z] << "=?"
            << efr[ez].decrypt(privkey) << std::endl;
  std::cout << " calculating efr[1] = efa * efb" << std:: endl;
  timer.start();
  efr[1] = efa * efb;
  timer.stop();
  std::cout << " efr[1] (float op) time = "
            << (PrintTime) timer.elapsedMilliseconds() << std::endl;
  std::cout << " efr[1] (float op) " << fr[1] << "=?"
            << efr[1].decrypt(privkey) << std::endl;
  std::cout << " calculating efr[2] = efa + efb" << std:: endl;
  timer.start();
  efr[2] = efa + efb;
  timer.stop();
  std::cout << " efr[2] (float op) time = "
            << (PrintTime) timer.elapsedMilliseconds() << std::endl;
  std::cout << " efr[2] (float op) " << fr[2] << "=?"
            << efr[2].decrypt(privkey) << std::endl;
  std::cout << " calculating efr[3] = efa - efb" << std:: endl;
  timer.start();
  efr[3] = efa - efb;
  timer.stop();
  std::cout << " efr[3] (float op) time = "
            << (PrintTime) timer.elapsedMilliseconds() << std::endl;
  std::cout << " efr[3] (float op) " << fr[3] << "=?"
            << efr[3].decrypt(privkey) << std::endl;
  std::cout << " calculating efr[4] = (efa > efb) && (efc < efd) ? efa : efb"
            << std:: endl;
  timer.start();
  efr[4] = select((efa > efb) && (efc < efd), efa ,efb);
  timer.stop();
  std::cout << " efr[4] (float op) time = "
            << (PrintTime) timer.elapsedMilliseconds() << std::endl;
  std::cout << " efr[4] (float op) " << fr[4] << "=?"
            << efr[4].decrypt(privkey) << std::endl;
#ifndef SHE_SKIP_DIV
  std::cout << " calculating efr[5] = efa / efb" << std:: endl;
#else
  std::cout << " calculating efr[5] = efc + efd" << std:: endl;
#endif
  timer.start();
#ifndef SHE_SKIP_DIV
  efr[5] = efa / efb;
#else
  efr[5] = efc + efd;
#endif
  timer.stop();
  std::cout << " efr[5] (float op) time = "
            << (PrintTime) timer.elapsedMilliseconds() << std::endl;
  std::cout << " efr[5] (float op) " << fr[5] << "=?"
            << efr[5].decrypt(privkey) << std::endl;
#ifndef SHE_SKIP_DIV
  std::cout << " calculating efr[6] = efc / efd" << std:: endl;
#else
  std::cout << " calculating efr[6] = efc * efd" << std:: endl;
#endif
  timer.start();
#ifndef SHE_SKIP_DIV
  efr[6] = efc / efd;
#else
  efr[6] = efc * efd;
#endif
  timer.stop();
  std::cout << " efr[6] (float op) time = "
            << (PrintTime) timer.elapsedMilliseconds() << std::endl;
  std::cout << " efr[6] (float op) " << fr[6] << "=?"
            << efr[6].decrypt(privkey) << std::endl;
  std::cout << " calculating efr[7] = efa*efb - efc*efd" << std:: endl;
  timer.start();
  efr[7] = efa*efb - efc*efd;
  timer.stop();
  std::cout << " efr[7] (float op) time = "
            << (PrintTime) timer.elapsedMilliseconds() << std::endl;
  std::cout << " efr[7] (float op) " << fr[7] << "=?"
            << efr[7].decrypt(privkey) << std::endl;
  std::cout << " calculating efr[8] = efr[b]" << std:: endl;
  timer.start();
  efr[8] = efr[b];
  timer.stop();
  std::cout << " efr[8] (float op) time = "
            << (PrintTime) timer.elapsedMilliseconds() << std::endl;
  std::cout << " efr[8] (float op) " << fr[8] << "=?"
            << efr[8].decrypt(privkey) << std::endl;

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
  for (int i = 0; i < FLOAT_TESTS; i++) {
    std::cout << "fr[" << i << "]=" << fr[i] << " dfr[" << i << "]="
              << dfr[i] << " ";
    if (FLOAT_CMP_EQ(fr[i],dfr[i])) {
      std::cout << "PASS";
    } else {
      failed++; std::cout << "FAIL";
    }
    tests++; std::cout << std::endl;
  }

  std::cout << failed << " test" << (char *)((failed == 1) ? "" : "s")
            << " failed out of " << tests << " tests." << std::endl;
  if (failed) {
    std::cout << "FAILED" << std::endl;
  } else {
    std::cout << "PASSED" << std::endl;
  }
}
