//
// Test program for Simple Homomorphic Encryption
//
#include <iostream>
#include "SHEKey.h"
#include "SHEInt.h"
#include "SHETime.h"

int main(int argc, char **argv)
{
  SHEPublicKey pubkey;
  SHEPrivateKey privkey;
  Timer timer;

  SHEContext::setLog(std::cout);
  SHEPublicKey::setLog(std::cout);
  SHEPrivateKey::setLog(std::cout);
#ifdef notdef
  SHEInt::setLog(std::cout);
#endif

  int security_level[] = {19,20,21,22,23,24,25,26,29,41,45,47,50,51,52,56,
                          57,59,60,61,64,65,66,67,72,73,78,80,85,97,98,99,
                          100,105,120,122,133,135,137,142,146,175,193};

  for (int i=0 ; i < sizeof(security_level)/sizeof(int) ; i++) {
    bool failed=false;
    std::cout << "------------------------ getting keys level " 
              << security_level[i] << std::endl;
    timer.start();
    try {
      SHEGenerate_BinaryKey(privkey, pubkey, security_level[i]);
    } catch (const std::exception& ex) {
      std::cout << "ERROR: " << ex.what() << std::endl;
      failed=true;
    } catch (...) {
      std::exception_ptr p = std::current_exception();
      std::cout << (p ? p.__cxa_exception_type()->name() : "null")
                <<  std::endl;
      failed=true;
    }
    timer.stop();
    std::cout << " keygen time (" << security_level[i] << ") = "
              << (PrintTime) timer.elapsedMilliseconds() << std::endl;
    if (failed) continue;
    double privSecLevel = privkey.securityLevel();
    if (security_level[i] != (long)floor(privSecLevel)) {
      std::cout << "************************* mismatch Requested level="
                << security_level[i] << ", actual level=" 
                << (long)floor(privSecLevel) << "("
                << privSecLevel << ")" << std::endl;
    }
    // clean up
    privkey.clear();
    SHEContext::FreeContext(SHEContextBinary, security_level[i]);
  }
  std::cout << "all context tests complete" << std::endl;

  SHEGenerate_BinaryKey(privkey, pubkey, 19);
#ifdef DEBUG
  SHEInt::setDebugPrivateKey(privkey);
#endif

  int16_t a,b,c,d,r1,r2,r3,r4,r5,r6,r7,r8,r9,r10,r11,r12,r13;
  uint16_t ua,ub,uc,ud,ur1,ur2,ur3,ur4,ur5,ur6,ur7,ur8,ur9,ur10,ur11,ur12,ur13;

  a = -14;
  b = 7;
  c = 25;
  d = -5;
  ua = (uint16_t)a;
  ub = (uint16_t)b;
  uc = (uint16_t)c;
  ud = (uint16_t)d;

  std::cout << "------------------------ encrypting" << std::endl;
  timer.start();
  SHEInt16 ea(pubkey,a,"a");
  SHEInt16 eb(pubkey,b,"b");
  SHEInt16 ec(pubkey,c,"c");
  SHEInt16 ed(pubkey,d,"d");
  SHEUInt16 eua(pubkey,ua,"ua");
  SHEUInt16 eub(pubkey,ub,"ub");
  SHEUInt16 euc(pubkey,uc,"uc");
  SHEUInt16 eud(pubkey,ud,"ud");
  SHEInt16 er1(pubkey,"r1");
  SHEInt16 er2(pubkey,"r2");
  SHEInt16 er3(pubkey,"r3");
  SHEInt16 er4(pubkey,"r4");
  SHEInt16 er5(pubkey,"r5");
  SHEInt16 er6(pubkey,"r6");
  SHEInt16 er7(pubkey,"r7");
  SHEInt16 er8(pubkey,"r8");
  SHEInt16 er9(pubkey,"r9");
  SHEInt16 er10(pubkey,"r10");
  SHEInt16 er11(pubkey,"r11");
  SHEInt16 er12(pubkey,"r12");
  SHEInt16 er13(pubkey,"r13");
  SHEUInt16 eur1(pubkey,"ur1");
  SHEUInt16 eur2(pubkey,"ur2");
  SHEUInt16 eur3(pubkey,"ur3");
  SHEUInt16 eur4(pubkey,"ur4");
  SHEUInt16 eur5(pubkey,"ur5");
  SHEUInt16 eur6(pubkey,"ur6");
  SHEUInt16 eur7(pubkey,"ur7");
  SHEUInt16 eur8(pubkey,"ur8");
  SHEUInt16 eur9(pubkey,"ur9");
  SHEUInt16 eur10(pubkey,"ur10");
  SHEUInt16 eur11(pubkey,"ur11");
  SHEUInt16 eur12(pubkey,"ur12");
  SHEUInt16 eur13(pubkey,"ur13");
  timer.stop();
  std::cout << " encrypt time = " << timer.elapsedMilliseconds()
            << " ms" << std::endl;

  int16_t da,db,dc,dd;
  uint16_t dua,dub,duc,dud;
  timer.start();
  std::cout << "------------------------ decrypting"  << std::endl;
  da = ea.decrypt(privkey);
  db = eb.decrypt(privkey);
  dc = ec.decrypt(privkey);
  dd = ed.decrypt(privkey);
  dua = eua.decrypt(privkey);
  dub = eub.decrypt(privkey);
  duc = euc.decrypt(privkey);
  dud = eud.decrypt(privkey);
  timer.stop();
  std::cout << " decrypt time = " << timer.elapsedMilliseconds()
            << " ms" << std::endl;

  std::cout << "-------------decrypted inputs\n" << std::endl;
  printf("a=%d da=%d\n",a,da);
  printf("b=%d db=%d\n",b,db);
  printf("c=%d dc=%d\n",c,dc);
  printf("d=%d dd=%d\n",d,dd);
  printf("ua=%u dua=%u\n",ua,dua);
  printf("ub=%u dub=%u\n",ub,dub);
  printf("uc=%u duc=%u\n",uc,duc);
  printf("ud=%d dud=%d\n",ud,dud);

   // basic add, subtract & multiply
   r1 = a + b*c - d;
   r2 = a*b - c*d;
   // basic bitwise operations
   r3 = a & b | c ^ d;
   // shifts
   r4 = a << 5;
   r5 = b << 4;
   r6 = c >> 6;
   r7 = d >> 3;
   // logical operations
   r8 = (a > b) && (c < d) ? a : b;
   r9 = (a == b) || (c != d) ? a : b;
   r10 = (a == a) && (c == c) ? c : d;
   r11 = (a == b) || (c == d) ? c : d;
   // division and mod
   r12 = a/b;
   r13 = d % c;

   // unsigned equivalences
   ur1 = ua + ub*uc - ud;
   ur2 = ua*ub - uc*ud;
   ur3 = ua & ub | uc ^ ud;
   ur4 = ua << 5;
   ur5 = ub << 4;
   ur6 = uc >> 6;
   ur7 = ud >> 3;
   ur8 = (ua > ub) && (uc < ud) ? ua : ub;
   ur9 = (ua == ub) || (uc != ud) ? ua : ub;
   ur10 = (ua == ua) && (uc == uc) ? uc : ud;
   ur11 = (ua == ub) || (uc == ud) ? uc : ud;
   ur12 = ua/ub;
   ur13 = ud % uc;

#ifdef notdef
   std::cout << " --------------------------checking bootstrapping" << std::endl;
   er1 = ea + 1;
   timer.start();
   er1.recrypt();
   timer.stop();
   std::cout << " boostrap time = " << timer.elapsedMilliseconds() << " ms " 
             << (SHEIntSummary)er1 << std::endl;
#endif

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
   std::cout << "key save time (binary)= " << timer.elapsedMilliseconds() 
             << " ms "  << std::endl;

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
   std::cout << "key restore time (binary)= " << timer.elapsedMilliseconds() 
             << " ms "  << std::endl;

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
   std::cout << "key save time (json1)= " << timer.elapsedMilliseconds() 
             << " ms "  << std::endl;

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
   std::cout << "key save time (json2)= " << timer.elapsedMilliseconds() 
             << " ms "  << std::endl;

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
   std::cout << "key restore time (json)= " << timer.elapsedMilliseconds() 
             << " ms "  << std::endl;

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
   printf("a=%d da=%d, dja=%d drestoreA=%d djrestore=%d\n", a, da2, dja,
          drestoreA, djrestoreA);

   std::cout << "------------- restored public key against previous priv key"
             << std::endl;
   int e = 303;
   SHEInt16 ef(restorePubKey,e,"e");

   printf("e=%d ef=%d\n",e,ef.decrypt(privkey));

   //Time the encrypted operations
   std::cout << "-------------- encrypted math tests"  << std::endl;
   std::cout << " calculating er1 = ea + eb * ec - ed" << std:: endl;
   timer.start();
   er1 = ea + eb * ec -ed;
   //er1 = eua/eub; //ea + eb * ec - ed;
   timer.stop();
   std::cout << " er1 (add) time = " << (PrintTime) timer.elapsedMilliseconds()
             << std::endl;
   std::cout << " er1 (add) " << r1 << "=?" << er1.decrypt(privkey)
             << std::endl;
   std::cout << " calculating er2 = ea * eb - ec * ed" << std:: endl;
   timer.start();
   er2 = ea*eb - ec*ed;
   timer.stop();
   std::cout << " er2 (mul) time = " << (PrintTime) timer.elapsedMilliseconds()
             << std::endl;
   std::cout << " er2 (mul) " << r2 << "=?" << er2.decrypt(privkey)
             << std::endl;
   std::cout << " calculating er3 = ea & eb | ec ^ ed" << std:: endl;
   timer.start();
   er3 = ea & eb | ec^ ed;
   timer.stop();
   std::cout << " er3 (bitwise) time = " << timer.elapsedMilliseconds()
             << " ms" << std::endl;
   std::cout << " er3 (bitwise) " << r3 << "=?" << er3.decrypt(privkey)
             << std::endl;
   std::cout << " calculating er4 = ea << 5" << std:: endl;
   timer.start();
   er4 = ea << 5;
   timer.stop();
   std::cout << " er4 (shift left) time = " << timer.elapsedMilliseconds()
             << " ms" << std::endl;
   std::cout << " er4 (shift left) " << r4 << "=?" << er4.decrypt(privkey)
             << std::endl;
   std::cout << " calculating er5 = eb << 4" << std:: endl;
   timer.start();
   er5 = eb << 4;
   timer.stop();
   std::cout << " er5 (shift left) time = " << (PrintTime) timer.elapsedMilliseconds() << std::endl;
   std::cout << " er5 (shift left) " << r5 << "=?" << er5.decrypt(privkey)
             << std::endl;
   std::cout << " calculating er6 = ec >> 6" << std:: endl;
   timer.start();
   er6 = ec >> 6;
   timer.stop();
   std::cout << " er6 (shift right) time = " << (PrintTime) timer.elapsedMilliseconds() << std::endl;
   std::cout << " er6 (shift right) " << r6 << "=?" << er6.decrypt(privkey)
             << std::endl;
   std::cout << " calculating er7 = ed >> 3" << std:: endl;
   timer.start();
   er7 = ed >> 3;
   timer.stop();
   std::cout << " er7 (shift right) time = " << (PrintTime) timer.elapsedMilliseconds() << std::endl;
   std::cout << " er7 (shift right) " << r7 << "=?" << er7.decrypt(privkey)
             << std::endl;
   std::cout << " calculating er8 = ((ea > eb) && (ec < ed)) ? ea : eb"
              << std:: endl;
   timer.start();
   er8 = ((ea > eb) && (ec < ed)).select(ea,eb);
   timer.stop();
   std::cout << " er8 (inequal &&) time = " << (PrintTime) timer.elapsedMilliseconds() << std::endl;
   std::cout << " er8 (inequal &&) " << r8 << "=?" << er8.decrypt(privkey)
             << std::endl;
   std::cout << " calculating er9 = ((ea == eb) || (ec != ed)) ? ea : eb"
              << std:: endl;
   timer.start();
   er9 = ((ea == eb) || (ec != ed)).select(ea,eb);
   timer.stop();
   std::cout << " er9 (inequal ||) time = " << (PrintTime) timer.elapsedMilliseconds() << std::endl;
   std::cout << " er9 (inequal ||) " << r9 << "=?" << er9.decrypt(privkey)
             << std::endl;
   std::cout << " calculating er10 = ((ea == eb) && (ec == ed)) ? ec : ed"
              << std:: endl;
   timer.start();
   er10 = ((ea == ea) && (ec == ec)).select(ec,ed);
   timer.stop();
   std::cout << " er10 (equality &&) time = " << (PrintTime) timer.elapsedMilliseconds() << std::endl;
   std::cout << " er10 (equality &&) " << r10 << "=?" << er10.decrypt(privkey)
             << std::endl;
   std::cout << " calculating er11 = ((ea == eb) && (ec == ed)) ? ec : ed"
              << std:: endl;
   timer.start();
   er11 = ((ea == eb) || (ec == ed)).select(ec,ed);
   timer.stop();
   std::cout << " er11 (equality ||) time = " << (PrintTime) timer.elapsedMilliseconds() << std::endl;
   std::cout << " er11 (equality ||) " << r11 << "=?" << er11.decrypt(privkey)
             << std::endl;
   std::cout << " calculating er12 = ea/eb" << std:: endl;
   timer.start();
   er12 = ea/eb;
   timer.stop();
   std::cout << " er12 (div) time = " << (PrintTime) timer.elapsedMilliseconds() << std::endl;
   std::cout << " er12 (div) " << r12 << "=?" << er12.decrypt(privkey)
             << std::endl;
   std::cout << " calculating er13 = ed % ec" << std:: endl;
   timer.start();
   er13 = ed % ec;
   std::cout << " er13 (mod) time = " << (PrintTime) timer.elapsedMilliseconds() << std::endl;
   std::cout << " er13 (mod) " << ur13 << "=?" << er13.decrypt(privkey)
             << std::endl;

   std::cout << " calculating eur1 = eua + eub * euc -eud" << std:: endl;
   timer.start();
   eur1 = eua + eub * euc - eud;
   timer.stop();
   std::cout << " eur1 (add) time = " << timer.elapsedMilliseconds()
             << " ms" << std::endl;
   std::cout << " eur1 (add) " << r1 << "=?" << eur1.decrypt(privkey)
             << std::endl;
   std::cout << " calculating eur2 = eua * eub - euc * eud" << std:: endl;
   timer.start();
   eur2 = eua*eub - euc*eud;
   timer.stop();
   std::cout << " eur2 (mul) time = " << (PrintTime) timer.elapsedMilliseconds()
             << std::endl;
   std::cout << " eur2 (mul) " << r2 << "=?" << eur2.decrypt(privkey)
             << std::endl;
   std::cout << " calculating eur3 = eua & eub | euc ^ eud" << std:: endl;
   timer.start();
   eur3 = eua & eub | euc^ eud;
   timer.stop();
   std::cout << " eur3 (bitwise) time = " << timer.elapsedMilliseconds()
             << " ms" << std::endl;
   std::cout << " eur3 (bitwise) " << ur3 << "=?" << eur3.decrypt(privkey)
             << std::endl;
   std::cout << " calculating eur4 = eua << 5" << std:: endl;
   timer.start();
   eur4 = eua << 5;
   timer.stop();
   std::cout << " eur4 (shift left) time = " << timer.elapsedMilliseconds()
             << " ms" << std::endl;
   std::cout << " eur4 (shift left) " << ur4 << "=?" << eur4.decrypt(privkey)
             << std::endl;
   std::cout << " calculating eur5 = eub << 4" << std:: endl;
   timer.start();
   eur5 = eub << 4;
   timer.stop();
   std::cout << " eur5 (shift left) time = " << timer.elapsedMilliseconds()
             << " ms" << std::endl;
   std::cout << " eur5 (shift left) " << ur5 << "=?" << eur5.decrypt(privkey)
             << std::endl;
   std::cout << " calculating eur6 = euc >> 6" << std:: endl;
   timer.start();
   eur6 = euc >> 6;
   timer.stop();
   std::cout << " eur6 (shift right) time = " << (PrintTime) timer.elapsedMilliseconds() << std::endl;
   std::cout << " eur6 (shift right) " << ur6 << "=?" << eur6.decrypt(privkey)
             << std::endl;
   std::cout << " calculating eur7 = eud >> 3" << std:: endl;
   timer.start();
   eur7 = eud >> 3;
   timer.stop();
   std::cout << " eur7 (shift right) time = " << (PrintTime) timer.elapsedMilliseconds() << std::endl;
   std::cout << " eur7 (shift right) " << ur7 << "=?" << eur7.decrypt(privkey)
             << std::endl;
   std::cout << " calculating eur8 = (eua > eub) && (euc < eud) ? eua:eub"
             << std:: endl;
   timer.start();
   eur8 = ((eua > eub) && (euc < eud)).select(eua,eub);
   timer.stop();
   std::cout << " eur8 (inequal &&) time = " << (PrintTime) timer.elapsedMilliseconds() << std::endl;
   std::cout << " eur8 (inequal &&) " << ur8 << "=?" << eur8.decrypt(privkey)
             << std::endl;
   std::cout << " calculating eur9 = (eua == eub) || (euc == eud) ? eua:eub"
             << std:: endl;
   timer.start();
   eur9 = ((eua == eub) || (euc != eud)).select(eua,eub);
   timer.stop();
   std::cout << " eur9 (inequal ||) time = " << (PrintTime) timer.elapsedMilliseconds() << std::endl;
   std::cout << " eur9 (inequal ||) " << ur9 << "=?" << eur9.decrypt(privkey)
             << std::endl;
   std::cout << " calculating eur10 = (eua == eua) || (euc == euc) ? euc:eud"
             << std:: endl;
   timer.start();
   eur10 = ((eua == eua) && (euc == euc)).select(euc,eud);
   timer.stop();
   std::cout << " eur10 (equality &&) time = " << (PrintTime) timer.elapsedMilliseconds() << std::endl;
   std::cout << " eur10 (equality &&) " << ur10 << "=?" << eur10.decrypt(privkey)
             << std::endl;
   std::cout << " calculating eur11 = (eua == eub) || (euc == eud) ? euc:eud"
             << std:: endl;
   timer.start();
   eur11 = ((eua == eub) || (euc == eud)).select(euc,eud);
   timer.stop();
   std::cout << " eur11 (equality ||) time = " << (PrintTime) timer.elapsedMilliseconds() << std::endl;
   std::cout << " eur11 (equality ||) " << ur11 << "=?" << eur11.decrypt(privkey)
             << std::endl;
   std::cout << " calculating eur12 = eua/eub" << std:: endl;
   timer.start();
   eur12 = eua/eub;
   timer.stop();
   std::cout << " eur12 (div) time = " << (PrintTime) timer.elapsedMilliseconds() << std::endl;
   std::cout << " eur12 (div) " << ur12 << "=?" << eur12.decrypt(privkey)
             << std::endl;
   std::cout << " calculating eur12 = eud % euc" << std:: endl;
   timer.start();
   eur13 = eud % euc;
   std::cout << " eur13 (mod) time = " << (PrintTime) timer.elapsedMilliseconds() << std::endl;
   std::cout << " eur13 (mod) " << ur13 << "=?" << eur13.decrypt(privkey)
             << std::endl;

   int16_t dr1,dr2,dr3,dr4,dr5,dr6,dr7,dr8,dr9,dr10,dr11,dr12,dr13;
   uint16_t dur1,dur2,dur3,dur4,dur5,dur6,dur7,dur8,dur9,dur10,dur11,dur12,dur13;

   std::cout << "-----------------------------decrypting results" << std::endl;
   timer.start();
   dr1 = er1.decrypt(privkey);
   dr2 = er2.decrypt(privkey);
   dr3 = er3.decrypt(privkey);
   dr4 = er4.decrypt(privkey);
   dr5 = er5.decrypt(privkey);
   dr6 = er6.decrypt(privkey);
   dr7 = er7.decrypt(privkey);
   dr8 = er8.decrypt(privkey);
   dr9 = er9.decrypt(privkey);
   dr10 = er10.decrypt(privkey);
   dr11 = er11.decrypt(privkey);
   dr12 = er12.decrypt(privkey);
   dr13 = er13.decrypt(privkey);
   dur1 = eur1.decrypt(privkey);
   dur2 = eur2.decrypt(privkey);
   dur3 = eur3.decrypt(privkey);
   dur4 = eur4.decrypt(privkey);
   dur5 = eur5.decrypt(privkey);
   dur6 = eur6.decrypt(privkey);
   dur7 = eur7.decrypt(privkey);
   dur8 = eur8.decrypt(privkey);
   dur9 = eur9.decrypt(privkey);
   dur10 = eur10.decrypt(privkey);
   dur11 = eur11.decrypt(privkey);
   dur12 = eur12.decrypt(privkey);
   dur13 = eur13.decrypt(privkey);
   timer.stop();
   std::cout << " decrypt time = " << timer.elapsedMilliseconds() 
             << " ms" << std::endl;

   std::cout << "-------------decrypted outputs verse originals\n" << std::endl;
   printf("r1=%d dr1=%d\n",r1,dr1);
   printf("r2=%d dr2=%d\n",r2,dr2);
   printf("r3=%d dr3=%d\n",r3,dr3);
   printf("r4=%d (0x%x) dr4=%d (0x%x)\n",r4,r4,dr4,dr4);
   printf("r5=%d (0x%x) dr5=%d (0x%x)\n",r5,r5,dr5,dr5);
   printf("r6=%d (0x%x) dr6=%d (0x%x)\n",r6,r6,dr6,dr6);
   printf("r7=%d (0x%x) dr7=%d (0x%x)\n",r7,r7,dr7,dr7);
   printf("r8=%d dr8=%d\n",r8,dr8);
   printf("r9=%d dr9=%d\n",r9,dr9);
   printf("r10=%d dr10=%d\n",r10,dr10);
   printf("r11=%d dr11=%d\n",r11,dr11);
   printf("r12=%d dr12=%d\n",r12,dr12);
   printf("r13=%d dr13=%d\n",r13,dr13);
   printf("ur1=%d dur1=%d\n",ur1,dur1);
   printf("ur2=%d dur2=%d\n",ur2,dur2);
   printf("ur3=%d dur3=%d\n",ur3,dur3);
   printf("ur4=%d (0x%x) dur4=%d (0x%x)\n",ur4,ur4,dur4,dur4);
   printf("ur5=%d (0x%x) dur5=%d (0x%x)\n",ur5,ur5,dur5,dur5);
   printf("ur6=%d (0x%x) dur6=%d (0x%x)\n",ur6,ur6,dur6,dur6);
   printf("ur7=%d (0x%x) dur7=%d (0x%x)\n",ur7,ur7,dur7,dur7);
   printf("ur8=%d dur8=%d\n",ur8,dur8);
   printf("ur9=%d dur9=%d\n",ur9,dur9);
   printf("ur10=%d dur10=%d\n",ur10,dur10);
   printf("ur11=%d dur11=%d\n",ur11,dur11);
   printf("ur12=%d dur12=%d\n",ur12,dur12);
   printf("ur13=%d dur13=%d\n",ur13,dur13);
}
