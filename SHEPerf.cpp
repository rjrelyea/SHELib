//
// Test program for Simple Homomorphic Encryption
//
#include <iostream>
#include "SHEKey.h"
#include "SHEInt.h"
#include "SHEConfig.h"

// simple timer harvested from the internet.
#include "SHETime.h"

void
do_timed_tests(SHEInt &a,SHEInt &b, SHEInt&r, SHEPrivateKey &privkey)
{
   SHEBool rb(r);
   Timer timer;
#ifdef SHE_PERF_QUICK
   SHEInt::resetRecryptCounters();
   timer.start();
   std::cout << "  > a+b: " << std::flush;
   r = a + b;
   timer.stop();
   std::cout << (PrintTime) timer.elapsedMilliseconds()  << " bootstraps="
             << SHEInt::getRecryptCounters() << std::endl;
#else
   std::cout << "  >decrypt time: " << std::flush;
   SHEInt::resetRecryptCounters();
   timer.start();
   uint64_t da = a.decryptRaw(privkey);
   uint64_t db = b.decryptRaw(privkey);
   timer.stop();
   std::cout << (PrintTime) timer.elapsedMilliseconds()  << " bootstraps="
             << SHEInt::getRecryptCounters() << std::endl;
   SHEInt::resetRecryptCounters();
   timer.start();
   std::cout << "  > a+b: " << std::flush;
   r = a + b;
   timer.stop();
   std::cout << (PrintTime) timer.elapsedMilliseconds()  << " bootstraps="
             << SHEInt::getRecryptCounters() << std::endl;
   std::cout << "  > a-b: " << std::flush;
   SHEInt::resetRecryptCounters();
   timer.start();
   r = a - b;
   timer.stop();
   std::cout << (PrintTime) timer.elapsedMilliseconds()  << " bootstraps="
             << SHEInt::getRecryptCounters() << std::endl;
   std::cout << "  > a*b: " <<  std::flush;
   SHEInt::resetRecryptCounters();
   timer.start();
   r = a * b;
   timer.stop();
   std::cout << (PrintTime) timer.elapsedMilliseconds()  << " bootstraps="
             << SHEInt::getRecryptCounters() << std::endl;
//#ifndef SHE_SKIP_DIV
   std::cout << "  > a/b: " <<  std::flush;
   SHEInt::resetRecryptCounters();
   timer.start();
   r = a / b;
   timer.stop();
   std::cout << (PrintTime) timer.elapsedMilliseconds()  << " bootstraps="
             << SHEInt::getRecryptCounters() << std::endl;
//#else
//   std::cout << "  > a/b: " <<  "skipped" << std::endl;
//#endif
   std::cout << "  > a&b: " <<  std::flush;
   SHEInt::resetRecryptCounters();
   timer.start();
   r = a & b;
   timer.stop();
   std::cout << (PrintTime) timer.elapsedMilliseconds()  << " bootstraps="
             << SHEInt::getRecryptCounters() << std::endl;
   std::cout << "  > a|b: " <<  std::flush;
   SHEInt::resetRecryptCounters();
   timer.start();
   r = a | b;
   timer.stop();
   std::cout << (PrintTime) timer.elapsedMilliseconds()  << " bootstraps="
             << SHEInt::getRecryptCounters() << std::endl;
   std::cout << "  > a==b: " << std::flush;
   SHEInt::resetRecryptCounters();
   timer.start();
   rb = a == b;
   timer.stop();
   std::cout << (PrintTime) timer.elapsedMilliseconds()  << " bootstraps="
             << SHEInt::getRecryptCounters() << std::endl;
   std::cout << "  > a<b: " << std::flush;
   SHEInt::resetRecryptCounters();
   timer.start();
   rb = a < b;
   timer.stop();
   std::cout << (PrintTime) timer.elapsedMilliseconds()  << " bootstraps="
             << SHEInt::getRecryptCounters() << std::endl;
   std::cout << "  > r?a:b: " << std::flush;
   SHEInt::resetRecryptCounters();
   timer.start();
   r = rb.select(a,b);
   timer.stop();
   std::cout << (PrintTime) timer.elapsedMilliseconds()  << " bootstraps="
             << SHEInt::getRecryptCounters() << std::endl;
   std::cout << "  >boostrap time: " << std::flush;
   SHEInt::resetRecryptCounters();
   timer.start();
   r.reCrypt(true);
   timer.stop();
   std::cout << (PrintTime) timer.elapsedMilliseconds()  << " bootstraps="
             << SHEInt::getRecryptCounters() << std::endl;
   std::cout << "  >double boostrap time: " << std::flush;
   SHEInt::resetRecryptCounters();
   timer.start();
   r.reCrypt(a, true);
   timer.stop();
   std::cout << (PrintTime) timer.elapsedMilliseconds()  << " bootstraps="
             << SHEInt::getRecryptCounters() << std::endl;
#endif
}

void
launch_integer_tests(SHEPublicKey &pubkey, SHEPrivateKey &privKey)
{
   Timer timer;

   std::cout << " ...SHEInt8 operations..." << std::endl;
   int8_t a8, b8;
   a8=-4;
   b8=15;
   std::cout << "  >encrypt time: " << std::flush;
   timer.start();
   SHEInt8 ea8(pubkey,a8,"a");
   SHEInt8 eb8(pubkey,b8,"b");
   SHEInt8 er8(pubkey,0,"r");
   timer.stop();
   std::cout << (PrintTime) timer.elapsedMilliseconds() << std::endl;
   do_timed_tests(ea8,eb8,er8,privKey);

   std::cout << " ...SHEUInt8 operations..." << std::endl;
   uint8_t au8, bu8;
   au8=-4;
   bu8=15;
   std::cout << "  >encrypt time: " << std::flush;
   timer.start();
   SHEUInt8 eau8(pubkey,au8,"a");
   SHEUInt8 ebu8(pubkey,bu8,"b");
   SHEUInt8 eru8(pubkey,0,"r");
   timer.stop();
   std::cout << (PrintTime) timer.elapsedMilliseconds() << std::endl;
   do_timed_tests(eau8,ebu8,eru8,privKey);

   std::cout << " ...SHEInt16 operations..." << std::endl;
   int16_t a16, b16;
   a16=-4;
   b16=15;
   std::cout << "  >encrypt time: " << std::flush;
   timer.start();
   SHEInt16 ea16(pubkey,a16,"a");
   SHEInt16 eb16(pubkey,b16,"b");
   SHEInt16 er16(pubkey,0,"r");
   timer.stop();
   std::cout << (PrintTime) timer.elapsedMilliseconds() << std::endl;
   do_timed_tests(ea16,eb16,er16,privKey);

   std::cout << " ...SHEUInt16 operations..." << std::endl;
   uint16_t au16, bu16;
   au16=-4;
   bu16=15;
   std::cout << "  >encrypt time: " << std::flush;
   timer.start();
   SHEUInt16 eau16(pubkey,au16,"a");
   SHEUInt16 ebu16(pubkey,bu16,"b");
   SHEUInt16 eru16(pubkey,0,"r");
   timer.stop();
   std::cout << (PrintTime) timer.elapsedMilliseconds() << std::endl;
   do_timed_tests(eau16,ebu16,eru16,privKey);

   std::cout << " ...SHEInt32 operations..." << std::endl;
   int32_t a32, b32;
   a32=-4;
   b32=15;
   std::cout << "  >encrypt time: " << std::flush;
   timer.start();
   SHEInt32 ea32(pubkey,a32,"a");
   SHEInt32 eb32(pubkey,b32,"b");
   SHEInt32 er32(pubkey,0,"r");
   timer.stop();
   std::cout << (PrintTime) timer.elapsedMilliseconds() << std::endl;
   do_timed_tests(ea32,eb32,er32,privKey);

   std::cout << " ...SHEUInt32 operations..." << std::endl;
   uint32_t au32, bu32;
   au32=-4;
   bu32=15;
   std::cout << "  >encrypt time: " << std::flush;
   timer.start();
   SHEUInt32 eau32(pubkey,au32,"a");
   SHEUInt32 ebu32(pubkey,bu32,"b");
   SHEUInt32 eru32(pubkey,0,"r");
   timer.stop();
   std::cout << (PrintTime) timer.elapsedMilliseconds() << std::endl;
   do_timed_tests(eau32,ebu32,eru32,privKey);

   std::cout << " ...SHEInt64 operations..." << std::endl;
   int64_t a64, b64;
   a64=-4;
   b64=15;
   std::cout << "  >encrypt time: " << std::flush;
   timer.start();
   SHEInt64 ea64(pubkey,a64,"a");
   SHEInt64 eb64(pubkey,b64,"b");
   SHEInt64 er64(pubkey,0,"r");
   timer.stop();
   std::cout << (PrintTime) timer.elapsedMilliseconds() << std::endl;
   do_timed_tests(ea64,eb64,er64,privKey);

   std::cout << " ...SHEUInt64 operations..." << std::endl;
   uint64_t au64, bu64;
   au64=-4;
   bu64=15;
   std::cout << "  >encrypt time: " << std::flush;
   timer.start();
   SHEUInt64 eau64(pubkey,au64,"a");
   SHEUInt64 ebu64(pubkey,bu64,"b");
   SHEUInt64 eru64(pubkey,0,"r");
   timer.stop();
   std::cout << (PrintTime) timer.elapsedMilliseconds() << std::endl;
   do_timed_tests(eau64,ebu64,eru64,privKey);
}

int main(int argc, char **argv)
{
   SHEPublicKey pubkey;
   SHEPrivateKey privkey;
   Timer timer;
 int level= 0;
  int lastLevel = 200;

  if (argc > 1) {
     level = atoi(argv[1]);
  }
  if (argc > 2) {
     lastLevel = atoi(argv[2]);
  }

#ifdef notdef
   SHEContext::setLog(std::cout);
   SHEPublicKey::setLog(std::cout);
   SHEPrivateKey::setLog(std::cout);
   SHEInt::setLog(std::cout);
#endif

   int security_level[] = {19,20,21,22,23,25,26,38,42,44,46,47,51,54,55,
                           59,60,66,88,89,94 };

   for (int i=0 ; i < sizeof(security_level)/sizeof(int) ; i++) {
     SHEPublicKey pubkey;
     SHEPrivateKey privkey;

    if (security_level[i] < level) continue;
    if (security_level[i] > lastLevel) break;

     std::cout << "----------------- security level "
               << security_level[i] << " ------------------" << std::endl;
     timer.start();
     try {
       SHEGenerate_BinaryKey(privkey, pubkey, security_level[i]);
     } catch (const std::exception& ex) {
       std::cout << "ERROR: " << ex.what() << std::endl;
       continue;
     } catch (...) {
       std::exception_ptr p = std::current_exception();
       std::cout << (p ? p.__cxa_exception_type()->name() : "null")
                 <<  std::endl;
       continue;
     }
     timer.stop();
     std::cout << " keygen time (" << security_level[i] << "): "
               << (PrintTime) timer.elapsedMilliseconds() << std::endl;
     launch_integer_tests(pubkey, privkey);
   }
}
