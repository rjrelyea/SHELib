//
// Test different Contexts for the best properties when used
// in Simple Homomorphic Encryption
//
#include <iostream>
#include "SHEKey.h"
#include "SHEInt.h"
#include "SHETime.h"

void
do_timed_tests(SHEInt &a,SHEInt &b, SHEInt&r, SHEPrivateKey &privkey)
{
  SHEBool rb(r);
  SHEBool rs(r);
  Timer timer;
  // comparison is the most level intensive operation.. compare
  // full level versus reCrypted version
  SHEInt::resetRecryptCounters();
  std::cout << "      >init bit capacity:" << a.bitCapacity() << std::endl;
  std::cout << "      > a<b: " << std::flush;
  timer.start();
  rb = a < b;
  timer.stop();
  std::cout << (PrintTime) timer.elapsedMilliseconds() << "boostraps = "
            << SHEInt::getRecryptCounters() << std::endl;
  std::cout << "      > a-b: " << std::flush;
  timer.start();
  rs = a - b;
  timer.stop();
  std::cout << (PrintTime) timer.elapsedMilliseconds() << "boostraps = "
            << SHEInt::getRecryptCounters() << std::endl;
  std::cout << "     >post cmp bit capacity:" << rb.bitCapacity() << std::endl;
  std::cout << "     >post sub bit capacity:" << rs.bitCapacity() << std::endl;
  std::cout << "  >double boostrap time: " << std::flush;
  SHEInt::resetRecryptCounters();
  timer.start();
  b.reCrypt(a);
  timer.stop();
  std::cout << (PrintTime) timer.elapsedMilliseconds() << "boostraps = "
            << SHEInt::getRecryptCounters() << std::endl;
  std::cout << "     >post bootstrap bit capacity:" << a.bitCapacity() << std::endl;
  std::cout << "     > a<b (post bootstrap): " << std::flush;
  SHEInt::resetRecryptCounters();
  timer.start();
  rb = a < b;
  timer.stop();
  std::cout << (PrintTime) timer.elapsedMilliseconds() << "boostraps = "
            << SHEInt::getRecryptCounters() << std::endl;
  std::cout << "     > a-b (post bootsrap): " << std::flush;
  SHEInt::resetRecryptCounters();
  timer.start();
  rs = a - b;
  timer.stop();
  std::cout << (PrintTime) timer.elapsedMilliseconds() << "boostraps = "
            << SHEInt::getRecryptCounters() << std::endl;
  std::cout << "     >post cmp bit capacity:" << rb.bitCapacity() << std::endl;
  std::cout << "     >post sub bit capacity:" << rs.bitCapacity() << std::endl;
}

void
launch_integer_tests(SHEPublicKey &pubkey, SHEPrivateKey &privKey)
{
  Timer timer;

  std::cout << " ............SHEInt8 operations............" << std::endl;
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

  std::cout << " ............SHEUInt8 operations............" << std::endl;
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

  std::cout << " ............SHEInt16 operations............" << std::endl;
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

  std::cout << " ............SHEUInt16 operations............" << std::endl;
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

  std::cout << " ............SHEInt32 operations............" << std::endl;
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

  std::cout << " ............SHEUInt32 operations............" << std::endl;
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

  std::cout << " ............SHEInt64 operations............" << std::endl;
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

  std::cout << " ............SHEUInt64 operations............" << std::endl;
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
  int security_level[] = {19,20,21,22,23,24,25,26,29,41,45,47,50,51,52,56,
                          57,59,60,61,64,65,66,67,72,73,78,80,85,97,98,99,
                          100,105,120,122,133,135,137,142,146,175,193};

  for (int i=0 ; i < sizeof(security_level)/sizeof(int) ; i++) {
    SHEPublicKey pubkey;
    SHEPrivateKey privkey;
    bool fail = false;

    if (security_level[i] < level) continue;
    if (security_level[i] > lastLevel) break;
    std::cout << "-------------------------- security level "
              << security_level[i] << " ---------------------------" << std::endl;
    timer.start();
    try {
      SHEGenerate_BinaryKey(privkey, pubkey, security_level[i]);
    } catch (const std::exception& ex) {
      std::cout << "ERROR: " << ex.what() << std::endl;
      fail=true;
      continue;
    } catch (...) {
      std::exception_ptr p = std::current_exception();
      std::cout << (p ? p.__cxa_exception_type()->name() : "null")
                <<  std::endl;
      fail=true;
      continue;
    }
    timer.stop();
    std::cout << " keygen time (" << security_level[i] << "): "
              << (PrintTime) timer.elapsedMilliseconds() << std::endl;
    if (fail) continue;
    launch_integer_tests(pubkey, privkey);
    privkey.clear();
    SHEContext::FreeContext(SHEContextBinary, security_level[i]);
  }
}
