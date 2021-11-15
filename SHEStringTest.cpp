//
// Test program for Simple Homomorphic Encryption
//
#include <iostream>
#include "SHEKey.h"
#include "SHEInt.h"
#include "SHETime.h"
#include "SHEVector.h"
#include "SHEString.h"
#include "getopt.h"

#define NUM_TESTS 6

static struct option longOptions[] =
{
   // options
   { "security-level", required_argument, 0, 's' },
   { "capacity", required_argument, 0, 'c' },
   { 0, 0, 0, 0 }
};
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
  std::cout << " "#target" \"" << expected << "\" =? \"" << target.decrypt(privkey) << "\"" \
            << std::endl;

#define RUN_TEST(target, expected, test) \
        RUN_TEST_ALIAS(target, expected, test, test)


void
do_tests(const SHEPublicKey &pubkey, SHEPrivateKey &privkey,
         std::string a, const char *c, bool encryptLength,  int &failed, int &tests)
{
  std::string r[NUM_TESTS];
  Timer timer;


  std::cout << "------------------------ encrypting" << std::endl;
  timer.start();
  SHEString ea(pubkey,a, encryptLength, "a");
  SHEString ec(pubkey,c, encryptLength, "c");
  SHEVector<SHEString> er(ea,NUM_TESTS);
  timer.stop();
  std::cout << " encrypt time = " << timer.elapsedMilliseconds()
            << " ms" << std::endl;

  std::string da;
  std::string dc;
  int result;
  timer.start();
  std::cout << "------------------------ decrypting"  << std::endl;
  da = ea.decrypt(privkey);
  dc = ec.decrypt(privkey);
  timer.stop();
  std::cout << " decrypt time = " << timer.elapsedMilliseconds()
            << " ms" << std::endl;

  std::cout << "-------------decrypted inputs\n" << std::endl;
  std::cout << "a=\"" << a << "\" da=\"" << da << "\" ";
  if (a != da) { failed++; std::cout << "FAILED"; }
  tests++; std::cout << std::endl;
  std::cout << "c=\"" << c << "\" dc=\"" << dc << "\" ";
  if (c != dc) { failed++; std::cout << "FAILED"; }
  tests++; std::cout << std::endl;

  // integer returning functions
  r[0] = a + c;
  r[1] = a.substr(2,2);
  r[2] = a;
  r[2].replace(2, 3, c);
  r[3] = a;
  r[3].insert(4, c);
  r[4] = a;
  r[4].erase(4, 2);
  r[5] = (a < c) ? a : c;
  //Time the encrypted operations
  std::cout << "-------------- encrypted string tests"  << std::endl;
  if (encryptLength) {
    std::cout << "::encryptedLength "
              << (const char *) (SHEString::getHasFixedSize() ? "fixed" : "variable")
              << " maxSize=" << SHEString::getFixedSize() << std::endl;
  } else {
    std::cout << "::unEncryptedLength "  << std::endl;
  }
  RUN_TEST(er[0], r[0], er[0] = ea + ec)
  RUN_TEST(er[1], r[1], er[1] = ea.substr(2,2))
  RUN_TEST(er[2], r[2], er[2] = ea ; er[2].replace(2, 3, ec) )
  RUN_TEST(er[3], r[3], er[3] = ea ; er[3].insert(4, ec) )
  RUN_TEST(er[4], r[4], er[4] = ea ; er[4].erase(4, 2) )
  RUN_TEST(er[5], r[5], er[5] = select(ea  < ec, ea, ec) )

  std::string dr[NUM_TESTS];

  std::cout << "-----------------------------decrypting results" << std::endl;
  timer.start();
  for (int i = 0; i < er.size(); i++) {
    std::cout << "er[" << i << "].bitCapacity: " << er[i].bitCapacity()
              << std::endl;
    dr[i] = er[i].decrypt(privkey);
  }
  timer.stop();
  std::cout << " decrypt time = "
            << (PrintTime) timer.elapsedMilliseconds() << std::endl;

  std::cout << "-------------decrypted outputs verse originals\n" << std::endl;
  for (int i = 0; i < NUM_TESTS; i++) {
    std::cout << "r[" << i << "]=\"" << r[i] << "\" dr[" << i << "]=\"" << dr[i]
              << "\" ";
    if (r[i] == dr[i]) {
      std::cout << "PASS";
    } else {
      failed++;
      std::cout << "FAIL" << "(sizes=<" << r[i].length()
                << "," << dr[i].length() << ">)"
                << (const char *) (er[i].lengthIsEncrypted() ? " El" : " Ul");
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
  SHEString::setLog(std::cout);
#endif

  SHEGenerate_BinaryKey(privkey, pubkey, securityLevel, capacity);
#ifdef DEBUG
  SHEInt::setDebugPrivateKey(privkey);
  SHEString::setDebugPrivateKey(privkey);
#endif

  std::string a="hello ";
  const char *c = " world";

  do_tests(pubkey, privkey, a, c, false, failed, tests);
  SHEString::setFixedSize(true,16);
  do_tests(pubkey, privkey, a, c, true, failed, tests);
  SHEString::setFixedSize(false,16);
  do_tests(pubkey, privkey, a, c, true, failed, tests);
  SHEString::setFixedSize(false,255);
  do_tests(pubkey, privkey, a, c, true, failed, tests);

  std::cout << failed << " test" << (char *)((failed == 1) ? "" : "s")
            << " failed out of " << tests << " tests." << std::endl;
  if (failed) {
    std::cout << "FAILED" << std::endl;
  } else {
    std::cout << "PASSED" << std::endl;
  }
  return failed;
}
