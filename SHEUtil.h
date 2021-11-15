//
// Common utility functions used in other headers
//
#ifndef SHEUtil_H
#define SHEUtil_H_ 1

#include "SHEConfig.h"
#include <iostream>
#include <climits>

#ifdef SHE_USE_CLZ_BUILTIN
static inline int log2i(int x) { return sizeof(int)*CHAR_BIT - __builtin_clz(x) -1; }
#else
static inline int log2i(int x) { int r = 1; while (x >>= 1) r++; return r;}
#endif


void write_raw_int(std::ostream& str, long num);
long read_raw_int(std::istream& str);



#endif

