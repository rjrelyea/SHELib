//
// the HE binio is private. fortunately we don't need abig library.
//
#ifndef SHEio_h
#define SHEio_h 1
#include <iostream>

void write_raw_int(std::ostream& str, long num);
long read_raw_int(std::istream& str);

#endif

