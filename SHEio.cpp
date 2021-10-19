//
// the HE binio is private. fortunately we don't need abig library.
//
#include <iostream>
#include "SHEio.h"

void write_raw_int(std::ostream& str, long num)
{
  char byte;

  for (long i = 0; i < 64; i++) {
    byte = num >> 8 * i; // serializing in little endian
    str.write(&byte, 1); // write byte out
  }
}

long read_raw_int(std::istream& str)
{
  long result = 0;
  char byte;

  for (long i = 0; i < 64; i++) {
    str.read(&byte, 1); // read a byte
    result |= (static_cast<long>(byte) & 0xff)
              << i * 8; // must be in little endian
  }

  return result;
}

