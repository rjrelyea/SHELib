#
# Simple Makefile: Todo move to some form of automake (cmake, etc.)
#
HELIB_DIR=/builds/HElib/helib_pack
HELIB_INCLUDE=${HELIB_DIR}/include
HELIB_LIB=${HELIB_DIR}/lib64

LDFLAGS=-g -Wl,-rpath,${HELIB_LIB} ${HELIB_LIB}/libhelib.a ${HELIB_LIB}/libntl.so ${HELIB_LIB}/libgmp.so -lpthread 
CPPFLAGS=-g -DHELIB_BOOT_THREADS -DHELIB_THREADS -isystem ${HELIB_INCLUDE} -std=c++17
#LDFLAGS=-g -L ${HELIB_LIB} -lhelib -lntl -lgmp


#OBJS=SHEKey.o SHEInt.o
OBJS=SHEio.o SHEContext.o SHEKey.o SHEInt.o
LIB=SHELib.a
PROG=SHETest SHEPerf SHEEval

all: ${LIB} ${PROG}

clean:
	rm -rf ${OBJS} ${PROG} 

SHELib.a: ${OBJS}
	ar -r SHELib.a $?

SHETest: SHETest.o ${OBJS} ${LIB}
	g++ -o $@ $< ${OBJS} ${LDFLAGS}

SHEPerf: SHEPerf.o ${OBJS} ${LIB}
	g++ -o $@ $< ${OBJS} ${LDFLAGS}

SHEEval: SHEEval.o ${OBJS} ${LIB}
	g++ -o $@ $< ${OBJS} ${LDFLAGS}

.cpp.o:
	g++ -g -c -o $@ ${CPPFLAGS} $<

SHEContext.o: SHEContext.h
SHEInt.o: SHEInt.h SHEKey.h SHEMagic.h SHEio.h
SHEKey.o: SHEKey.h SHEContext.h SHEMagic.h SHEio.h
SHEio.o: SHEio.h
SHETest.o: SHEInt.h SHEKey.h SHEContext.h SHEMagic.h SHEio.h
SHEPerf.o: SHEInt.h SHEKey.h SHEContext.h SHEMagic.h SHEio.h
SHEEval.o: SHEInt.h SHEKey.h SHEContext.h SHEMagic.h SHEio.h
