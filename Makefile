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
OBJS=SHEio.o SHEContext.o SHEKey.o SHEInt.o SHEFp.o SHEMath.o
LIB=libSHELib.a
PROG=SHETest SHEPerf SHEEval

all: ${LIB} ${PROG}

clean:
	rm -rf ${OBJS} ${PROG} 

libSHELib.a: ${OBJS}
	ar -r $@ $?

SHETest: SHETest.o ${LIB}
	g++ -o $@ $< ${LIB} ${LDFLAGS}

SHEPerf: SHEPerf.o ${LIB}
	g++ -o $@ $< ${LIB} ${LDFLAGS}

SHEEval: SHEEval.o ${LIB}
	g++ -o $@ $< ${LIB} ${LDFLAGS}

.cpp.o:
	g++ -g -c -o $@ ${CPPFLAGS} $<

SHEContext.o: SHEContext.h
SHEMath.o: SHEInt.h SHEKey.h SHEMagic.h SHEio.h SHEFp.h SHEConfig.h SHEMath.h
SHEFp.o: SHEInt.h SHEKey.h SHEMagic.h SHEio.h SHEFp.h SHEConfig.h
SHEInt.o: SHEInt.h SHEKey.h SHEMagic.h SHEio.h SHEConfig.h
SHEKey.o: SHEKey.h SHEContext.h SHEMagic.h SHEio.h SHEConfig.h
SHEio.o: SHEio.h SHEConfig.h
SHETest.o: SHEInt.h SHEKey.h SHEContext.h SHEMagic.h SHEio.h SHEVector.h SHEFp.h SHEConfig.h
SHEPerf.o: SHEInt.h SHEKey.h SHEContext.h SHEMagic.h SHEio.h SHEConfig.h
SHEEval.o: SHEInt.h SHEKey.h SHEContext.h SHEMagic.h SHEio.h SHEConfig.h
