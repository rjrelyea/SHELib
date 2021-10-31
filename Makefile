#
# Simple Makefile: Todo move to some form of automake (cmake, etc.)
#
ifdef HELIB_DIR
USE_EXTERNAL_HELIB=1
else
HELIB_DIR=/usr
endif
HELIB_INCLUDE=${HELIB_DIR}/include
HELIB_LIB=${HELIB_DIR}/lib64

ifdef USE_EXTERNAL_HELIB
ISYSTEM=-isystem ${HELIB_DIR}/include
RPATH=g -Wl,-rpath,${HELIB_LIB}
endif

LDFLAGS=${RPATH} ${HELIB_LIB}/libhelib.a ${HELIB_LIB}/libntl.so ${HELIB_LIB}/libgmp.so -lpthread
CPPFLAGS=-g -DHELIB_BOOT_THREADS -DHELIB_THREADS ${ISYSTEM} -std=c++17
#LDFLAGS=-g -L ${HELIB_LIB} -lhelib -lntl -lgmp


#OBJS=SHEKey.o SHEInt.o
OBJS=SHEio.o SHEContext.o SHEKey.o SHEInt.o SHEFp.o SHEMath.o
LIB=libSHELib.a
PROG=SHETest SHEPerf SHEEval
INCLUDE=SHEInt.h SHEKey.h SHEContext.h SHEMagic.h SHEio.h SHEVector.h SHEFp.h SHEConfig.h

all: ${LIB} ${PROG}

clean:
	rm -rf ${LIB} ${OBJS} ${PROG}

install: ${LIB} ${PROG}
	mkdir -p ${DESTDIR}/${HELIB_LIB}
	mkdir -p ${DESTDIR}/usr/bin
	mkdir -p ${DESTDIR}/usr/include/SHELib
	install -c -m 0644 ${LIB} ${DESTDIR}/${HELIB_LIB}
	install -c -m 0755 ${PROG} ${DESTDIR}/usr/bin
	install -c -m 0644 ${INCLUDE} ${DESTDIR}/usr/include/SHELib

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
