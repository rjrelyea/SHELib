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
RPATH=-Wl,-rpath,${HELIB_LIB}
endif

ifndef TARGET_INCLUDE
TARGET_INCLUDE=/usr/include
endif

ifndef TARGET_LIB
TARGET_LIB=/usr/lib64
endif

ifndef TARGET_BIN
TARGET_BIN=/usr/bin
endif

ifndef TARGET_MAN
TARGET_BIN=/usr/share/man
endif

ifndef TARGET_DOC
TARGET_BIN=/usr/share/doc
endif

ifndef VERSION
VERSION=0.0
endif

LDFLAGS=-g ${RPATH} ${HELIB_LIB}/libhelib.a ${HELIB_LIB}/libntl.so ${HELIB_LIB}/libgmp.so -lpthread
CPPFLAGS=-g -DHELIB_BOOT_THREADS -DHELIB_THREADS ${ISYSTEM} -std=c++17
#LDFLAGS=-g -L ${HELIB_LIB} -lhelib -lntl -lgmp


#OBJS=SHEio.o SHEContext.o SHEKey.o SHEInt.o SHEFp.o SHEString.o SHEMath.o
OBJS=SHEio.o SHEContext.o SHEKey.o SHEInt.o SHEFp.o SHEMath.o
LIB=libSHELib.a
PROG=SHETest SHEPerf SHEEval SHEMathTest
#INCLUDE=SHEInt.h SHEKey.h SHEContext.h SHEMagic.h SHEio.h SHEVector.h SHEFp.h SHEString.h SHEConfig.h helibio.h
INCLUDE=SHEInt.h SHEKey.h SHEContext.h SHEMagic.h SHEio.h SHEVector.h SHEFp.h SHEConfig.h helibio.h
BUILD=SHELib.pc
MANPAGES=SHELib.3
HTMLPAGES=SHELib.html
DOCS=${MANPAGES} ${HTMLPAGES} ${HTMLPAGES:%.html=%.xml}

.SUFFIXES: .odt .html .xml .3

all: ${LIB} ${PROG} ${BUILD} ${MANPAGES} ${HTMLPAGES}

nodoc: ${LIB} ${PROG} ${BUILD}

clean:
	rm -rf ${LIB} ${OBJS} ${PROG} ${BUILD} ${DOCS}

install: ${LIB} ${PROG} ${BUILD} ${MANPAGES} ${HTMLPAGES}
	mkdir -p ${DESTDIR}/${TARGET_LIB}
	mkdir -p ${DESTDIR}/${TARGET_BIN}
	mkdir -p ${DESTDIR}/${TARGET_LIB}/pkgconfig
	mkdir -p ${DESTDIR}/${TARGET_INCLUDE}/SHELib
	mkdir -p ${DESTDIR}/${TARGET_MAN}/man3
	mkdir -p ${DESTDIR}/${TARGET_DOC}/SHELib
	install -c -m 0644 ${LIB} ${DESTDIR}/${TARGET_LIB}
	install -c -m 0755 ${PROG} ${DESTDIR}/${TARGET_BIN}
	install -c -m 0644 ${INCLUDE} ${DESTDIR}/${TARGET_INCLUDE}/SHELib
	install -c -m 0644 SHELib.pc ${DESTDIR}/${TARGET_LIB}/pkgconfig
	install -c -m 0644 ${MANPAGES} ${DESTDIR}/${TARGET_MAN}/man3
	install -c -m 0644 ${HTMLPAGES} ${DESTDIR}/${TARGET_DOC}/SHELib

install-nodoc: ${LIB} ${PROG} ${BUILD}
	mkdir -p ${DESTDIR}/${TARGET_LIB}
	mkdir -p ${DESTDIR}/${TARGET_BIN}
	mkdir -p ${DESTDIR}/${TARGET_LIB}/pkgconfig
	mkdir -p ${DESTDIR}/${TARGET_INCLUDE}/SHELib
	install -c -m 0644 ${LIB} ${DESTDIR}/${TARGET_LIB}
	install -c -m 0755 ${PROG} ${DESTDIR}/${TARGET_BIN}
	install -c -m 0644 ${INCLUDE} ${DESTDIR}/${TARGET_INCLUDE}/SHELib
	install -c -m 0644 SHELib.pc ${DESTDIR}/${TARGET_LIB}/pkgconfig

SHELib.pc: SHELib.pc.in
	cat $< | sed -e "s,%%libdir%%,${TARGET_LIB},g" \
                     -e "s,%%includedir%%,${TARGET_INCLUDE}/HELib,g" \
                     -e "s,%%VERSION%%,${VERSION},g" \
	              > $@

libSHELib.a: ${OBJS}
	ar -r $@ $?

SHEMathTest: SHEMathTest.o ${LIB}
	g++ -o $@ $< ${LIB} ${LDFLAGS}

SHETest: SHETest.o ${LIB}
	g++ -o $@ $< ${LIB} ${LDFLAGS}

SHEPerf: SHEPerf.o ${LIB}
	g++ -o $@ $< ${LIB} ${LDFLAGS}

SHEEval: SHEEval.o ${LIB}
	g++ -o $@ $< ${LIB} ${LDFLAGS}

.cpp.o:
	g++ -g -c -o $@ ${CPPFLAGS} $<

.odt.xml:
	pandoc $< -t docbook -o $@

.xml.html:
	pandoc $< -t html -o $@

.xml.3:
	pandoc $< -t man -o $@

SHEContext.o: SHEContext.h
SHEMath.o: SHEInt.h SHEKey.h SHEMagic.h SHEio.h SHEFp.h SHEConfig.h SHEMath.h
SHEFp.o: SHEInt.h SHEKey.h SHEMagic.h SHEio.h SHEFp.h SHEConfig.h
SHEInt.o: SHEInt.h SHEKey.h SHEMagic.h SHEio.h SHEConfig.h
SHEKey.o: SHEKey.h SHEContext.h SHEMagic.h SHEio.h SHEConfig.h
SHEio.o: SHEio.h SHEConfig.h
SHETest.o: SHEInt.h SHEKey.h SHEContext.h SHEMagic.h SHEio.h SHEVector.h SHEFp.h SHEConfig.h
SHEPerf.o: SHEInt.h SHEKey.h SHEContext.h SHEMagic.h SHEio.h SHEConfig.h
SHEEval.o: SHEInt.h SHEKey.h SHEContext.h SHEMagic.h SHEio.h SHEConfig.h
