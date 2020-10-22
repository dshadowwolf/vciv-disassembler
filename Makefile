##
# Project Title
#
# @file
# @version 0.1

CC=g++
CFLAGS=--std=c++17
FILES=disasm_scalar16.o disasm_scalar32.o disasm_scalar48.o driver.o

.c.o:
	${CC} ${CFLAGS} -c -o $@ $<

.cpp.o:
	${CC} ${CFLAGS} -c -o $@ $<

all: ${FILES}
	g++ -o disasm_test ${FILES}

# end
