##
# Project Title
#
# @file
# @version 0.1

CC=g++
FILES=disasm_scalar16.o disasm_scalar32.o disasm_scalar48.o driver.o

all: ${FILES}
	g++ -o disasm_test ${FILES}

# end
