#include <disasm_config.h>
#include <disasm_scalar16.hpp>
#include <disasm_scalar32.hpp>
#include <disasm_scalar48.hpp>
#include <disasm_vector48.hpp>
#include <disasm_vector80.hpp>
#include <disasm_insn_raw.hpp>

#include <vector>

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <cstdint>
#include <cstdio>

#include <iostream>

#include <boost/format.hpp>

using namespace std;

namespace disasm {
	namespace scalar16 {
		extern scalar16_insn *getInstruction(uint8_t *);
	}
	namespace scalar32 {
		extern scalar32_insn *getInstruction(uint8_t *);
	}
	namespace scalar48 {
		extern scalar48_insn *getInstruction(uint8_t *);
	}
	namespace vector48 {
		extern vector48_insn *getInstruction(uint8_t *);
	}
	namespace vector80 {
		extern vector80_insn *getInstruction(uint8_t *);
	}
}

unsigned char reverse(unsigned char b) {
	b = (b & 0xF0) >> 4 | (b & 0x0F) << 4;
	b = (b & 0xCC) >> 2 | (b & 0x33) << 2;
	b = (b & 0xAA) >> 1 | (b & 0x55) << 1;
	return b;
}

int main(int argc, char *argv[]) {
	struct stat st;
	uint8_t *buffer;
	uint8_t *work;

	int fd;
	vector<disasm::vc4_insn> instructions;

	std::cout << "Wolfs VC-IV Disassembler version " << VCIV_VERSION << std::endl;
	std::cout << "(c) 2020 Daniel \"DShadowWolf\" Hazelton <dshadowwolf@gmailcom>" << std::endl;

	const std::vector<std::string> usage = { "\n", "\tUSAGE:", (boost::format { "\t\t%s <binary file name>" } % argv[0]).str(), "\n" };

	if (argc < 2 || argc > 2) {
		for(auto line : usage) std::cout << line << std::endl;

		return -2;
	}

	if (stat(argv[1], &st) != 0) {
		perror("stat: ");
		return -1;
	}

	fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		perror("open: ");
		return fd;
	}

	buffer = new uint8_t[st.st_size];
	work = buffer;

	ssize_t d = read(fd, buffer, st.st_size);
	if ( d < 0 ) {
		perror("read: ");
		close(fd);
		return -1;
	}

	close(fd);

	while (work - buffer < st.st_size) {
		disasm::vc4_insn *ci;
		uint16_t insn_raw = READ_WORD(work);
		uint8_t qsz = (((uint8_t)(insn_raw >> 8)) & 0xf8) >> 3;
		uint8_t ssz;

		if ( qsz < 16 ) ci = disasm::scalar16::getInstruction(work);
		else if ( qsz >= 16 && qsz < 28 ) ci = disasm::scalar32::getInstruction(work);
		else if ( qsz >= 28 && qsz < 30 ) ci = disasm::scalar48::getInstruction(work);
		else if ( qsz == 30 ) ci = disasm::vector48::getInstruction(work);
		else if ( qsz == 31 ) ci = disasm::vector80::getInstruction(work);
		else { std::cerr << "bad size " << std::bitset<5>(qsz) << "!!!" << std::endl; abort(); }

		if (ci != NULL) {
			ssz = (ci->getReadable()=="*unknown*")?2:ci->getSizeBytes();
			instructions.push_back(*ci);
		} else {
			ssz = 10;
		}

		work += ssz;
	}

	uint32_t addr;
	for ( auto it = instructions.begin(); it != instructions.end(); it++ ) {
		disasm::vc4_insn curr = *it;

		std::cout << (boost::format { "0x%08X" } % addr ).str() << "\t" << curr.toString() << std::endl;
		addr += (curr.getReadable()=="*unknown*")?2:curr.getSizeBytes();
	}
}
