#include <disasm_config.h>
#include "disasm_scalar16.hpp"
#include "disasm_scalar32.hpp"
#include "disasm_scalar48.hpp"
#include "disasm_insn_raw.hpp"

#include <vector>

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <cstdint>
#include <cstdio>

#include <iostream>

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
}

unsigned char reverse(unsigned char b) {
   b = (b & 0xF0) >> 4 | (b & 0x0F) << 4;
   b = (b & 0xCC) >> 2 | (b & 0x33) << 2;
   b = (b & 0xAA) >> 1 | (b & 0x55) << 1;
   return b;
}

int main() {
    struct stat st;
    uint8_t *buffer, *work;
    int fd;
    vector<disasm::vc4_insn> instructions;

    std::cout << "Wolfs VC-IV Disassembler version " << VCIV_VERSION << std::endl;
    std::cout << "(c) 2020 Daniel \"DShadowWolf\" Hazelton <dshadowwolf@gmailcom>" << std::endl;
    
    if (stat("blinker01.bin", &st) != 0) {
        perror("stat: ");
        return -1;
    }
    
    fd = open("blinker01.bin", O_RDONLY);
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

    while (work - buffer < st.st_size) {
        disasm::vc4_insn *ci;
        uint16_t insn_raw = *((uint16_t *)work);
        uint8_t sz = reverse( (uint8_t)(insn_raw >> 8) ) & 0x1f;
        uint8_t ssz;
        
        if (!(sz & 1)) ci = disasm::scalar16::getInstruction(work);
        else if( (sz & 1) && !(sz & 2)) ci = disasm::scalar32::getInstruction(work);
        else if( (sz & 7) && !(sz & 8)) ci = disasm::scalar48::getInstruction(work);
        else std::cerr << "currently unhandled instruction size -- " << std::bitset<16>(*work) << " (" << std::bitset<8>(sz) << ") " << std::endl;

        if (ci != NULL) {
            ssz = ci->getSizeBytes();
            instructions.push_back(*ci);
        } else {
            ssz = (sz & 0x1f)?10:6;
        }

        work += ssz;
    }

    for ( auto it = instructions.begin(); it != instructions.end(); it++ ) {
        disasm::vc4_insn curr = *it;
        std::cout << curr.toString() << std::endl;
    }
}
