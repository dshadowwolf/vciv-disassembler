#include "disasm_vector48.hpp"
#include "vc4_data.hpp"

using namespace std;

namespace disasm {
    namespace vector48 {
        vector48_insn *vector48memory(uint64_t insn) {
            string acc_ops[] = { "ns", "s32", "nop", "s16" };
            uint8_t w = ((insn >> 34) & 0x03);
            string mop(vector_ops_48[((insn >> 36) & 0x1f)]);
            string width(mop==48?acc_ops[w]:vector_widths[w]);
            string opc("v");
            opc += mop;
            opc += ".";
            opc += width;

            string rsd = vector_rs[(insn >> 31) & 0x07];
            string dreg = disasm::vector::decode_vector_register((insn >> 21) & 0x03ff);
            string areg = disasm::vector::decode_vector_register((insn >> 11) & 0x03ff);
            // temporarily (in lieu of doing a variant data type for vc4_parameter)
            // we are doing the vector registers encoded directly in the opcode
            opc += " " + dreg + rsd + ", " + areg + rsd;
            
            uint8_t has_p = (insn >> 10) & 1;
            uint8_t pf = (insn >> 7) & 7;

            string flags;

            if ((insn >> 6) & 1) flags += " SETF";
            if (has_p) flags += " " + vector_flags_w[pf];

            if (has_p) {
                opc += ", " + string(boost::format{"0x%04X"} % insn & 0x003f);
            } else if (pf == 7) {
                opc += ", r" + to_string(insn & 0x003f);
            }

            opc += flags;
            
            return new vector48_insn(opc);
        }
        
        vector48_insn *getInstruction(uint8_t *buffer) {
            // read the instruction and check the type
            // this should be possible by checking for
            // certain bit-patterns
            uint64_t insn = (uint16_t)(*((uint16_t *)buffer));
            insn <<= 32;
            uint16_t param_high = (uint16_t)(*((uint16_t *)(buffer+2)));
            uint16_t param_low = (uint16_t)(*((uint16_t *)(buffer+4)));
            uint32_t param = param_high;
            param <<= 16;
            param |= param_low;
            insn |= param;
            
            uint8_t op_class = insn >> 42;
            op_class &= 0x01; // though 2 bits are set aside for this
                              // only 1 of those bits is used

            if (op_class) return vector48data(insn);
            else return vector48memory(insn);
            
            assert("Code Should Not Hit This!");
            return NULL;
        }
    }
}
