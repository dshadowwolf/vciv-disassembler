#include "disasm_scalar16.hpp"
#include "vc4_data.h"

using namespace std;

namespace disasm {
    scalar16_insn *getSimpleInsn(uint16_t insn) {
        scalar16_insn *rv;
        string noargs[] = { "bkpt", "nop", "sleep", "user", "ei", "di", "cbclr",
                            "cbadd1", "cbadd2", "cbadd3", "rti" };
        if (insn <= 10) rv = new scalar16_insn(noargs[insn]);
        else if (((insn & 0x0020) && !(insn & 0x0040))) {
            rv = new scalar16_insn("swi");
            vc4_parameter p(REGISTER, insn & 0x001f);
            rv->addParameter(p);
        } else if ((insn & 0x0040)) {
            vc4_parameter p(REGISTER, insn & 0x001f);
            if (insn & 0x0020) rv = new scalar16_insn("bl");
            else rv = new scalar16_insn("b");
            rv->addParameter(p);
        } else if ((insn & 0x0080) && !(insn & 0x0040)) {
            vc4_parameter p(REGISTER, insn & 0x000F);
            if (insn & 0x0020) rv = new scalar16_insn("switch.b");
            else rv = new scalar16_insn("switch");
            rv->addParameter(p);
        } else if ((insn & 0x00D0)) {
            vc4_parameter p(REGISTER, insn & 0x001f);
            rv = new scalar16_insn("version");
            rv->addParameter(p);
        } else {
            vc4_parameter p(IMMEDIATE, insn & 0x003f);
            rv = new scalar16_insn("swi");
            rv->addParameter(p);
        }
        
        return rv;
    }

    uint8_t which_b_reg(uint16_t insn) {
        uint8_t bb = (uint8_t)((insn & 0x0060) >> 4);
        return bb==0?0:(bb==1?6:(bb==2?16:24));
    }
    
    scalar16_insn *getMemoryOperation(uint16_t insn) {
        scalar16_insn *rv;

        if (!(insn & 0x1000 && insn & 0x2000)) {
            if ((insn & 0x0200) && !((insn & 0x0400) && (insn & 0x0800))) {
                vc4_parameter b(REGISTER, which_b_reg(insn));
                vc4_parameter m(REGISTER, insn & 0x001f);
                vc4_parameter lr(REGISTER, 26); // this is actually part of
                                                // the architecture!
                rv = new scalar16_insn(insn&0x0080?"stm":"ldm");
                rv->addParameter(b).addParameter(m);
                if ((insn & 0x0100)) {
                    rv->addParameter(lr);
                }
            } else if((insn & 0x0400) & !(insn & 0x0800)) {
                vc4_parameter d(REGISTER, insn & 0x000F);
                vc4_parameter o(IMMEDIATE, (insn & 0x01F) >> 4);
                rv = new scalar16_insn(insn& 0x0200?"st":"ld");
                rv->addParameter(d).addParameter(o);
            } else {
                string widths[] = { "", "h", "b", "s"};
                string opcode(insn & 0x0100?"st":"ld");
                opcode.append(widths[(insn & 0x0600) >> 9]);
                rv = new scalar16_insn(opcode);
                vc4_parameter s(REGISTER, (insn & 0x00F0) >> 4);
                vc4_parameter d(REGISTER, (insn & 0x000F));
                rv->addParameter(s).addParameter(d);
            }
        } else {
            if (!(insn & 0x2000)) {
                if (insn & 0x0800) {
                    rv = new scalar16_insn("add");
                    vc4_parameter d(REGISTER, insn & 0x001f);
                    vc4_parameter o(IMMEDIATE, (insn & 0x07e) >> 5);
                    rv->addParameter(d).addParameter(o);
                } else {
                    string codes[] = { "eq", "ne", "cs", "cc", "ns", "nc", "vs",
                                       "vc", "gt", "lte", "gte", "lt", "gt",
                                       "lte", "always", "never" };
                    uint8_t cc = (insn & 0x0780) >> 7;
                    rv = new scalar16_insn(string("b.").append(codes[cc]));
                    vc4_parameter o(IMMEDIATE, insn & 0x007f);
                    rv->addParameter(o);
                }
            } else {
                rv = new scalar16_insn((insn& 0x0100)?"st":"ld");
                vc4_parameter u(IMMEDIATE, (insn & 0x0F00) >> 8);
                vc4_parameter s(REGISTER, (insn & 0x00F0) >> 4);
                vc4_parameter d(REGISTER, (insn & 0x000F));
                rv->addParameter(u).addParameter(s).addParameter(d);
            }
        }

        return rv;
    }

#define FOUR_BIT(x) (al_ops[((x)&0x000f) << 1])
#define FIVE_BIT(x) (al_ops[((x)&0x001f)])
    
    scalar16_insn *getALRR(uint16_t insn) {
        scalar16_insn *rv = new scalar16_insn(FIVE_BIT((insn & 0x1F00) >> 8));
        vc4_parameter d(REGISTER, insn & 0x000F);
        vc4_parameter s(REGISTER, (insn & 0x00F0) >> 4);
        rv->addParameter(d).addParameter(s);
        return rv;
    }

    scalar16_insn *getALRI(uint16_t insn) {
        scalar16_insn *rv = new scalar16_insn(FOUR_BIT((insn & 0x1E00) >> 8));
        vc4_parameter d(REGISTER, insn & 0x000F);
        vc4_parameter u(IMMEDIATE, (insn & 0x01F0) >> 4);
        rv->addParameter(d).addParameter(u);
        return rv;
    }
#undef FOUR_BIT
#undef FIVE_BIT
    
    scalar16_insn *getArithLogical(uint16_t insn) {
        return insn&0x6000?getALRI(insn):getALRR(insn);
    }

    scalar16_insn *getInstruction(uint8_t *buffer) {
        // read the instruction and check the type
        // this should be possible by checking for
        // certain bit-patterns
        uint16_t insn_raw = (uint16_t)(*((uint16_t *)buffer));
        if ( (insn_raw & 0xFF00) == 0 ) return getSimpleInsn(insn_raw);
        else if ( (insn_raw & 0x4000) == 0 ) return getMemoryOperation(insn_raw);
        else return getArithLogical(insn_raw);
    }
}
