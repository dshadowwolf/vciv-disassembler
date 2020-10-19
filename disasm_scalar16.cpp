#include "disasm_scalar16.hpp"
#include "vc4_data.h"

using namespace std;

namespace disasm {
    scalar16_insn *getSimpleInsn(uint16_t insn) {
        scalar16_insn *rv;
        string noargs[] = { "bkpt", "nop", "sleep", "user", "ei", "di", "cbclr",
                            "cbadd1", "cbadd2", "cbadd3", "rti" };
        if (insn <= 10) rv = new scalar16_insn(noargs[insn], "");
        else if (((insn & 0x0020) && !(insn & 0x0040))) {
            rv = new scalar16_insn("swi", "r{d}");
            vc4_parameter p(REGISTER, insn & 0x001f);
            rv->addParameter("d", p);
        } else if ((insn & 0x0040)) {
            vc4_parameter p(REGISTER, insn & 0x001f);
            if (insn & 0x0020) rv = new scalar16_insn("bl", "r{d}");
            else rv = new scalar16_insn("b", "r{d}");
            rv->addParameter("d", p);
        } else if ((insn & 0x0080) && !(insn & 0x0040)) {
            vc4_parameter p(REGISTER, insn & 0x000F);
            if (insn & 0x0020) rv = new scalar16_insn("switch.b", "r{d}");
            else rv = new scalar16_insn("switch", "r{d}");
            rv->addParameter("d", p);
        } else if ((insn & 0x00D0)) {
            vc4_parameter p(REGISTER, insn & 0x001f);
            rv = new scalar16_insn("version", "r{d}");
            rv->addParameter("d", p);
        } else {
            vc4_parameter p(IMMEDIATE, insn & 0x003f);
            rv = new scalar16_insn("swi", "{u}");
            rv->addParameter("u", p);
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
                uint8_t f = insn&0x0080;
                string name(f?"stm":"ldm");
                string fmt(insn&0x0100?
                           (f?"r{b}-r{m},lr,(--sp)":f?"r{b}-r{m},lr,(sp++)"):
                           (f?"r{b}-r{m},(--sp)":f?"r{b}-r{m},(sp++)"));
                rv = new scalar16_insn(name, fmt);
                rv->addParameter("b", b)->addParameter("m", m);
            } else if((insn & 0x0400) & !(insn & 0x0800)) {
                vc4_parameter d(REGISTER, insn & 0x000F);
                vc4_parameter o(IMMEDIATE, (insn & 0x01F) >> 4);
                rv = new scalar16_insn(insn& 0x0200?"st":"ld", "r{d}, (sp+({o}*4))");
                rv->addParameter("d", d)->addParameter("o", o);
            } else {
                string widths[] = { "", "h", "b", "s"};
                string opcode(insn & 0x0100?"st":"ld");
                uint8_t w =(insn & 0x0600) >> 9;
                opcode.append(w==0?"":(string(".") + widths[w]));
                rv = new scalar16_insn(opcode, "r{d}, (r{s})");
                vc4_parameter s(REGISTER, (insn & 0x00F0) >> 4);
                vc4_parameter d(REGISTER, (insn & 0x000F));
                rv->addParameter("s", s)->addParameter("d", d);
            }
        } else {
            if (!(insn & 0x2000)) {
                if (insn & 0x0800) {
                    rv = new scalar16_insn("add", "r{d}, sp, {o}*4");
                    vc4_parameter d(REGISTER, insn & 0x001f);
                    vc4_parameter o(IMMEDIATE, (insn & 0x07e) >> 5);
                    rv->addParameter("d", d)->addParameter("o", o);
                } else {
                    uint8_t cc = (insn & 0x0780) >> 7;
                    string opcode("b.");
                    opcode += condition_codes[cc];
                    rv = new scalar16_insn(opcode, "$+{o}*2");
                    vc4_parameter o(IMMEDIATE, insn & 0x007f);
                    rv->addParameter("o", o);
                }
            } else {
                rv = new scalar16_insn((insn& 0x0100)?"st":"ld",
                                       "r{d}, r{s}+({u}*4)");
                vc4_parameter u(IMMEDIATE, (insn & 0x0F00) >> 8);
                vc4_parameter s(REGISTER, (insn & 0x00F0) >> 4);
                vc4_parameter d(REGISTER, (insn & 0x000F));
                rv->addParameter("u", u)
                    ->addParameter("s", s)
                    ->addParameter("d", d);
            }
        }

        return rv;
    }

#define FOUR_BIT(x) (al_ops[((x)&0x000f) << 1])
#define FIVE_BIT(x) (al_ops[((x)&0x001f)])
    
    scalar16_insn *getALRR(uint16_t insn) {
        uint8_t dc = (insn & 0x1f00) >> 8;
        string fmt("r{d}, r{s}");
        string add;
        if( dc == 19 ) add = " << 1";
        else if( dc > 20 && dc < 24 ) add = string(" << ") + std::to_string(dc - 19);
        if (add.length() > 0) fmt += add;
        
        scalar16_insn *rv = new scalar16_insn(FIVE_BIT((insn & 0x1F00) >> 8), fmt);
        vc4_parameter d(REGISTER, insn & 0x000F);
        vc4_parameter s(REGISTER, (insn & 0x00F0) >> 4);
        rv->addParameter("d", d)->addParameter("s", s);
        return rv;
    }

    scalar16_insn *getALRI(uint16_t insn) {
        uint8_t dc = (insn & 0x1e00) >> 8;
        scalar16_insn *rv = new scalar16_insn(FOUR_BIT(dc), dc==11?"r{d}, r{a} << 3");
        vc4_parameter d(REGISTER, insn & 0x000F);
        vc4_parameter u(IMMEDIATE, (insn & 0x01F0) >> 4);
        rv->addParameter("d", d)->addParameter("u", u);
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
