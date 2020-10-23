#include <disasm_config.h>
#include "disasm_scalar32.hpp"
#include "vc4_data.hpp"
#include "vc4_parameter.hpp"

using namespace std;

namespace disasm {
    namespace scalar32 {
        scalar32_insn *addCmpBr(uint32_t insn) {
            uint8_t cc_raw = insn & 0x0F000000 >> 24;
            uint8_t type = insn & 0x0000C000 >> 14;
            string cc(condition_codes[cc_raw]);
            scalar32_insn *rv;
            switch( type ) {
                case 0:
                    do {
                        rv = new scalar32_insn(string("addcmpb")+cc,
                                               "r{d}, r{a}, r{s}, $+({o}*2)");
                        vc4_parameter d0(ParameterTypes::REGISTER, (uint32_t)((insn >> 16) & 0x0000000f));
                        vc4_parameter a0(ParameterTypes::REGISTER, (uint32_t)((insn >> 16) & 0x000000f0));
                        vc4_parameter s0(ParameterTypes::REGISTER, (uint32_t)((insn >> 10) & 0x0000000f));
                        vc4_parameter o0(ParameterTypes::IMMEDIATE, (uint32_t)(insn & 0x000003ff));
                        rv->addParameter("d", d0)->addParameter("a", a0)
                            ->addParameter("s", s0)->addParameter("o", o0);
                    } while(0);
                    break;
                case 1:
                    do {
                        rv = new scalar32_insn(string("addcmpb")+cc,
                                               "r{d}, {i}, r{s}, $+({o}*2)");
                        vc4_parameter d1(ParameterTypes::REGISTER, (uint32_t)((insn >> 16) & 0x0000000f));
                        vc4_parameter i0(ParameterTypes::REGISTER, (uint32_t)((insn >> 16) & 0x000000f0));
                        vc4_parameter s1(ParameterTypes::REGISTER, (uint32_t)((insn >> 10) & 0x0000000f));
                        vc4_parameter o1(ParameterTypes::IMMEDIATE, (uint32_t)(insn & 0x000003ff));
                        rv->addParameter("d", d1)->addParameter("i", i0)
                            ->addParameter("s", s1)->addParameter("o", o1);
                    } while(0);
                    break;
                case 2:
                    do {
                        rv = new scalar32_insn(string("addcmpb")+cc,
                                               "r{d}, r{a}, {u}, $+({o}*2)");
                        vc4_parameter d2(ParameterTypes::REGISTER, (uint32_t)((insn >> 16) & 0x0000000f));
                        vc4_parameter a1(ParameterTypes::REGISTER, (uint32_t)((insn >> 16) & 0x000000f0));
                        vc4_parameter u0(ParameterTypes::REGISTER, (uint32_t)((insn >> 8) & 0x0000003f));
                        vc4_parameter o2(ParameterTypes::IMMEDIATE, (uint32_t)(insn & 0x000000ff));
                        rv->addParameter("d", d2)->addParameter("a", a1)
                            ->addParameter("u", u0)->addParameter("o", o2);
                    } while(0);
                    break;
                case 3:
                    do {
                        rv = new scalar32_insn(string("addcmpb")+cc,
                                               "r{d}, {i}, {u}, $+({o}*2)");
                        vc4_parameter d3(ParameterTypes::REGISTER, (uint32_t)((insn >> 16) & 0x0000000f));
                        vc4_parameter i1(ParameterTypes::REGISTER, (uint32_t)((insn >> 16) & 0x000000f0));
                        vc4_parameter u1(ParameterTypes::REGISTER, (uint32_t)((insn >> 8) & 0x0000003f));
                        vc4_parameter o3(ParameterTypes::IMMEDIATE, (uint32_t)(insn & 0x000000ff));
                        rv->addParameter("d", d3)->addParameter("i", i1)
                            ->addParameter("u", u1)->addParameter("o", o3);
                    } while(0);
                    break;
            }
            return rv;
        }

        scalar32_insn *branch(uint32_t insn) {
            scalar32_insn *rv;
            
            if (insn & 0x00800000) {
                rv = new scalar32_insn("bl", "$+({o}*2)");
                vc4_parameter o(ParameterTypes::IMMEDIATE, (uint32_t)(insn & 0x0fffffff));
                rv->addParameter("o", o);
            } else {
                uint8_t cc_raw = insn & 0x0F000000 >> 24;
                string cc(condition_codes[cc_raw]);
                rv = new scalar32_insn( string("b")+cc, "$+({o}*2)" );
                vc4_parameter o(ParameterTypes::IMMEDIATE, (uint32_t)(insn & 0x007fffff));
                rv->addParameter("o", o);
            }

            return rv;
        }

        scalar32_insn *condIndexed(uint32_t insn) {
            uint8_t sz = (uint8_t)((insn >> 22) & 0x00000003);
            string w(mem_op_widths[sz]);
            uint8_t cc_raw = (uint8_t)((insn >> 7) & 0x0000000f);
            string cc(condition_codes[cc_raw]);
            string op = ((insn >> 21) & 1)?"st":"ld";
            vc4_parameter b(ParameterTypes::REGISTER, (uint32_t)(insn & 0x0000001f));
            vc4_parameter a(ParameterTypes::REGISTER, (uint32_t)((insn >> 11) & 0x0000001f));
            vc4_parameter d(ParameterTypes::REGISTER, (uint32_t)((insn >> 16) & 0x0000001f));
            vc4_parameter ww(ParameterTypes::IMMEDIATE, (uint32_t)(sz));
            scalar32_insn *rv = new scalar32_insn(op+w+"."+cc,
                                                  "r{d}, (r{a} + r{b} << {w})");
            rv->addParameter("d", d)->addParameter("a", a)
                ->addParameter("b", b)->addParameter("w", ww);
            return rv;
        }

        scalar32_insn *__dMt(uint32_t insn) {
            uint8_t sz = (uint8_t)((insn >> 22) & 0x00000003);
            string w(mem_op_widths[sz]);
            string op = ((insn >> 21) & 1)?"st":"ld";
            scalar32_insn *rv = new scalar32_insn(op+w, "r{d}, (r{a}+{o})");
            vc4_parameter o(ParameterTypes::IMMEDIATE, (uint32_t)(insn & 0x000003ff));
            vc4_parameter a(ParameterTypes::REGISTER, (uint32_t)((insn >> 11) & 0x0000001f));
            vc4_parameter d(ParameterTypes::REGISTER, (uint32_t)((insn >> 16) & 0x0000001f));
            rv->addParameter("d", d)->addParameter("a", a)
                ->addParameter("o", o);
            return rv;
        }

        scalar32_insn * __dMx(uint32_t insn) {
            uint8_t sz = (uint8_t)((insn >> 22) & 0x00000003);
            string w(mem_op_widths[sz]);
            string op = ((insn >> 21) & 1)?"st":"ld";
            string fmt("r{d}, ");
            switch((insn >> 24) & 0x00000003) {
                case 0:
                    fmt += "(r24 + {o})";
                    break;
                case 1:
                    fmt += "(sp + {o})";
                    break;
                case 2:
                    fmt += "(pc + {o})";
                    break;
                case 3:
                    fmt += "(r0 + {o})";
                    break;
            }

            vc4_parameter d(ParameterTypes::REGISTER, (uint32_t)((insn >> 16) & 0x0000001f));
            vc4_parameter o(ParameterTypes::IMMEDIATE, (uint32_t)(insn & 0x0000ffff));
            scalar32_insn *rv = new scalar32_insn(op+w, fmt);
            rv->addParameter("d", d)->addParameter("o", o);
            return rv;
        }
        
        scalar32_insn *displacedMem(uint8_t size, uint32_t insn) {
            if (size == 12) return __dMt(insn);
            else return __dMx(insn);
        }

        scalar32_insn *condDecInc(uint8_t df, uint32_t insn) {
            uint8_t sz = (uint8_t)((insn >> 22) & 0x00000003);
            string w(mem_op_widths[sz]);
            string fd(df?"(r{a}++)":"(--r{a})");
            string op = ((insn >> 21) & 1)?"st":"ld";
            uint8_t cc_raw = (uint8_t)((insn >> 7) & 0x0000000f);
            string cc(condition_codes[cc_raw]);
            string opcode(op+w+"."+cc);
            string format("r{d}, ");
            format += fd;
            vc4_parameter a(ParameterTypes::REGISTER, (uint32_t)((insn >> 11) & 0x0000001f));
            vc4_parameter d(ParameterTypes::REGISTER, (uint32_t)((insn >> 16) & 0x0000001f));
            scalar32_insn *rv = new scalar32_insn(opcode, format);
            rv->addParameter("d", d)->addParameter("a", a);
            return rv;
        }

        scalar32_insn *alu_raw(uint32_t insn) {
            uint8_t vv = (insn >> 24) & 0x0000000f;
            string fmt;
            string op;

            if( (vv >> 2) > 0 ) {
                op = "add";
                if( vv == 15 ) fmt = "r{d}, pc, {o}";
                else fmt = "r{d}, r{s}, {o}";
            } else {
                op = al_ops[(insn >> 21) & 0x0000001f];
                fmt = "r{d}, {o}";
            }

            vc4_parameter o(ParameterTypes::IMMEDIATE, (uint32_t)(insn & 0x0000ffff));
            vc4_parameter d(ParameterTypes::REGISTER, (uint32_t)((insn >> 16) & 0x0000001f));
            vc4_parameter s(ParameterTypes::REGISTER, (uint32_t)((insn >> 21) & 0x0000001f));
            scalar32_insn *rv = new scalar32_insn(op, fmt);
            rv->addParameter("o", o)->addParameter("d", d)
                ->addParameter("s", s);
            return rv;
        }

        scalar32_insn *alu_cond(uint32_t insn) {
            uint8_t is_five = !((insn >> 6) & 0x00000001);
            uint8_t operation = (insn >> 21) & 0x0000003f;
            uint8_t param;
            string fmt("r{d}, r{a}, ");
            string n;
            ParameterTypes pt = ParameterTypes::ERROR;
            
            if (is_five) {
                param = insn & 0x0000003f;
                fmt += "{i}";
                n = "i";
                pt = ParameterTypes::IMMEDIATE;
            } else {
                param = insn & 0x0000003f;
                fmt += "r{b}";
                n = "b";
                pt = ParameterTypes::REGISTER;
            }
            
            uint8_t cc_raw = (uint8_t)((insn >> 7) & 0x0000000f);
            string cc(condition_codes[cc_raw]);

            vc4_parameter a(ParameterTypes::REGISTER, (uint32_t)((insn >> 11) & 0x0000001f ));
            vc4_parameter d(ParameterTypes::REGISTER, (uint32_t)((insn >> 16) & 0x0000001f ));
            vc4_parameter pr(pt, param);
            
            scalar32_insn *rv = new scalar32_insn(al_ops[operation], fmt);
            rv->addParameter("a", a)->addParameter("d", d)
                ->addParameter(n, pr);
            return NULL;
        }

        scalar32_insn *__fB(uint32_t insn) {
            uint8_t op   = (insn >> 21) & 0x0000000f;
            uint8_t cc_r = (insn >> 7 ) & 0x0000000f;
            uint8_t a    = (insn >> 11) & 0x0000001f;
            uint8_t d    = (insn >> 16) & 0x0000001f;
            bool is_five = !((insn >> 6) & 1);
            uint8_t param;
            ParameterTypes pt = ParameterTypes::ERROR;
            string pn;
            string fmt("r{d}, r{a}, ");
            
            if (is_five) {
                param = insn & 0x0000001f;
                pt = ParameterTypes::REGISTER;
                fmt += "r{b}";
                pn = "b";
            } else {
                param = insn & 0x0000003f;
                pt = ParameterTypes::IMMEDIATE;
                fmt += "{i}";
                pn = "i";
            }

            string cc(condition_codes[cc_r]);
            string opc(float_ops[op]);
            scalar32_insn *rv = new scalar32_insn(opc, fmt);
            rv->addParameter("a", vc4_parameter(ParameterTypes::REGISTER, a))
                ->addParameter("d", vc4_parameter(ParameterTypes::REGISTER, d))
                ->addParameter(pn, vc4_parameter(pt, param));
            return rv;
        }

        scalar32_insn *__fI(uint32_t insn) {
            string dd[] = { "ftrunc", "floor", "flts", "fltu" };
            uint8_t op   = (insn >> 21) & 0x00000003;
            uint8_t cc_r = (insn >> 7 ) & 0x0000000f;
            string cc(condition_codes[cc_r]);
            uint8_t a    = (insn >> 11) & 0x0000001f;
            uint8_t d    = (insn >> 16) & 0x0000001f;
            bool is_five = !((insn >> 6) & 1);
            uint8_t param;
            ParameterTypes pt = ParameterTypes::ERROR;
            string pn;
            string fmt("r{d}, r{a}, ");
            string opc(dd[op]);

            if (op < 2) fmt += "sasl ";
            else fmt += "sasr ";
            
            if (is_five) {
                param = insn & 0x0000001f;
                pt = ParameterTypes::REGISTER;
                fmt += "r{b}";
                pn = "b";
            } else {
                param = insn & 0x0000003f;
                pt = ParameterTypes::IMMEDIATE;
                fmt += "{i}";
                pn = "i";
            }

            scalar32_insn *rv = new scalar32_insn(opc, fmt);
            rv->addParameter("a", vc4_parameter(ParameterTypes::REGISTER, a))
                ->addParameter("d", vc4_parameter(ParameterTypes::REGISTER, d))
                ->addParameter(pn, vc4_parameter(pt, param));
            return rv;
        }

        scalar32_insn *controlReg(uint32_t insn) {
            string fmt = ((insn >> 21) & 1)?"r{d}, p{a}":"p{d}, r{a}";
            vc4_parameter a(ParameterTypes::REGISTER, (uint32_t)(insn & 0x0000001f));
            vc4_parameter d(ParameterTypes::REGISTER, (uint32_t)((insn >> 16) & 0x0000001f));
            scalar32_insn *rv = new scalar32_insn("mov", fmt);
            rv->addParameter("a", a)->addParameter("d", d);
            return rv;
        }
        
        scalar32_insn *floatOp(uint32_t insn) {
            // top 3 bits of the bottom nibble of the most signficant byte indicates whether this is a pure float op or an integer conversion
            uint8_t typ = (insn >> 25) & 0x00000007;
            switch(typ) {
                case 4:
                    return __fB(insn);
                case 5:
                    return __fI(insn);
                case 6:
                    return controlReg(insn);
                default:
                    assert("Code Should Not Hit This!");
                    return NULL;
            }
        }
        
        scalar32_insn *getInstruction(uint8_t *buffer) {
            // read the instruction and check the type
            // this should be possible by checking for
            // certain bit-patterns
            uint32_t insn_raw = READ_DWORD(buffer);
            uint8_t insn_type = insn_raw >> 28 & 0x03;

            switch( insn_type ) {
                case 0:
                    return addCmpBr(insn_raw);
                case 1:
                    return branch(insn_raw);
                case 2:
                    do {
                        switch(((insn_raw >> 24) & 0x0f) >> 1) {
                            case 0:
                                return condIndexed(insn_raw);
                            case 1:
                                return displacedMem(12, insn_raw);
                            case 2:
                                return condDecInc((uint8_t)((insn_raw >> 24) & 0x01), insn_raw);
                            case 3:
                                return displacedMem(16, insn_raw);
                        }
                    } while(0); // nice trick Linus - thanks for teaching it to me
                    break;
                case 3:
                    return alu_raw(insn_raw);
                case 4:
                    if ( insn_raw >> 24 & 0x08 ) return floatOp(insn_raw);
                    return alu_cond(insn_raw);
                default:
                    assert("Code Should Not Hit This!");
                    return NULL;
            }
            assert("Code Should Not Hit This!");
            return NULL;
        }
    }
}
