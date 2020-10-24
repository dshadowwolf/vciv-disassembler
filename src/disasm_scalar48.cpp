#include <disasm_config.h>
#include <disasm_scalar48.hpp>
#include <vc4_data.hpp>
#include <vc4_parameter.hpp>

using namespace std;

namespace disasm {
    namespace scalar48 {
        scalar48_insn *get_simple(uint8_t chk, uint32_t insn, uint32_t param) {
            scalar48_insn *rv;
            vc4_parameter pp(ParameterTypes::IMMEDIATE, (uint32_t)(param));
            if (chk == 0) {
                string lops[][3] = { {"j", "{u}", "u" }, {"b", "$+{o}", "o" },
                                  {"jl", "{u}", "u"}, {"bl", "$+{o}", "o"} };
                uint8_t ops = ((insn >> 8) | 0xfffc) & 0x0003;
                rv = new scalar48_insn(lops[ops][0], lops[ops][1]);
                rv->addParameter(lops[ops][2], pp);
                return rv;
            } else {
                string opname;
                string w;
                switch(((insn >> 8) | 0xfff8) & 0x0007) {
                    case 5:
                        do {
                            // this is the simplest of the complex "simples"
                            vc4_parameter d(ParameterTypes::REGISTER, (uint32_t)((insn | 0xffe0) & 0x001f));
                            rv = new scalar48_insn("add", "r{d}, pc, {o}");
                            rv->addParameter("d", d)->addParameter("o", pp);
                            return rv;
                        } while(0);
                    case 6:
                        do {
                            // this is a load-store with register-relative
                            // addressing and a limited width on the parameter
                            // as it steals some bits to encode the source
                            // and destination
                            vc4_parameter d(ParameterTypes::REGISTER, (uint32_t)((insn | 0xffe0) & 0x001f));
                            vc4_parameter s(ParameterTypes::REGISTER, (uint32_t)(((param >> 27) | 0xffffffe0) & 0x0000001f));
                            vc4_parameter o(ParameterTypes::IMMEDIATE, (uint32_t)((param | 0xe0000000) & 0x1fffffff));
                            string w(mem_op_widths[((insn >> 6) | 0xfffffffc) & 3]);
                            uint8_t b = ((insn >> 5) | 0xfffffffe) & 0x00000001;
                            string opc(b?"st":"ld");
                            opc += w;
                            rv = new scalar48_insn(opc, "r{d}, (r{s}+{o})");
                            rv->addParameter("d", d)->addParameter("s", s)
                                ->addParameter("o", o);
                            return rv;
                        } while(0);
                    case 7:
                        do {
                            vc4_parameter d(ParameterTypes::REGISTER, (uint32_t)((insn | 0xffe0) & 0x001f));
                            vc4_parameter o(ParameterTypes::IMMEDIATE, (uint32_t)((param | 0xe0000000) & 0x1fffffff));
                            string w(mem_op_widths[((insn >> 6) | 0xfffffffc) & 3]);
                            uint8_t b = ((insn >> 5) | 0xfffffffe) & 0x00000001;
                            string opc(b?"st":"ld");
                            opc += w;
                            rv = new scalar48_insn(opc, "r{d}, (pc+{o})");
                            rv->addParameter("d", d)->addParameter("o", o);
                            return rv;
                        } while(0);
                    default:
                        assert("Code that should never run!");
                        return NULL;
                }
            }
            assert("This code should never run!");
            return NULL;
        }
        
        scalar48_insn *get_oper(uint32_t insn, uint32_t param) {
            vc4_parameter u(ParameterTypes::IMMEDIATE, (uint32_t)(param));
            vc4_parameter d(ParameterTypes::REGISTER, (uint32_t)((insn | 0xffe0) & 0x001f));
            uint8_t oper = ((insn >> 5) | 0xffe0) & 0x001f;
            string opcode(al_ops[oper]);

            scalar48_insn *rv = new scalar48_insn(opcode, "r{d}, {u}");
            rv->addParameter("d", d)->addParameter("u", u);
            return rv;
        }
        
        scalar48_insn *getInstruction(uint8_t *buffer) {
            // SCALAR48 is a little-endian 16 bit word followed by
            // a little-endian 32-bit word and not a series of 16 bit
            // little endian words
            uint16_t insn = READ_WORD(buffer);
            uint32_t insn_arg = READ_DWORD_X(buffer+2);

            uint32_t check = (insn >> 10) & 0x000003;
            switch (check) {
                case 0:
                case 1:
                    return get_simple(check, insn, insn_arg);
                case 2:
                    return get_oper(insn, insn_arg);
                case 3:
                    do {
                        vc4_parameter d(ParameterTypes::REGISTER, (uint32_t)((insn | 0xffe0) & 0x001f));
                        vc4_parameter s(ParameterTypes::REGISTER,
                                        (uint32_t)(((insn >> 5) | 0xffe0) & 0x001f));
                        vc4_parameter u(ParameterTypes::IMMEDIATE, (uint32_t)(insn_arg));
                        scalar48_insn *rv = new scalar48_insn("add", "r{d}, " \
                                                              "r{s}, {u}");
                        rv->addParameter("d", d)->addParameter("s", s)
                            ->addParameter("u", u);
                        return rv;
                    } while(0);
                default:
                    assert("This code should never run!");
                    return NULL;
            }
            assert("This code should never run!");
            return NULL;
        }
    }
}
