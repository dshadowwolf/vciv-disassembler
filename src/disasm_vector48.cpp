#include "disasm_vector48.hpp"
#include "vc4_data.hpp"
#include "vector_helpers.hpp"

using namespace std;

namespace disasm {
    namespace vector48 {
        vector48_insn *vector48memory(uint64_t insn) {
            uint8_t w = ((insn >> 35) & 0x03);
            uint8_t check = ((insn >> 37) & 0x1f);
            string mop(vector_ops_48[check]);
            string width(check==24?"":vector_widths[w]);
            string opc("v");
            opc += width;
            opc += mop;

            string dest_register = disasm::vector::decode_vector_register((insn >> 22) & 0x03ff);
            string source_register_a = disasm::vector::decode_vector_register((insn >> 12) & 0x03ff);
            
            bool has_p = ((insn >> 10) & 1) == 1;
            bool pf = ((insn >> 7) & 7) == 7;

            string flags;
            uint8_t p;

            if (((insn >> 6) & 1) && (has_p || (((insn >> 7) & 7) == 7))) flags += " SETF";
            
            if (has_p) flags += " " + vector_flags_w[pf];

            if (has_p) {
                p = (insn & 0x003f);
            }

            vc4_parameter d(ParameterTypes::VECTOR_REGISTER, dest_register);
            vc4_parameter a(ParameterTypes::VECTOR_REGISTER, source_register_a);
            vc4_parameter o(ParameterTypes::ERROR, 0);
            
            if (has_p)
                o = vc4_parameter(ParameterTypes::IMMEDIATE, (uint32_t)(insn & 0x0000003f));
            else if(pf)
                o = vc4_parameter(ParameterTypes::REGISTER, (uint32_t)(insn & 0x0000003f));
            else
                o = vc4_parameter(ParameterTypes::VECTOR_REGISTER, disasm::vector::decode_vector_register(insn & 0x000003ff));

            uint8_t rs = ((insn & 0x000007000000) >> 32);
            string fmt;
            if (rs > 0)
                fmt = string("{d}+r{s}") + (source_register_a == "DISCARD-IGNORE" ? "" : ", {a}+r{s}");
            else
                fmt = string("{d}") + (source_register_a == "DISCARD-IGNORE" ? "" : ", {a}");//+", {o} {flags}";

            if (has_p) {
                fmt += ", {o}";
            } else if(pf) {
                fmt += ", (r{o})";
            } else if (!has_p && !pf) {
                if (rs > 0) fmt += ", {o}+r{s}";
                else fmt += ", {o}";
            }

            fmt += " {flags}";

            vc4_parameter flag_p(ParameterTypes::DATA, flags);
            vector48_insn *rv = new vector48_insn(opc, fmt);
            rv->addParameter("d", d)->addParameter("a", a)
                ->addParameter("o", o)
                ->addParameter("flags", flag_p)
                ->addParameter("s", vc4_parameter(ParameterTypes::IMMEDIATE, (uint32_t)(rs)));
            
            return rv;
        }

        vector48_insn *vector48data(uint64_t insn) {
            uint8_t opc = ((insn >> 35) & 0x3f);
            string vop(vector_ops_full[opc]);
            bool X = !!((insn >> 41) & 0x01);
            if (opc < 48) vop += (X?".h":".l");
            else if (X) {
                vop = std::string(vector48_alts[opc - 48]);
            }

            string dr(disasm::vector::decode_vector_register((insn >> 22) & 0x000000000000000003ff ));
            string ar(disasm::vector::decode_vector_register((insn >> 12) & 0x000000000000000003ff ));
            string flags;
            
            vc4_parameter d(ParameterTypes::VECTOR_REGISTER, dr);
            vc4_parameter a(ParameterTypes::VECTOR_REGISTER, ar);
            vc4_parameter o(ParameterTypes::ERROR, 0);
            
            if (insn >> 7 & 0x00000007) {
                if ( (insn >> 6) & 1 ) flags += "SETF";
                o = vc4_parameter(ParameterTypes::REGISTER, (uint32_t)(insn & 0x3f));
            } else if((insn >> 10) & 1) {
                if ( (insn >> 6) & 1 ) flags += "SETF";
                flags += " " + vector_flags_w[(insn >> 7) & 7];
                o = vc4_parameter(ParameterTypes::IMMEDIATE, (uint32_t)(insn & 0x3f));
            } else {
                o = vc4_parameter(ParameterTypes::VECTOR_REGISTER, disasm::vector::decode_vector_register(insn & 0x000003ff));
            }

            uint8_t rsd = ((insn & 0x000007000000) >> 32);

            string fmt;
            if (rsd > 0)
                fmt = "{d}+r{s}, {a}+r{s}, {o} {flags}";
            else
                fmt = "{d}, {a}, {o} {flags}";
            vc4_parameter flag_p(ParameterTypes::DATA, flags);
            vector48_insn *rv = new vector48_insn(vop, fmt);
            rv->addParameter("d", d)->addParameter("a", a)
                ->addParameter("o", o)
                ->addParameter("flags", vc4_parameter(ParameterTypes::DATA, flags))
                ->addParameter("s", vc4_parameter(ParameterTypes::IMMEDIATE, (uint32_t)(rsd)));
            
            return rv;
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
