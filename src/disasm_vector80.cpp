#include <disasm_vector80.hpp>
#include <vc4_data.hpp>
#include <vector_helpers.hpp>


using namespace std;

namespace disasm {
  namespace vector80 {
    struct v80_dmap {
      uint16_t first;
			uint32_t mid;
			uint16_t trail;
			uint16_t end;

			v80_dmap(uint8_t *buff) {
				first = readWord(buff);
				mid = readDWord(buff + 2);
				trail = readWord(buff + 6);
				end = readWord(buff + 8);
			}
		};

    vector80_insn *vector80memory(v80_dmap insn) {
			// for memory operations, this is fixed encoding
			uint8_t rep = insn.first & 7;
			uint8_t width = (insn.first >> 3) & 3;
			uint8_t oper = (insn.first >> 5) & 0x1f;
			uint8_t p = (insn.end >> 13) & 7;
			uint8_t rax = insn.trail & 0x000f;
			uint8_t fa = (insn.trail >> 4) & 0x003f;
			uint8_t fd = (insn.trail >> 10) & 0x003f;
			string opname("v");
			opname += vector_widths[width];
			opname += vector_ops_full[oper];

			string reps(vector_reps[rep]);

			vector80_insn *rv;

			string G[] = { "", "*", "++ ", "*++ " };
			string D[] = { "H8(y,0)", "V8(0,0+x)", "H8(y,16)", "V8(y,16)", "H8(y,32)", "V8(0,32+x)",
				"H8(y,48)", "V8(0,48+x)", "H16(0+y,0)", "V16(0,0+x)", "H16(y,32)", "V16(y,32+x)",
				"H32(y,0)", "V32(0,0+x)", "-", "-d??" };
			string A[] = { "H8(y,0)", "V8(y,0)", "H8(y,16)", "V8(y,16)", "H8(y,32)", "V8(y,32)",
				"H8(y,48)", "V8(y,48)", "H16(0+y,0)", "V16(0,0+x)", "H16(y,32)", "V16(y,32+x)",
				"H32(y,0)", "V32(0,0+x)", "-", "-a??" };
			string B[] = { "H8(y,0)", "V8(y,0)", "H8(y,16)", "V8(y,16)", "H8(y,32)", "V8(y,32)",
				"H8(y,48)", "V8(y,48)", "H16(0+y,0)", "V16(0,0+x)", "H16(y,32)", "V16(y,32+x)",
				"H32(y,0)", "V32(0,0+x)", "-", "-b??" };
			string Z[] = { "H8(y,0)", "H8(y,16)", "H8(y,32)", "H8(y,48)", "H16(0+y,0)", "H16(y,32)", "H32(y,0)", "-" };
			string Y[] = { "V8(y,0)", "V8(y,16)", "V8(y,32)", "V8(y,48)", "V16(0+y,0)", "V16(y,32)", "V32(y,0)", "-" };

			if ( ((insn.mid >> 28) & 0xe) == 0xe ) {
				rv = new vector80_insn(opname, "-, {d}{G}{g}, {A}[y={a}, x={rax}]{H}{h}, {i}({s}+={f}) {R} {IF} {SETF}");

				uint8_t _r = (insn.trail >> 12) & 0xf;
				uint8_t _A = (insn.mid >> 18) & 0xf;
				uint8_t _h = (insn.trail >> 6) & 0xf;
				uint32_t _i = ((((insn.end >> 4) & 0x7f) << 2) & (insn.end & 3));
				bool _F = ((insn.mid >> 11) == 1);

				vc4_parameter rd(ParameterTypes::IMMEDIATE, (uint32_t)((insn.mid >> 26) & 0x3f));
				vc4_parameter _g(ParameterTypes::DATA, string(G[((insn.trail >> 10) & 3)]));
				vc4_parameter g_(ParameterTypes::DATA, _r<=14?(string("+r")+std::to_string(_r)):"");
				vc4_parameter A_(ParameterTypes::DATA, A[_A]);
				vc4_parameter a_(ParameterTypes::IMMEDIATE, (uint32_t)((insn.mid >> 12) & 0x3f));
				vc4_parameter ra_x(ParameterTypes::IMMEDIATE, (uint32_t)rax);
				vc4_parameter _H(ParameterTypes::DATA, H[(insn.trail >> 4) & 3]);
				vc4_parameter h(ParameterTypes::DATA, _h>=15?"":(string("+r")+std::to_string(_h)));
				vc4_parameter imm16(ParameterTypes::IMMEDIATE, (uint32_t)((_i << 7) | (insn.mid & 0x7f)));
				vc4_parameter s(ParameterTypes::REGISTER, (uint32_t)(((insn.end) >> 2) & 0xf));
				vc4_parameter f(ParameterTypes::REGISTER, (uint32_t)(((insn.trail) >> 12) & 0xf));
				vc4_parameter REP(ParameterTypes::DATA, reps);
				vc4_parameter IF(ParameterTypes::DATA, string(vector_flags_w[p+2]));
				vc4_parameter SETF(ParameterTypes::DATA, _F?"SETF":"");
				rv->addParameter("d", rd)->addParameter("G", _g)->addParameter("g", g_)
					->addParameter("A", A_)->addParameter("a", a_)->addParameter("rax", ra_x)
					->addParameter("H", _H)->addParameter("h", h)->addParameter("i", imm16)
					->addParameter("s", s)->addParameter("f", f)->addParameter("R", REP)
					->addParameter("IF", IF)->addParameter("SETF", SETF);
				return rv;
			} else if( ((insn.mid >> 18) & 0xe) == 0xe ) {
				// d:10 1110 ra:6 F 0 111 l:7 f_d:6 f_a:6 Ra_x:4 P:3 i:7 rs:4 i:2
			} else if( !((insn.mid >> 10) & 1) ) {
				// d:10 a:10 F 0 b:10 f_d:6 f_a:6 Ra_x:4 P:3 f_i:7 f_b:6
			} else if( ((insn.mid >> 10) & 1) ) {
				// d:10 a:10 F 1 l:10 f_d:6 f_a:6 Ra_x:4 P:3 f_i:7 j:6
			} else {
				return new vector80_insn("*unknown*", "");
			}

			return NULL;
		}

    vector80_insn *vector80data(v80_dmap insn) {
			return NULL;
		}

    vector80_insn *getInstruction(uint8_t *buffer) {
			v80_dmap insn(buffer);

			if ( (insn.first >> 10) & 1 ) return vector80data(insn);
			else return vector80memory(insn);

			assert(true && "This should never be hit!");
			return NULL;
    }
  }
}
