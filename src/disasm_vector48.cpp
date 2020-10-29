#include <disasm_config.h>
#include <disasm_vector48.hpp>
#include <vc4_data.hpp>
#include <vector_helpers.hpp>

using namespace std;

#define INSTRUCTION_TYPE vector48_insn
#define INSTRUCTION_STORAGE uint64_t

namespace disasm {
	namespace vector48 {
		enum v48flags {
			SIXBIT = 1,
			HASA = 2,
			HASB = 4,
			HASD = 8,
			IMM = 16,
			ISMEM = 32,
			SETF = 64,
			IFZ = 128
		};

		struct v48_shared {
			string operation;
			string width;
			string setf;
			string ifz;
			string flags_s;
			string d;
			string a;
			string b;
			string rs;
			uint8_t rb;
			uint8_t imm;

			v48_shared(uint64_t insn, uint8_t flags) {
				string rop;
#define CHECK(v, f) ((v & f) != 0)
				if (CHECK(flags, v48flags::SIXBIT)) {
					uint8_t raw_op = (insn >> 35) & 0x3f;
					bool x_set = (((insn >> 41)&1) == 1);
					bool opalt = ((raw_op >= 48) && x_set);
					rop = opalt?vector48_alts[raw_op - 48]:vector_ops_full[raw_op];
					width = string(x_set?"32":"16");
					operation = string("v")+width+rop;
				} else {
					uint8_t raw_op = ((insn >> 37) & 0x1f);
					if (CHECK(flags, ISMEM)) {
						rop = vector_ops_48[raw_op];
					}
					width = string(vector_widths[((insn >>35) & 3)]);
					operation = string("v")+width+rop;
				}

				if (CHECK(flags, v48flags::SETF))
					setf = ((insn >> 6)&1)?"SETF":"";
				else
					setf = string("");

				if (CHECK(flags, v48flags::IFZ))
					ifz = vector_flags_w[(insn >> 6) & 7];

				if (setf.length() > 0 && ifz.length() > 0) {
					setf += " ";
				}

				flags_s = setf+ifz;

				// no need to actually check flags, all VECTOR48 ops
				// have both D and A registers.
				d = disasm::vector::decode_vector_register(((insn >> 22) & 0x3ff));
				a = disasm::vector::decode_vector_register(((insn >> 12) & 0x3ff));
				uint8_t rrs = ((insn >> 32) & 7);
				rs = string(rrs==0?"":("+r"+std::to_string(rrs)));

				if(CHECK(flags, v48flags::HASB))
					b = disasm::vector::decode_vector_register(insn & 0x3ff);

				if(!CHECK(flags, v48flags::IFZ) && !CHECK(flags, v48flags::HASB) && !CHECK(flags, v48flags::IMM))
					rb = insn & 0x3f;

				if(CHECK(flags, v48flags::IMM))
					imm = insn & 0x3f;
			}
#undef CHECK
		};

		std::string make_format(v48_shared s, uint8_t type) {
			std::string rv;
			if (s.d != "DISCARD-IGNORE")
				rv += "{D}{d}, ";
			if (s.a != "DISCARD-IGNORE")
				rv += "{A}{d}, ";

			switch(type) {
			case 1:
				rv += "(r{rb}) ";
				break;
			case 2:
				if (s.b != "DISCARD-IGNORE")
					rv += "{B}{d} ";
			  break;
			case 3:
				rv += "{imm}";
				break;
			}
			rv += "{F}";
			return rv;
		}

		D(vector48mrro) {
			v48_shared cmn(insn, v48flags::HASD|v48flags::HASA|v48flags::SETF|v48flags::ISMEM);
			std::string fmt(make_format(cmn, 1));
			RV(NI(cmn.operation, fmt)->addParameter("D", PV(cmn.d))
				 ->addParameter("d", PD(cmn.rs))->addParameter("A", PV(cmn.a))
				 ->addParameter("rb", PR(cmn.rb))->addParameter("F", PD(cmn.flags_s)));
		}

		D(vector48mrrr) {
			v48_shared cmn(insn, v48flags::HASD|v48flags::HASA|v48flags::HASB|v48flags::ISMEM);
			std::string fmt(make_format(cmn, 2));
			RV(NI(cmn.operation, fmt)->addParameter("D", PV(cmn.d))
				 ->addParameter("d", PD(cmn.rs))->addParameter("A", PV(cmn.a))
				 ->addParameter("B", PV(cmn.b))->addParameter("F", PD(string(""))));
		}

		D(vector48mrri) {
			v48_shared cmn(insn, v48flags::HASD|v48flags::HASA|v48flags::SETF|v48flags::IFZ|v48flags::IMM|v48flags::ISMEM);
			std::string fmt(make_format(cmn, 3));
			RV(NI(cmn.operation, fmt)->addParameter("D", PV(cmn.d))
				 ->addParameter("d", PD(cmn.rs))->addParameter("A", PV(cmn.a))
				 ->addParameter("imm", P_I(cmn.imm))->addParameter("F", PD(cmn.flags_s)));
		}

		D(vector48drro) {
			v48_shared cmn(insn, v48flags::SIXBIT|v48flags::HASD|v48flags::HASA|v48flags::SETF);
			std::string fmt(make_format(cmn, 1));
			RV(NI(cmn.operation, fmt)->addParameter("D", PV(cmn.d))
				 ->addParameter("d", PD(cmn.rs))->addParameter("A", PV(cmn.a))
				 ->addParameter("rb", PR(cmn.rb))->addParameter("F", PD(cmn.flags_s)));
		}

		D(vector48drrr) {
			v48_shared cmn(insn, v48flags::SIXBIT|v48flags::HASD|v48flags::HASA|v48flags::HASB);
			std::string fmt(make_format(cmn, 2));
			vector48_insn * rv = new vector48_insn(cmn.operation, fmt);
			RV(NI(cmn.operation, fmt)->addParameter("D", PV(cmn.d))
				 ->addParameter("d", PD(cmn.rs))->addParameter("A", PV(cmn.a))
				 ->addParameter("B", PV(cmn.b))->addParameter("F", PD(string(""))));
		}

		D(vector48drri) {
			v48_shared cmn(insn, v48flags::SIXBIT|v48flags::HASD|v48flags::HASA|v48flags::SETF|v48flags::IFZ|v48flags::IMM);
			std::string fmt(make_format(cmn, 3));
			RV(NI(cmn.operation, fmt)->addParameter("D", PV(cmn.d))
				 ->addParameter("d", PD(cmn.rs))->addParameter("A", PV(cmn.a))
				 ->addParameter("imm", P_I(cmn.imm))->addParameter("F", PD(cmn.flags_s)));
		}

		D(v48m_dispatch) {
			if (((insn >> 7) & 7) == 7) return vector48mrro(insn);
			else if (((insn >> 10) & 1) == 0) return vector48mrrr(insn);
			else return vector48mrri(insn);
		}

		D(v48d_dispatch) {
			if (((insn >> 7) & 7) == 7) return vector48drro(insn);
			else if (((insn >> 10) & 1) == 0) return vector48drrr(insn);
			else return vector48drri(insn);
		}

		vector48_insn *getInstruction(uint8_t *buffer) {
			uint64_t insn = READ_WORD(buffer);
			insn <<= 16;
			insn |= READ_WORD(buffer+2);
			insn <<= 16;
			insn |= READ_WORD(buffer+4);
			if ((insn >> 42) & 1) return v48d_dispatch(insn);
			else return v48m_dispatch(insn);
		}
	}
}

#undef INSTRUCTION_TYPE
#undef INSTRUCTION_STORAGE
