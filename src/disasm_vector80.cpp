#include <disasm_config.h>
#include <disasm_vector80.hpp>
#include <vc4_data.hpp>
#include <vector_helpers.hpp>


using namespace std;

#define INSTRUCTION_TYPE vector80_insn
#define INSTRUCTION_STORAGE v80_dmap

namespace disasm {
	namespace vector80 {
		enum V80_FLAGS {
			BASE = 0,
			HASA = 1,
			HASB,
			HASD
		};

		struct v80_dmap {
			uint16_t first;
			uint32_t mid;
			uint16_t trail;
			uint16_t end;

			v80_dmap(uint8_t *buff) {
				first = READ_WORD(buff);
				mid = READ_DWORD(buff + 2);
				trail = READ_WORD(buff + 6);
				end = READ_WORD(buff + 8);
			}
		};

		struct v80_shared {
			uint8_t opcode;
			uint8_t Ra_x;
			string d;
		  string a;
			string b;
			string reps;
			string ifz;
			string setf;
			string width;
			string flags_s;

			v80_shared(v80_dmap insn, uint8_t flags) {
#define CHECKFLAG(f, F) ((F)==BASE?true:!!(((f) & (1 << (F)))))
				// the instruction repeat count is always the first 3 bits of insn.first
				reps = string(vector_reps[insn.first & 7]);

				// Ra_x is always the first 4 bits (ie (v) & 0xf) of insn.trail
				Ra_x = (insn.trail & 0xf);

				// setf is always 11 bits into insn.mid
				setf = string(((insn.mid >> 10)&1)==1?"SETF":"");
				// ifz is always the top 3 bits of insn.end
				ifz = string(vector_flags_w[((insn.end >> 13) & 7)]);

				// adjust things so the final creation of `string flags_s` works
				if (ifz.length() > 0 || (ifz.length() == 0 && reps.length() >0))
						setf += " ";

				if (ifz.length() > 0 && reps.length() > 0) {
					if( setf.length() > 0 ) setf += " ";
					ifz += " ";
				}

				// make the flags_s variable
				flags_s = string("")+setf+ifz+reps;

				// variable size/position stuff
				// if the instruction opens with the first byte having the top 6 bits set
				// we're in an ALU op and the instruction is a full 6 bits with the size
				// being flatly 16 or 32 bits depending on bit 2 of the top byte.
				if (CHECKFLAG(insn.first, 10)) {
					opcode = ((insn.first >> 3) & 0x3f);
					width = string((((insn.first >> 9) & 1) == 1)?"32":"16");
				} else {
					opcode = ((insn.first >> 5) & 0x1f);
					width = string(vector_widths[((insn.first) >> 3) & 3]);
				}

				if (width.empty() || width.length() == 0) width = string("-err-");
				// regardless, if we have `HASD` set in our input flags, we can
				// find it in a fixed location.
				if (CHECKFLAG(flags, V80_FLAGS::HASD))
					d = string(disasm::vector::decode_vector_register((insn.mid >> 22) & 0x3ff));
				// and if `HASA`, the same thing
				if (CHECKFLAG(flags, V80_FLAGS::HASA))
					a = string(disasm::vector::decode_vector_register((insn.mid >> 12) & 0x3ff));
				// same for `HASB`
				if (CHECKFLAG(flags, V80_FLAGS::HASB))
					b = string(disasm::vector::decode_vector_register(insn.mid & 0x3ff));
			}
		};

#undef CHECKFLAG

		string make_reg_add(uint8_t rr) {
			return rr==15?string(""):(string("+r")+std::to_string(rr));
		}

#define F(S) (1 << S)

		D(v80rni) {
			v80_shared cmn(insn, (uint8_t)F(V80_FLAGS::HASD));

			string opname("v");
			opname += std::string(cmn.width) + std::string(vector_ops_48[cmn.opcode]);

			// now get the stuff somewhat specific to this encoding
			string rd_add(make_reg_add((insn.trail >> 12) & 0xf));
			uint32_t offset = ((((insn.end >> 6) & 0x3f) << 2) | (insn.end & 3));
			offset *= 128;
			offset |= (insn.mid & 0x7f);
			uint32_t o_r = ((insn.end >> 2) & 0xf);

			RV(NI(opname, "{D}{da}, (r{r}+{o}) {F}")
				 ->addParameter("D", PV(cmn.d))->addParameter("da", PD(rd_add))
				 ->addParameter("rs", PR(o_r))->addParameter("o", P_I(offset))
				 ->addParameter("F", PD(cmn.flags_s)));
		}

		D(v80nri) {
			v80_shared cmn(insn, (uint8_t)F(V80_FLAGS::HASA));

			string opname("v");
			opname += cmn.width + vector_ops_48[cmn.opcode];

			// now get the stuff somewhat specific to this encoding
			string rd_add(make_reg_add((insn.trail >> 12) & 0xf));
			uint32_t offset = ((((insn.end >> 6) & 0x3f) << 2) | (insn.end & 3));
			offset *= 128;
			offset |= (insn.mid & 0x7f);
			uint32_t o_r = ((insn.end >> 2) & 0xf);


			RV(NI(opname, "{D}{da}, (r{r}+{o}) {F}")
				 ->addParameter("D", PV(cmn.d))->addParameter("da", PD(rd_add))
				 ->addParameter("rs", PR(o_r))->addParameter("o", P_I(offset))
				 ->addParameter("F", PD(cmn.flags_s)));
		}

		std::string* getRegAdds(v80_dmap insn) {
			std::string* rv = new string[3];
			rv[0] = make_reg_add((insn.trail >> 12) & 0xf);
			rv[1] = make_reg_add((insn.trail >> 6) & 0xf);
			rv[2] = make_reg_add((insn.end >> 2) & 0xf);

			return rv;
		}

		D(v80rrr) {
			v80_shared cmn(insn, (uint8_t)F(V80_FLAGS::HASA)|F(V80_FLAGS::HASB)|F(V80_FLAGS::HASD));

			string opname("v");
			opname += cmn.width + vector_ops_48[cmn.opcode];

			string* adds = getRegAdds(insn);


			RV(NI(opname, "{D}{rd}, {A}{ra}, {B}{rb} {F}")
				 ->addParameter("D", PV(cmn.d))->addParameter("rd", PD(adds[0]))
				 ->addParameter("A", PV(cmn.a))->addParameter("ra", PD(adds[1]))
				 ->addParameter("B", PV(cmn.b))->addParameter("rb", PD(adds[2]))
				 ->addParameter("F", PD(cmn.flags_s)));
		}

		D(v80rri) {
			v80_shared cmn(insn, (uint8_t)F(V80_FLAGS::HASA)|F(V80_FLAGS::HASD));

			string opname("v");
			opname += cmn.width + vector_ops_48[cmn.opcode];

			string rd_add(make_reg_add((insn.trail >> 6) & 0xf));
			string ra_add(make_reg_add((insn.end >> 2) & 0xf));

			uint32_t j = insn.end & 0x3f;
			uint32_t l = (insn.mid & 0x3ff);
			uint32_t offset = ((j << 10) | l);

			RV(NI(opname, "{D}{rd}, {A}{ra}, {imm} {F}")
				 ->addParameter("D", PV(cmn.d))->addParameter("rd", PD(rd_add))
				 ->addParameter("A", PV(cmn.a))->addParameter("ra", PD(ra_add))
				 ->addParameter("imm", P_I(offset))->addParameter("F", PD(cmn.flags_s)));
		}

    D(vector80memory) {
			bool remove_reg = (((insn.mid >> 7) & 7) == 7);
			if ( ((insn.mid >> 18) & 0x0e) == 0x0e && remove_reg) return v80rni(insn);
			else if( ((insn.mid >> 28) & 0x0e) == 0x0e && remove_reg) return v80nri(insn);
			else if( !remove_reg && ((insn.mid >> 10) & 1) == 0 ) return v80rrr(insn);
			else if( !remove_reg && ((insn.mid >> 10) & 1) == 1 ) return v80rri(insn);
			return new vector80_insn("*unknown vector80", "");
		}

		D(v80arrr) {
			v80_shared cmn(insn, (uint8_t)F(V80_FLAGS::HASA)|F(V80_FLAGS::HASB)|F(V80_FLAGS::HASD));
			string opname("v");
			opname += cmn.width + vector_ops_full[cmn.opcode];

			string* adds = getRegAdds(insn);

			RV(NI(opname, "{D}{rd}, {A}{ra}, {B}{rb} {F}")
				 ->addParameter("D", PV(cmn.d))->addParameter("rd", PD(adds[0]))
				 ->addParameter("A", PV(cmn.a))->addParameter("ra", PD(adds[1]))
				 ->addParameter("B", PV(cmn.b))->addParameter("rb", PD(adds[2]))
				 ->addParameter("F", PD(cmn.flags_s)));
		}

		D(v80arri) {
			v80_shared cmn(insn, (uint8_t)F(V80_FLAGS::HASA)|F(V80_FLAGS::HASD));
			string opname("v");
			opname += cmn.width + vector_ops_full[cmn.opcode];

			string* adds = getRegAdds(insn);

		  uint32_t off_add = insn.mid & 0x3ff;
			uint32_t off_base = insn.end & 0x3f;
			uint32_t offset = (off_base << 10) | off_add;

			RV(NI(opname, "{D}{rd}, {A}{ra}, {imm} {F}")
				 ->addParameter("D", PV(cmn.d))->addParameter("rd", PD(adds[0]))
				 ->addParameter("A", PV(cmn.a))->addParameter("ra", PD(adds[1]))
				 ->addParameter("imm", P_I(offset))->addParameter("F", PD(cmn.flags_s)));
		}

		D(vector80alu) {
			bool check = (((insn.mid >> 10) & 1) == 1);

			if( !check ) return v80arrr(insn);
			else return v80arri(insn);
		}

		vector80_insn *getInstruction(uint8_t *buffer) {
			v80_dmap insn(buffer);

			if ( (insn.first >> 10) & 1 ) return vector80alu(insn);
			else return vector80memory(insn);
		}
	}
}

#undef INSTRUCTION_TYPE
#undef INSTRUCTION_STORAGE
