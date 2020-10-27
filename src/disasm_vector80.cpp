#include <disasm_config.h>
#include <disasm_vector80.hpp>
#include <vc4_data.hpp>
#include <vector_helpers.hpp>


using namespace std;

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
			uint16_t d;
			uint16_t a;
			uint16_t b;
			string reps;
			string ifz;
			string setf;
			string width;
			string flags_s;

			v80_shared() {
				Ra_x = opcode = d = a = b = 0;
				reps = ifz = setf = width = string("");
			}

#define CHECKFLAG(f, F) ((F)==BASE?true:!!(((f) & (1 << (F))>>(F))))
			void load(v80_dmap insn, uint8_t flags) {
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
				uint8_t op_base;
				if (CHECKFLAG(insn.first, 10)) {
					op_base = ((insn.first >> 3) & 0x3f);
					width = string((((insn.first >> 9) & 1) == 1)?"32":"16");
				} else {
					op_base = ((insn.first >> 5) & 0x1f);
					width = vector_widths[((insn.first) >> 3) & 3];
				}

				// regardless, if we have `HASD` set in our input flags, we can
				// find it in a fixed location.
				if (CHECKFLAG(flags, V80_FLAGS::HASD))
					d = ((insn.mid >> 22) & 0x3ff);
				// and if `HASA`, the same thing
				if (CHECKFLAG(flags, V80_FLAGS::HASA))
					a = ((insn.mid >> 12) & 0x3ff);
				// same for `HASB`
				if (CHECKFLAG(flags, V80_FLAGS::HASB))
					b = (insn.mid & 0x3ff);
			}
		};

#undef CHECKFLAG

		string make_reg_add(uint8_t rr) {
			return rr==15?string(""):(string("+r")+std::to_string(rr));
		}

		vector80_insn *v80rni(v80_dmap insn) {
			v80_shared cmn;
			cmn.load(insn, ((uint8_t)(1 << V80_FLAGS::HASD)));

			string opname("v");
			opname += cmn.width + vector_ops_48[cmn.opcode];

			// now get the stuff somewhat specific to this encoding
			string rd_add(make_reg_add((insn.trail >> 12) & 0xf));
			uint32_t offset = ((((insn.end >> 6) & 0x3f) << 2) | (insn.end & 3));
			offset *= 128;
			offset |= (insn.mid & 0x7f);
			uint32_t o_r = ((insn.end >> 2) & 0xf);

			vector80_insn *rv = new vector80_insn(opname, "{D}{da}, (r{r}+{o}) {F}");
			vc4_parameter D(ParameterTypes::VECTOR_REGISTER, cmn.d);
			vc4_parameter RDA(ParameterTypes::DATA, rd_add);
			vc4_parameter rs(ParameterTypes::REGISTER, (uint32_t)o_r);
			vc4_parameter off(ParameterTypes::IMMEDIATE, (uint32_t)offset);
			vc4_parameter flags(ParameterTypes::DATA, cmn.flags_s);
			rv->addParameter("D", D)->addParameter("da", RDA)->addParameter("r", rs)
				->addParameter("o", off)->addParameter("F", flags);

			return rv;
		}

#define F(S) (1 << 2)

		vector80_insn *v80nri(v80_dmap insn) {
			v80_shared cmn;
			cmn.load(insn, (uint8_t)F(V80_FLAGS::HASA));

			string opname("v");
			opname += cmn.width + vector_ops_48[cmn.opcode];

			// now get the stuff somewhat specific to this encoding
			string rd_add(make_reg_add((insn.trail >> 12) & 0xf));
			uint32_t offset = ((((insn.end >> 6) & 0x3f) << 2) | (insn.end & 3));
			offset *= 128;
			offset |= (insn.mid & 0x7f);
			uint32_t o_r = ((insn.end >> 2) & 0xf);

			vector80_insn *rv = new vector80_insn(opname, "{D}{da}, (r{r}+{o}) {F}");
			vc4_parameter D(ParameterTypes::VECTOR_REGISTER, cmn.d);
			vc4_parameter RDA(ParameterTypes::DATA, rd_add);
			vc4_parameter rs(ParameterTypes::REGISTER, (uint32_t)o_r);
			vc4_parameter off(ParameterTypes::IMMEDIATE, (uint32_t)offset);
			vc4_parameter flags(ParameterTypes::DATA, cmn.flags_s);
			rv->addParameter("D", D)->addParameter("da", RDA)->addParameter("r", rs)
				->addParameter("o", off)->addParameter("F", flags);

			return rv;
		}

		std::string* getRegAdds(v80_dmap insn) {
			std::string* rv = new string[3];
			rv[0] = make_reg_add((insn.trail >> 12) & 0xf);
			rv[1] = make_reg_add((insn.trail >> 6) & 0xf);
			rv[2] = make_reg_add((insn.end >> 2) & 0xf);
			
			return rv;
		}

		vector80_insn *v80rrr(v80_dmap insn) {
			v80_shared cmn;
			cmn.load(insn, (uint8_t)F(V80_FLAGS::HASA)|F(V80_FLAGS::HASB)|F(V80_FLAGS::HASD));

			string opname("v");
			opname += cmn.width + vector_ops_48[cmn.opcode];

			string* adds = getRegAdds(insn);

			vector80_insn *rv = new vector80_insn(opname, "{D}{rd}, {A}{ra}, {B}{rb} {F}");
			vc4_parameter D(ParameterTypes::VECTOR_REGISTER, cmn.d);
			vc4_parameter RD(ParameterTypes::DATA, adds[0]);
			vc4_parameter A(ParameterTypes::VECTOR_REGISTER, cmn.a);
			vc4_parameter RA(ParameterTypes::DATA, adds[1]);
			vc4_parameter B(ParameterTypes::VECTOR_REGISTER, cmn.b);
			vc4_parameter RB(ParameterTypes::DATA, adds[2]);
			vc4_parameter flags(ParameterTypes::DATA, cmn.flags_s);

			rv->addParameter("D", D)->addParameter("rd", RD)
				->addParameter("A", A)->addParameter("ra", RA)
				->addParameter("B", B)->addParameter("rb", RB)
				->addParameter("F", flags);

			return rv;
		}

		vector80_insn *v80rri(v80_dmap insn) {
			v80_shared cmn;
			cmn.load(insn, (uint8_t)F(V80_FLAGS::HASA)|F(V80_FLAGS::HASB)|F(V80_FLAGS::HASD));

			string opname("v");
			opname += cmn.width + vector_ops_48[cmn.opcode];

			string rd_add(make_reg_add((insn.trail >> 6) & 0xf));
			string ra_add(make_reg_add((insn.end >> 2) & 0xf));

			uint32_t j = insn.end & 0x3f;
			uint32_t l = ((insn.mid >> 12) & 0x3ff);
			uint32_t offset = ((j << 10) | l);

			vector80_insn *rv = new vector80_insn(opname, "{D}{rd}, {A}{ra}, {imm} {F}");
			vc4_parameter D(ParameterTypes::VECTOR_REGISTER, cmn.d);
			vc4_parameter RD(ParameterTypes::DATA, rd_add);
			vc4_parameter A(ParameterTypes::VECTOR_REGISTER, cmn.a);
			vc4_parameter RA(ParameterTypes::DATA, ra_add);
			vc4_parameter IMM(ParameterTypes::IMMEDIATE, offset);
			vc4_parameter flags(ParameterTypes::DATA, cmn.flags_s);

			rv->addParameter("D", D)->addParameter("rd", RD)
				->addParameter("A", A)->addParameter("ra", RA)
				->addParameter("imm", IMM)->addParameter("F", flags);

			return rv;
		}

    vector80_insn *vector80memory(v80_dmap insn) {
			bool remove_reg = (((insn.mid >> 7) & 7) == 7);
			if ( ((insn.mid >> 18) & 0x0e) == 0x0e && remove_reg) return v80rni(insn);
			else if( ((insn.mid >> 28) & 0x0e) == 0x0e && remove_reg) return v80nri(insn);
			else if( !remove_reg && ((insn.mid >> 10) & 1) == 0 ) return v80rrr(insn);
			else if( !remove_reg && ((insn.mid >> 10) & 1) == 1 ) return v80rri(insn);
			return new vector80_insn("!!!ERROR!!!", "");
		}

		vector80_insn *v80arrr(v80_dmap insn) {
			v80_shared cmn;
			cmn.load(insn, (uint8_t)F(V80_FLAGS::HASA)|F(V80_FLAGS::HASB)|F(V80_FLAGS::HASD));
			string opname("v");
			opname += cmn.width + vector_ops_full[cmn.opcode];

			string* adds = getRegAdds(insn);

			vector80_insn *rv = new vector80_insn(opname, "{D}{rd}, {A}{ra}, {B}{rb} {F}");
			vc4_parameter D(ParameterTypes::VECTOR_REGISTER, cmn.d);
			vc4_parameter RD(ParameterTypes::DATA, adds[0]);
			vc4_parameter A(ParameterTypes::VECTOR_REGISTER, cmn.a);
			vc4_parameter RA(ParameterTypes::DATA, adds[1]);
			vc4_parameter B(ParameterTypes::VECTOR_REGISTER, cmn.b);
			vc4_parameter RB(ParameterTypes::DATA, adds[2]);
			vc4_parameter flags(ParameterTypes::DATA, cmn.flags_s);

			rv->addParameter("D", D)->addParameter("rd", RD)
				->addParameter("A", A)->addParameter("ra", RA)
				->addParameter("B", B)->addParameter("rb", RB)
				->addParameter("F", flags);

			return rv;
		}

		vector80_insn *v80arri(v80_dmap insn) {
			v80_shared cmn;
			cmn.load(insn, (uint8_t)F(V80_FLAGS::HASA)|F(V80_FLAGS::HASB)|F(V80_FLAGS::HASD));
			string opname("v");
			opname += cmn.width + vector_ops_full[cmn.opcode];

			string* adds = getRegAdds(insn);

		  uint32_t off_add = insn.mid & 0x3ff;
			uint32_t off_base = insn.end & 0x3f;
			uint32_t offset = (off_base << 10) | off_add;

			vector80_insn *rv = new vector80_insn(opname, "{D}{rd}, {A}{ra}, {i} {F}");
			vc4_parameter D(ParameterTypes::VECTOR_REGISTER, cmn.d);
			vc4_parameter RD(ParameterTypes::DATA, adds[0]);
			vc4_parameter A(ParameterTypes::VECTOR_REGISTER, cmn.a);
			vc4_parameter RA(ParameterTypes::DATA, adds[1]);
			vc4_parameter I(ParameterTypes::IMMEDIATE, offset);
			vc4_parameter flags(ParameterTypes::DATA, cmn.flags_s);

			rv->addParameter("D", D)->addParameter("rd", RD)
				->addParameter("A", A)->addParameter("ra", RA)
				->addParameter("i", I)->addParameter("F", flags);

			return rv;
		}

		vector80_insn *vector80alu(v80_dmap insn) {
			bool check = (((insn.mid >> 10) & 1) == 1);

			if( !check ) return v80arrr(insn);
			else return v80arri(insn);
		}

		vector80_insn *getInstruction(uint8_t *buffer) {
			v80_dmap insn(buffer);

			if ( (insn.first >> 10) & 1 ) return vector80alu(insn);
			else return vector80memory(insn);

			assert(true && "This should never be hit!");
			return NULL;
		}
	}
}
