#include <disasm_config.h>
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
				first = READ_WORD(buff);
				mid = READ_DWORD(buff + 2);
				trail = READ_WORD(buff + 6);
				end = READ_WORD(buff + 8);
			}
		};


		string make_reg_add(uint8_t rr) {
			return rr==15?string(""):(string("+r")+std::to_string(rr));
		}

		vector80_insn *v80rni(v80_dmap insn) {
			uint8_t op_base = (insn.first >> 5) & 0x1f;
			string insn_rep = vector_reps[insn.first & 7];
			string memwid(vector_widths[((insn.first >> 3) & 3)]);
			string rd = disasm::vector::decode_vector_register((insn.mid >> 22) & 0x3ff);
			string setf = (((insn.mid >> 11) & 1) == 1)?"SETF ":"";
			string rd_add = make_reg_add((insn.trail >> 12) & 0xf);
			uint8_t offset_add = (insn.mid & 0x7f);
			uint8_t offset_reg = ((insn.end >> 2) & 0xf);
			uint32_t offset_base = (((insn.end >> 6) & 0x3f) << 2) | (insn.end & 3);
			uint32_t offset = (offset_base*128)+offset_add;

			string ifz(vector_flags_w[((insn.end >> 13) & 7)]);
			string opname;
			opname += "v" + memwid + vector_ops_48[op_base];

			if(ifz.length() > 0) ifz += " ";

			vector80_insn *rv = new vector80_insn(opname, "{D}{da}, (r{r}+{o}) {F}");
			vc4_parameter D(ParameterTypes::VECTOR_REGISTER, rd);
			vc4_parameter RDA(ParameterTypes::DATA, rd_add);
			vc4_parameter rs(ParameterTypes::REGISTER, (uint32_t)offset_reg);
			vc4_parameter off(ParameterTypes::IMMEDIATE, (uint32_t)offset);
			vc4_parameter flags(ParameterTypes::DATA, string(setf+ifz+insn_rep));
			rv->addParameter("D", D)->addParameter("da", RDA)->addParameter("r", rs)
				->addParameter("o", off)->addParameter("F", flags);

			return rv;
		}

		vector80_insn *v80nri(v80_dmap insn) {
			uint8_t op_base = (insn.first >> 5) & 0x1f;
			string insn_rep = vector_reps[insn.first & 7];
			string memwid(vector_widths[((insn.first >> 3) & 3)]);
			string ra = disasm::vector::decode_vector_register((insn.mid >> 12) & 0x3ff);
			string setf = (((insn.mid >> 11) & 1) == 1)?"SETF ":"";
			string ra_add = make_reg_add((insn.trail >> 6) & 0xf);
			uint8_t offset_add = (insn.mid & 0x7f);
			uint8_t offset_reg = ((insn.end >> 2) & 0xf);
			uint32_t offset_base = (((insn.end >> 6) & 0x3f) << 2) | (insn.end & 3);
			uint32_t offset = (offset_base*128)+offset_add;

			string ifz(vector_flags_w[((insn.end >> 13) & 7)]);
			string opname;
			opname += "v" + memwid + vector_ops_48[op_base];

			if(ifz.length() > 0) ifz += " ";

			vector80_insn *rv = new vector80_insn(opname, "{A}{ra}, (r{r}+{o}) {F}");
			vc4_parameter D(ParameterTypes::VECTOR_REGISTER, ra);
			vc4_parameter RDA(ParameterTypes::DATA, ra_add);
			vc4_parameter rs(ParameterTypes::REGISTER, (uint32_t)offset_reg);
			vc4_parameter off(ParameterTypes::IMMEDIATE, (uint32_t)offset);
			vc4_parameter flags(ParameterTypes::DATA, string(setf+ifz+insn_rep));
			rv->addParameter("A", D)->addParameter("ra", RDA)->addParameter("r", rs)
				->addParameter("o", off)->addParameter("F", flags);

			return rv;
		}

		vector80_insn *v80rrr(v80_dmap insn) {
			uint8_t op_base = (insn.first >> 5) & 0x1f;
			string insn_rep = vector_reps[insn.first & 7];
			string memwid(vector_widths[((insn.first >> 3) & 3)]);
			string rd = disasm::vector::decode_vector_register((insn.mid >> 22) & 0x3ff);
			string ra = disasm::vector::decode_vector_register((insn.mid >> 12) & 0x3ff);
			string setf = (((insn.mid >> 11) & 1) == 1)?"SETF ":"";
			string rb = disasm::vector::decode_vector_register(insn.mid & 0x3ff);
			string rd_add = make_reg_add((insn.trail >> 12) & 0xf);
			string ra_add = make_reg_add((insn.trail >> 6) & 0xf);
			string rb_add = make_reg_add((insn.end >> 2) & 0xf);
			string ifz(vector_flags_w[((insn.end >> 7) & 7)]);

			string opname;
			opname += "v" + memwid + vector_ops_48[op_base];

			if(ifz.length() > 0) ifz += " ";

			vector80_insn *rv = new vector80_insn(opname, "{D}{rd}, {A}{ra}, {B}{rb} {F}");
			vc4_parameter D(ParameterTypes::VECTOR_REGISTER, rd);
			vc4_parameter RD(ParameterTypes::DATA, rd_add);
			vc4_parameter A(ParameterTypes::VECTOR_REGISTER, ra);
			vc4_parameter RA(ParameterTypes::DATA, ra_add);
			vc4_parameter B(ParameterTypes::VECTOR_REGISTER, rb);
			vc4_parameter RB(ParameterTypes::DATA, rb_add);
			vc4_parameter flags(ParameterTypes::DATA, string(setf+ifz+insn_rep));

			rv->addParameter("D", D)->addParameter("rd", RD)
				->addParameter("A", A)->addParameter("ra", RA)
				->addParameter("B", B)->addParameter("rb", RB)
				->addParameter("F", flags);

			return rv;
		}

		vector80_insn *v80rri(v80_dmap insn) {
			uint8_t op_base = (insn.first >> 5) & 0x1f;
			string insn_rep = vector_reps[insn.first & 7];
			string memwid(vector_widths[((insn.first >> 3) & 3)]);
			string rd = disasm::vector::decode_vector_register((insn.mid >> 22) & 0x3ff);
			string ra = disasm::vector::decode_vector_register((insn.mid >> 12) & 0x3ff);
			string setf = (((insn.mid >> 11) & 1) == 1)?"SETF ":"";
			uint32_t off_add = insn.mid & 0x3ff;
			uint32_t off_base = insn.end & 0x3f;
			uint32_t offset = (off_base << 10) | off_add;
			string rd_add = make_reg_add((insn.trail >> 12) & 0xf);
			string ra_add = make_reg_add((insn.trail >> 6) & 0xf);
			string ifz(vector_flags_w[((insn.end >> 7) & 7)]);

			string opname;
			opname += "v" + memwid + vector_ops_48[op_base];

			if(ifz.length() > 0) ifz += " ";

			vector80_insn *rv = new vector80_insn(opname, "{D}{rd}, {A}{ra}, {i} {F}");
			vc4_parameter D(ParameterTypes::VECTOR_REGISTER, rd);
			vc4_parameter RD(ParameterTypes::DATA, rd_add);
			vc4_parameter A(ParameterTypes::VECTOR_REGISTER, ra);
			vc4_parameter RA(ParameterTypes::DATA, ra_add);
			vc4_parameter I(ParameterTypes::IMMEDIATE, offset);
			vc4_parameter flags(ParameterTypes::DATA, string(setf+ifz+insn_rep));

			rv->addParameter("D", D)->addParameter("rd", RD)
				->addParameter("A", A)->addParameter("ra", RA)
				->addParameter("i", I)->addParameter("F", flags);

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
			string size((((insn.first >> 9) & 1) == 1)?"32":"16");
			uint8_t op_base = (insn.first >> 3) & 0x3f; // 6 bits!
			string reps(vector_reps[insn.first & 7]);
			string rd = disasm::vector::decode_vector_register((insn.mid >> 22) & 0x3ff);
			string ra = disasm::vector::decode_vector_register((insn.mid >> 12) & 0x3ff);
			string setf((((insn.mid >> 11)&1)==1)?"SETF ":"");
			string rb = disasm::vector::decode_vector_register(insn.mid & 0x3ff);
			string rda = make_reg_add((insn.trail >> 12) & 0xf);
			string raa = make_reg_add((insn.trail >> 6) & 0xf);
			string rba = make_reg_add((insn.end >> 2) & 0xf);
			string ifz(vector_flags_w[((insn.end >> 7) & 7)]);

			if(ifz.length() > 0) ifz += " ";

			string opname;
			opname += "v" + size + vector_ops_full[op_base];

			vector80_insn *rv = new vector80_insn(opname, "{D}{rd}, {A}{ra}, {B}{rb} {F}");
			vc4_parameter D(ParameterTypes::VECTOR_REGISTER, rd);
			vc4_parameter RD(ParameterTypes::DATA, rda);
			vc4_parameter A(ParameterTypes::VECTOR_REGISTER, ra);
			vc4_parameter RA(ParameterTypes::DATA, raa);
			vc4_parameter B(ParameterTypes::VECTOR_REGISTER, rb);
			vc4_parameter RB(ParameterTypes::DATA, rba);
			vc4_parameter flags(ParameterTypes::DATA, string(setf+ifz+reps));

			rv->addParameter("D", D)->addParameter("rd", RD)
				->addParameter("A", A)->addParameter("ra", RA)
				->addParameter("B", B)->addParameter("rb", RB)
				->addParameter("F", flags);

			return rv;
		}

		vector80_insn *v80arri(v80_dmap insn) {
			string size((((insn.first >> 9) & 1) == 1)?"32":"16");
			uint8_t op_base = (insn.first >> 3) & 0x3f; // 6 bits!
			string reps(vector_reps[insn.first & 7]);
			string rd = disasm::vector::decode_vector_register((insn.mid >> 22) & 0x3ff);
			string ra = disasm::vector::decode_vector_register((insn.mid >> 12) & 0x3ff);
			string setf((((insn.mid >> 11)&1)==1)?"SETF ":"");
		  uint32_t off_add = insn.mid & 0x3ff;
			uint32_t off_base = insn.end & 0x3f;
			uint32_t offset = (off_base << 10) | off_add;
			string rda = make_reg_add((insn.trail >> 12) & 0xf);
			string raa = make_reg_add((insn.trail >> 6) & 0xf);
			string ifz(vector_flags_w[((insn.end >> 7) & 7)]);

			if(ifz.length() > 0) ifz += " ";

			string opname;
			opname += "v" + size + vector_ops_full[op_base];

			vector80_insn *rv = new vector80_insn(opname, "{D}{rd}, {A}{ra}, {i} {F}");
			vc4_parameter D(ParameterTypes::VECTOR_REGISTER, rd);
			vc4_parameter RD(ParameterTypes::DATA, rda);
			vc4_parameter A(ParameterTypes::VECTOR_REGISTER, ra);
			vc4_parameter RA(ParameterTypes::DATA, raa);
			vc4_parameter I(ParameterTypes::IMMEDIATE, offset);
			vc4_parameter flags(ParameterTypes::DATA, string(setf+ifz+reps));

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
