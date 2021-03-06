#include <disasm_config.h>
#include <disasm_scalar32.hpp>
#include <vc4_data.hpp>
#include <vc4_parameter.hpp>

using namespace std;

#define INSTRUCTION_TYPE scalar32_insn
#define INSTRUCTION_STORAGE uint32_t

namespace disasm {
	namespace scalar32 {
		DZ(addCmpBrRRRO) {
			uint32_t rd = ((insn >> 16) & 0x0000000f);
			uint32_t ra = ((insn >> 20) & 0x0000000f);
			uint32_t rs = ((insn >> 10) & 0x0000000f);
			int32_t offs = insn & 0x000003ff;
			offs *= 2;

			uint32_t target = src_addr + offs;

			RV(NI(opname, "r{d}, r{a}, r{s}, {o}")
				 ->addParameter("d", PR(rd))->addParameter("a", PR(ra))
				 ->addParameter("s", PR(rs))->addParameter("o", P_I(target)));
		}

		DZ(addCmpBrRIRO) {
			uint32_t rd = ((insn >> 16) & 0x0000000f);
			uint32_t rs = ((insn >> 10) & 0x0000000f);
			uint32_t i = ((insn >> 20) & 0x0000000f);
			int32_t offs = insn & 0x000003ff;
			offs *= 2;

			uint32_t target = src_addr + offs;

			RV(NI(opname, "r{d}, {i}, r{s}, {o}")
				 ->addParameter("d", PR(rd))->addParameter("i", P_I(i))
				 ->addParameter("s", PR(rs))->addParameter("o", P_I(target)));
		}

		DZ(addCmpBrRRIO) {
			uint32_t rd = ((insn >> 16) & 0x0000000f);
			uint32_t ra = ((insn >> 20) & 0x0000000f);
			uint32_t u = ((insn >> 8) & 0x0000003f);
			int32_t offs = insn & 0x000003ff;
			offs *= 2;

			uint32_t target = src_addr + offs;

			RV(NI(opname, "r{d}, r{a}, {u}, {o}")
				 ->addParameter("d", PR(rd))->addParameter("a", PR(ra))
				 ->addParameter("u", P_I(u))->addParameter("o", P_I(target)));
		}

		DZ(addCmpBrRIIO) {
			uint32_t rd = ((insn >> 16) & 0x0000000f);
			uint32_t i = ((insn >> 20) & 0x0000000f);
			uint32_t u = ((insn >> 8) & 0x0000003f);
			int32_t offs = insn & 0x000000ff;
			offs *= 2;

			uint32_t target = src_addr + offs;

			RV(NI(opname, "r{d}, {i}, {u}, {o}")
				 ->addParameter("d", PR(rd))->addParameter("i", P_I(i))
				 ->addParameter("u", P_I(u))->addParameter("o", P_I(target)));
		}

		D(addCmpBr) {
			std::string cc(condition_codes[((insn >> 24) & 0x0000000f)]);
			uint8_t type = insn & 0x0000C000 >> 14;
			std::string opname("addcmpb");
			opname += cc;

			switch( type ) {
			case 0:
				return addCmpBrRRRO(insn, src_addr, opname);
			case 1:
				return addCmpBrRIRO(insn, src_addr, opname);
			case 2:
				return addCmpBrRRIO(insn, src_addr, opname);
			case 3:
				return addCmpBrRIIO(insn, src_addr, opname);
			default:
				return new scalar32_insn("*unknown scalar32 addcmpbr<cc>*", "");
			}
		}

		D(branch) {
			uint32_t mask = (insn & 0x00800000)?0x0fffffff:0x007fffff;
			std::string opname("b");
			opname += (insn & 0x00800000)?"l":condition_codes[((insn & 0x0f000000) >> 24)];
			int32_t offs = insn & mask;
			offs *= 2;
			uint32_t target = src_addr + offs;

			RV(NI(opname, "{o}")->addParameter("o", P_I(target)));
		}

		D(dispatchBranched) {
			switch( (insn >> 24) & 0xf ) {
			case 0x80:
				return addCmpBr(insn, src_addr);
			case 0x81:
				return branch(insn, src_addr);
			default:
				return new scalar32_insn("*unknown scalar32 branch instruction*", "");
			}
		}

		D(condIndexed) {
			std::string width(mem_op_widths[((insn >> 22) & 3)]);
			std::string opname(((insn >> 21)&1)?"st":"ld");
			opname += width;
			opname += "." + condition_codes[((insn >> 7) & 0xf)];
			uint32_t rb = insn & 0x1f;
			uint32_t ra = (insn >> 11) & 0x1f;
			uint32_t rd = (insn >> 16) & 0x1f;
			RV(NI(opname, "r{d}, (r{a} + r{b})")
				 ->addParameter("d", PR(rd))->addParameter("a", PR(ra))
				 ->addParameter("b", PR(rb)));
		}

		D(loadStoreRRo) {
			std::string width(mem_op_widths[((insn >> 22) & 3)]);
			std::string opname(((insn >> 21)&1)?"st":"ld");
			opname += width;
			uint32_t rd = ((insn >> 16) & 0x1f);
			uint32_t ra = ((insn >> 11) & 0x1f);
			uint32_t offs = insn & 0x3ff;

			RV(NI(opname, "r{d}, (r{a}+{o})")
				 ->addParameter("d", PR(rd))->addParameter("a", PR(ra))
				 ->addParameter("o", P_I(offs)));
		}

		D(loadStoreOffset) {
			std::string p[] = { "r24", "sp", "pc", "r0" };
			std::string width(mem_op_widths[((insn >> 22) & 3)]);
			std::string opname(((insn >> 21)&1)?"st":"ld");
			opname += width;
			uint32_t rd = ((insn >> 16) & 0x1f);
			uint32_t ra = ((insn >> 11) & 0x1f);
			uint32_t offs = insn & 0x3ff;
			uint8_t sel = ((insn >> 24) & 3);

			RV(NI(opname, "r{d}, ({t} + {o})")
				 ->addParameter("d", PR(rd))->addParameter("a", PR(ra))
				 ->addParameter("t", PD(p[sel]))->addParameter("o", P_I(offs)));
		}

		D(condLSWIncDec) {
			std::string width(mem_op_widths[((insn >> 22) & 3)]);
			std::string opname(((insn >> 21)&1)?"st":"ld");
			opname += width;
			uint32_t rd = ((insn >> 16) & 0x1f);
			uint32_t ra = ((insn >> 11) & 0x1f);
			std::string incOrDec(((insn >> 24) & 0x01)?"(r{a}++)":"(--r{a})");
			std::string fmt("r{d}, ");
			fmt += incOrDec;

			RV(NI(opname, fmt)->addParameter("d", PR(rd))->addParameter("a", PR(ra)));
		}

		D(memoryAccessDispatch) {
			uint8_t type = ((insn >> 20) & 0xf);
			if (type == 0) return condIndexed(insn, src_addr);
			else if (type == 2 || type == 3) return loadStoreRRo(insn, src_addr);
			else if (type == 4) return condLSWIncDec(insn, src_addr);
			else if (type == 5) return condLSWIncDec(insn, src_addr);
			else if (type == 6 || type == 7) return new scalar32_insn("*unknown scalar32 memory access*", "");
			else if (type == 8 || type == 9 || type == 10 || type == 11) return loadStoreOffset(insn, src_addr);
			else return new scalar32_insn("*unknown scalar32 memory access*", "");
		}

		D(aluRegisterImmediate) {
			std::string operation(al_ops[((insn >> 21) & 0x1f)]);
			uint32_t rd = ((insn >> 16) & 0x1f);
			uint32_t imm = insn & 0xffff;

			RV(NI(operation, "r{d}, {i}")
				 ->addParameter("d", PR(rd))->addParameter("i", P_I(imm)));
		}

		D(aluAddRRI) {
			uint32_t rs = ((insn >> 21) & 0x1f);
			uint32_t rd = ((insn >> 16) & 0x1f);
			uint32_t imm = (insn & 0xffff);

			RV(NI("add", "r{d}, r{s}, {i}")
				 ->addParameter("d", PR(rd))->addParameter("s", PR(rs))
				 ->addParameter("i", P_I(imm)));
		}

		D(aluAddRPCO) {
			uint32_t rd = ((insn >> 16) & 0x1f);
			uint32_t offs = insn & 0xffff;

			RV(NI("add", "r{d}, pc, {o}")
				 ->addParameter("d", PR(rd))->addParameter("o", P_I(offs)));
		}

		D(aluConditionalRRR) {
			std::string operation(al_ops[((insn >> 21) & 0x3f)]);
			uint32_t rd = ((insn >> 16) & 0xf);
			uint32_t ra = ((insn >> 11) & 0xf);
			uint32_t rb = (insn & 0xf);
			operation += "." + condition_codes[((insn >> 7) & 0xf)];

			RV(NI(operation, "r{d}, r{a}, r{b}")->addParameter("d", PR(rd))
				 ->addParameter("a", PR(ra))->addParameter("b", PR(rb)));
		}

		D(aluConditionalRRI) {
			std::string operation(al_ops[((insn >> 21) & 0x3f)]);
			uint32_t rd = ((insn >> 16) & 0xf);
			uint32_t ra = ((insn >> 11) & 0xf);
			uint32_t imm = (insn & 0xf);
			operation += "." + condition_codes[((insn >> 7) & 0xf)];

			RV(NI(operation, "r{d}, r{a}, {i}")->addParameter("d", PR(rd))
				 ->addParameter("a", PR(ra))->addParameter("i", P_I(imm)));
		}

		D(aluDispatch) {
			bool conditional = (((insn >> 24) & 0xf) == 0xc);
			uint8_t check_code = ((insn >> 22) & 3);
			if (conditional) {
				if ((insn >> 6) & 1) return aluConditionalRRI(insn, src_addr);
				else return aluConditionalRRR(insn, src_addr);
			} else {
				switch(check_code) {
				case 0:
					return aluRegisterImmediate(insn, src_addr);
				case 1:
					return aluAddRRI(insn, src_addr);
				case 2:
					return new scalar32_insn("*unknown scalar32 alu*", "");
				case 3:
					return aluAddRPCO(insn, src_addr);
				default:
					return new scalar32_insn("*unknown scalar32 alu*", "");
				}
			}
		}

		D(floatOpRRR) {
			std::string op(float_ops[((insn >> 21) & 0xf)]);
			op += "." + condition_codes[((insn >> 7) & 0xf)];
			uint32_t rb = insn & 0x1f;
			uint32_t ra = ((insn >> 11) & 0x1f);
			uint32_t rd = ((insn >> 16) & 0x1f);

			RV(NI(op, "r{d}, r{a}, r{b}")->addParameter("d", PR(rd))
				 ->addParameter("a", PR(rd))->addParameter("b", PR(rb)));
		}

		D(floatOpRRI) {
			std::string op(float_ops[((insn >> 21) & 0xf)]);
			op += "." + condition_codes[((insn >> 7) & 0xf)];
			vc4_parameter imm(ParameterTypes::IMMEDIATE, (uint32_t)(insn & 0x3f));
			imm.setContainsFloat();
			uint32_t ra = ((insn >> 11) & 0x1f);
			uint32_t rd = ((insn >> 16) & 0x1f);

			RV(NI(op, "r{d}, r{a}, {i}")->addParameter("d", PR(rd))
				 ->addParameter("a", PR(rd))->addParameter("i", imm));
		}

		D(floatOpDispatch) {
			if ( (insn >> 6) & 1 ) return floatOpRRI(insn, src_addr);
			else return floatOpRRR(insn, src_addr);
		}

		D(floatTruncRRR) {
			std::string op("ftrunc.");
			op += condition_codes[((insn >> 7) & 0xf)];

			uint32_t rb = insn & 0x1f;
			uint32_t ra = (insn >> 11) & 0x1f;
			uint32_t rd = (insn >> 16) & 0x1f;

			RV(NI(op, "r{d}, r{a}, sasl r{b}")->addParameter("d", PR(rd))
				 ->addParameter("a", PR(ra))->addParameter("b", PR(rb)));
		}

		D(floatTruncRRI) {
			std::string op("ftrunc.");
			op += condition_codes[((insn >> 7) & 0xf)];

			uint32_t i = insn & 0x3f;
			uint32_t ra = (insn >> 11) & 0x1f;
			uint32_t rd = (insn >> 16) & 0x1f;

			RV(NI(op, "r{d}, r{a}, sasl {i}")->addParameter("d", PR(rd))
				 ->addParameter("a", PR(ra))->addParameter("i", P_I(i)));
		}

		D(floatFloorRRR) {
			std::string op("floor.");
			op += condition_codes[((insn >> 7) & 0xf)];

			uint32_t rb = insn & 0x1f;
			uint32_t ra = (insn >> 11) & 0x1f;
			uint32_t rd = (insn >> 16) & 0x1f;

			RV(NI(op, "r{d}, r{a}, sasl r{b}")->addParameter("d", PR(rd))
				 ->addParameter("a", PR(ra))->addParameter("b", PR(rb)));
		}

		D(floatFloorRRI) {
			std::string op("floor.");
			op += condition_codes[((insn >> 7) & 0xf)];

			uint32_t i = insn & 0x3f;
			uint32_t ra = (insn >> 11) & 0x1f;
			uint32_t rd = (insn >> 16) & 0x1f;

			RV(NI(op, "r{d}, r{a}, sasl {i}")->addParameter("d", PR(rd))
				 ->addParameter("a", PR(ra))->addParameter("i", P_I(i)));
		}

		D(floatFLTSRRR) {
			std::string op("flts.");
			op += condition_codes[((insn >> 7) & 0xf)];

			uint32_t rb = insn & 0x1f;
			uint32_t ra = (insn >> 11) & 0x1f;
			uint32_t rd = (insn >> 16) & 0x1f;

			RV(NI(op, "r{d}, r{a}, sasl r{b}")->addParameter("d", PR(rd))
				 ->addParameter("a", PR(ra))->addParameter("b", PR(rb)));
		}

		D(floatFLTSRRI) {
			std::string op("flts.");
			op += condition_codes[((insn >> 7) & 0xf)];

			uint32_t i = insn & 0x3f;
			uint32_t ra = (insn >> 11) & 0x1f;
			uint32_t rd = (insn >> 16) & 0x1f;

			RV(NI(op, "r{d}, r{a}, sasl {i}")->addParameter("d", PR(rd))
				 ->addParameter("a", PR(ra))->addParameter("i", P_I(i)));
		}

		D(floatFLTURRR) {
			std::string op("fltu.");
			op += condition_codes[((insn >> 7) & 0xf)];

			uint32_t rb = insn & 0x1f;
			uint32_t ra = (insn >> 11) & 0x1f;
			uint32_t rd = (insn >> 16) & 0x1f;

			RV(NI(op, "r{d}, r{a}, sasl r{b}")->addParameter("d", PR(rd))
				 ->addParameter("a", PR(ra))->addParameter("b", PR(rb)));
		}

		D(floatFLTURRI) {
			std::string op("fltu.");
			op += condition_codes[((insn >> 7) & 0xf)];

			uint32_t i = insn & 0x3f;
			uint32_t ra = (insn >> 11) & 0x1f;
			uint32_t rd = (insn >> 16) & 0x1f;

			RV(NI(op, "r{d}, r{a}, sasl {i}")->addParameter("d", PR(rd))
				 ->addParameter("a", PR(ra))->addParameter("i", P_I(i)));
		}

		D(floatTrunc) {
			if( (insn >> 6) & 1 ) return floatTruncRRI(insn, src_addr);
			else return floatTruncRRR(insn, src_addr);
		}

		D(floatFloor) {
			if( (insn >> 6) & 1 ) return floatFloorRRI(insn, src_addr);
			else return floatFloorRRR(insn, src_addr);
		}

		D(floatFLTS) {
			if( (insn >> 6) & 1 ) return floatFLTSRRI(insn, src_addr);
			else return floatFLTSRRR(insn, src_addr);
		}

		D(floatFLTU) {
			if( (insn >> 6) & 1 ) return floatFLTURRI(insn, src_addr);
			else return floatFLTURRR(insn, src_addr);
		}

		D(floatDispatchConvert) {
			if (((insn >> 22) & 1) == 1) return new scalar32_insn("*unknown scalar32 (possible control register access)*", "");
			switch( ((insn >> 21) & 3) ) {
			case 0:
				return floatTrunc(insn, src_addr);
			case 1:
				return floatFloor(insn, src_addr);
			case 2:
				return floatFLTS(insn, src_addr);
			case 3:
				return floatFLTU(insn, src_addr);
			default:
				return new scalar32_insn("*unknown scalar32 (float int conversion)*", "");
			}
		}

		D(floatDispatch) {
			if ( (insn >> 26) & 1 ) return floatDispatchConvert(insn, src_addr);
			else return floatDispatchConvert(insn, src_addr);
		}

		D(controlRegisterAccess) {
			std::string fmt = ((insn >> 21) & 1)?"r{d}, p{a}":"p{d}, r{a}";
			uint32_t reg_dest = (insn & 0x0000001f);
			uint32_t reg_src = ((insn >> 16) & 0x0000001f);

			RV(NI("mov", fmt)->addParameter("a", PR(reg_dest))->addParameter("d", PR(reg_src)));
		}

		GI {
			// read the instruction and check the type
			// this should be possible by checking for
			// certain bit-patterns
			uint32_t insn_raw = READ_DWORD(buffer);
			uint8_t insn_type = (insn_raw >> 28) ^ 0x08;

			scalar32_insn *rv;
			switch( insn_type ) {
			case 0: // 0b000
			case 1: // 0b001
				rv = dispatchBranched(insn_raw, src_addr);
				break;
			case 2: // 0b010
				rv = memoryAccessDispatch(insn_raw, src_addr);
				break;
			case 3: // 0b011
			case 4: // 0b100
				if ( insn_raw >> 24 & 0x08 ) rv = floatDispatch(insn_raw, src_addr);
				else rv = aluDispatch(insn_raw, src_addr);
				break;
			default: // 0b101 only - 0b110 would be part of the size flags for SCALAR48
				rv = new scalar32_insn("*unknown scalar32 (starts 1101/0x0d)*", "");
			}
			uint8_t srcData[4];
			for( int i = 0; i < 4; i++ ) srcData[i] = (uint8_t)(*(buffer+i));
			rv->setSourceData(srcData);
			return rv;
		}
	}
}

#undef INSTRUCTION_TYPE
#undef INSTRUCTION_STORAGE
