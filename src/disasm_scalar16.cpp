#include <string>

#include <disasm_config.h>
#include <disasm_scalar16.hpp>
#include <vc4_data.hpp>
#include <vc4_parameter.hpp>

using namespace std;

#define INSTRUCTION_TYPE scalar16_insn
#define INSTRUCTION_STORAGE uint16_t

namespace disasm {
	namespace scalar16 {
		D(getSimpleInsn) {
			scalar16_insn *rv;
			std::any argv;
			string noargs[] = { "bkpt", "nop", "sleep", "user", "ei", "di", "cbclr",
				"cbadd1", "cbadd2", "cbadd3", "rti" };
			uint16_t mask = 0x001f;
			ParameterTypes type = ParameterTypes::REGISTER;

			if (insn < 10) rv = new scalar16_insn(noargs[insn], "");
			else if (insn >= 10 && insn <= 31) return new scalar16_insn("*unknown scalar16 simple*", "");
			else if ((insn & 0x0080) && !(insn & 0x0040)) {
				if (insn & 0x0020) rv = new scalar16_insn("switch.b", "r{p}");
				else rv = new scalar16_insn("switch", "r{p}");
				mask = 0x000f;
			} else if ((insn & 0x0040)) {
				if (insn & 0x0020) rv = new scalar16_insn("bl", "r{p}");
				else rv = new scalar16_insn("b", "r{p}");
			} else if (insn & 0x0020)
				rv = new scalar16_insn("swi", "r{p}");
			else if ((insn & 0x00c0) == 0x00c0)
				rv = new scalar16_insn("version", "r{p}");
			else {
				rv = new scalar16_insn("swi", "{p}");
				type = ParameterTypes::OFFSET;
				mask = 0x003f;
			}

			if (type == ParameterTypes::OFFSET) // eg: signed
				rv->addParameter("p", vc4_parameter(type, (int32_t)(insn & mask)));
			else
				rv->addParameter("p", vc4_parameter(type, (uint32_t)(insn & mask)));

			return rv;
		}

		uint8_t which_b_reg(uint16_t insn) {
			uint8_t bb = (uint8_t)((insn & 0x0060) >> 4);
			return bb==0?0:(bb==1?6:(bb==2?16:24));
		}

		D(loadStoreRange) {
			std::string opname((((insn >> 6) & 1) == 1)?"stm":"ldm");
			std::string spdir((((insn >> 6) & 1) == 1)?"--sp":"sp++");
			uint32_t rb = which_b_reg(insn);
			uint32_t rm = (insn & 0x000f);
			std::string fmt((rb == rm)?"r{b}, ({d})":"r{b}-r{m}, ({d})");
			RV(NI(opname, fmt)->addParameter("b", PR(rb))
				 ->addParameter("m", PR(rm))->addParameter("d", PD(spdir)));
		}

		D(loadStoreSPOffset) {
			std::string opname((((insn >> 9) & 1) == 1)?"st":"ld");
			std::string spd("sp");
			int32_t offs = ((insn >> 4) & 0x001f) * 4;
			uint32_t rd = insn & 0x000f;

			if (offs < 0) {
				spd += "-";
				offs *= -1;
			}	else spd += "+";

			RV(NI(opname, "r{d}, ({s}{o})")->addParameter("d", PR(rd))
				 ->addParameter("s", PD(spd))->addParameter("o", PO(offs)));
		}

		D(loadStoreWidth) {
			std::string opname((((insn >> 8) & 1) == 1)?"st":"ld");
			opname += mem_op_widths[(insn >> 9) & 3];
			uint32_t rd = insn & 0x000f;
			uint32_t rs = (insn >> 4) & 0x000f;
			RV(NI(opname, "r{d}, (r{s})")->addParameter("d", PR(rd))
				 ->addParameter("s", PR(rs)));
		}

		D(addSPOffset) {
			uint32_t rd = insn & 0x001f;
			int32_t offs = (insn >> 5) & 0x001f;
			offs *= 4;

			RV(NI("add", "r{d}, sp, {o}")->addParameter("d", PR(rd))
				 ->addParameter("o", PO(offs)));
		}

		D(branchWithCondition) {
			std::string opname("b");
			opname += condition_codes[(insn >> 7) & 7];
			int32_t offs = (int8_t)(insn & 0x7f);
			offs *= 2;
			RV(NI(opname, "{o}")->addParameter("o", PO(offs)));
		}

		D(loadStoreRegisterOffset) {
			std::string opname((((insn >> 12) & 1) == 1)?"st":"ld");
			uint32_t rd = insn & 0x000f;
			uint32_t rs = (insn & 0x00f0) >> 4;
			uint32_t u = ((insn & 0x0f00) >> 8) * 4;
			RV(NI(opname, "r{d}, (r{s}+{u})")->addParameter("d", PR(rd))
				 ->addParameter("s", PR(rs))->addParameter("u", P_I(u)));
		}

		D(getMemoryOperation) {
			uint8_t c = (insn >> 7) & 0x007f;  // seven bits tells which op, overall

			if( c & 0x0100 ) return loadStoreRegisterOffset(insn, src_addr);
			else if( ((c & 0x0030) >> 4) == 3 ) return branchWithCondition(insn, src_addr);
			else if( c & 64 ) return addSPOffset(insn, src_addr);
			else if( c & 16 ) return loadStoreWidth(insn, src_addr);
			else if( c & 8 ) return loadStoreSPOffset(insn, src_addr);
			else if ( c & 4 ) return loadStoreRange(insn, src_addr);
			else return new scalar16_insn("*unknown scalar16 memory*", "");
		}


#define FOUR_BIT(x) (al_ops[((x)&0x000f) << 1])
#define FIVE_BIT(x) (al_ops[((x)&0x001f)])

		D(getArithOrLogicalRegisterRegister) {
			uint8_t dc = ((insn & 0x1f00) >> 8);
			uint32_t rd = insn & 0x000f;
			uint32_t rs = (insn >> 4) & 0x000f;
			std::string fmt("r{d}, r{s}");
			std::string add;
			if( dc == 19 ) add = " << 1";
			else if( dc > 20 && dc < 24 ) add = string(" << ") + std::to_string(dc - 19);
			if (add.length() > 0) fmt += add;

			RV(NI(FIVE_BIT((insn & 0x1f00) >> 8), fmt)
				 ->addParameter("d", PR(rd))->addParameter("s", PR(rs)));
		}

		D(getArithOrLogicalRegisterImmediate) {
			std::string fmt((((insn & 0x1e00) >> 9) == 3)?"r{d}, {u} << 3":"r{d}, {u}");
			uint32_t rd = insn & 0x000f;
			uint32_t u = (insn >> 4) & 0x001f;
			RV(NI(FOUR_BIT((insn & 0x1e00) >> 9), fmt)
				 ->addParameter("d", PR(rd))
				 ->addParameter("u", P_I(u)));
		}

#undef FOUR_BIT
#undef FIVE_BIT
		D(getArithLogical) {
			return ((insn&0x6000) == 0x6000)?
				getArithOrLogicalRegisterImmediate(insn, src_addr):
				getArithOrLogicalRegisterRegister(insn, src_addr);
		}

		GI {
			// read the instruction and check the type
			// this should be possible by checking for
			// certain bit-patterns
			uint16_t insn_raw = READ_WORD(buffer);
			scalar16_insn *rv;
			if ( (insn_raw & 0xFF00) == 0 ) rv = getSimpleInsn(insn_raw, src_addr);
			else if ( (insn_raw & 0x4000) == 0 ) rv = getMemoryOperation(insn_raw, src_addr);
			else rv = getArithLogical(insn_raw, src_addr);

			uint8_t srcData[] = { (uint8_t)(*buffer), (uint8_t)(*(buffer+1)) };
			rv->setSourceData( srcData );
			return rv;
		}
	}
}

#undef INSTRUCTION_TYPE
#undef INSTRUCTION_STORAGE
