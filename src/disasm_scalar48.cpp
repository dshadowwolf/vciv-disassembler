#include <disasm_config.h>
#include <disasm_scalar48.hpp>
#include <vc4_data.hpp>
#include <vc4_parameter.hpp>

#define INSTRUCTION_TYPE scalar48_insn
#define INSTRUCTION_STORAGE s48d
namespace disasm {
	struct s48d {
		uint16_t insn;
		uint32_t arg;

		s48d(uint8_t *b) {
			insn = READ_WORD(b);
			arg = READ_DWORD_X(b+2);
		}
	};

	namespace scalar48 {
		D(simpleBranch) {
			int32_t offs = insn.arg;
			std::string op(((insn.insn >> 9) & 3)?"bl":"b");
			uint32_t target = src_addr + offs;
			RV(NI(op, "{t}")
				 ->addParameter("t", P_I(target)));
		}

		D(simpleJump) {
			std::string op(((insn.insn >> 8) & 1)?"jl":"j");
			RV(NI(op, "{o}")->addParameter("o", P_I(insn.arg)));
		}

		D(pcRelAdd) {
			RV(NI("add", "r{d}, pc, {o}")
				 ->addParameter("d", PR((insn.insn & 0x1f)))
				 ->addParameter("o", P_I(insn.arg)));
		}

		D(loadStoreRel) {
			uint32_t arg = (insn.arg & 0x07ffffff);
			uint32_t rd = (insn.insn & 0x1f);
			uint32_t rs = ((insn.arg >> 27) & 0x1f);
			std::string op(((insn.insn >> 5)&1)?"st":"ld");
			op += mem_op_widths[((insn.insn >> 6) & 3)];
			RV(NI(op, "r{d}, (r{s} + {o})")
				 ->addParameter("d", PR(rd))->addParameter("s", PR(rs))
				 ->addParameter("o", P_I(arg)));
		}

		D(loadStorePCRel) {
			uint32_t arg = (insn.arg & 0x07ffffff);
			uint32_t rd = (insn.insn & 0x1f);
			std::string op(((insn.insn >> 5)&1)?"st":"ld");
			op += mem_op_widths[((insn.insn >> 6) & 3)];
			RV(NI(op, "r{d}, (pc + {o})")
				 ->addParameter("d", PR(rd))->addParameter("o", P_I(arg)));
		}

		D(simpleDispatch) {
			switch((insn.insn >> 8) & 0xf) {
			case 0:
			case 2:
				return simpleBranch(insn, src_addr);
			case 1:
			case 3:
				return simpleJump(insn, src_addr);
			case 4:
				RV(NI("*unknown scalar48 simple*", ""));
			case 5:
				return pcRelAdd(insn, src_addr);
			case 6:
				return loadStoreRel(insn, src_addr);
			case 7:
				return loadStorePCRel(insn, src_addr);
			default:
				RV(NI("*unknown scalar48 simple*", ""));
			}
		}

		D(aluRegImm) {
			uint32_t rd = (insn.insn & 0x1f);
			std::string op(al_ops[((insn.insn >> 5) & 0x1f)]);
			RV(NI(op, "r{d}, {u}")->addParameter("d", PR(rd))
				 ->addParameter("u", P_I(insn.arg)));
		}

		D(aluRegRegImm) {
			uint32_t rd = (insn.insn & 0x1f);
			uint32_t rs = ((insn.insn >> 5) & 0x1f);
			RV(NI("add", "r{d}, r{s}, {u}")->addParameter("d", PR(rd))
				 ->addParameter("u", P_I(insn.arg))
				 ->addParameter("s", PR(rs)));
		}

		D(dispatchALU) {
			return ((insn.insn >> 10)&1)?aluRegRegImm(insn, src_addr):aluRegImm(insn, src_addr);
		}

		GI {
			s48d i(buffer);
			scalar48_insn *rv = (((i.insn >> 11) & 1)==1)?dispatchALU(i, src_addr):simpleDispatch(i, src_addr);
			uint8_t srcData[6];
			for( int i = 0; i < 6; i++ ) srcData[i] = (uint8_t)(*(buffer+i));
			rv->setSourceData( srcData );
			return rv;
		}
	}
}

#undef INSTRUCTION_TYPE
#undef INSTRUCTION_STORAGE
