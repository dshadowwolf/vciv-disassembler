#include <string>

#include <disasm_config.h>
#include <disasm_scalar16.hpp>
#include <vc4_data.hpp>
#include <vc4_parameter.hpp>

using namespace std;

namespace disasm {
	namespace scalar16 {
		scalar16_insn *getSimpleInsn(uint16_t insn) {
			scalar16_insn *rv;
			std::any argv;
			string noargs[] = { "bkpt", "nop", "sleep", "user", "ei", "di", "cbclr",
				"cbadd1", "cbadd2", "cbadd3", "rti" };
			if (insn < 10) rv = new scalar16_insn(noargs[insn], "");
			else if (insn >= 10 && insn <= 31) return new scalar16_insn("*unknown*", "");
			else if ((insn & 0x0080) && !(insn & 0x0040)) {
				vc4_parameter p(ParameterTypes::REGISTER, (uint32_t)(insn & 0x000f));
				if (insn & 0x0020) rv = new scalar16_insn("switch.b", "r{d}");
				else rv = new scalar16_insn("switch", "r{d}");
				rv->addParameter("d", p);
			} else if ((insn & 0x0040)) {
				vc4_parameter p(ParameterTypes::REGISTER, (uint32_t)(insn & 0x001f));
				if (insn & 0x0020) rv = new scalar16_insn("bl", "r{d}");
				else rv = new scalar16_insn("b", "r{d}");
				rv->addParameter("d", p);
			} else if (insn & 0x0020) {
				rv = new scalar16_insn("swi", "r{d}");
				vc4_parameter p(ParameterTypes::REGISTER, (uint32_t)(insn & 0x001f));
				rv->addParameter("d", p);
			} else if ((insn & 0x00c0) == 0x00c0) {
				vc4_parameter p(ParameterTypes::REGISTER, (uint32_t)(0x001f));
				rv = new scalar16_insn("version", "r{d}");
				rv->addParameter("d", p);
			} else {
				vc4_parameter p(ParameterTypes::IMMEDIATE, (uint32_t)(insn & 0x003f));
				rv = new scalar16_insn("swi", "{u}");
				rv->addParameter("u", p);
			}

			return rv;
		}

		uint8_t which_b_reg(uint16_t insn) {
			uint8_t bb = (uint8_t)((insn & 0x0060) >> 4);
			return bb==0?0:(bb==1?6:(bb==2?16:24));
		}

		scalar16_insn *getMemoryOperation(uint16_t insn) {
			scalar16_insn *rv;
			uint8_t top = (insn & 0xff00) >> 8;

			switch (top) {
			case 0:
			case 1:
				rv = new scalar16_insn("*unknown*", "flop");
				break;
			case 2:
				do {
					bool rm = (which_b_reg(insn)==(insn & 0x001f));
					vc4_parameter b(ParameterTypes::REGISTER, (uint32_t)(which_b_reg(insn)));
					vc4_parameter m(ParameterTypes::REGISTER, (uint32_t)(insn & 0x001f));
					bool ldst = (insn&0x0080 == 0);
					string name(ldst?"ldm":"stm");
					string fmt(rm?
										 ((!ldst)?"r{b}, (--sp)":"r{b}, (sp++)"):
										 ((!ldst)?"r{b}-r{m}, (--sp)":"r{b}-r{m},(sp++)"));
					rv = new scalar16_insn(name, fmt);
					rv->addParameter("b", b)->addParameter("m", m);
				} while(0);
				break;
			case 3:
				do {
					bool rm = (which_b_reg(insn)==(insn & 0x001f));
					vc4_parameter b(ParameterTypes::REGISTER, (uint32_t)(which_b_reg(insn)));
					vc4_parameter m(ParameterTypes::REGISTER, (uint32_t)(insn & 0x001f));
					bool ldst = (insn&0x0080 == 0);
					string name(ldst?"ldm":"stm");
					string fmt((rm?
											((!ldst)?"r{b}, lr, (--sp)":"r{b}, lr, (sp++)"):
											((!ldst)?"r{b}-r{m},lr,(--sp)":"r{b}-r{m},lr,(sp++)")));
					rv = new scalar16_insn(name, fmt);
					rv->addParameter("b", b)->addParameter("m", m);
				} while(0);
				break;
			case 4:
			case 5:
				do {
					vc4_parameter d(ParameterTypes::REGISTER, (uint32_t)(insn & 0x000f));
					vc4_parameter o(ParameterTypes::IMMEDIATE, (uint32_t)((insn >> 4) & 0x001f));
					rv = new scalar16_insn("ld", "r{d}, (sp+({o}*4))");
					rv->addParameter("d", d)->addParameter("o", o);
				} while(0);
				break;
			case 6:
			case 7:
				do {
					vc4_parameter d(ParameterTypes::REGISTER, (uint32_t)(insn & 0x000f));
					vc4_parameter o(ParameterTypes::IMMEDIATE, (uint32_t)((insn >> 4) & 0x001f));
					rv = new scalar16_insn("st", "r{d}, (sp+({o}*4))");
					rv->addParameter("d", d)->addParameter("o", o);
				} while(0);
				break;
			default:
				do {
					if ( top < 16 ) {
						string opname(((top & 1) == 0)?"ld":"st");
						vc4_parameter d(ParameterTypes::REGISTER, (uint32_t)(insn & 0x000f));
						vc4_parameter s(ParameterTypes::REGISTER, (uint32_t)((insn >> 4) & 0x000f));
						opname += mem_op_widths[(top >> 1) & 0x0003];
						rv = new scalar16_insn(opname, "r{d}, (r{s})");
						rv->addParameter("d", d)->addParameter("s", s);
					} else {
						uint8_t type = ((insn & 0xf800) >> 11);
						switch(type) {
						case 0:
						case 1:
							// how did his happen ?
							rv = new scalar16_insn("*unknown*", "");
							break;
						case 2:
							do {
								vc4_parameter d(ParameterTypes::REGISTER, (uint32_t)(insn & 0x001f));
								vc4_parameter o(ParameterTypes::IMMEDIATE, (uint32_t)((insn >> 5) & 0x003f));
								rv = new scalar16_insn("add", "r{d}, sp, {o}*4");
								rv->addParameter("d", d)->addParameter("o", o);
							} while(0);
							break;
						case 3:
							do {
								vc4_parameter o(ParameterTypes::IMMEDIATE, (uint32_t)(insn & 0x003f));
								string c = condition_codes[(insn >> 6) & 0x0007];
								rv = new scalar16_insn(string("b")+c, "$+{o}*2");
								rv->addParameter("o", o);
							} while(0);
							break;
						case 4:
						case 5:
							do {
								vc4_parameter d(ParameterTypes::REGISTER, (uint32_t)(insn & 0x000f));
								vc4_parameter s(ParameterTypes::REGISTER, (uint32_t)((insn >> 4) & 0x000f));
								vc4_parameter u(ParameterTypes::IMMEDIATE, (uint32_t)((insn >> 8) & 0x000f));
								rv = new scalar16_insn("ld", "r{d}, (r{s}+{u}*4)");
								rv->addParameter("d", d)->addParameter("s", s)->addParameter("u", u);
							} while(0);
						case 6:
						case 7:
							do {
								vc4_parameter d(ParameterTypes::REGISTER, (uint32_t)(insn & 0x000f));
								vc4_parameter s(ParameterTypes::REGISTER, (uint32_t)((insn >> 4) & 0x000f));
								vc4_parameter u(ParameterTypes::IMMEDIATE, (uint32_t)((insn >> 8) & 0x000f));
								rv = new scalar16_insn("st", "r{d}, (r{s}+{u}*4)");
								rv->addParameter("d", d)->addParameter("s", s)->addParameter("u", u);
							} while(0);
						default:
							rv = new scalar16_insn("*unknown*", "{name}");
						}
					}
				} while(0);
			}
			return rv;
		}

#define FOUR_BIT(x) (al_ops[((x)&0x000f) << 1])
#define FIVE_BIT(x) (al_ops[((x)&0x001f)])

		scalar16_insn *getALRR(uint16_t insn) {
			uint8_t dc = ((insn & 0x1f00) >> 8);
			string fmt("r{d}, r{s}");
			string add;
			if( dc == 19 ) add = " << 1";
			else if( dc > 20 && dc < 24 ) add = string(" << ") + std::to_string(dc - 19);
			if (add.length() > 0) fmt += add;
			scalar16_insn *rv = new scalar16_insn(FIVE_BIT((insn & 0x1F00) >> 8), fmt);

			vc4_parameter d(ParameterTypes::REGISTER, (uint32_t)(insn & 0x000f));
			vc4_parameter s(ParameterTypes::REGISTER, (uint32_t)((insn & 0x00f0) >> 4));
			rv->addParameter("d", d)->addParameter("s", s);
			return rv;
		}

		scalar16_insn *getALRI(uint16_t insn) {
			uint8_t dc = (insn & 0x1e00) >> 9;
			scalar16_insn *rv = new scalar16_insn(FOUR_BIT(dc), dc==3?"r{d}, {u} << 3":"r{d}, {u}");
			vc4_parameter d(ParameterTypes::REGISTER, (uint32_t)(insn & 0x000f));
			vc4_parameter u(ParameterTypes::IMMEDIATE, (uint32_t)((insn & 0x1f0) >> 4));
			rv->addParameter("d", d)->addParameter("u", u);
			return rv;
		}
#undef FOUR_BIT
#undef FIVE_BIT

		scalar16_insn *getArithLogical(uint16_t insn) {
			return ((insn&0x6000) == 0x6000)?getALRI(insn):getALRR(insn);
		}

		scalar16_insn *getAddOrBranch(uint16_t insn) {
			scalar16_insn *rv;

			if (insn & 0x0800) {
				uint8_t cc_r = (insn & 0x0780) >> 7;
				string cc(condition_codes[cc_r]);
				rv = new scalar16_insn(string("b")+cc, "$+({o}*2)");
				rv->addParameter("o", vc4_parameter(ParameterTypes::IMMEDIATE, (uint32_t)(insn & 0x007f)));
			} else {
				vc4_parameter d(ParameterTypes::REGISTER, (uint32_t)(insn & 0x001f));
				vc4_parameter o(ParameterTypes::IMMEDIATE, (uint32_t)((insn & 0x03f0) >> 5));
				rv = new scalar16_insn("add", "r{d}, sp, ({o}*4)");
				rv->addParameter("d", d)->addParameter("o", o);
			}

			return rv;
		}

		scalar16_insn *getInstruction(uint8_t *buffer) {
			// read the instruction and check the type
			// this should be possible by checking for
			// certain bit-patterns
			uint16_t insn_raw = READ_WORD(buffer);//(uint16_t)(*((uint16_t *)buffer));
			if ( (insn_raw & 0xFF00) == 0 ) return getSimpleInsn(insn_raw);
			else if ( (insn_raw & 0x1000) && !(insn_raw & 0x4000) ) return getAddOrBranch(insn_raw);
			else if ( (insn_raw & 0x4000) == 0 ) return getMemoryOperation(insn_raw);
			else return getArithLogical(insn_raw);
		}
	}
}
