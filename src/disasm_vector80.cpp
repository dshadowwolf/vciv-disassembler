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

		const static string G[] = { "", "*", "++ ", "*++ " };
		const static string D[] = { "H8(y,0)", "V8(0,0+x)", "H8(y,16)", "V8(y,16)", "H8(y,32)", "V8(0,32+x)",
			"H8(y,48)", "V8(0,48+x)", "H16(0+y,0)", "V16(0,0+x)", "H16(y,32)", "V16(y,32+x)",
			"H32(y,0)", "V32(0,0+x)", "-", "-d??" };
		const static string A[] = { "H8(y,0)", "V8(y,0)", "H8(y,16)", "V8(y,16)", "H8(y,32)", "V8(y,32)",
			"H8(y,48)", "V8(y,48)", "H16(0+y,0)", "V16(0,0+x)", "H16(y,32)", "V16(y,32+x)",
			"H32(y,0)", "V32(0,0+x)", "-", "-a??" };
		const static string B[] = { "H8(y,0)", "V8(y,0)", "H8(y,16)", "V8(y,16)", "H8(y,32)", "V8(y,32)",
			"H8(y,48)", "V8(y,48)", "H16(0+y,0)", "V16(0,0+x)", "H16(y,32)", "V16(y,32+x)",
			"H32(y,0)", "V32(0,0+x)", "-", "-b??" };
		const static string Z[] = { "H8(y,0)", "H8(y,16)", "H8(y,32)", "H8(y,48)", "H16(0+y,0)", "H16(y,32)", "H32(y,0)", "-" };
		const static string Y[] = { "V8(y,0)", "V8(y,16)", "V8(y,32)", "V8(y,48)", "V16(0+y,0)", "V16(y,32)", "V32(y,0)", "-" };
		const static string S[] = { "", "sru001[unused]", "sru002[unused]", "sru003[unused]", "sru004[unused]", "sru005[unused]",
			"(clra)", "sru007[unused]", "sru008[unused]", "sru009[unused]", "sru010[unused]", "sru011[unused]",
			"sru012[unused]", "sru013[unused]", "sru014[unused]", "sru015[unused]", "sru016[unused]", "sru017[unused]",
			"sru018[unused]", "sru019[unused]", "sru020[unused]", "sru021[unused]", "sru022[unused]", "sru023[unused]",
			"sru024[unused]", "sru025[unused]", "sru026[unused]", "sru027[unused]", "sru028[unused]", "sru029[unused]",
			"sru030[unused]", "sru031[unused]", "UADD", "USUB", "UACC", "UDEC", "CLRA", "CLRA USUB", "CLRA UACC",
			"CLRA UDEC", "SADD", "SSUB", "SACC", "SDEC", "CLRA SADD", "CLRA SSUB", "CLRA SACC", "CLR SDEC", "UADDH",
			"USUBH", "UACCH", "UDECH", "CLRA UADDH", "CLRA USUBH", "CLRA UACCH", "CLR UDECH", "SADDH", "SSUBH", "SACCH",
			"SDECH", "CLRA SADDH", "CLRA SSUBH", "CLRA SACCH", "CLRA SDECH", "SUMU r0", "SUMU r1", "SUMU r2", "SUMU r3",
			"SUMU r4", "SUMU r5", "SUMU r6", "SUMU r7", "SUMS r0", "SUMS r1", "SUMS r2", "SUMS r3", "SUMS r4", "SUMS r5",
			"SUMS r6", "SUMS r7", "MAX2 r0", "MAX2 r1", "MAX2 r2", "MAX2 r3", "MAX2 r4", "MAX2 r5", "MAX2 r6", "MAX2 r7",
			"IMIN r0", "IMIN r1", "IMIN r2", "IMIN r3", "IMIN r4", "IMIN r5", "IMIN r6", "IMIN r7", "MAX4 r0", "MAX4 r1",
			"MAX4 r2", "MAX4 r3", "MAX4 r4", "MAX4 r5", "MAX4 r6", "MAX4 r7", "IMAX r0", "IMAX r1", "IMAX r2", "IMAX r3",
			"IMAX r4", "IMAX r5", "IMAX r6", "IMAX r7", "MAX6 r0", "MAX6 r1", "MAX6 r2", "MAX6 r3", "MAX6 r4", "MAX6 r5",
			"MAX6 r6", "MAX6 r7", "MAX r0", "MAX r1", "MAX r2", "MAX r3", "MAX r4", "MAX r5", "MAX r6", "MAX r7" };

    vector80_insn *vector80memory(v80_dmap insn) {
			// for memory operations, this is fixed encoding
			uint8_t rep = insn.first & 7;
			uint8_t width = (insn.first >> 3) & 3;
			uint8_t oper = (insn.first >> 5) & 0x1f;
			uint8_t p = (insn.end >> 13) & 7;
			string opname("v");
			opname += vector_widths[width];
			opname += vector_ops_full[oper];

			string reps(vector_reps[rep]);

			vector80_insn *rv;

			if ( ((insn.mid >> 28) & 0xe) == 0xe ) {
				rv = new vector80_insn(opname, "-, {d}{G}{g}, {A}[y={a}, x={rax}]{H}{h}, {i}({s}+={f}) {R} {IF} {SETF}");

				uint8_t rax = insn.trail & 0x000f;
				uint8_t fa = (insn.trail >> 4) & 0x003f;
				uint8_t fd = (insn.trail >> 10) & 0x003f;
				uint8_t _r = (insn.trail >> 12) & 0xf;
				uint8_t _A = (insn.mid >> 18) & 0xf;
				uint8_t _h = (insn.trail >> 6) & 0xf;
				uint32_t _i = ((((insn.end >> 4) & 0x7f) << 2) & (insn.end & 3));
				bool _F = ((insn.mid >> 11) == 1);

				vc4_parameter rd(ParameterTypes::IMMEDIATE, (uint32_t)((insn.mid >> 26) & 0x3f));
				vc4_parameter _g(ParameterTypes::DATA, string(G[((insn.trail >> 10) & 3)]));
				vc4_parameter g_(ParameterTypes::DATA, _r<=14?(string("+r")+std::to_string(_r)):"");
				vc4_parameter A_(ParameterTypes::VECTOR_REGISTER, A[_A]);
				vc4_parameter a_(ParameterTypes::IMMEDIATE, (uint32_t)((insn.mid >> 12) & 0x3f));
				vc4_parameter ra_x(ParameterTypes::IMMEDIATE, (uint32_t)rax);
				vc4_parameter _H(ParameterTypes::DATA, G[(insn.trail >> 4) & 3]);
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
			} else if( ((insn.mid >> 18) & 0xe) == 0xe ) {
				uint16_t _i = ((insn.end & 3) | (((insn.end >> 4) & 0x7f) << 2));
				uint8_t  rs = ((insn.end >> 2) & 0xf);
				string  ifz(vector_flags_w[p+2]);
				uint8_t  _m = (insn.trail & 0x0f);
				uint8_t  _H = ((insn.trail >> 4) & 3);
				uint8_t  _h = ((insn.trail >> 6) & 0xf);
				uint8_t  _G = ((insn.trail >> 10) & 3);
				uint8_t  _g = ((insn.trail >> 12) & 0xf);
				uint8_t  _b = (insn.mid & 0x7f);
				bool   setf = (((insn.mid >> 11) & 1) == 1);
				uint8_t  _a = ((insn.mid >> 12) & 0x3f);
				uint8_t  _d = ((insn.mid >> 22) & 0x3f);
				uint8_t  _D = ((insn.mid >> 28) & 0xf);
				uint16_t im = (_i*128)+_b;

				rv = new vector80_insn(opname, "{D}{d}{G}{g}, -[y={a}, x={m}]{H}{h1}] {i}({s}+={h2}) {REP} {IFZ} {SETF}");

				vc4_parameter D(ParameterTypes::VECTOR_REGISTER, A[_D]);
				vc4_parameter d(ParameterTypes::IMMEDIATE, (uint32_t)_d);
				vc4_parameter G_(ParameterTypes::DATA, G[_G]);
				vc4_parameter g(ParameterTypes::DATA, _g>=15?"":(string("+r")+std::to_string(_g)));
				vc4_parameter a_(ParameterTypes::IMMEDIATE, (uint32_t)_a);
				vc4_parameter m(ParameterTypes::IMMEDIATE, (uint32_t)_m);
				vc4_parameter H_(ParameterTypes::DATA, G[_H]);
				vc4_parameter h_(ParameterTypes::DATA, _h>=15?"":(string("+r")+std::to_string(_h)));
				vc4_parameter imm(ParameterTypes::IMMEDIATE, (uint32_t)im);
				vc4_parameter s(ParameterTypes::REGISTER, (uint32_t)rs);
				vc4_parameter _h_(ParameterTypes::REGISTER, (uint32_t)_h);
				vc4_parameter REP(ParameterTypes::DATA, reps);
				vc4_parameter IF(ParameterTypes::DATA, ifz);
				vc4_parameter SETF(ParameterTypes::DATA, setf?"SETF":"");

				rv->addParameter("D", D)->addParameter("d", d)->addParameter("G", G_)->addParameter("a", a_)
					->addParameter("m", m)->addParameter("H", H_)->addParameter("h1", h_)->addParameter("i", imm)
					->addParameter("s", s)->addParameter("h2", _h_)->addParameter("REP", REP)->addParameter("IFZ", IF)
					->addParameter("SETF", SETF);
			} else if( !((insn.mid >> 10) & 1) ) {
				string _k(G[((insn.end >> 2) & 0xf)]);
				string _K(G[(insn.end & 3)]);
				string ACC_(S[((insn.end >> 6) & 0x3f)]);
				string ifz(vector_flags_w[p+2]);
			  uint8_t _m = (insn.trail & 0xf);
				string _H(G[((insn.trail >> 4) & 3)]);
				string h((((insn.trail >> 6) & 0xf)>=15?"":(string("+r")+std::to_string(((insn.trail >> 6) & 0xf)))));
				string _G(G[(insn.mid >> 10) & 3]);
				string g((((insn.trail >> 12) & 0xf)>=15?"":(string("+r")+std::to_string(((insn.trail >> 12) & 0xf)))));
				uint8_t _b = (insn.mid & 0x3f);
				string _B(A[((insn.mid >> 6) & 0xf)]);
				bool setf = ((insn.mid >> 11) & 1) == 1;
				uint8_t _a = ((insn.mid >> 12) & 0x3f);
				string _A(A[((insn.mid >> 18) & 0xf)]);
				uint8_t _d = ((insn.mid >> 22) & 0x3f);
 				string _D(A[((insn.mid >> 28) & 0xf)]);

				rv = new vector80_insn(opname, "{D}{d}{G}{g}, {A}[y={a}, x={m}]{H}{h}, {B}{b}{K}{k} {REP} {IFZ} {SETF} {ACC}");

				vc4_parameter D(ParameterTypes::VECTOR_REGISTER, _D);
				vc4_parameter d(ParameterTypes::DATA, _d);
				vc4_parameter G_(ParameterTypes::DATA, _G);
				vc4_parameter _g(ParameterTypes::DATA, g);
				vc4_parameter A_(ParameterTypes::VECTOR_REGISTER, _A);
				vc4_parameter a_(ParameterTypes::IMMEDIATE, (uint32_t)_a);
				vc4_parameter m_(ParameterTypes::IMMEDIATE, (uint32_t)_m);
				vc4_parameter H_(ParameterTypes::DATA, _H);
				vc4_parameter _h(ParameterTypes::DATA, h);
				vc4_parameter B_(ParameterTypes::VECTOR_REGISTER, _B);
				vc4_parameter b_(ParameterTypes::IMMEDIATE, (uint8_t)_b);
				vc4_parameter K(ParameterTypes::DATA, _K);
				vc4_parameter k(ParameterTypes::DATA, _k);
			  vc4_parameter REP(ParameterTypes::DATA, reps);
				vc4_parameter IFZ(ParameterTypes::DATA, ifz);
				vc4_parameter SETF(ParameterTypes::DATA, setf?"SETF":"");
				vc4_parameter ACC(ParameterTypes::DATA, ACC_);

				rv->addParameter("D", D)->addParameter("d", d)->addParameter("G", G_)->addParameter("g", _g)
					->addParameter("A", A_)->addParameter("a", a_)->addParameter("m", m_)->addParameter("H", H_)
					->addParameter("h", _h)->addParameter("B", B_)->addParameter("b", b_)->addParameter("K", K)
					->addParameter("k", k)->addParameter("REP", REP)->addParameter("IFZ", IFZ)->addParameter("SETF", SETF)
					->addParameter("ACC", ACC);
			} else if( ((insn.mid >> 10) & 1) ) {
				// 1111 10 mop:5 width:2 r:3 d:10 a:10 F 1 l:10 f_d:6 f_a:6 Ra_x:4 P:3 f_i:7 j:6
				// 1111 10MM MMMW WRRR DDDD dddd ddAA AAaa aaaa F1ll llll llll gggg GGhh hhHH mmmm PPPS SSSS SSbb bbbb
				// "; v%s{W}%s{M} %s{D}%d{d}%s{G}%s{g}, %s{A}[y=%d{a},x=%d{m}]%s{H}%s{h}, %d{(b*1024)+l} %s{R}%s{P}%s{F} %s{S}"
				// v{W}{M} {D}{d}{G}{g}, {A}[y={a}, x={m}]{H}{h}, {imm} {REPS} {IFZ} {SETF} {ACC}
				uint32_t _b = ((insn.end & 0x3f) * 1024);
				string _ACC(S[((insn.end) >> 6) & 0x3f]);
				string _IFZ(vector_flags_w[p+2]);
				uint8_t  _m = (insn.trail & 0xf);
				string _H(G[(insn.trail >> 4) & 3]);
				string _h((((insn.trail >> 6) & 0xf)>=15?"":(string("+r")+std::to_string(((insn.trail >> 6) & 0xf)))));
				string _G(G[(insn.trail >> 10) & 3]);
				string _g((((insn.trail >> 12) & 0xf)>=15?"":(string("+r")+std::to_string(((insn.trail >> 12) & 0xf)))));
				uint16_t _l = (insn.mid & 0x3ff);
				uint32_t im = _b+_l;
				uint8_t  _a = (insn.mid >> 12) & 0x3f;
				string _A(A[((insn.mid >> 18) & 0xf)]);
				uint8_t  _d = (insn.mid >> 22) & 0x3f;
 				string _D(A[((insn.mid >> 28) & 0xf)]);

				rv = new vector80_insn(opname, "{D}{d}{G}{g}, {A}[y={a}, x={m}]{H}{h}, {imm} {REPS} {IFZ} {SETF} {ACC}");

				vc4_parameter rD(ParameterTypes::VECTOR_REGISTER, _D);
				vc4_parameter rDd(ParameterTypes::IMMEDIATE, (uint32_t)_d);
				vc4_parameter rDG(ParameterTypes::DATA, _G);
				vc4_parameter rDGg(ParameterTypes::DATA, _g);
				vc4_parameter rA(ParameterTypes::VECTOR_REGISTER, _A);
				vc4_parameter rAa(ParameterTypes::IMMEDIATE, (uint32_t)_a);
				vc4_parameter rAm(ParameterTypes::IMMEDIATE, (uint32_t)_m);
				vc4_parameter rAH(ParameterTypes::DATA, _H);
				vc4_parameter rAHh(ParameterTypes::DATA, _h);
				vc4_parameter imm(ParameterTypes::IMMEDIATE, (uint32_t)im);
				vc4_parameter REPS(ParameterTypes::DATA, reps);
				vc4_parameter IFZ(ParameterTypes::DATA, _IFZ);
				vc4_parameter SETF(ParameterTypes::DATA, (((insn.mid >> 11)& 1) == 1)?"SETF":"");
				vc4_parameter ACC(ParameterTypes::DATA, _ACC);

				rv->addParameter("D", rD)->addParameter("d", rDd)->addParameter("G", rDG)->addParameter("g", rDGg)
					->addParameter("A", rA)->addParameter("a", rAa)->addParameter("m", rAm)->addParameter("H", rAH)
					->addParameter("h", rAHh)->addParameter("imm", imm)->addParameter("REP", REPS)
					->addParameter("IFZ", IFZ)->addParameter("SETF", SETF)->addParameter("ACC", ACC);
			} else {
				rv = new vector80_insn("*unknown*", "");
			}

			return rv;
		}

		vector80_insn *vector80alu(v80_dmap insn) {
			vector80_insn *rv;
			
			string sz(((insn.first >> 9) & 1)==1?"32":"16");
			uint8_t opc = (insn.first >> 3) & 0x3f;
			string opname("v");
			opname += sz + vector_ops_full[opc];
			string _D(A[((insn.mid >> 28) & 0xf)]);
			uint8_t _d = ((insn.mid >> 22) & 0x3f);
			string _A(A[((insn.mid >> 18) & 0xf)]);
			uint8_t _a = ((insn.mid >> 12) & 0x3f);
			string setf((((insn.mid >> 11) & 1) == 1)?"SETF":"");
			uint8_t f_i = (insn.end >> 6) & 0x7f;
			string ifz(vector_flags_w[((insn.end >> 13) & 7)+2]);
			uint8_t _m = insn.trail & 0xf;
			string _H(G[((insn.trail >> 4) & 3)]);
			uint8_t __h = ((insn.trail >> 6) & 0xf);
			string _h( __h==15?"":string("+r")+std::to_string(__h));
			string _G(G[((insn.trail >> 10) & 3)]);
			uint8_t __g = ((insn.trail >> 12) & 0xf);
			string _g( __g==15?"":string("+r")+std::to_string(__g));
			string _ACC(S[f_i]);
			string _REPS(vector_reps[(insn.first & 7)]);

			if ( ((insn.mid >> 10) & 1) == 1 ) {
				uint32_t imm = (((insn.end & 0x3f) * 1024) + (insn.mid & 0x3ff));

				rv = new vector80_insn(opname, "{D}{d}{G}{g}, {A}[y={a}, x={m}]{H}{h}, {imm} {REPS} {IFZ} {SETF} {X}");

				vc4_parameter D_(ParameterTypes::VECTOR_REGISTER, _D);
				vc4_parameter A_(ParameterTypes::VECTOR_REGISTER, _A);

				vc4_parameter d_(ParameterTypes::IMMEDIATE, (uint32_t)_d);
				vc4_parameter a_(ParameterTypes::IMMEDIATE, (uint32_t)_a);
				vc4_parameter m_(ParameterTypes::IMMEDIATE, (uint32_t)_m);
				vc4_parameter _imm(ParameterTypes::IMMEDIATE, (uint32_t)imm);

				vc4_parameter H_(ParameterTypes::DATA, _H);
				vc4_parameter h_(ParameterTypes::DATA, _h);
				vc4_parameter G_(ParameterTypes::DATA, _G);
				vc4_parameter g_(ParameterTypes::DATA, _g);
				vc4_parameter R_(ParameterTypes::DATA, _REPS);
				vc4_parameter I_(ParameterTypes::DATA, ifz);
				vc4_parameter SF(ParameterTypes::DATA, setf);
				vc4_parameter AC(ParameterTypes::DATA, _ACC);

				rv->addParameter("D", D_)->addParameter("d", d_)->addParameter("G", G_)->addParameter("d", g_)
					->addParameter("A", A_)->addParameter("a", a_)->addParameter("m", m_)
					->addParameter("H", H_)->addParameter("h", h_)->addParameter("imm", _imm)
					->addParameter("REPS", R_)->addParameter("IFZ", I_)->addParameter("SETF", SF)->addParameter("X", AC);
			} else {
				// 1111 11X   v:6  r:3 d:10         a:10        F0 b:10        f_d:6  f_a:6  Ra_x:4 P:3 f_i:7   f_b:6
				// 1111 11Lv vvvv vRRR DDDD dddd ddAA AAaa aaaa F0BB BBbb bbbb gggg GGhh hhHH mmmm PPPS SSSS SSkk kkKK
				// "; v%s{L}%s{v} %s{D}%d{d}%s{G}%s{g}, %s{A}[y=%d{a},x=%d{m}]%s{H}%s{h}, %s{B}%d{b}%s{K}%s{k} %s{R}%s{P}%s{F} %s{S}"
				// v{L}{v} {D}{d}{G}{g}, {A}[y={a}, x={m}]{H}{h}, {B}{b}{K}{k} {REPS} {IFZ} {SETF} {X}
				string _K(G[insn.end & 3]);
				uint8_t __k = (insn.end >> 2) & 0xf;
				string _k(__k==15?"":(string("+r")+std::to_string(__k)));
				uint8_t _b = (insn.mid & 0x3f);
				string _B(A[((insn.mid >> 6) & 0xf)]);

				rv = new vector80_insn(opname, "{D}{d}{G}{g}, {A}[y={a}, x={m}]{H}{h}, {B}{b}{K}{k} {REPS} {IFZ} {SETF} {X}");

				vc4_parameter D_(ParameterTypes::VECTOR_REGISTER, _D);
				vc4_parameter A_(ParameterTypes::VECTOR_REGISTER, _A);
				vc4_parameter B_(ParameterTypes::VECTOR_REGISTER, _B);

				vc4_parameter d_(ParameterTypes::IMMEDIATE, (uint32_t)_d);
				vc4_parameter a_(ParameterTypes::IMMEDIATE, (uint32_t)_a);
				vc4_parameter b_(ParameterTypes::IMMEDIATE, (uint32_t)_b);
				vc4_parameter m_(ParameterTypes::IMMEDIATE, (uint32_t)_m);

				vc4_parameter H_(ParameterTypes::DATA, _H);
				vc4_parameter h_(ParameterTypes::DATA, _h);
				vc4_parameter G_(ParameterTypes::DATA, _G);
				vc4_parameter g_(ParameterTypes::DATA, _g);
				vc4_parameter K_(ParameterTypes::DATA, _K);
				vc4_parameter k_(ParameterTypes::DATA, _k);
				vc4_parameter R_(ParameterTypes::DATA, _REPS);
				vc4_parameter I_(ParameterTypes::DATA, ifz);
				vc4_parameter SF(ParameterTypes::DATA, setf);
				vc4_parameter AC(ParameterTypes::DATA, _ACC);

				rv->addParameter("D", D_)->addParameter("d", d_)->addParameter("G", G_)->addParameter("d", g_)
					->addParameter("A", A_)->addParameter("a", a_)->addParameter("m", m_)
					->addParameter("H", H_)->addParameter("h", h_)
					->addParameter("B", B_)->addParameter("b", b_)->addParameter("K", K_)->addParameter("k", k_)
					->addParameter("REPS", R_)->addParameter("IFZ", I_)->addParameter("SETF", SF)->addParameter("X", AC);
			}

			return rv;
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
