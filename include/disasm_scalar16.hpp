#ifndef __DISASM_SCALAR16_H_
#define __DISASM_SCALAR16_H_

#include <disasm_insn_raw.hpp>

using namespace std;

namespace disasm {
	class scalar16_insn : public vc4_insn {
	public:
		inline scalar16_insn(string insn_name, string format)
			: vc4_insn(insn_name, string("{name} ")+format, 16) {};
		inline size_t getSizeBytes() { return 2; };
	};
};

#endif // __DISASM_SCALAR16_H_
