#ifndef __DISASM_VECTOR80_H_
#define __DISASM_VECTOR80_H_

#include <disasm_insn_raw.hpp>

using namespace std;

namespace disasm {
    class vector80_insn : public vc4_insn {
        public:
            inline vector80_insn(string insn_name, string fmt)
                : vc4_insn(insn_name, string("{name} ")+fmt, 80) {};
   };
};

#endif // __DISASM_VECTOR80_H_
