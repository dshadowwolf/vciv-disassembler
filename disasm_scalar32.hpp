#ifndef __DISASM_SCALAR32_H_
#define __DISASM_SCALAR32_H_

#include "disasm_insn_raw.hpp"

using namespace std;

namespace disasm {
    class scalar32_insn : public vc4_insn {
        public:
            inline scalar32_insn(string insn_name, string format)
                : vc4_insn(insn_name, string("{name} ")+format, 32) {};
   };
};

#endif // __DISASM_SCALAR32_H_
