#ifndef __DISASM_SCALAR48_H_
#define __DISASM_SCALAR48_H_

#include "disasm_insn_raw.hpp"

using namespace std;

namespace disasm {
    class scalar48_insn : public vc4_insn {
        public:
            inline scalar48_insn(string insn_name, string format)
                : vc4_insn(insn_name, string("{name} ")+format, 48) {};
   };
};

#endif // __DISASM_SCALAR48_H_
