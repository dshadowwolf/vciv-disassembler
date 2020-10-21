#ifndef __DISASM_VECTOR48_H_
#define __DISASM_VECTOR_H_

#include "disasm_insn_raw.hpp"

using namespace std;

namespace disasm {
    class vector48_insn : public vc4_insn {
        public:
            inline vector48_insn(string insn_name)
                : vc4_insn(insn_name, string("{name}"), 48) {};
   };
};

#endif // __DISASM_SCALAR32_H_
