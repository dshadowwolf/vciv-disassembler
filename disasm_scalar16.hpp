#ifndef __DISASM_SCALAR16_H_
#define __DISASM_SCALAR16_H_

#include "disasm_insn_raw.hpp"

using namespace std;

namespace disasm {
    class scalar16_insn : public vc4_insn {
        private:
            string readable;
            vector<vc4_parameter> params;
            
        public:
            inline scalar16_insn(string insn_name) { readable = insn_name; };
            inline string getReadable() { return readable; };
            inline size_t getSize() { return 16; };
            inline vector<vc4_parameter> getParameters() {
                return params;
            };
            inline scalar16_insn addParameter(vc4_parameter param) {
                params.push_back(param);
                return *this;
            };
    };
};

#endif // __DISASM_SCALAR16_H_
