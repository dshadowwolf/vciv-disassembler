#ifndef __DISASM_INSN_RAW_H_
#define __DISASM_INSN_RAW_H_

#include <string>
#include <vector>
#include <cstdint>

using namespace std;

namespace disasm {

    typedef enum param_type_e : uint8_t {
      REGISTER = 0,
      MEMORY,
      OFFSET,
      CC,
      SIZE_CODE,
      IMMEDIATE,
      ERROR
    } param_type_t;

    class vc4_parameter {
        private:
            param_type_t p_type = ERROR;
            uint32_t p_value = 0;
            
        public:
            inline vc4_parameter( param_type_t type, uint32_t value ) {
                p_type = type;
                p_value = value;
            };
            
            inline param_type_t getType() { return p_type; };
            inline uint32_t value() { return p_value; };
    };
        
    class vc4_insn {
        public:
            virtual inline string getReadable() = 0;
            virtual inline size_t getSize() = 0;
            virtual inline vector<vc4_parameter> getParameters() = 0;
    };
}

#endif // __DISASM_INSN_RAW_H_
