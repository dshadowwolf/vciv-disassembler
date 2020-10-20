#ifndef __DISASM_INSN_RAW_H_
#define __DISASM_INSN_RAW_H_

#include <string>
#include <unordered_map>
#include <cstdint>
#include <regex>
// uncomment the following to disable all assert() checks
// #define NDEBUG
#include <cassert>

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
            float _f_val = 0.0f;
            bool is_float = false;
            
            inline float float6(uint32_t imm) {
                uint32_t b = 0;
                if (imm & 0x20) {
                    b |= 0x80000000;
                }
                int exponent = (imm >> 2) & 0x7;
                if (exponent != 0) {
                    b |= (exponent + 124) << 23;
                    int mantissa = imm & 0x3;
                    b |= mantissa << 21;
                }
                return *(float *)&b;
            };
            
        public:
            inline vc4_parameter( param_type_t type, uint32_t value ) {
                p_type = type;
                p_value = value;
            };

            inline vc4_parameter( param_type_t type, uint32_t value, bool do_float ) {
                p_type = type;
                _f_val = float6(value);
                is_float = do_float;
                p_value = value;
            };
            
            inline vc4_parameter() {};
            inline param_type_t getType() { return p_type; };
            inline uint32_t value() { return is_float?0:p_value; };
            inline float floatValue() { return is_float?_f_val:0.0F; };
            inline bool isFloat() { return is_float; };
    };
        
    class vc4_insn {
        protected:
            string name;
            string format;
            uint8_t size;
            unordered_map<string, vc4_parameter> parameters;
            
        public:
            inline vc4_insn(string name, string format, uint8_t bitsize) {
                this->name = name;
                this->format = format;
                this->size = bitsize;
            }
            inline string getReadable() { return name; };
            inline uint8_t getSize() { return size; }
            inline size_t getSizeBytes() { return sizeof(uint8_t) * (size / 8); };
            inline string toString() {
                assert( format.length() > 0 && "No format string!");
                string rv(format);
                for (auto it = parameters.begin(); it != parameters.end(); ++it) {
                    string item_name(it->first);
                    uint32_t i_val = it->second.value();
                    float f_val = it->second.floatValue();
                    bool flag = it->second.isFloat();
                    
                    regex_replace(rv,
                                  regex("({\\s*" + it->first + "\\s*})"),
                                  std::to_string(flag?f_val:i_val));
                }
                regex_replace(rv, regex("({\\s*name\\s*})"), name);
                return rv;
            };
            inline unordered_map<string, vc4_parameter> getParameters() { return parameters; };
            inline vc4_insn *addParameter(string name, vc4_parameter p0) {
                parameters[name] = p0;
                return this;
            };
    };
}

#endif // __DISASM_INSN_RAW_H_
