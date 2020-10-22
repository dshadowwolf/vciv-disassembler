#ifndef __DISASM_INSN_RAW_H_
#define __DISASM_INSN_RAW_H_

#include <boost/format.hpp>

#include <iostream>
#include <string>
#include <unordered_map>
#include <cstdint>
#include <regex>
// uncomment the following to disable all assert() checks
// #define NDEBUG
#include <cassert>

#include "vc4_parameter.hpp"

using namespace std;

namespace disasm {
        
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
                string nm("(\\{name\\})");

                if(parameters.size() <= 0) return name;
                
                for (auto it = parameters.begin(); it != parameters.end(); ++it) {
                    string item_name(it->first);
                    vc4_parameter p = it->second;
                    string outs;
                    
                    if (p.getContainedType() == "i" || p.getContainedType() == "j") {
                        if (p.getType() == ParameterTypes::IMMEDIATE)
                            outs = (boost::format { "0x%08X" } % p.value<int>()).str();
                        else outs = std::to_string(p.value<int>());
                    } else outs = std::to_string(p.value<float>());
                    
                    string re_s(string("(\\{\\s*") + it->first + string("\\s*\\})"));
                    regex fx(re_s);
                    rv = regex_replace(rv, fx, outs);
                }
                
                rv = regex_replace(rv, regex(nm), name);

                return rv;
            };
            inline unordered_map<string, vc4_parameter> getParameters() { return parameters; };
            inline vc4_insn *addParameter(string name, vc4_parameter p0) {
                parameters.insert( std::pair<std::string, vc4_parameter>(name, p0) );
                return this;
            };
    };
}

#endif // __DISASM_INSN_RAW_H_
