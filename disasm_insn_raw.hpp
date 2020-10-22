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
                
                for (auto it = parameters.begin(); it != parameters.end(); ++it) {
                    string item_name(it->first);
                    vc4_parameter p = it->second;
                    uint32_t iv;
                    float fv;
                    try {
                        iv = p.value<uint32_t>();
                        fv = p.value<float>();
                    } catch( const std::bad_any_cast &e ) {
                        string emsg("Error fetching value from std::any - type <<");
                        emsg += p.getContainedType();
                        emsg += ">>";
                        emsg += e.what();
                        assert(emsg.c_str());
                    }
                    
                    bool isFloat = iv==fv?true:false;
                    string outs;
                    if(isFloat) outs = std::to_string(fv);
                    else if ( p.getType() == ParameterTypes::IMMEDIATE ) {
                        outs = (boost::format { "0x%08X" } % iv).str();
                    } else outs = std::to_string(iv);
                    
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
