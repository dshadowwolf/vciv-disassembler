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

#include <vc4_parameter.hpp>

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
				string rval;
				try {
					switch( p.getType() ) {
					case ParameterTypes::REGISTER:
						rval = std::to_string(p.value<uint32_t>());
						break;
					case ParameterTypes::IMMEDIATE:
						if (p.getContainedType() == "f")
							rval = std::to_string(p.value<float>());
						else {
							uint32_t val = p.value<uint32_t>();
							if (val < 0x00010000) rval = std::to_string(val);
							else rval = (boost::format { "0x%08X" } % p.value<uint32_t>()).str();
						}
						break;
					case ParameterTypes::OFFSET:
						rval = std::to_string(p.value<int32_t>());
						break;
					case ParameterTypes::VECTOR_REGISTER:
					case ParameterTypes::DATA:
						rval = p.value<string>();
						break;
					case ParameterTypes::ERROR:
						rval = "ERROR - Parameter Type is ParameterTypes::ERROR";
						break;
					default:
						rval = string("ERROR - unknown Parameter Type ")+p.getType()._to_string();
					}
				} catch( const std::bad_any_cast &e ) {
					std::cerr << "caught bad_any_cast (" << e.what() << ")" << std::endl;
					std::cerr << "processing type " << p.getType()._to_string() << " - parameter has internal type flag of \"" << p.getContainedType() << "\"" << std::endl;
					std::cerr << "op name: " << name << " -- size: " << std::to_string((uint8_t)(size/8)) << std::endl;
					abort();
				}
				string re_s(string("(\\{\\s*") + it->first + string("\\s*\\})"));
				regex fx(re_s);
				rv = regex_replace(rv, fx, rval);
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
