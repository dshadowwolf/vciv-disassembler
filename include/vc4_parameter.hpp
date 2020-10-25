#ifndef __VC4_PARAMETER_H_
#define __VC4_PARAMETER_H_

#include <any>
#include <string>
#include <cstdint>

#include <enum_magic.hpp>

/*
** -*-mode:cc; fill-column: 79; std: c++17
*/
namespace disasm {
	ENUM(ParameterTypes, REGISTER, IMMEDIATE, VECTOR_REGISTER, DATA, ERROR);

	class vc4_parameter {
	private:
		ParameterTypes _type = ParameterTypes::ERROR;
		std::any _value;

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
		vc4_parameter( ParameterTypes type, std::any value ) {
			_type = type;
			_value = value;
		};

		vc4_parameter( ParameterTypes type, const char* value) {
			_type = type;
			_value = value==NULL?std::string(""):std::string(value);
		}

		vc4_parameter(vc4_parameter&& other) {
			_type = other._type;
			_value = other._value;
			other._type = ParameterTypes::ERROR;
			other._value = 0;
		};

		vc4_parameter( const vc4_parameter &other )
			: _type(other._type), _value(other._value) {};

		vc4_parameter &operator=(const vc4_parameter &other) {
			_type = other._type;
			_value = other._value;
			return *this;
		}

		inline void setContainsFloat() {
			uint32_t temp = std::any_cast<uint32_t>(_value);
			_value = float6(temp);
		};

		inline ParameterTypes getType() { return _type; };
		inline std::string getTypeName() { return _type._to_string(); };
		inline std::string getContainedType() { return _value.type().name(); };
		inline std::any getContainer() { return _value; };

		template <typename T> T value() {
			T rr;
			try {
				rr = std::any_cast<T>(_value);
			} catch(const std::bad_any_cast &e) {
				std::any z = -1;
				rr = std::any_cast<T>(z);
			}
			return rr;
		};
	};
}

#endif // __VC4_PARAMETER_H_
