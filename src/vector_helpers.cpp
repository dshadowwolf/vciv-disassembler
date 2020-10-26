#include <string>
#include <boost/format.hpp>

using namespace std;

namespace disasm {
	namespace vector {
		string decode_vector_register(uint16_t _reg) {
			uint16_t cleaned = _reg & 0x03ff; // only 10 bits, be certain
			string rv;
			uint8_t x, y;
			uint8_t isV = (cleaned & 0x0040);
			switch (isV) {
			case 0: // H[XY](y, ??)
				rv += "H";
				x = 0;
				y = (cleaned & 0x003f);
				break;
			case 1: //  V[XY](y, ??+x)
				rv += "V";
				x = (cleaned & 0x000f);
				y = ((cleaned & 0x0030) << 4);
				break;
			}

			uint8_t xy = (cleaned & 0x03c0) >> 6;

			if (xy == 12 || xy == 13) rv += "Y";
			else if (xy >= 8 && xy <= 11) rv += "X";
			else if (xy == 14) return string("DISCARD-IGNORE");
			rv += "(";
			rv += std::to_string(y);
			rv += ", ";

			uint8_t szm = (cleaned & 0x0380) >> 7;
			switch (szm) {
			case 0:
			case 1:
			case 2:
			case 3:
				rv += std::to_string(szm * 16);
				break;
			case 4:
				rv += "0";
				break;
			case 5:
				rv += "32";
				break;
			case 6:
				rv += "0";
				break;
			case 7:
			default:
				// Hermans docs break down here and are incomplete
				rv += "???";
				break;
			}

			if (isV) rv += " + " + std::to_string(x);
			rv += ")";

			return rv;
		}
	}
}
