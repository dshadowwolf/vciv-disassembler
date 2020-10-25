#ifndef __VC4_DATA_H_
#define __VC4_DATA_H_

#include <string>
#include <boost/format.hpp>

using namespace std;

namespace disasm {
	const string al_ops[] = { "mov", "cmn", "add", "bic", "mul", "eor", "sub",
		"and", "not", "ror", "cmp", "rsub", "btest", "or",
		"bmask", "max", "bitset", "min", "bitclear",
		"addscale", "bitflip", "addscale", "addscale",
		"addscale", "signext", "neg", "lsr", "msb", "shl",
		"brev", "asr", "abs", "mulhd.ss", "mulhd.su",
		"mulhd.us", "mulhd.uu", "div.ss", "div.su",
		"div.us", "div.uu", "adds", "subs", "shls",
		"clipsh", "addscale", "addscale", "addscale",
		"addscale", "count", "subscale", "subscale",
		"subscale", "subscale", "subscale", "subscale",
		"subscale", "subscale" };

	const string condition_codes[] = { "eq", "ne", "cs", "cc", "ns", "nc", "vs",
		"vc", "gt", "lte", "gte", "lt", "gt",
		"lte", "ra", ".never" };

	const string mem_op_widths[] = { "", "h", "b", "s"};

	const string float_ops[] = { "fadd", "fsub", "fmul", "fabs", "frsub",
		"fmax", "frcp", "frsqrt", "fnmul", "fmin",
		"fceil", "ffloor", "flog2", "fexp2" };

	const string vector_widths[] = { "8", "16", "32", "[8]" };

	const string vector_ops_48[] = { "ld", "lookupmh", "lookupml",
		"mem03[unused]", "st", "indexwritemh", "indexwriteml", "mem07[unused]",
		"memread", "memwrite", "mem10[unused]",	"mem11[unused]", "mem12[unused]",
		"mem13[unused]", "mem14[unused]", "mem15[unused]", "mem16[unused]",
		"mem17[unused]", "mem18[unused]", "mem19[unused]", "mem20[unused]",
		"mem21[unused]", "mem22[unused]", "mem23[unused]", "getacc",
		"mem25[unused]", "mem26[unused]", "mem27[unused]", "mem28[unused]",
		"mem29[unused]", "mem30[unused]", "mem31[unused]" };

	const string vector_flags_w[] = { "", "NV", "IFNZ", "IFN", "IFNN", "IFC", "IFNC" };

	const string vector_ops_full[] = { "mov", "bitplanes", "even", "odd", "interl",
		"interh", "brev", "ror", "shl", "shls", "lsr", "asr", "signshl", "op13[unused]",
		"signasl", "signasls", "and", "or", "eor", "bic", "count", "msb","op22[unused]",
		"op23[unused]", "min", "max", "dist", "dists", "clip", "sign", "clips",
		"testmag", "add", "adds", "addc", "addsc", "sub", "subs", "subc", "subsc",
		"rsub", "rsubs", "rsubc", "rsubsc", "op44[unused]", "op45[unused]",
		"op46[unused]", "op47[unused]", "mull", "mulls", "mulm", "mulms", "mulhd.ss",
		"mulhd.su", "mulhd.us", "mulhd.uu", "mulhn.ss", "mulhn.su", "mulhn.us",
		"mulhn.uu", "mulht.ss", "mulht.su", "op62[unused]", "op63[unused]" };

	const string vector48_alts[] = { "op48[unused]", "op49[unused]", "op50[unused]",
		"op51[unused]",	"mul32.ss", "mul32.su", "mul32.us",	"mul32.uu", "op56[unused]",
		"op57[unused]", "op58[unused]",	"op59[unused]", "op60[unused]",	"op61[unused]",
		"op62[unused]",	"op63[unused]" };

	const string vector_reps[] = { "",  "REP2", "REP4", "REP8", "REP16", "REP32", "REP64", "REP r0" };

}

#endif // __VC4_DATA_H_
