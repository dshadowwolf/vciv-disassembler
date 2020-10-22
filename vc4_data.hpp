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
    
    const string vector_widths[] = { "b", "s", "l", ".reserved" };
    
    const string vector_ops_48[] = { "ld", "lookupmh", "lookupml",
                                     "undefined(00011)", "st", "indexwritemh",
                                     "indexwriteml",    "undefined(00111)",
                                     "readlut", "writelut",
                                     "undefined(01010)",
                                     "undefined(01011)", "undefined(01100)",
                                     "undefined(01101)", "undefined(01110)",
                                     "undefined(01111)", "undefined(10000)",
                                     "undefined(10001)", "undefined(10010)",
                                     "undefined(10011)", "undefined(10100)",
                                     "undefined(10101)", "undefined(10110)",
                                     "undefined(10111)", "readacc",
                                     "undefined(11001)", "undefined(11011)",
                                     "undefined(11100)", "undefined(11101)",
                                     "undefined(11110)", "undefined(11111)" };
    
    const string vector_flags_w[] = { "", "NV", "IFNZ", "IFN", "IFNN", "IFC", "IFNC" };
    
    const string vector_rs[] = { " + r0", " + r1", " + r2", " + r3", " + r4", " + r5", " + r6", " + r7" };
    
}

#endif // __VC4_DATA_H_
