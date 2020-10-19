#ifndef __VC4_DATA_H_
#define __VC4_DATA_H_

namespace disasm {
    const string al_ops[] = { "move", "cmn", "add", "bic", "mul", "eor", "sub",
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

}

#endif // __VC4_DATA_H_
