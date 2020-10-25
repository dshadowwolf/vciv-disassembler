# VideoCore-IV Disassembler
## Raison d'être

This project was born of a request from a friend for help in possibly resurrecting the open-source Pi Firmware project and finding that existing tools for understanding how the existing firmware handled the boot of multiple revisions of the various boards managed it.

It was quickly found that the work done by @hermanhermitage in documenting the GPU/Boot Processor of the RPi was extremely helpful, but his disassembler was less than useful in that a lot of state that could be used to help track what was happening was lost. An unfinished software emulation of the processor was found, but was, again, of limited utility as it was completely unfinished and the author had decided to do a live "emulation" on the RPi itself rather than try to account for the almost completely undocumented hardware side of things.

Hence this project was born - a system that retains as much information as possible about the raw machine code so that an analysis can be done to better understand what is being done and the why of it all.

## Current State
### Instructions
SCALAR16, SCALAR32 and SCALAR48 (2-byte, 4-byte and 6-byte "classic" ALU) operations all have decoding implemented and limited tests show this decoding to work properly. (tested using a binary from @hermanhermitage that blinks an LED on the Pi, the version for the B+ and later)

VECTOR48 has an implementation, but building that appears to have made it clear that the current state of some extended internals - such as the `vc4_parameter` class - need a rework/extension to allow coverage of the VideoCore-IV's special encoding and language for its vector registers. This is being examined and worked on, currently. Note that this decoding is not tested at all and not linked into the current test binary.

VECTOR80 is completely unimplemented and is expected to raise as many issues with the decoding as the VECTOR48 has.

### Build System
The build system has been massively reworked to be based on CMake (3.13 at a minimum has been tested). On top of that there is now a requirement for the compiler used to support C++17 (for std::any) and you'll need an install of Boost (at least version 1.62.0), Boost::Multiprecision (libboost-mpi-dev is the debian package name to get this correct) and that should also pull in Boost::Serialization (libboost-serialization-dev, if memory serves).

While there was some hopes to have this use nothing but standard C++, it was found that a version of Boost was needed - first for Boost::format (since std::format is a C++20 feature that I do not have a compiler with support for, yet) and later for a means of handling (in a truly cross-platform manner) integers larger than 64bits wide (VECTOR80 instructions are, surprise, 80 bits wide). There are likely to be further tools and libraries relied upon in the future, as the project moves from being several chunks of inter-related code and single-threaded to being something thread-safe and a library that can be relied on to provide instruction decoding handling.

### Utility Internals
To some extent there is a major need to refactor the current code into a more coherent and cohesive system. This is planned but not documented, as needs and extended requirements are being found as things progress. At a minimum some internal math system is going to be required for handling some chunks of instruction encodings, such as the SCALAR32 "conditional branch" instructions, which jump to "program memory start plus \"offset*2\"" (in @hermanhermitage's documentation, `b<cc> $+o*2*`).

More than that a full refactor to replace the "magic number" bit-masks and shifts into constants, along with a portable replacement for the current instruction-stream read and decode into proper input for instructions is necessary.

Lastly the current system is a few small classes and a "big mess of methods in separate namespaces" - this really needs to be cleaned up, but at this time there are no solid ideas of how to do this and not lose the current flexibility.

## Future Plans
### Immediate Plans
Extension of the decoders so they store the bytes (as they appear in the instruction stream) that the instructions are composed of in the actual returned instruction. Alongside this will be some work to allow for those parameters that are signed to be handled internally as such (currently all integers, regardless of whether or not the VC-IV core would treat the value as signed, are treated as unsigned in the code). The latter change, specifically, is needed for places where the branch instruction actually encodes an PC relative offset, but decodes such into a direct address.

### Near Future
Conversion and testing for thread safety and re-entrancy concerns leading towards reworking the code into a support library, some testing binaries and a console application/utility that provides as much of the libraries functionality as possible without requiring people to write new code to use it.

### Far Future
Implementation of a layer on top of the planned library for inspection and tracking of data related to the decoded instruction stream to assist in actual decompilation and not just disassembly.

## License
Nominally I like to license code that I write under the MIT or 2-clause "Simplified" BSD licenses, as these offer more freedom to the end user, even as they violate some of the protected freedoms of the GPL family of licenses. At this time the license is undecided, though leaning towards MIT - any contributors should accept that this change will happen, even if the current license is "undecided" - so technically "all rights reserved".

## Closing
In the end I work in bursts of inspiration followed by sometimes years long lulls in activity. It is also a preference of mine to leave any legalities that are not immediately necessary until such a time as a decision needs to be made about them, giving me a long time to think about things and get advice from any number of sources.

Anyone looking to contribute to this project will, hopefully, understand this and not be troubled by it.
