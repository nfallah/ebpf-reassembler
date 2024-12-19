## ebpf-reassembler

The tool aims to take a series of .txt files generated from the [ebpf-extractor](https://github.com/smartnic/ebpf-extractor/tree/master) tool and reassemble everything back into an object file.

## Usage

1) gcc ebpf_reconstructor.c -o prog libbpf/src/libbpf.a -lelf -lz
2) ./prog <original.o> <prog_1.txt> ... <prog_n.txt>

## Background

When ebpf-extractor is applied to an eBPF object file, it produces a separate set of files (including .txt) for each of its programs. These files are then fed into K2, where the number of instructions post-optimization is <= the original number of instructions. If the number of instructions is smaller, it is nontrivial to get back the original object file with fewer instructions, as both the eBPF instructions use local offsets and the ELF object file sections do as well. This tool is one attempt at fixing these issues: for each prog_i that is <= the original number of instructions, the *i*th prog in the original object file is recreated in high-level C, and instructions in prog_i are inserted as inline ebpf assembly. Then, one can simply invoke clang to re-build the object file that should hopefully still remain equivalent even with the reduced instruction count.

To test if the object file is in fact equivalent, one can (a) see if it loads after passing the verifier and (b) can run an eBPF equivalence checker.

## Challenges

However, the current approach implemented in the code is flawed and may not perfectly reproduce the original object file. For example, maps are not currently declared, as recreating them requires knowledge of custom structs, etc. that are no longer "available" to us through our decompilation method. However, if the code has NO maps, then this reassembling tool will be able to work.

## Notes
- there is a file called notes.txt provided in this project that outlines our current approach (1) while also discussing approaches 2 and 3.
