# get-the-EBFF-out
An IDA script to eliminate the EBFF (JMP RIP+1 or JMP -1) anti-disassembly technique

Someone shared this tool https://github.com/weak1337/Alcatraz/tree/master?tab=readme-ov-file#anti-disassembly . One of its feature is anti-disassembly via inserting 0xEB before every instruction that start with 0xFF in order to break the disassembler while keeping the same logic. I wrote this IDA script to eliminate this anti-disassembly technique.
