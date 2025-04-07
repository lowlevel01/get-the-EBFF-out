import ida_segment
import ida_bytes
import ida_ua

def get_text_segment():
    seg = ida_segment.get_segm_by_name(".text")
    if not seg:
        print("'.text' segment not found.")
        return None
    return seg.start_ea, seg.end_ea

def dump_instruction_bytes(start_ea, end_ea):
    ea = start_ea
    while ea < end_ea:
        insn = ida_ua.insn_t()
        size = ida_ua.decode_insn(insn, ea)
        if not ida_bytes.is_code(ida_bytes.get_flags(ea)):
            ea += 1
            continue
        bytes_seq = ida_bytes.get_bytes(ea, size)
        if bytes_seq:
            print(f"{ea:08X}: {bytes_seq.hex()}")
            if bytes_seq == b"\xeb\xff":
                pass
                patch_first_byte_with_nop(ea)
        ea += size


def patch_first_byte_with_nop(ea):
    NOP_OPCODE = 0x90
    ida_bytes.patch_byte(ea, NOP_OPCODE)
    print(f"Patched first byte at address {ea:#010x} with NOP.")


def eliminate():
    start, end = get_text_segment()
    if start and end:
        dump_instruction_bytes(start, end)

eliminate()
