from unicorn import *
from unicorn.x86_const import *
from capstone import *
from ida_bytes import set_cmt,patch_bytes
import ida_funcs
import ida_name
import ida_ida
import ida_idaapi
import idautils
import ida_bytes
import ida_lines


# CONSTANTS
SIZE_MIN_THRESHOLD = 0x20
SIZE_MAX_THRESHOLD = 0x400
LIMIT_NUM_OF_FUNC = 20  # Set to -1 for no limit
DEBUG_SINGLE_FUNC = 0
DECRYPTED_SEGMENT_BASE=None
SEGMENT_OFFSET=0
SEGMENT_NAME='DecryptedHub'
SEGMENT_ADDRESS=set()
VERBOS = False
REGISTERS = {
    UC_X86_REG_RAX: "RAX",
    UC_X86_REG_RBX: "RBX",
    UC_X86_REG_RCX: "RCX",
    UC_X86_REG_RDX: "RDX",
    UC_X86_REG_RSI: "RSI",
    UC_X86_REG_RDI: "RDI",
    UC_X86_REG_RSP: "RSP",
    UC_X86_REG_RBP: "RBP",
    UC_X86_REG_R8: "R8",
    UC_X86_REG_R9: "R9",
    UC_X86_REG_R10: "R10",
    UC_X86_REG_R11: "R11",
    UC_X86_REG_R12: "R12",
    UC_X86_REG_R13: "R13",
    UC_X86_REG_R14: "R14",
    UC_X86_REG_R15: "R15",
    UC_X86_REG_RIP: "RIP",
}

reg_map = {
    "rax": "rax", "eax": "rax", "ax": "rax", "ah": "rax", "al": "rax",
    "rbx": "rbx", "ebx": "rbx", "bx": "rbx", "bh": "rbx", "bl": "rbx",
    "rcx": "rcx", "ecx": "rcx", "cx": "rcx", "ch": "rcx", "cl": "rcx",
    "rdx": "rdx", "edx": "rdx", "dx": "rdx", "dh": "rdx", "dl": "rdx",
    "rsi": "rsi", "esi": "rsi", "si": "rsi", "sil": "rsi",
    "rdi": "rdi", "edi": "rdi", "di": "rdi", "dil": "rdi",
    "rsp": "rsp", "esp": "rsp", "sp": "rsp", "spl": "rsp",
    "rbp": "rbp", "ebp": "rbp", "bp": "rbp", "bpl": "rbp",
    "r8": "r8", "r8d": "r8", "r8w": "r8", "r8b": "r8",
    "r9": "r9", "r9d": "r9", "r9w": "r9", "r9b": "r9",
    "r10": "r10", "r10d": "r10", "r10w": "r10", "r10b": "r10",
    "r11": "r11", "r11d": "r11", "r11w": "r11", "r11b": "r11",
    "r12": "r12", "r12d": "r12", "r12w": "r12", "r12b": "r12",
    "r13": "r13", "r13d": "r13", "r13w": "r13", "r13b": "r13",
    "r14": "r14", "r14d": "r14", "r14w": "r14", "r14b": "r14",
    "r15": "r15", "r15d": "r15", "r15w": "r15", "r15b": "r15",
}

def create_decrypted_segment(segment_size=0x10000):
    """
    Create a new segment in IDA for storing decrypted strings or return an existing one.
    """
    # Check if the segment already exists
    existing_segment = ida_segment.get_segm_by_name(SEGMENT_NAME)
    if existing_segment:
        print(f"Segment '{SEGMENT_NAME}' already exists at {hex(existing_segment.start_ea)}")
        return existing_segment.start_ea

    # Find the next available address
    page_size = 0x1000
    max_ea = 0
    for i in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(i)
        if seg.end_ea > max_ea:
            max_ea = seg.end_ea

    # Align the address to the next page boundary
    next_base = (max_ea + page_size - 1) & ~(page_size - 1)
    next_end = next_base + segment_size

    # Create the new segment
    if not ida_segment.add_segm(0, next_base, next_end, SEGMENT_NAME, "DATA"):
        print(f"Failed to create segment '{SEGMENT_NAME}'!")
        return None

    print(f"Created segment '{SEGMENT_NAME}' at {hex(next_base)} - {hex(next_end)}")
    return next_base

def load_written_strings(segment_base):
    """
    Parse existing strings in the segment and rebuild the mapping.
    """
    segment = ida_segment.get_segm_by_name(SEGMENT_NAME)
    if not segment:
        print(f"Segment '{SEGMENT_NAME}' not found.")
        return {}, 0

    written_mapping = {}  # Maps original_address -> segment_offset
    current_offset = 0
    segment_end = segment.end_ea

    while segment_base + current_offset < segment_end:
        addr = segment_base + current_offset
        # Read until null terminator
        data = ida_bytes.get_bytes(addr, segment_end - addr)
        if not data:
            break

        null_index = data.find(b'\x00')
        if null_index == -1:
            break  # No null terminator found

        # Extract string and metadata
        string = data[:null_index].decode("utf-8", errors="ignore")
        metadata_start = null_index + 1
        metadata_size = 8  # Original address (8 bytes)
        if metadata_start + metadata_size > len(data):
            break  # Incomplete metadata

        original_address = int.from_bytes(data[metadata_start:metadata_start + metadata_size], byteorder="little")
        written_mapping[original_address] = current_offset
        current_offset += len(string) + 1 + metadata_size

    print(f"Loaded {len(written_mapping)} strings from segment '{SEGMENT_NAME}'")
    return written_mapping, current_offset



def create_or_load_segment(segment_size=0x10000):
    """
    Create a new segment or load an existing one, and parse its contents.
    """
    global SEGMENT_ADDRESS
    segment_base = create_decrypted_segment(segment_size)
    written_mapping, current_offset = load_written_strings(segment_base)
    SEGMENT_ADDRESS = set(written_mapping.keys())  # Populate the global set
    return segment_base, SEGMENT_ADDRESS, current_offset

def add_comment_to_address(addr, comment):
    """
    Add a comment to the given address in IDA.
    """
    set_cmt(addr, comment, False)
    print(f"Added comment at {hex(addr)}: {comment}")

def extract_function_code(func_addr):
    """
    Extracts the function's binary code from IDA Pro.
    """
    func = ida_funcs.get_func(func_addr)
    if not func:
        print(f"Failed to find function at {hex(func_addr)}")
        return None

    start = func.start_ea
    end = func.end_ea
    size = end - start
    code = ida_bytes.get_bytes(start, size)
    if not code:
        print(f"Failed to read bytes for function at {hex(start)}")
        return None

    print(f"Function bytes at {hex(start)} (size {size}): {code.hex()}")
    return code, start, size


def create_function_near(addr):
    """
    Scrolls up from the given address until an 'align 20h' instruction is found,
    and then creates a function starting at the address after the alignment.
    """
    current_addr = addr

    # Set the minimum boundary
    min_boundary = ida_ida.inf_get_min_ea()

    # Iterate upwards to find the alignment instruction
    while current_addr > min_boundary:
        current_addr = ida_bytes.prev_head(current_addr, min_boundary)
        if current_addr == ida_idaapi.BADADDR:
            break

        # Check if it's an alignment instruction
        disasm_line = ida_lines.generate_disasm_line(current_addr, ida_lines.GENDSM_REMOVE_TAGS)
        if "align 20h" in disasm_line.lower():
            # Move to the next valid instruction after align
            new_func_addr = ida_bytes.next_head(current_addr, addr)
            if ida_funcs.add_func(new_func_addr):
                print(f"Created function at {hex(new_func_addr)}")
                return new_func_addr
            else:
                print(f"Failed to create function at {hex(new_func_addr)}")
                return None

    print(f"Alignment instruction not found near {hex(addr)}")
    return None


def dump_registers(uc):
    """
    Dump register state for debugging.
    """
    if VERBOS: print("Register State:")
    for reg, name in REGISTERS.items():
        try:
            value = uc.reg_read(reg)
            if VERBOS: print(f"  {name}: {hex(value)}")
        except UcError as e:
            print(f"  {name}: Error ({e})")


def print_mapped_regions(mapped_regions):
    """
    Print all currently mapped memory regions.
    """
    if VERBOS: print("Current mapped regions:")
    for start, end in mapped_regions:
        if VERBOS: print(f"  {hex(start)} - {hex(end)}")


def release_mapped_memory(uc, mapped_regions):
    """
    Release all mapped memory regions in Unicorn.
    """
    if VERBOS: print("Releasing mapped memory...")
    for start, end in mapped_regions:
        try:
            uc.mem_unmap(start, end - start)
            if VERBOS: print(f"Unmapped memory: {hex(start)} - {hex(end)}")
        except UcError as e:
            print(f"Failed to unmap memory at {hex(start)}: {e}")
    mapped_regions.clear()
    if VERBOS: print("After release:")
    print_mapped_regions(mapped_regions)


def mem_invalid(uc, access, address, size, value, user_data):
    """
    Hook to handle invalid memory accesses and provide detailed debugging information.
    """
    if access == UC_MEM_FETCH_UNMAPPED:
        print(f"Invalid memory fetch at {hex(address)}")
    elif access == UC_MEM_READ_UNMAPPED:
        print(f"Invalid memory read at {hex(address)}")
    elif access == UC_MEM_WRITE_UNMAPPED:
        print(f"Invalid memory write at {hex(address)}")

    # Print mapped regions for debugging
    mapped_regions = user_data.get("mapped_regions", [])
    print(f"Mapped regions:")
    for start, end in mapped_regions:
        print(f"  {hex(start)} - {hex(end)}")

    uc.emu_stop()
    return False


def hook_memory_write(uc, access, address, size, value, user_data):
    print(f"Memory WRITE at {hex(address)} (size {size}): Value = {hex(value)}")


def map_memory(uc, base, size, prot, mapped_regions):
    """
    Map memory in Unicorn, avoiding overlaps with previously mapped regions.
    """
    page_size = 0x1000
    aligned_base = base - (base % page_size)
    aligned_size = (size + page_size - 1) & ~(page_size - 1)

    # Check for overlaps with existing regions
    for start, end in mapped_regions:
        if start <= aligned_base < end or aligned_base <= start < aligned_base + aligned_size:
            if VERBOS: print(f"Memory overlap detected: {hex(aligned_base)} overlaps with {hex(start)}-{hex(end)}")
            return aligned_base, aligned_size  # Skip remapping

    # Map the memory region
    try:
        uc.mem_map(aligned_base, aligned_size, prot)
        mapped_regions.append((aligned_base, aligned_base + aligned_size))
        if VERBOS: print(f"Mapped memory: {hex(aligned_base)} - {hex(aligned_base + aligned_size)}")
    except UcError as e:
        print(f"Failed to map memory at {hex(aligned_base)}: {e}")
        raise e

    return aligned_base, aligned_size

def write_decrypted_string(segment_base, offset, string, original_address):
    """
    Write a string to the segment if it hasn't been written already.
    """
    global SEGMENT_ADDRESS
    addr = segment_base + offset

    # Check if the address has already been written
    if original_address in SEGMENT_ADDRESS:
        print(f"Skipping write: Address {hex(original_address)} already contains data.")
        return None, 0

    # Write the string and metadata
    string_data = f"{string}\x00".encode("utf-8")  # Null-terminated string
    metadata = original_address.to_bytes(8, byteorder="little")  # Store original address
    full_data = string_data + metadata

    patch_bytes(addr, full_data)
    ida_bytes.create_strlit(addr, len(string_data),get_inf_attr(INF_STRTYPE))
    ida_bytes.create_dword(addr+len(string_data),4)

    SEGMENT_ADDRESS.add(original_address)
    print(f"Written: '{string}' at {hex(addr)} (source: {hex(original_address)})")

    return addr, len(full_data)

def trace(uc, address, size, user_data):
    """
    Hook to trace execution, skip specific patterns, validate memory reads, and handle slice function calls.
    """
    global SEGMENT_OFFSET, DECRYPTED_SEGMENT_BASE, SEGMENT_ADDRESS
    cs = user_data["cs"]
    state = user_data["state"]
    runtime_address = user_data["runtime_address"]
    initialized_registers = state.setdefault("initialized_registers", set())
    initialized_registers.add("rsp")
    initialized_registers.add("esp")
    initialized_registers.add("sp")
    try:
        # Read the current instruction bytes
        instruction_bytes = uc.mem_read(address, 16)
        insn = next(cs.disasm(instruction_bytes[:size], address))

        if VERBOS: print(f"{address:#010x}: {insn.mnemonic} {insn.op_str}")

        # **Skip cmp + jbe/jle Patterns**
        if insn.mnemonic == "cmp" and state.get("rsp_register") and state["rsp_register"] in insn.op_str:
            if VERBOS: print(f"Detected 'cmp {insn.op_str}' at {hex(address)}")
            next_addr = address + insn.size
            try:
                next_insn = next(cs.disasm(uc.mem_read(next_addr, 16), next_addr))
                if next_insn.mnemonic in ["jbe", "jle"]:
                    if VERBOS: print(f"Skipping tampering check: '{next_insn.mnemonic}' following 'cmp'")
                    uc.reg_write(UC_X86_REG_RIP, next_addr + next_insn.size)
                    state.clear()
                    return
            except UcError as e:
                print(f"Memory access error during tampering check at {hex(address)}: {e}")
                uc.reg_write(UC_X86_REG_RIP, address + insn.size)  # Skip cmp
                return

        # Clear skip state if past the skip point
        if "skip_after" in state and address > state["skip_after"]:
            state.clear()

        # **Validate Source Registers and Memory Operands**
        if insn.mnemonic in ["mov", "lea", "cmp", "movzx", "movabs", "xor"]:
            operands = insn.op_str.split(",")
            if len(operands) > 1:
                src = operands[1].strip()
                dest = operands[0].strip()

                # Check for memory dereference in source operand
                if "[" in src and "]" in src:
                    # Check if any register is used in the memory operand
                    if any(reg.lower() in src.lower() for reg in reg_map.keys()):
                        # Validate all registers in the memory operand
                        for reg in reg_map.keys():
                            if reg.lower() in src.lower() and reg not in initialized_registers and reg.lower() not in [
                                "rsp"]:
                                if VERBOS: print(
                                    f"Skipping instruction with uninitialized base register: '{reg}' in '{src}'")
                                uc.reg_write(UC_X86_REG_RIP, address + insn.size)
                                next_addr = address + insn.size
                                next_insn = next(cs.disasm(uc.mem_read(next_addr, 16), next_addr))
                                if next_insn.mnemonic in ["jbe", "jle", "je", "jne", "jg", "jl"]:
                                    if VERBOS: print(
                                        f"Skipping conditional jump '{next_insn.mnemonic}' following 'cmp' at {hex(next_addr)}")
                                    uc.reg_write(UC_X86_REG_RIP, next_addr + next_insn.size)
                                    state.clear()
                                return

                        # Attempt to read memory to ensure accessibility
                        try:
                            uc.mem_read(address, 1)  # Simplify access test
                        except UcError:
                            print(f"Skipping instruction due to inaccessible memory at '{src}'")
                            uc.reg_write(UC_X86_REG_RIP, address + insn.size)
                            return

            dest = dest.lower()
            if dest not in initialized_registers:
                if dest.startswith("r") and insn.mnemonic not in ["cmp"]:
                    if dest in ["rax", "rbx", "rcx", "rdx", "rsi", "rdi"]:
                        initialized_registers.add(dest)
                        initialized_registers.add("e" + dest[1:])
                        initialized_registers.add(dest[1:])
                        if dest in ["rsi", "rdi"]:
                            initialized_registers.add(dest[1:] + "l")
                        else:
                            initialized_registers.add(dest[1] + "l")
                            initialized_registers.add(dest[1] + "h")
                    else:
                        if dest[-1] in ["w", "d", "b"]:
                            dest = dest[:-1]
                        initialized_registers.add(dest + "w")
                        initialized_registers.add(dest + "d")
                        initialized_registers.add(dest + "b")
                        initialized_registers.add(dest)
                    if VERBOS: print(f"Marking destination register '{dest}' as initialized.")
                if dest.startswith("e") and insn.mnemonic not in ["cmp"]:
                    initialized_registers.add(dest)
                    initialized_registers.add(dest[1] + "l")
                    initialized_registers.add(dest[1] + "h")
                    initialized_registers.add(dest[1:])
                    initialized_registers.add("r" + dest[1:])
                    if VERBOS: print(f"Marking destination register '{dest}' as initialized.")

        # **Handle Call to runtime.slicebytetostring**
        if insn.mnemonic == "call":
            try:
                target_address = int(insn.op_str, 16)
                if target_address == runtime_address:
                    print(f"Detected call to runtime.slicebytetostring at {hex(address)}")
                    param1_ptr = uc.reg_read(UC_X86_REG_RBX)  # First parameter: RBX
                    param2_size = uc.reg_read(UC_X86_REG_RCX)  # Second parameter: RCX

                    if VERBOS: print(f"Pointer to byte array: {hex(param1_ptr)}")
                    if VERBOS: print(f"Size of byte array: {param2_size}")

                    if param2_size > 0:
                        try:
                            byte_array = uc.mem_read(param1_ptr, param2_size)
                            try:
                                as_string = byte_array.decode("utf-8", errors="ignore")
                                print(f"Byte array as string: +++++++{as_string}++++++++")  # Red color output
                                if DECRYPTED_SEGMENT_BASE:
                                    decrypted_addr, string_size = write_decrypted_string(
                                        DECRYPTED_SEGMENT_BASE,
                                        SEGMENT_OFFSET,
                                        as_string,
                                        address,
                                    )
                                    if decrypted_addr:
                                        SEGMENT_OFFSET+=string_size
                                        add_comment_to_address(address, f"Decrypted: {as_string} (at {hex(decrypted_addr)})")
                            except UnicodeDecodeError:
                                print(f"Byte array could not be decoded as UTF-8: {byte_array.hex()}")
                        except UcError:
                            print(f"Failed to access byte array at {hex(param1_ptr)}")
                    uc.emu_stop()
                    return
            except ValueError:
                print(f"Target operand '{insn.op_str}' is not a valid address")

    except UcError as e:
        print(f"Memory access error at {hex(address)}: {e}. Skipping instruction.")
        uc.reg_write(UC_X86_REG_RIP, address + size)  # Move to the next instruction
    except Exception as e:
        print(f"Error processing instruction at {hex(address)}: {e}")
        uc.emu_stop()


def emulate_function(func_addr, uc, data_base, mapped_regions, runtime_address):
    """
    Emulates the execution of the function with proper memory alignment and code placement.
    """
    code_data = extract_function_code(func_addr)
    if not code_data:
        return False

    code, target_base, code_size = code_data
    target_size = (code_size + 0x1000 - 1) & ~(0x1000 - 1)
    target_base_aligned = target_base - (target_base % 0x1000)
    map_size = target_size + 0x1000  # Extra page

    if VERBOS: print("Before mapping code:")
    print_mapped_regions(mapped_regions)

    try:
        if VERBOS: print(f"Mapping code at {hex(target_base_aligned)}, size {hex(map_size)}")
        map_memory(uc, target_base_aligned, map_size, UC_PROT_ALL, mapped_regions)

        # Write the function code at the correct offset
        offset = func_addr - target_base_aligned
        uc.mem_write(target_base_aligned + offset, code)
    except UcError as e:
        print(f"Memory mapping failed for code: {e}")
        return False

    try:
        if VERBOS: print(f"Mapping data section at {hex(data_base)}, size 0x1000")
        map_memory(uc, data_base, 0x1000, UC_PROT_ALL, mapped_regions)
    except UcError as e:
        print(f"Data section mapping failed: {e}")
        return False

    # Map stack
    stack_base = 0x100000
    stack_size = 0x1000
    try:
        if VERBOS: print(f"Mapping stack at {hex(stack_base)}, size {hex(stack_size)}")
        map_memory(uc, stack_base, stack_size, UC_PROT_ALL, mapped_regions)  # Track the stack in mapped_regions
        uc.reg_write(UC_X86_REG_RSP, stack_base + stack_size // 2)
    except UcError as e:
        print(f"Stack mapping failed: {e}")
        return False

    uc.reg_write(UC_X86_REG_RIP, func_addr)

    # Add hooks
    cs = Cs(CS_ARCH_X86, CS_MODE_64)
    cs.detail = True
    state = {}
    uc.hook_add(UC_HOOK_CODE, trace,
                {"cs": cs, "state": state, "runtime_address": runtime_address, "mapped_regions": mapped_regions})
    if VERBOS: uc.hook_add(UC_HOOK_MEM_UNMAPPED, mem_invalid, {"mapped_regions": mapped_regions})
    if VERBOS: uc.hook_add(UC_HOOK_MEM_WRITE, hook_memory_write)

    if VERBOS: print(f"Emulating function at {hex(func_addr)}...")
    try:
        uc.emu_start(func_addr, target_base + code_size)
        return True
    except UcError as e:
        print(f"Unicorn error during emulation: {e}")
        print(f"Current RIP: {hex(uc.reg_read(UC_X86_REG_RIP))}")
        return False


def process_references(target_func_name):
    """
    Process all cross-references to the target function.
    """
    target_func_addr = ida_name.get_name_ea(ida_idaapi.BADADDR, target_func_name)
    if target_func_addr == ida_idaapi.BADADDR:
        print(f"Function '{target_func_name}' not found.")
        return

    print(f"Function '{target_func_name}' found at {hex(target_func_addr)}")
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    mapped_regions = []
    data_base = 0x700000
    counter = 0

    for xref in idautils.XrefsTo(target_func_addr):
        if LIMIT_NUM_OF_FUNC > 0 and counter >= LIMIT_NUM_OF_FUNC:
            print(f"Reached function limit: {LIMIT_NUM_OF_FUNC}")
            return

        if DEBUG_SINGLE_FUNC > 0:
            xref.frm = DEBUG_SINGLE_FUNC

        calling_func = ida_funcs.get_func(xref.frm)
        if not calling_func:
            print(f"Undefined function at reference: {hex(xref.frm)}")
            new_func_addr = create_function_near(xref.frm)
            if new_func_addr:
                calling_func = ida_funcs.get_func(new_func_addr)

        if calling_func:
            
            func_addr = calling_func.start_ea
            if xref.frm in SEGMENT_ADDRESS:
                print(f"Skipping already analyzed function at {hex(func_addr)}")
                continue
            func_name = ida_name.get_name(calling_func.start_ea)
            if not func_name.startswith("sub_"):
                print(f"Skipping renamed function: {func_name} at {hex(calling_func.start_ea)}")
                continue
            func_type = idc.get_type(calling_func.start_ea)
            if func_type and (func_type.split("(")[1].split(")")[0] != ''):
                print(f"Skipping function with arguments: {func_name} at {hex(calling_func.start_ea)}")
                continue
            func_size = calling_func.end_ea - calling_func.start_ea
            if func_size < SIZE_MIN_THRESHOLD or func_size > SIZE_MAX_THRESHOLD:
                print(f"Skipping function at {hex(calling_func.start_ea)} (size {func_size:#x}).")
                continue

            result = emulate_function(calling_func.start_ea, uc, data_base, mapped_regions, target_func_addr)

            # Release mapped memory after analyzing the function
            release_mapped_memory(uc, mapped_regions)
            if DEBUG_SINGLE_FUNC > 0:
                return
            if result: counter += 1


# Main Execution
if __name__ == "__main__":
    # Initialize segment and load existing data
    DECRYPTED_SEGMENT_BASE, SEGMENT_ADDRESS, SEGMENT_OFFSET = create_or_load_segment()

    # Start processing references
    process_references("runtime.slicebytetostring")

