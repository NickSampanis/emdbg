"""Export Hex-Rays pseudocode, line numbers, types and variables for emdbg.

Run from IDA (File > Script file...). For CpuDxe.dll it writes CpuDxe.c and
CpuDxe.ids next to the input executable (next to the IDB if the executable is no
longer there).

.ids version 2, little endian, packed. The layout is shared with the PDB and ELF
loaders in dbgeng, so it describes symbols generically.

    header     char magic[4] = "EIDS", u32 version = 2, u32 section_count,
               u32 reserved, u64 module_size
    directory  section_count x { char tag[4], u32 entry_size, u64 offset, u64 size }

Every section is an array of fixed-size records; entry_size lets later versions
append fields. Unknown tags are skipped. Names are offsets into STRS (0 = "").
Addresses are RVAs (offsets from the image base). Type index 0 means "unknown".

    STRS  NUL-terminated strings
    FILE  u32 path
    FUNC  u64 start, u64 end, u32 name, u32 type, u32 first_var, u32 var_count,
          u32 first_cfa, u32 cfa_count
    LINE  u64 start, u64 end, u32 line, u32 file           [start, end), 1-based line
    TYPE  u8 kind, u8 flags, u16 reserved, u32 size, u32 name, u32 target, u32 count,
          u32 first_member, u32 member_count
    MEMB  u32 name, u32 type, u64 offset, u16 bit_offset, u16 bit_size, u32 reserved
    ENUM  u32 name, u32 reserved, i64 value
    VAR   u32 name, u32 type, u32 flags, u32 first_loc, u32 loc_count, u32 reserved,
          u64 scope_start, u64 scope_end                  scope 0,0 = whole function
    GVAR  same as VAR, for globals
    LOC   u8 kind, u8 reserved, u16 reserved, u32 reg, i64 offset, u64 start, u64 end
    CFA   u64 start, u32 reg, u32 reserved, i64 offset    CFA = reg + offset from start on,
          until the rule with the next higher start (this script writes them sorted)

The CFA (canonical frame address) is the stack pointer before the call that
entered the function, the same as in DWARF call frame information.
"""

import os
import struct
import sys

import ida_bytes
import ida_frame
import ida_funcs
import ida_hexrays
import ida_ida
import ida_lines
import ida_nalt
import ida_typeinf
import idaapi
import idautils
import idc

IDS_MAGIC = b"EIDS"
IDS_VERSION = 2

T_NONE, T_VOID, T_BOOL, T_INT, T_UINT, T_FLOAT, T_POINTER, T_ARRAY, T_STRUCT, T_UNION, \
    T_ENUM, T_FUNCTION, T_TYPEDEF = range(13)
TF_CONST, TF_VOLATILE, TF_CHAR, TF_FORWARD, TF_VARARGS = 1, 2, 4, 8, 16

V_PARAM, V_LOCAL, V_GLOBAL, V_STATIC = 1, 2, 4, 8

L_NONE, L_ABSOLUTE, L_CFA, L_REG_RELATIVE, L_REGISTER, L_VALUE = range(6)

RECORDS = {
    b"FILE": "<I",
    b"FUNC": "<QQIIIIII",
    b"LINE": "<QQII",
    b"TYPE": "<BBHIIIIII",
    b"MEMB": "<IIQHHI",
    b"ENUM": "<IIq",
    b"VAR ": "<IIIIIIQQ",
    b"GVAR": "<IIIIIIQQ",
    b"LOC ": "<BBHIqQQ",
    b"CFA ": "<QIIq",
}


def line_of_address(cfunc, address):
    item = cfunc.body.find_closest_addr(address)
    if item is None:
        return None
    y_holder = idaapi.int_pointer()
    if not cfunc.find_item_coords(item, None, y_holder):
        return None
    return y_holder.value()


def decompile(func_ea):
    try:
        return ida_hexrays.decompile(func_ea)
    except ida_hexrays.DecompilationFailure:
        return None


def output_directory():
    input_path = ida_nalt.get_input_file_path()
    if input_path and os.path.isfile(input_path):
        return os.path.dirname(os.path.abspath(input_path))
    return os.path.dirname(os.path.abspath(idaapi.get_path(idaapi.PATH_TYPE_IDB)))


def module_name_of_input():
    """CpuDxe.dll -> CpuDxe, so the debugger finds CpuDxe.ids next to CpuDxe.dll."""
    name = ida_nalt.get_root_filename()
    if not name:
        name = os.path.basename(idaapi.get_path(idaapi.PATH_TYPE_IDB))
        for extension in (".i64", ".idb"):
            if name.lower().endswith(extension):
                name = name[:-len(extension)]
    return os.path.splitext(name)[0] or name


def address_lines(cfunc, func_ea, first_line, base):
    records = []
    current_line = None
    start = 0
    end = 0
    for address in idautils.FuncItems(func_ea):
        line = line_of_address(cfunc, address)
        if line is None:
            continue
        if line != current_line:
            if current_line is not None:
                records.append((start - base, end - base, first_line + current_line, 0))
            current_line = line
            start = address
        end = idc.get_item_end(address)
    if current_line is not None:
        records.append((start - base, end - base, first_line + current_line, 0))
    return records


class Symbols:
    def __init__(self, base, wide):
        self.base = base
        self.wide = wide
        self.pointer_size = 8 if wide else 4
        self.sp_name = "rsp" if wide else "esp"
        self.strings = bytearray(b"\0")
        self.string_index = {"": 0}
        self.sections = {tag: [] for tag in RECORDS}
        self.sections[b"TYPE"].append((T_NONE, 0, 0, 0, 0, 0, 0, 0, 0))
        self.type_index = {}

    def string(self, text):
        text = text or ""
        if text not in self.string_index:
            self.string_index[text] = len(self.strings)
            self.strings += text.encode("utf-8", "replace") + b"\0"
        return self.string_index[text]

    # --- types --------------------------------------------------------------------

    def basic_type(self, kind, size, name, flags=0):
        key = ("basic", kind, size, name, flags)
        if key not in self.type_index:
            self.type_index[key] = len(self.sections[b"TYPE"])
            self.sections[b"TYPE"].append((kind, flags, 0, size, self.string(name), 0, 0, 0, 0))
        return self.type_index[key]

    def type_id(self, tif):
        if tif is None or tif.empty():
            return 0
        key = (tif.dstr(), tif.get_size())
        if key in self.type_index:
            return self.type_index[key]
        index = len(self.sections[b"TYPE"])
        self.type_index[key] = index
        self.sections[b"TYPE"].append(None)
        self.sections[b"TYPE"][index] = self.describe(tif)
        return index

    def describe(self, tif):
        flags = 0
        if tif.is_const():
            flags |= TF_CONST
        if tif.is_volatile():
            flags |= TF_VOLATILE
        size = tif.get_size()
        if size == ida_typeinf.BADSIZE:
            size = 0
        name = self.string(tif.get_type_name() or "")
        if tif.is_ptr():
            return (T_POINTER, flags, 0, size or self.pointer_size, name,
                    self.type_id(tif.get_pointed_object()), 0, 0, 0)
        if tif.is_array():
            count = tif.get_array_nelems()
            return (T_ARRAY, flags, 0, size, name, self.type_id(tif.get_array_element()),
                    max(count, 0), 0, 0)
        if tif.is_func():
            return self.describe_function(tif, flags, size, name)
        if tif.is_enum():
            return self.describe_enum(tif, flags, size, name)
        if tif.is_struct() or tif.is_union():
            return self.describe_udt(tif, flags, size, name)
        if tif.is_void():
            return (T_VOID, flags, 0, 0, name, 0, 0, 0, 0)
        if tif.is_bool():
            return (T_BOOL, flags, 0, size, name, 0, 0, 0, 0)
        if tif.is_floating():
            return (T_FLOAT, flags, 0, size, name, 0, 0, 0, 0)
        if tif.is_char() or tif.is_uchar():
            flags |= TF_CHAR
        if tif.is_integral() or flags & TF_CHAR:
            return (T_INT if tif.is_signed() else T_UINT, flags, 0, size, name, 0, 0, 0, 0)
        return (T_NONE, flags, 0, size, name, 0, 0, 0, 0)

    def describe_udt(self, tif, flags, size, name):
        details = ida_typeinf.udt_type_data_t()
        kind = T_UNION if tif.is_union() else T_STRUCT
        if not tif.get_udt_details(details):
            return (kind, flags | TF_FORWARD, 0, size, name, 0, 0, 0, 0)
        members = []
        for member in details:
            bit_size = member.size if member.is_bitfield() else 0
            bit_offset = member.offset % 8 if bit_size else 0
            members.append((self.string(member.name), self.type_id(member.type),
                            member.offset // 8, bit_offset, bit_size, 0))
        first = len(self.sections[b"MEMB"])
        self.sections[b"MEMB"].extend(members)
        return (kind, flags, 0, size, name, 0, 0, first, len(members))

    def describe_enum(self, tif, flags, size, name):
        details = ida_typeinf.enum_type_data_t()
        values = []
        if tif.get_enum_details(details):
            for value in details:
                number = value.value
                if number >= 1 << 63:
                    number -= 1 << 64
                values.append((self.string(value.name), 0, number))
        first = len(self.sections[b"ENUM"])
        self.sections[b"ENUM"].extend(values)
        return (T_ENUM, flags, 0, size, name, 0, 0, first, len(values))

    def describe_function(self, tif, flags, size, name):
        details = ida_typeinf.func_type_data_t()
        if not tif.get_func_details(details):
            return (T_FUNCTION, flags, 0, 0, name, 0, 0, 0, 0)
        result = self.type_id(details.rettype)
        params = []
        for index, param in enumerate(details):
            params.append((self.string(param.name), self.type_id(param.type), index, 0, 0, 0))
        first = len(self.sections[b"MEMB"])
        self.sections[b"MEMB"].extend(params)
        return (T_FUNCTION, flags, 0, 0, name, result, 0, first, len(params))

    def sized_type(self, size):
        if size in (1, 2, 4, 8):
            return self.basic_type(T_UINT, size, "uint%d_t" % (size * 8))
        byte = self.basic_type(T_UINT, 1, "uint8_t")
        key = ("bytes", size)
        if key not in self.type_index:
            self.type_index[key] = len(self.sections[b"TYPE"])
            self.sections[b"TYPE"].append((T_ARRAY, 0, 0, size, 0, byte, size, 0, 0))
        return self.type_index[key]

    # --- variables ----------------------------------------------------------------

    def add_var(self, tag, name, type_index, flags, location):
        kind, reg, offset = location
        loc_index = len(self.sections[b"LOC "])
        self.sections[b"LOC "].append((kind, 0, 0, self.string(reg), offset, 0, 0))
        self.sections[tag].append((self.string(name), type_index, flags, loc_index, 1, 0, 0, 0))

    def function_vars(self, cfunc, pfn):
        first = len(self.sections[b"VAR "])
        frame_bias = pfn.frsize + pfn.frregs + ida_frame.get_frame_retsize(pfn)
        for var in cfunc.get_lvars():
            if not var.name:
                continue
            if var.location.is_stkoff():
                ida_offset = cfunc.mba.stkoff_vd2ida(var.location.stkoff())
                location = (L_CFA, "", ida_offset - frame_bias)
            elif var.location.is_reg1():
                register = ida_hexrays.get_mreg_name(var.location.reg1(), var.width) or ""
                if not register:
                    continue
                location = (L_REGISTER, register.lower(), 0)
            else:
                continue
            flags = V_PARAM if var.is_arg_var else V_LOCAL
            self.add_var(b"VAR ", var.name, self.type_id(var.type()), flags, location)
        return first, len(self.sections[b"VAR "]) - first

    def function_cfa(self, func_ea, pfn):
        first = len(self.sections[b"CFA "])
        return_size = ida_frame.get_frame_retsize(pfn)
        register = self.string(self.sp_name)
        deltas = []
        for address in idautils.FuncItems(func_ea):
            delta = idc.get_spd(address)
            if delta is not None:
                deltas.append((address, return_size - delta))
        last = None
        for address, offset in sorted(deltas):
            if offset != last:
                self.sections[b"CFA "].append((address - self.base, register, 0, offset))
                last = offset
        return first, len(self.sections[b"CFA "]) - first

    def globals(self):
        for address, name in idautils.Names():
            flags = ida_bytes.get_flags(address)
            if not ida_bytes.is_data(flags):
                continue
            tif = ida_typeinf.tinfo_t()
            if ida_nalt.get_tinfo(tif, address):
                type_index = self.type_id(tif)
            else:
                type_index = self.sized_type(ida_bytes.get_item_size(address))
            self.add_var(b"GVAR", name, type_index, V_GLOBAL,
                         (L_ABSOLUTE, "", address - self.base))

    # --- output -------------------------------------------------------------------

    def write(self, path, module_size):
        sections = [(b"STRS", 1, bytes(self.strings))]
        for tag, layout in RECORDS.items():
            records = self.sections[tag]
            data = b"".join(struct.pack(layout, *record) for record in records)
            sections.append((tag, struct.calcsize(layout), data))
        header_size = struct.calcsize("<4sIIIQ")
        entry_size = struct.calcsize("<4sIQQ")
        offset = header_size + entry_size * len(sections)
        with open(path, "wb") as out:
            out.write(struct.pack("<4sIIIQ", IDS_MAGIC, IDS_VERSION, len(sections), 0,
                                  module_size))
            for tag, size, data in sections:
                out.write(struct.pack("<4sIQQ", tag, size, offset, len(data)))
                offset += len(data)
            for tag, size, data in sections:
                out.write(data)


def export():
    if not ida_hexrays.init_hexrays_plugin():
        print("Hex-Rays decompiler is not available.")
        return
    sys.setrecursionlimit(20000)

    base = ida_nalt.get_imagebase()
    module_name = module_name_of_input()
    directory = output_directory()
    c_path = os.path.join(directory, module_name + ".c")
    ids_path = os.path.join(directory, module_name + ".ids")
    symbols = Symbols(base, ida_ida.inf_is_64bit())
    symbols.sections[b"FILE"].append((symbols.string(c_path),))

    next_line = 1
    with open(c_path, "w", encoding="ascii", errors="replace", newline="\n") as c_file:
        for func_ea in idautils.Functions():
            pfn = ida_funcs.get_func(func_ea)
            cfunc = decompile(func_ea)
            first_var, var_count = 0, 0
            func_type = 0
            if cfunc is not None:
                pseudocode = cfunc.get_pseudocode()
                for line in pseudocode:
                    c_file.write(ida_lines.tag_remove(line.line) + "\n")
                c_file.write("\n")
                symbols.sections[b"LINE"].extend(address_lines(cfunc, func_ea, next_line, base))
                next_line += len(pseudocode) + 1
                first_var, var_count = symbols.function_vars(cfunc, pfn)
                tif = ida_typeinf.tinfo_t()
                if cfunc.get_func_type(tif):
                    func_type = symbols.type_id(tif)
            first_cfa, cfa_count = symbols.function_cfa(func_ea, pfn)
            symbols.sections[b"FUNC"].append((func_ea - base, pfn.end_ea - base,
                                              symbols.string(ida_funcs.get_func_name(func_ea)),
                                              func_type, first_var, var_count,
                                              first_cfa, cfa_count))
    symbols.globals()
    symbols.write(ids_path, ida_ida.inf_get_max_ea() - base)

    print("%d functions, %d types, %d locals, %d globals -> %s, %s" % (
        len(symbols.sections[b"FUNC"]), len(symbols.sections[b"TYPE"]) - 1,
        len(symbols.sections[b"VAR "]), len(symbols.sections[b"GVAR"]), c_path, ids_path))


if __name__ == "__main__":
    export()
