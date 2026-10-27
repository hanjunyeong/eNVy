"""Read PE metadata for display. Does not execute the file or decide malware status."""
import hashlib
import math
from collections import Counter

import pefile

MAX_SECTIONS = 128
MAX_DLLS = 128
MAX_FUNCTIONS = 128
MAX_WARNINGS = 20
MAX_TEXT = 256


def _text(value, fallback=""):
    if value is None:
        return fallback
    if isinstance(value, bytes):
        value = value.split(b"\0", 1)[0].decode("ascii", errors="replace")
    value = str(value)
    return "".join(c if c.isprintable() else "\ufffd" for c in value)[:MAX_TEXT] or fallback


def _entropy(data):
    if not data:
        return 0.0
    length = len(data)
    result = -sum((n / length) * math.log2(n / length) for n in Counter(data).values())
    return round(max(0.0, min(8.0, result)), 4)


def analyze_pe(data: bytes, pe) -> dict:
    """Return bounded display metadata from an already validated pefile.PE object.

    The caller owns and closes ``pe``. Only the standard import directory is
    parsed; delay-loaded imports and runtime API resolution are not enumerated.
    Display caps bound response size, not the work pefile does while parsing.
    """
    warnings = []
    warning_count = 0

    def warn(message):
        nonlocal warning_count
        warning_count += 1
        if len(warnings) < MAX_WARNINGS:
            warnings.append(_text(message)[:300])

    try:
        initial_warnings = list(pe.get_warnings())
    except Exception:
        initial_warnings = []
    for warning in initial_warnings:
        warn(warning)

    magic = int(pe.OPTIONAL_HEADER.Magic)
    pe_format = {0x10B: "PE32 (32-bit)", 0x20B: "PE32+ (64-bit)"}.get(magic, f"Unknown (0x{magic:X})")
    machine_id = int(pe.FILE_HEADER.Machine)
    machine = pefile.MACHINE_TYPE.get(machine_id, f"Unknown (0x{machine_id:X})")
    sections = []
    parsed_sections = list(pe.sections)
    for section in parsed_sections[:MAX_SECTIONS]:
        name = _text(section.Name, "(unnamed)")
        offset = int(section.PointerToRawData)
        raw_size = int(section.SizeOfRawData)
        start = min(max(0, offset), len(data))
        end = min(max(start, offset + raw_size), len(data))
        if raw_size and (offset < 0 or offset + raw_size > len(data)):
            warn(f"Section {name}: raw data exceeds file bounds; entropy uses available bytes.")
        characteristics = int(section.Characteristics)
        permissions = " ".join(label for bit, label in (
            (0x40000000, "R"), (0x80000000, "W"), (0x20000000, "X")
        ) if characteristics & bit) or "-"
        sections.append({
            "name": name,
            "virtual_size": int(section.Misc_VirtualSize),
            "raw_size": raw_size,
            "entropy": _entropy(data[start:end]),
            "permissions": permissions,
        })
    sections_truncated = len(parsed_sections) > MAX_SECTIONS
    if sections_truncated:
        warn(f"Section display limited to {MAX_SECTIONS} parsed sections.")

    imports = []
    imports_status = "none"
    imports_truncated = False
    dll_count = 0
    directory_id = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]
    directories = pe.OPTIONAL_HEADER.DATA_DIRECTORY
    declared_imports = len(directories) > directory_id and bool(directories[directory_id].VirtualAddress)
    parse_failed = False
    try:
        pe.parse_data_directories(directories=[directory_id])
    except Exception:
        parse_failed = True
        warn("Standard import directory parsing failed; the import list may be incomplete.")
    try:
        post_warnings = list(pe.get_warnings())
    except Exception:
        post_warnings = initial_warnings
    # pefile can report recoverable import errors via warnings without raising.
    new_import_warnings = post_warnings[len(initial_warnings):]
    for warning in new_import_warnings:
        warn(warning)
    entries = getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []
    dll_count = len(entries)
    any_functions_truncated = False
    for entry in entries[:MAX_DLLS]:
        all_functions = getattr(entry, "imports", []) or []
        functions = []
        for symbol in all_functions[:MAX_FUNCTIONS]:
            name = _text(getattr(symbol, "name", None))
            if not name:
                ordinal = getattr(symbol, "ordinal", None)
                name = f"ordinal #{ordinal}" if ordinal is not None else "(unnamed import)"
            functions.append(name)
        functions_truncated = len(all_functions) > MAX_FUNCTIONS
        any_functions_truncated |= functions_truncated
        imports.append({
            "dll": _text(getattr(entry, "dll", None), "(unnamed DLL)"),
            "functions": functions,
            "function_count": len(all_functions),
            "functions_truncated": functions_truncated,
        })
    imports_truncated = dll_count > MAX_DLLS
    if imports_truncated:
        warn(f"Import display limited to {MAX_DLLS} parsed DLLs.")
    if any_functions_truncated:
        warn(f"Function display limited to {MAX_FUNCTIONS} imports per DLL.")
    if entries:
        imports_status = "partial" if (parse_failed or new_import_warnings or imports_truncated or any_functions_truncated) else "parsed"
    elif parse_failed or declared_imports:
        imports_status = "failed"
        if not parse_failed:
            warn("A standard import directory is declared but could not be read.")
    elif new_import_warnings:
        imports_status = "partial"

    declared_sections = int(pe.FILE_HEADER.NumberOfSections)
    if declared_sections != len(parsed_sections):
        warn("Declared and parsed section counts differ.")
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "size_bytes": len(data),
        "pe_format": pe_format,
        "machine": str(machine),
        "kind": "DLL" if int(pe.FILE_HEADER.Characteristics) & 0x2000 else "EXE",
        "entry_point": f"0x{int(pe.OPTIONAL_HEADER.AddressOfEntryPoint):X}",
        "section_count": declared_sections,
        "parsed_section_count": len(parsed_sections),
        "sections": sections,
        "sections_truncated": sections_truncated,
        "imports": imports,
        "import_dll_count": dll_count,
        "imports_truncated": imports_truncated,
        "imports_status": imports_status,
        "warnings": warnings,
        "warnings_truncated": warning_count > len(warnings),
    }
