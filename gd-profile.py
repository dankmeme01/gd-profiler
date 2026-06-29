#!/usr/bin/env python3
from __future__ import annotations
import sys
import os
import subprocess
import argparse
import time
import requests
import json
import pefile
import multi_demangle
import shutil
import codecs
import hashlib
import profile
import re
from pydantic import BaseModel
from datetime import datetime
from pathlib import Path
from threading import Thread, Lock
from multiprocessing import Queue

# TODO: perf crashes
# TODO: script cache

SYMBOL_THREADS = 8
SYMBOL_CACHE_PATH = Path.home() / ".cache" / "gd-profiler-symbol-cache.json"

class MemoryMapping(BaseModel):
    start: int
    end: int
    pathname: str | None

class LoadedModule(BaseModel):
    name: str
    full_path: Path
    base: int

def _demangle(s: str) -> str:
    return multi_demangle.demangle_symbol(s) # type: ignore

class Symbol(BaseModel):
    name: str
    module: LoadedModule
    offset: int
    size: int

    def address(self) -> int:
        return self.module.base + self.offset

    def demangled(self) -> str:
        if self.name.startswith("__imp___load_?"):
            mangled_part = self.name.replace("__imp___load_", "")
            demangled = _demangle(mangled_part)
            return f"{demangled} (delayload thunk)"

        demangled = _demangle(self.name)

        if demangled.startswith("public:") or demangled.startswith("private:") or demangled.startswith("protected:"):
            demangled = demangled.partition(":")[2].strip()

        return demangled

    def to_cached(self) -> CachedSymbol:
        return CachedSymbol(
            name=self.name,
            offset=self.offset,
            size=self.size
        )

class CachedSymbol(BaseModel):
    name: str
    offset: int
    size: int

    def to_symbol(self, module: LoadedModule) -> Symbol:
        return Symbol(
            name=self.name,
            module=module,
            offset=self.offset,
            size=self.size
        )

class SymbolCacheEntry(BaseModel):
    module: LoadedModule
    module_hash: str
    symbols: list[CachedSymbol]

class SymbolCache(BaseModel):
    modules: dict[str, SymbolCacheEntry]

    @classmethod
    def load(cls):
        if SYMBOL_CACHE_PATH.exists():
            try:
                return cls.model_validate_json(SYMBOL_CACHE_PATH.read_text())
            except Exception as e:
                print(f"Error loading symbol cache: {e}")

        return cls(modules={})

    def save(self):
        SYMBOL_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        SYMBOL_CACHE_PATH.write_text(self.model_dump_json())

class PDBSection(BaseModel):
    number: int
    name: str
    address: int


work_dir: Path = Path.cwd()
symbol_cache = SymbolCache.load()
symbol_cache_lock = Lock()

def parse_maps(pid: int) -> list[MemoryMapping]:
    mappings: list[MemoryMapping] = []

    with open(f"/proc/{pid}/maps", "r") as maps_file:
        for line in maps_file:
            parts = line.split()
            if len(parts) >= 6:
                address_range = parts[0]
                pathname = parts[5] if len(parts) > 5 else None

                start, end = [int(x, 16) for x in address_range.split('-')]
                mappings.append(MemoryMapping(start=start, end=end, pathname=pathname))

    # second pass
    out_mappings: list[MemoryMapping] = []
    checked_dlls = set()

    for map in mappings:
        if not map.pathname or (not map.pathname.endswith(".dll") and not map.pathname.endswith(".exe")):
            out_mappings.append(map)
            continue

        # this is a dll or exe, we want to find true shit
        if map.pathname in checked_dlls:
            continue

        checked_dlls.add(map.pathname)
        out_mappings.append(map) # pe header

        try:
            pe = pefile.PE(str(map.pathname), fast_load=True)
            for section in pe.sections:
                section_start = map.start + section.VirtualAddress
                out_mappings.append(MemoryMapping(
                    start=section_start,
                    end=section_start + section.Misc_VirtualSize,
                    pathname=map.pathname
                ))
        except Exception as e:
            print(f"!! Error parsing PE file {map.pathname}: {e}")

            continue

    return out_mappings

def get_loaded_modules(maps: list[MemoryMapping]) -> dict[str, LoadedModule]:
    modules = {}

    for map in maps:
        if not map.pathname:
            continue

        pathname = map.pathname
        lower = pathname.lower()
        if "." in pathname and lower != ".glXXXXXX" and ".ttf" not in lower and ".nls" not in lower:
            module_name = os.path.basename(pathname)

            if module_name not in modules:
                modules[module_name] = LoadedModule(
                    name=module_name,
                    full_path=Path(pathname),
                    base=map.start
                )

    return modules

# Returns all symbols for gd.exe
def get_cached_codegen_data(module: LoadedModule) -> list[Symbol]:
    cache_path = Path("/tmp/gd-profiler-CodegenData.json")

    if not cache_path.exists():
        r = requests.get("https://prevter.github.io/bindings-meta/CodegenData-2.2081-Win64.json", stream=True)
        r.raise_for_status()

        with open(cache_path, "wb") as f:
            for chunk in r.iter_content(chunk_size=8192):
                f.write(chunk)

    output = []
    for (offset, name) in json.loads(cache_path.read_text()):
        output.append(Symbol(name=name, module=module, offset=offset, size=0))
    return output

def _verify_pdb_match(path: Path, guid: str, age: int) -> bool:
    output = subprocess.run(
        ['llvm-pdbutil', 'dump', '--summary', path],
        capture_output=True, text=True, check=True
    ).stdout
    guid_match = re.search(r'GUID\s*:\s*{?([A-Fa-f0-9\-]+)}?', output)
    age_match = re.search(r'Age\s*:\s*(\d+)', output)

    if guid_match and age_match:
        pdb_guid = guid_match.group(1).replace('-', '').upper()
        pdb_age = int(age_match.group(1))
        return guid == pdb_guid and age == pdb_age

    return False

def _parse_pdb_sections(path: Path) -> list[PDBSection]:
    result = subprocess.run(
        [shutil.which("llvm-pdbutil") or "llvm-pdbutil", "dump", "--section-headers", str(path)],
        capture_output=True,
        text=True,
        check=True
    ).stdout

    current_section = None
    sections = []

    for line in result.splitlines():
        line = line.strip()
        if "SECTION HEADER #" in line:
            current_section = int(line.split("#")[-1].strip())

        elif "virtual address" in line and current_section is not None:
            match = re.search(r'([0-9a-fA-F]+)\s+virtual address', line)
            if match:
                base = int(match.group(1), 16)
                sections.append(PDBSection(number=current_section, name=f"Section_{current_section}", address=base))

    return sections

def _parse_pdb_symbol(line1: str, line2: str, sections: list[PDBSection], module: LoadedModule) -> Symbol | None:
    # 833892 | S_PUB32 [size = 44] `??_R2SetIDPopupDelegate@@8`
    # flags = none, addr = 0002:140480

    line1_match = re.search(r'size\s*=\s*(\d+)\].*?`([^`]+)`', line1)
    line2_match = re.search(r'addr\s*=\s*(\d+):(\d+)', line2)

    if not line1_match or not line2_match:
        print(f"Symbol not eligible 1")
        return None

    size = int(line1_match.group(1))
    offset_in_section = int(line2_match.group(2))
    section_index = int(line2_match.group(1))

    section = None
    for sec in sections:
        if sec.number == section_index:
            section = sec
            break

    if section is None:
        print(f"Searched for section {section_index} and did not find, sections: {sections}")
        return None

    rva = section.address + offset_in_section

    return Symbol(
        name=line1_match.group(2),
        module=module,
        offset=rva,
        size=size
    )


def get_symbols_for(module: LoadedModule) -> list[Symbol]:
    if module.name.endswith(".exe"):
        # this is gd.exe, fetch the symbols
        return get_cached_codegen_data(module)

    if not module.name.endswith(".dll") or not module.full_path.exists():
        return []

    # check if it's cached
    with symbol_cache_lock:
        if cached_symbols := symbol_cache.modules.get(module.name):
            binary_hash = hashlib.blake2b(module.full_path.read_bytes()).hexdigest()
            if cached_symbols.module_hash == binary_hash:
                return [s.to_symbol(module) for s in cached_symbols.symbols]

    # this is a dll file, first let's try getting the exported symbols
    found_offsets = set()
    symbols: list[Symbol] = []
    binary_guid = None
    binary_age = None
    alternate_pdb_path = None

    try:
        pe = pefile.PE(str(module.full_path), fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT'],
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_DEBUG']
        ])

        if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            return []

        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols: # type: ignore
            if exp.name:
                func_name = exp.name.decode('utf-8')
            else:
                func_name = f"Ordinal_{exp.ordinal}"

            symbols.append(Symbol(name=func_name, module=module, offset=exp.address, size=0))
            found_offsets.add(exp.address)

        if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'):
            for directory in pe.DIRECTORY_ENTRY_DEBUG: # type: ignore
                entry = directory.entry
                if hasattr(entry, 'Signature_Data1'):
                    # i hate everything
                    binary_guid = f"{entry.Signature_Data1:08X}{entry.Signature_Data2:04X}{entry.Signature_Data3:04X}{entry.Signature_Data4:02X}{entry.Signature_Data5:02X}{codecs.encode(entry.Signature_Data6, 'hex').decode()}".upper()
                    binary_age = entry.Age
                    break

                if hasattr(entry, 'PdbFileName'):
                    # it has a null byte for whatever reason
                    alternate_pdb_path = entry.PdbFileName.rstrip(b'\x00').decode()

    except Exception as e:
        print(f"!! Error parsing PE file {module.full_path}: {e}")

    # try to locate the pdb for this dll
    mod_id = module.name.rpartition(".")[0]
    pdb_name = f"{mod_id}.pdb"

    pdb_paths = [
        module.full_path.parent / pdb_name,
        work_dir / pdb_name,
        work_dir / "geode" / "mods" / pdb_name,
        Path.cwd() / pdb_name,
    ]
    if alternate_pdb_path:
        pdb_paths.append(Path(alternate_pdb_path))

    pre_pdb = len(symbols)
    found_pdb = None

    for pdb_path in pdb_paths:
        if not pdb_path.exists():
            continue

        found_pdb = pdb_path
        if binary_guid and binary_age and not _verify_pdb_match(pdb_path, binary_guid, binary_age):
            print(f"[profiler] !! PDB {pdb_path} does not match the binary {module.full_path}")
            print(f"[profiler] !! DLL GUID: {binary_guid}, Age: {binary_age}")
            continue

        print(f"[profiler] found matching PDB for {module.name} at {pdb_path}, loading symbols..")

        sections = _parse_pdb_sections(pdb_path)

        # run llvm-pdbutil
        output = subprocess.run(
            [shutil.which("llvm-pdbutil") or "llvm-pdbutil", "dump", "-publics", str(pdb_path)],
            capture_output=True,
            text=True,
            check=True
        ).stdout

        output = output.partition("Records")[2].strip().splitlines()
        assert len(output) % 2 == 0

        # Example output of each record:
        # 833892 | S_PUB32 [size = 44] `??_R2SetIDPopupDelegate@@8`
        # flags = none, addr = 0002:140480
        # addr contains section index (not same as array index)
        for i in range(0, len(output), 2):
            line1 = output[i].strip()
            line2 = output[i + 1].strip()
            if symbol := _parse_pdb_symbol(line1, line2, sections, module):
                if symbol.offset in found_offsets:
                    continue
                symbols.append(symbol)
                print(f"PDB: found {symbol.name} at {symbol.offset:x}")
                found_offsets.add(symbol.offset)

        break

    pdb_sym_count = len(symbols) - pre_pdb
    if found_pdb:
        print(f"[profiler] {module.name}: found PDB at {found_pdb} and loaded {pdb_sym_count} symbols from it")

    # save to cache
    binary_hash = hashlib.blake2b(module.full_path.read_bytes()).hexdigest()
    with symbol_cache_lock:
        symbol_cache.modules[module.name] = SymbolCacheEntry(
            module=module,
            module_hash=binary_hash,
            symbols=[s.to_cached() for s in symbols]
        )

    return symbols

def get_wine_version(wine_path: Path) -> str:
    result = subprocess.run([str(wine_path), "--version"], capture_output=True, text=True, check=True)
    return result.stdout.strip()

# Run GD in Wine and return the PID
def run_gd(wine_path: Path, gd_path: Path, gd_args: list[str]) -> subprocess.Popen:
    global work_dir

    if not wine_path.exists():
        print(f"Wine executable not found at {wine_path}")
        print("Please specify the path to wine via --wine-path")
        sys.exit(1)

    work_dir = gd_path.parent
    print(f"[profiler] Running {gd_path} with Wine {wine_path} (version {get_wine_version(wine_path)}), extra args: {gd_args}")

    return subprocess.Popen(
        [str(wine_path), str(gd_path), *gd_args],
        cwd=work_dir,
    )

def run_perf(pid: int, freq: int = 1000, use_lbr: bool = False, use_cpu_clock: bool = False) -> subprocess.Popen:
    cmdline = ["perf", "record", "-g", "-F", str(freq), "-p", str(pid)]

    if use_lbr:
        cmdline.extend(["--call-graph", "lbr"])
    if use_cpu_clock:
        cmdline.extend(["-e", "cpu-clock"])

    print(f"[profiler] perf args: {cmdline}")

    return subprocess.Popen(
        cmdline,
        stdout=subprocess.DEVNULL,
    )

def run_perf_conversion() -> Path:
    p = Path.cwd() / "profile.perf"
    f = open(p, "w")
    subprocess.run(
        ["perf", "script", "-F", "+pid"],
        stdout=f,
        check=True,
    )
    f.close()
    return p

def run_fxprof_conversion(pid: int, perf_script_path: Path, frequency: int, gd_exe: Path, start_time: int) -> Path | None:
    p = Path.cwd() / "profile.json"
    f = open(p, "w")

    exe = shutil.which("fxprof-converter")
    if not exe:
        return None

    args = [exe, str(perf_script_path), str(pid), str(frequency), shutil.which(gd_exe) or gd_exe, str(start_time)]
    print(f"[profiler] fxprof-converter args: {args}")
    subprocess.run(
        args,
        stdout=f,
        check=True,
    )
    f.close()
    return p

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--wine-path", type=Path, required=False, help="Path to the Wine executable")
    parser.add_argument("--frequency", "-F", type=int, required=False, default=1000, help="Sampling frequency for perf")
    parser.add_argument("--use-lbr", action="store_true", help="Use LBR (Last Branch Record) for perf")
    parser.add_argument("--use-cpu-clock", action="store_true", help="Use CPU clock for perf")
    parser.add_argument("gd_exe", type=Path, nargs="?", default=Path("GeometryDash.exe"), help="Path to the GD executable")
    parser.add_argument("gd_args", nargs=argparse.REMAINDER, help="Additional arguments to pass to GD")

    args = parser.parse_args()

    gd = run_gd(
        wine_path=args.wine_path or Path("/usr/bin/wine"),
        gd_path=args.gd_exe,
        gd_args=args.gd_args
    )
    pid = gd.pid
    print(f"[profiler] GD is running, pid: {pid}")

    start_time = int(time.time() * 1000)
    perf = run_perf(pid=pid, freq=args.frequency, use_lbr=args.use_lbr, use_cpu_clock=args.use_cpu_clock)
    print(f"[profiler] perf is now capturing samples")

    print(f"[profiler] waiting for the game to finish launching..")
    last_modules_added = time.time()
    last_modules = 0

    while True:
        maps = parse_maps(gd.pid)
        modules = get_loaded_modules(maps)
        if len(modules) != last_modules:
            last_modules = len(modules)
            last_modules_added = time.time()

        if time.time() - last_modules_added > 3.0:
            print(f"[profiler] nothing has been loaded in the last 3 seconds, assuming the game finished launching")
            break

        time.sleep(0.25)

    print(f"[profiler] total modules loaded: {len(modules)}")

    with open(f"/tmp/perf-{gd.pid}.meta.txt", 'w') as f:
        f.write(f"Modules:\n")
        for module in modules.values():
            f.write(f"{module.base:x} {module.full_path}\n")

        f.write(f"\nMaps:\n")
        for map in maps:
            f.write(f"{map.start:x} {map.end:x} {map.pathname}\n")


    print(f"[profiler] writing metadata to /tmp/perf-{gd.pid}.meta.txt")
    print(f"[profiler] beginning to fetch symbols for all modules..")

    all_syms: list[Symbol] = []
    all_syms_lock = Lock()
    pending_modules = Queue()
    for module in modules.values():
        pending_modules.put(module)

    def worker():
        while True:
            try:
                module = pending_modules.get_nowait()
            except:
                break

            syms = get_symbols_for(module)
            with all_syms_lock:
                all_syms.extend(syms)
            print(f"[profiler] {module.name}: {len(syms)} symbols")

    threads = []
    for _ in range(SYMBOL_THREADS):
        t = Thread(target=worker)
        t.start()
        threads.append(t)
    [t.join() for t in threads]

    all_syms.sort(key=lambda s: s.address())
    symbol_cache.save()
    print(f"[profiler] total symbols fetched: {len(all_syms)}")

    with open(f"/tmp/perf-{gd.pid}.map", 'w') as f:
        for i, sym in enumerate(all_syms):
            size = sym.size
            if sym.size == 0 and i + 1 < len(all_syms):
                # if size is unavailable, fill it to be the distance to next symbol
                size = all_syms[i + 1].address() - sym.address()
                if size > 0x10000:
                    # likely erroneous
                    size = 1

            f.write(f"{sym.address():x} {size or 0:x} {sym.demangled()}\n")

    print(f"[profiler] symbols written to /tmp/perf-{gd.pid}.map, waiting for the game to exit now..")
    gd.wait()
    print(f"[profiler] game exit detected, stopping perf")
    perf.terminate()
    perf.wait()

    print(f"[profiler] running perf script to convert the profile into text...")
    p = run_perf_conversion()
    print(f"[profiler] raw profile now available at {p}, let's see if we can convert to fxprof...")
    fxp = run_fxprof_conversion(gd.pid, p, args.frequency, args.gd_exe, start_time)
    if fxp:
        print(f"[profiler] fxprof profile now available at {fxp} and can be loaded at https://profiler.firefox.com/")
    else:
        print(f"[profiler] converter is unavailable! please ensure you built 'fxprof-converter' and put it in PATH")
        print(f"[profiler] for now, you can still use the raw perf script output by loading it at https://profiler.firefox.com/")
