#!/usr/bin/env python3
from __future__ import annotations
import sys
import os
import subprocess
import argparse
import time
import pefile
import shutil
from pydantic import BaseModel
from pathlib import Path

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

work_dir: Path = Path.cwd()

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

def run_perf_conversion(pid: int) -> Path:
    p = Path.cwd() / "profile.perf"
    f = open(p, "w")
    subprocess.run(
        ["perf", "script", "-F", "+pid", f"--pid={pid}", "--stitch-lbr"],
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
    parser.add_argument("--no-lbr", action="store_true", help="Do not use LBR for perf")
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
    perf = run_perf(pid=pid, freq=args.frequency, use_lbr=not args.no_lbr)
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
    print(f"[profiler] nothing else to do, waiting for the game to exit...")
    gd.wait()
    print(f"[profiler] game exit detected, stopping perf")
    perf.terminate()
    perf.wait()

    print(f"[profiler] running perf script to convert the profile into text...")
    p = run_perf_conversion(pid)
    print(f"[profiler] raw profile now available at {p}, let's see if we can convert to fxprof...")
    fxp = run_fxprof_conversion(gd.pid, p, args.frequency, args.gd_exe, start_time)
    if fxp:
        print(f"[profiler] fxprof profile now available at {fxp} and can be loaded at https://profiler.firefox.com/")
    else:
        print(f"[profiler] converter is unavailable! please ensure you built 'fxprof-converter' and put it in PATH")
        print(f"[profiler] for now, you can still use the raw perf script output by loading it at https://profiler.firefox.com/")
