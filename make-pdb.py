#!/usr/bin/env python3
"""
NOTE: small preface, this script is entirely AI generated.
invoke as: make-pdb.py --json CodegenData.json --exe GeometryDash.exe --out GeometryDash.pdb
CodegenData.json comes from `build/bindings/bindings/Geode/` in the build folder of any Geode mod you build.

Resulting PDB is loadable in samply, x64dbg, ida, etc.

--------------------------------------------------------------------------------------

Generate a public-symbols PDB that is actually loadable by pdb2 / pdb-addr2line /
wholesym, from a Geode "CodegenData.json" (function name -> win RVA).

Only the parts a symbol resolver needs are produced:
  * MSF container
  * PDB stream (GUID/Age taken from the target exe so the PDB "matches" it)
  * empty TPI/IPI streams
  * DBI stream with a section-contribution substream (required by pdb-addr2line)
  * public symbol records (S_PUB32)
  * section header table (raw sizes included: pdb2 bounds RVAs with them)
  * /names string table

Deliberately omitted (not needed by wholesym/pdb2, and empty is better than stale):
  * types, modules, line info, OMAP
"""
import argparse
import json
import struct
import sys
from pathlib import Path

MSF_MAGIC = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00"

# stream indices (the PDB stream's named-stream map below hardcodes /LinkInfo=5 and /names=10)
ST_PDB, ST_TPI, ST_DBI, ST_IPI, ST_LINKINFO, ST_GSI, ST_PSI, ST_RECORDS, ST_SECTIONS, ST_NAMES = range(1, 11)

# --- structural constants (empty type streams / empty string table) ---
PDB_STREAM = bytes.fromhex(
    "942e3101548b426a03000000"                                  # version, signature, age
    "508da6a1db4a0e4dab9810df06f76345"                          # guid
    "110000002f4c696e6b496e666f002f6e616d657300"                  # named stream map: /LinkInfo, /names
    "02000000040000000100000006000000000000000a0000000a0000000000000005000000"
    "00000000"
)
EMPTY_TYPE_STREAM = bytes.fromhex(
    "0bca310138000000001000000010000000000000ffffffff04000000ffff0300"
    "000000000000000000000000000000000000000000000000"
)
NAMES_STREAM = bytes.fromhex("feeffeef010000000100000000010000000000000000000000")

S_PUB32 = 0x110E
PUBSYM_CODE = 0x1
PUBSYM_FUNCTION = 0x2
SC_VERSION = 0xEFFE_0000 + 19_970_605
DBI_VERSION_HEADER = 19990903
DBI_BUILD_NUMBER = 36363
IMAGE_SCN_MEM_EXECUTE = 0x20000000

# GSI/PSI hash table (see llvm/lib/DebugInfo/PDB/GSIStreamBuilder.cpp)
IPHR_HASH = 4096
GSI_HDR_SIGNATURE = 0xFFFFFFFF
GSI_HDR_VERSION = 0xEFFE_0000 + 19_990_810
HASH_BITMAP_WORDS = (IPHR_HASH + 32) // 32


# --------------------------------------------------------------------- PE
def parse_pe(path):
    d = Path(path).read_bytes()
    e = struct.unpack_from("<I", d, 0x3C)[0]
    coff = e + 4
    machine = struct.unpack_from("<H", d, coff)[0]
    nsec = struct.unpack_from("<H", d, coff + 2)[0]
    optsize = struct.unpack_from("<H", d, coff + 16)[0]
    opt = coff + 20
    magic = struct.unpack_from("<H", d, opt)[0]
    dd = opt + (0x70 if magic == 0x20B else 0x60)
    secoff = opt + optsize

    sections = []
    for i in range(nsec):
        s = secoff + i * 40
        sections.append(dict(
            name=d[s:s + 8].rstrip(b"\0"),
            vsize=struct.unpack_from("<I", d, s + 8)[0],
            va=struct.unpack_from("<I", d, s + 12)[0],
            rawsize=struct.unpack_from("<I", d, s + 16)[0],
            rawptr=struct.unpack_from("<I", d, s + 20)[0],
            chars=struct.unpack_from("<I", d, s + 36)[0],
        ))

    def rva2off(rva):
        for s in sections:
            if s["va"] <= rva < s["va"] + max(s["vsize"], 1):
                return s["rawptr"] + (rva - s["va"])

    drva, dsz = struct.unpack_from("<II", d, dd + 6 * 8)
    off = rva2off(drva)
    for j in range(dsz // 28):
        _, ts, _, _, typ, sz, _, ptr = struct.unpack_from("<IIHHIIII", d, off + j * 28)
        if typ == 2:  # CODEVIEW / RSDS
            return dict(
                machine=machine, guid=d[ptr + 4:ptr + 20],
                age=struct.unpack_from("<I", d, ptr + 20)[0],
                timestamp=ts, sections=sections,
            )
    raise SystemExit(f"{path}: no RSDS record")


# -------------------------------------------------------------------- MSF
def read_msf(path):
    data = Path(path).read_bytes()
    (bs, _, _, dir_bytes, _, bmap) = struct.unpack_from("<IIIIII", data, 32)
    ndir = (dir_bytes + bs - 1) // bs
    dir_blocks = struct.unpack_from("<%dI" % ndir, data, bmap * bs)
    dbuf = b"".join(data[b * bs:(b + 1) * bs] for b in dir_blocks)
    nstreams = struct.unpack_from("<I", dbuf, 0)[0]
    sizes = list(struct.unpack_from("<%dI" % nstreams, dbuf, 4))
    off = 4 + 4 * nstreams
    streams = []
    for sz in sizes:
        cnt = 0 if sz in (0, 0xFFFFFFFF) else (sz + bs - 1) // bs
        blocks = list(struct.unpack_from("<%dI" % cnt, dbuf, off)) if cnt else []
        off += 4 * cnt
        buf = bytearray()
        for b in blocks:
            buf += data[b * bs:(b + 1) * bs]
        streams.append(bytes(buf[:sz]) if cnt else b"")
    return bs, sizes, streams


def write_msf(path, bs, streams):
    sizes = [len(s) for s in streams]
    blockcounts = [(len(s) + bs - 1) // bs if s else 0 for s in streams]
    dir_bytes = 4 + 4 * len(sizes) + 4 * sum(blockcounts)
    ndir = (dir_bytes + bs - 1) // bs

    nextblk = 4
    assign = []
    for cnt in blockcounts:
        assign.append(list(range(nextblk, nextblk + cnt)))
        nextblk += cnt
    dir_blocks = list(range(nextblk, nextblk + ndir))
    nextblk += ndir
    nblocks = nextblk

    out = bytearray(nblocks * bs)
    out[0:32] = MSF_MAGIC
    struct.pack_into("<IIIIII", out, 32, bs, 2, nblocks, dir_bytes, 0, 3)
    struct.pack_into("<%dI" % ndir, out, 3 * bs, *dir_blocks)

    dbuf = bytearray(struct.pack("<I", len(sizes)))
    dbuf += struct.pack("<%dI" % len(sizes), *sizes)
    for blocks in assign:
        if blocks:
            dbuf += struct.pack("<%dI" % len(blocks), *blocks)
    assert len(dbuf) == dir_bytes
    dbuf += b"\0" * (ndir * bs - len(dbuf))
    for i, b in enumerate(dir_blocks):
        out[b * bs:(b + 1) * bs] = dbuf[i * bs:(i + 1) * bs]
    for blocks, sdata in zip(assign, streams):
        for j, b in enumerate(blocks):
            chunk = sdata[j * bs:(j + 1) * bs]
            out[b * bs:b * bs + len(chunk)] = chunk
    Path(path).write_bytes(out)
    return nblocks


# --------------------------------------------------------------- records
def _looks_placeholder(name):
    return name.startswith("sub_") or name.startswith("loc_") or name.startswith("unknown_")


def encode_pub32(segment, offset, flags, name):
    body = struct.pack("<HIIH", S_PUB32, flags, offset, segment) + name.encode("utf-8") + b"\0"
    while (2 + len(body)) % 4:
        body += b"\0"
    return struct.pack("<H", len(body)) + body


def decode_pub32(stream):
    """Yield (segment, offset, flags, name) from a symbol-records stream."""
    pos = 0
    while pos + 4 <= len(stream):
        ln = struct.unpack_from("<H", stream, pos)[0]
        if ln == 0:
            break
        kind = struct.unpack_from("<H", stream, pos + 2)[0]
        if kind == S_PUB32:
            flags, off, seg = struct.unpack_from("<IIH", stream, pos + 4)
            name = stream[pos + 14:pos + 2 + ln].split(b"\0")[0].decode("utf-8", "replace")
            yield seg, off, flags, name
        pos += 2 + ln


def hash_string_v1(name):
    """PDB name hash, see llvm/lib/DebugInfo/PDB/Native/Hash.cpp."""
    result = 0
    n = len(name)
    for i in range(n // 4):
        result ^= int.from_bytes(name[i * 4:i * 4 + 4], "little")
    rem = name[n - n % 4:]
    if len(rem) >= 2:
        result ^= int.from_bytes(rem[:2], "little")
        rem = rem[2:]
    if len(rem) == 1:
        result ^= rem[0]
    result |= 0x20202020
    result ^= result >> 11
    return (result ^ (result >> 16)) & 0xFFFFFFFF


def _gsi_record_cmp(a, b):
    # See caseInsensitiveComparePchPchCchCch in Microsoft's gsi.cpp
    if len(a) != len(b):
        return -1 if len(a) < len(b) else 1
    if any(c >= 0x80 for c in a) or any(c >= 0x80 for c in b):
        return (a > b) - (a < b)
    la, lb = a.lower(), b.lower()
    return (la > lb) - (la < lb)


def build_hash_table(entries):
    """Serialize a GSI/PSI hash table. `entries` is a list of (name_bytes, sym_offset)."""
    n = len(entries)
    buckets = [hash_string_v1(name) % IPHR_HASH for name, _ in entries]

    starts = [0] * IPHR_HASH
    for b in buckets:
        starts[b] += 1
    total = 0
    for i in range(IPHR_HASH):
        cnt = starts[i]
        starts[i] = total
        total += cnt
    cursors = starts[:]

    order = [0] * n
    for i, b in enumerate(buckets):
        order[cursors[b]] = i
        cursors[b] += 1

    for bi in range(IPHR_HASH):
        begin, end = starts[bi], cursors[bi]
        if begin != end:
            order[begin:end] = sorted(
                order[begin:end],
                key=__import__("functools").cmp_to_key(
                    lambda i, j: _gsi_record_cmp(entries[i][0], entries[j][0])
                    or (entries[i][1] - entries[j][1])),
            )

    hash_records = b"".join(struct.pack("<II", entries[i][1] + 1, 1) for i in order)

    bitmap = [0] * HASH_BITMAP_WORDS
    chain_starts = []
    for bi in range(IPHR_HASH):
        if starts[bi] != cursors[bi]:
            bitmap[bi // 32] |= 1 << (bi % 32)
            chain_starts.append(starts[bi] * 12)

    header = struct.pack("<IIII", GSI_HDR_SIGNATURE, GSI_HDR_VERSION,
                         n * 8, HASH_BITMAP_WORDS * 4 + len(chain_starts) * 4)
    out = header + hash_records + struct.pack("<%dI" % HASH_BITMAP_WORDS, *bitmap)
    if chain_starts:
        out += struct.pack("<%dI" % len(chain_starts), *chain_starts)
    return out


def build_publics_stream(pubs):
    """Publics stream = header + hash table + address map (see GSIStreamBuilder.cpp)."""
    hash_table = build_hash_table([(p["name_bytes"], p["sym_offset"]) for p in pubs])
    by_address = sorted(range(len(pubs)),
                        key=lambda i: (pubs[i]["segment"], pubs[i]["offset"], pubs[i]["name_bytes"]))
    addr_map = b"".join(struct.pack("<I", pubs[i]["sym_offset"]) for i in by_address)
    header = struct.pack("<IIIIH2xII", len(hash_table), len(addr_map), 0, 0, 0, 0, 0)
    assert len(header) == 28
    return header + hash_table + addr_map


def build_sections_stream(sections):
    out = bytearray()
    for s in sections:
        out += s["name"].ljust(8, b"\0")[:8]
        out += struct.pack("<IIIIII", s["vsize"], s["va"], s["rawsize"], s["rawptr"], 0, 0)
        out += struct.pack("<HH", 0, 0)
        out += struct.pack("<I", s["chars"])
    return bytes(out)


def build_dbi(age, machine, sections):
    exec_sections = [(i + 1, s) for i, s in enumerate(sections) if s["chars"] & IMAGE_SCN_MEM_EXECUTE]
    sc = struct.pack("<I", SC_VERSION)
    for seg, s in exec_sections:
        sc += struct.pack("<HHIIIHHII", seg, 0, 0, s["vsize"], s["chars"], 0, 0, 0, 0)

    extra = struct.pack("<11H", 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
                        ST_SECTIONS, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF)

    hdr = struct.pack(
        "<iIIHHHHHHiiiiiIiiHHI",
        -1,                    # VersionSignature
        DBI_VERSION_HEADER,    # VersionHeader
        age,                   # Age
        ST_GSI,                # GlobalStreamIndex
        DBI_BUILD_NUMBER,      # BuildNumber
        ST_PSI,                # PublicStreamIndex
        0,                     # PdbDllVersion
        ST_RECORDS,            # SymRecordStream
        0,                     # PdbDllRbld
        0,                     # ModInfoSize
        len(sc),               # SectionContributionSize
        0,                     # SectionMapSize
        0,                     # SourceInfoSize
        0,                     # TypeServerMapSize
        0,                     # MFCTypeServerIndex
        len(extra),            # OptionalDbgHeaderSize
        0,                     # ECSubstreamSize
        0,                     # Flags
        machine,               # MachineType
        0,                     # Reserved
    )
    assert len(hdr) == 64, len(hdr)
    return hdr + sc + extra


# ------------------------------------------------------------------- main
def load_json_functions(path):
    data = json.loads(Path(path).read_text())

    def ok(f):
        return isinstance(f.get("bindings", {}).get("win"), int)

    out = []
    for f in data.get("functions", []):
        if ok(f):
            out.append((None, f, f["bindings"]["win"]))
    for c in data.get("classes", []):
        for f in c.get("functions", []):
            if ok(f):
                out.append((c["name"], f, f["bindings"]["win"]))
    return out


def make_name(class_name, f, with_args):
    name = f["name"]
    if class_name is None:
        base = name
    elif f.get("kind") == "ctor":
        base = f"{class_name}::{class_name.split('::')[-1]}"
    elif f.get("kind") == "dtor":
        base = f"{class_name}::~{class_name.split('::')[-1]}"
    else:
        base = f"{class_name}::{name}"
    if with_args:
        base += "(" + ", ".join(a.get("type", "?") for a in (f.get("args") or [])) + ")"
    return base


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--json", required=True)
    ap.add_argument("--exe", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--merge", help="existing PDB whose symbols to keep; JSON names win on conflicts")
    ap.add_argument("--signatures", action="store_true", help="append (arg types) to names")
    ap.add_argument("--keep-named", action="store_true",
                    help="with --merge: only replace base names that look like sub_* placeholders")
    args = ap.parse_args()

    exe = parse_pe(args.exe)
    sections = exe["sections"]

    def rva_to_seg_off(rva):
        for i, s in enumerate(sections):
            if s["va"] <= rva < s["va"] + s["vsize"]:
                return i + 1, rva - s["va"]
        return None

    # rva -> (segment, offset, flags, name)
    syms = {}
    if args.merge:
        _, _, base_streams = read_msf(args.merge)
        for seg, off, flags, name in decode_pub32(base_streams[ST_RECORDS]):
            va = sections[seg - 1]["va"] if seg - 1 < len(sections) else None
            if va is None:
                continue
            syms[(seg, off)] = (flags, name)

    stats = dict(total=0, kept=0, bad_sec=0, overridden=0, skipped_named=0)
    for class_name, f, rva in load_json_functions(args.json):
        stats["total"] += 1
        seg_off = rva_to_seg_off(rva)
        if seg_off is None:
            stats["bad_sec"] += 1
            continue
        seg, off = seg_off
        name = make_name(class_name, f, args.signatures)
        existing = syms.get((seg, off))
        if existing is not None:
            if args.keep_named and not _looks_placeholder(existing[1]):
                stats["skipped_named"] += 1
                continue
            stats["overridden"] += 1
        syms[(seg, off)] = (PUBSYM_CODE | PUBSYM_FUNCTION, name)
        stats["kept"] += 1

    pubs = []
    records = bytearray()
    for (seg, off), (flags, name) in sorted(syms.items()):
        rec = encode_pub32(seg, off, flags, name)
        pubs.append(dict(name=name, name_bytes=name.encode("utf-8"), segment=seg,
                         offset=off, flags=flags, sym_offset=len(records)))
        records += rec
    records = bytes(records)

    age = exe["age"]
    guid = exe["guid"]
    pdb_stream = bytearray(PDB_STREAM)
    struct.pack_into("<I", pdb_stream, 4, exe["timestamp"])
    struct.pack_into("<I", pdb_stream, 8, age)
    pdb_stream[12:28] = guid

    streams = [b""] * 11
    streams[ST_PDB] = bytes(pdb_stream)
    streams[ST_TPI] = EMPTY_TYPE_STREAM
    streams[ST_DBI] = build_dbi(age, exe["machine"], sections)
    streams[ST_IPI] = EMPTY_TYPE_STREAM
    streams[ST_RECORDS] = records
    streams[ST_GSI] = build_hash_table([])          # no global (S_GDATA32/S_UDT/...) records
    streams[ST_PSI] = build_publics_stream(pubs)
    streams[ST_SECTIONS] = build_sections_stream(sections)
    streams[ST_NAMES] = NAMES_STREAM

    nblocks = write_msf(args.out, 4096, streams)

    print(f"json functions with a win RVA : {stats['total']}")
    print(f"  emitted                     : {stats['kept']}")
    if args.merge:
        print(f"  kept from existing pdb      : {len(syms) - stats['kept']}")
        if args.keep_named:
            print(f"  skipped (base name kept)    : {stats['skipped_named']}")
    print(f"  overrode an existing name   : {stats['overridden']}")
    print(f"  dropped (rva not in a section): {stats['bad_sec']}")
    print(f"symbol records                : {len(syms)} ({len(records)} bytes)")
    print(f"GUID {guid.hex().upper()} age {age} machine 0x{exe['machine']:04x}")
    print(f"wrote {args.out} ({nblocks} blocks)")


if __name__ == "__main__":
    main()
