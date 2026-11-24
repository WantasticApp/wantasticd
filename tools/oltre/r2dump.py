#!/usr/bin/env python3
"""r2dump.py - dump the vendor OLT webserver binary through radare2.

Usage:
    python3 -I tools/oltre/r2dump.py <webserver-binary> <out.json>

Runs radare2 once (no analysis pass is needed: the binary keeps its dynsym
with every form*/web* function and var*/desc* table symbol) and writes one
JSON file holding everything the other oltre tools consume:

    sections  iSj  (vaddr -> file offset mapping)
    symbols   isj  (FUNC/OBJ symbols incl. imports at their PLT stub)
    relocs    irj  (GOT slot -> symbol name)
    insns     the whole .text disassembled, compact:
              [addr, type, jump, ptr, opcode] per instruction

Operands are rendered raw (no flag names, no variable names) so that the
tracker in oltre.py can parse them with fixed regular expressions.

The dump is a cache of the binary; it is not meant to be committed.
"""

import json
import subprocess
import sys

R2_FLAGS = [
    "-q",
    "-e", "scr.color=0",
    "-e", "scr.utf8=false",
    "-e", "asm.sub.var=false",
    "-e", "asm.sub.names=false",
    "-e", "asm.sub.rel=false",
    "-e", "asm.flags.real=false",
]

CHUNK = 0x8000  # bytes of .text per pDj call


def r2(binary, cmds):
    out = subprocess.run(
        ["r2", *R2_FLAGS, "-c", ";".join(cmds), binary],
        check=True, capture_output=True, text=True,
    ).stdout
    dec = json.JSONDecoder()
    docs, i = [], 0
    while i < len(out):
        while i < len(out) and out[i] in " \r\n\t":
            i += 1
        if i >= len(out):
            break
        d, i = dec.raw_decode(out, i)
        docs.append(d)
    return docs


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    binary, outpath = sys.argv[1], sys.argv[2]

    sections, symbols, relocs = r2(binary, ["iSj", "isj", "irj"])
    text = next(s for s in sections if s["name"] == ".text")
    start, size = text["vaddr"], text["size"]

    cmds = []
    off = 0
    while off < size:
        n = min(CHUNK, size - off)
        cmds.append("pDj %d @ 0x%x" % (n, start + off))
        off += n
    insns = []
    for doc in r2(binary, cmds):
        for op in doc:
            insns.append([op["addr"], op.get("type", ""), op.get("jump"),
                          op.get("ptr"), op.get("opcode", "")])
    insns.sort(key=lambda x: x[0])

    with open(outpath, "w") as f:
        json.dump({
            "binary": binary,
            "sections": sections,
            "symbols": symbols,
            "relocs": relocs,
            "insns": insns,
        }, f)
    print("sections=%d symbols=%d relocs=%d insns=%d -> %s" % (
        len(sections), len(symbols), len(relocs), len(insns), outpath))


if __name__ == "__main__":
    main()
