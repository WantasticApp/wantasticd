#!/usr/bin/env python3
"""oltre.py - recover goform handler shapes from the OLT webserver dump.

Setup (the vendor binary is not kept in the repo; extract it from the app
image, e.g. app.live-20261123.xz, md5 ebc0a80aed7c5d74830e011c6394c8ba
for /tmp/app/webserver of firmware 1.1.3.18):

    mkdir scratch && xz -dc app.live-20261123.xz | tar -x -C scratch ./webserver
    python3 -I tools/oltre/r2dump.py scratch/webserver scratch/webserver.dump.json

Usage:

    python3 -I tools/oltre/oltre.py <webserver> <dump.json> tables  > internal/oltd/endpoints/tables_gen.go
    python3 -I tools/oltre/oltre.py <webserver> <dump.json> classify [names...]
    python3 -I tools/oltre/oltre.py <webserver> <dump.json> rows [names...]
    python3 -I tools/oltre/oltre.py <webserver> <dump.json> trace <goform-name|handler>...
    python3 -I tools/oltre/oltre.py <webserver> <dump.json> disasm <goform-name|handler>...
    python3 -I tools/oltre/oltre.py <webserver> <dump.json> registry

tables    regenerates internal/oltd/endpoints/tables_gen.go: the
          formGetListCommon getters (listCommonSpecs), the
          formQuickParamToBuf + setCmdResultWebServiceWithString setters
          (quickSetterSpecs), the getters that call formQuickListStrToJson
          themselves (listQuickSpecs) and the one-request / strtok loop /
          sscanf-per-line getters (rowSpecs), exactly as the vendor
          handlers are compiled. Run gofmt on the output.
classify  buckets every registered goform endpoint (or the given names) by
          the IPC helpers its handler calls: listcommon, quicksetter,
          getter-bespoke, setter-plain (setCmdResultWebService),
          setter-handbuilt (setCmdResultWebServiceWithString without
          formQuickParamToBuf), cli-line (web_service_cmd /
          http_cmd_config_execute), local (no daemon IPC).
rows      reports which bespoke getters match the row-spec template (and
          why the others do not).
trace     prints a pseudo-C call trace of a handler: every call with its
          resolved arguments (strings, stack-frame offsets, GOT symbols),
          every store into the stack frame, and every branch. This is what
          the hand ports in endpoints/ports_*.go are written and reviewed
          from; "?" marks a value the tracker could not resolve.
disasm    raw instructions with literal / string / GOT annotations, for the
          conditional parts a trace cannot show.
registry  prints the websDefineAction table: goform name -> handler.

The vendor code is unoptimised (-O0) ARM: every call argument is staged in
r0-r3 / [sp, n] right before the bl, so a linear tracker that follows
constants, PC-relative literals, GOT loads and fp-relative stack slots
recovers the arguments exactly. Values the tracker cannot resolve print as
'?' - a port must never guess them.
"""

import json
import re
import struct
import sys

GOT_BASE = None  # set from sections (.got vaddr)


# ---------------------------------------------------------------- image ---

class Image:
    def __init__(self, path, sections):
        self.b = open(path, "rb").read()
        self.secs = [s for s in sections if s.get("vaddr") and s.get("size")]

    def sec(self, va):
        for s in self.secs:
            if s["vaddr"] <= va < s["vaddr"] + s["vsize"]:
                return s
        return None

    def read(self, va, n):
        s = self.sec(va)
        if s is None or s["name"] == ".bss" or s["size"] == 0:
            return None
        off = s["paddr"] + (va - s["vaddr"])
        if va + n > s["vaddr"] + s["size"]:
            return None
        return self.b[off:off + n]

    def u32(self, va):
        r = self.read(va, 4)
        return None if r is None else struct.unpack("<I", r)[0]

    def u16(self, va):
        r = self.read(va, 2)
        return None if r is None else struct.unpack("<H", r)[0]

    def cstr(self, va, limit=4096):
        s = self.sec(va)
        if s is None or s["name"] == ".bss":
            return None
        off = s["paddr"] + (va - s["vaddr"])
        end = self.b.find(b"\0", off, off + limit)
        if end < 0:
            return None
        try:
            return self.b[off:end].decode("ascii")
        except UnicodeDecodeError:
            return self.b[off:end].decode("latin1")

    def is_string(self, va):
        s = self.sec(va)
        return s is not None and s["name"] == ".rodata" and self.cstr(va) is not None


# ------------------------------------------------------------- symbols ---

class Syms:
    def __init__(self, dump):
        self.by_addr = {}
        self.funcs = {}
        self.objs = {}
        for s in dump["symbols"]:
            name = s["name"]
            if s["type"] == "FUNC":
                if name.startswith("imp."):
                    name = name[4:]
                self.by_addr.setdefault(s["vaddr"], name)
                self.funcs.setdefault(name, (s["vaddr"], s["size"]))
            elif s["type"] == "OBJ":
                self.objs[name] = (s["vaddr"], s["size"])
        self.relocs = {r["vaddr"]: r["name"] for r in dump["relocs"]}

    def fname(self, va):
        return self.by_addr.get(va, "fcn_%x" % va)


# ------------------------------------------------------------- tracker ---

REG = r"(r\d+|sb|sl|fp|ip|sp|lr|pc)"
REGMAP = {"sb": "r9", "sl": "r10", "fp": "fp", "ip": "r12", "sp": "sp", "lr": "lr", "pc": "pc"}


def reg(n):
    return REGMAP.get(n, n)


def imm(s):
    return int(s, 0)


def s32(v):
    v &= 0xFFFFFFFF
    return v - 0x100000000 if v >= 0x80000000 else v


class Val:
    """Symbolic values: int (constant/address), FP(off) stack address,
    Ret(callee) opaque return value, Sym(name) function pointer."""


class FP(Val):
    def __init__(self, off):
        self.off = off

    def __repr__(self):
        return "fp%+#x" % self.off if self.off else "fp"

    def __eq__(self, o):
        return isinstance(o, FP) and o.off == self.off

    def __hash__(self):
        return hash(("fp", self.off))


class Ret(Val):
    def __init__(self, callee, site):
        self.callee, self.site = callee, site

    def __repr__(self):
        return "ret(%s@%x)" % (self.callee, self.site)


class Sym(Val):
    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return "&" + self.name


class Arg(Val):
    """A function argument as received (r0..r3 at entry)."""

    def __init__(self, n):
        self.n = n

    def __repr__(self):
        return "arg%d" % self.n

    def __eq__(self, o):
        return isinstance(o, Arg) and o.n == self.n

    def __hash__(self):
        return hash(("arg", self.n))


class Deref(Val):
    """A load the tracker could not resolve, kept for display."""

    def __init__(self, base, width):
        self.base, self.width = base, width

    def __repr__(self):
        return "*%s" % (self.base,)


class Call:
    def __init__(self, addr, name, args, stack):
        self.addr, self.name, self.args, self.stack = addr, name, args, stack

    def arg(self, i):
        return self.args[i] if i < 4 else self.stack.get((i - 4) * 4)


class Store:
    def __init__(self, addr, dest, width, val):
        self.addr, self.dest, self.width, self.val = addr, dest, width, val


class Branch:
    def __init__(self, addr, op, target, cmp):
        self.addr, self.op, self.target, self.cmp = addr, op, target, cmp


class Trace:
    def __init__(self):
        self.calls, self.stores, self.branches, self.events = [], [], [], []
        self.labels = set()


RE_MOV = re.compile(r"^(mov|mvn|movw|movt)\s+" + REG + r",\s*(-?0x[0-9a-f]+|-?\d+)$")
RE_MOVR = re.compile(r"^mov\s+" + REG + r",\s*" + REG + "$")
RE_LDRPC = re.compile(r"^ldr\s+" + REG + r",\s*\[pc,\s*(-?0x[0-9a-f]+|-?\d+)\]$")
RE_ALU3I = re.compile(r"^(add|sub|rsb|and|orr|eor|lsl|lsr|asr|bic)\s+" + REG + r",\s*" + REG + r",\s*(-?0x[0-9a-f]+|-?\d+)$")
RE_ALU3R = re.compile(r"^(add|sub|rsb|and|orr|eor|lsl|lsr|asr|bic)\s+" + REG + r",\s*" + REG + r",\s*" + REG + r"(?:,\s*(lsl|lsr|asr)\s+(\d+))?$")
RE_MEM = re.compile(r"^(ldr|ldrh|ldrb|ldrsb|ldrsh|str|strh|strb)\s+" + REG + r",\s*\[" + REG + r"(?:,\s*(-?0x[0-9a-f]+|-?\d+|-?" + REG + r"))?\]$")
RE_BL = re.compile(r"^bl\s+(0x[0-9a-f]+)$")
RE_B = re.compile(r"^b(eq|ne|cs|cc|mi|pl|vs|vc|hi|ls|ge|lt|gt|le|al|hs|lo)?\s+(0x[0-9a-f]+)$")
RE_CMP = re.compile(r"^(cmp|cmn|tst)\s+" + REG + r",\s*(.+)$")
RE_EXT = re.compile(r"^(uxth|uxtb|sxth|sxtb)\s+" + REG + r",\s*" + REG + "$")
RE_ADDFP = re.compile(r"^add\s+fp,\s*sp,\s*(0x[0-9a-f]+|\d+)$")
RE_SUBSP = re.compile(r"^(sub|add)\s+sp,\s*sp,\s*(0x[0-9a-f]+|\d+)$")
RE_SPFP = re.compile(r"^sub\s+sp,\s*fp,\s*(0x[0-9a-f]+|\d+)$")

WIDTH = {"ldr": 4, "str": 4, "ldrh": 2, "strh": 2, "ldrsh": 2, "ldrb": 1, "strb": 1, "ldrsb": 1}


class Tracker:
    def __init__(self, img, syms, insns):
        self.img, self.syms = img, syms
        self.insns = insns  # list of [addr, type, jump, ptr, opcode]
        self.index = {x[0]: i for i, x in enumerate(insns)}

    def run(self, start, end):
        """Track from start (inclusive) to end (exclusive) linearly."""
        t = Trace()
        i0 = self.index.get(start)
        if i0 is None:
            return t
        regs = {"r0": Arg(0), "r1": Arg(1), "r2": Arg(2), "r3": Arg(3)}
        stack = {}
        sp_off = 0  # sp = fp + sp_off
        # branch targets inside the range are block starts
        for k in range(i0, len(self.insns)):
            a, typ, jump, ptr, op = self.insns[k]
            if a >= end:
                break
            if typ in ("cjmp", "jmp") and jump is not None and start <= jump < end:
                t.labels.add(jump)

        def val(r):
            return regs.get(r)

        def norm(v):
            return s32(v) if isinstance(v, int) else v

        def addr_of(base, off):
            b = val(base) if base not in ("fp", "sp") else (FP(0) if base == "fp" else FP(sp_off))
            if isinstance(off, str):  # register
                o = val(reg(off.lstrip("-")))
                if o is None:
                    return None
                if isinstance(o, int):
                    o = s32(o)
                    if off.startswith("-"):
                        o = -o
                elif isinstance(b, int) and isinstance(o, FP):
                    b, o = o, b
                else:
                    return None
            else:
                o = off
            if isinstance(b, FP) and isinstance(o, int):
                return FP(b.off + o)
            if isinstance(b, int) and isinstance(o, int):
                return (b + o) & 0xFFFFFFFF
            return None

        def load(addr, width, signed=False):
            if isinstance(addr, FP):
                v = stack.get(addr.off)
                if v is None:
                    return Deref(addr, width)
                return v[0]
            if isinstance(addr, int):
                if addr in self.syms.relocs:
                    name = self.syms.relocs[addr]
                    if name in self.syms.objs:
                        return self.syms.objs[name][0]
                    return Sym(name)
                if width == 4:
                    v = self.img.u32(addr)
                elif width == 2:
                    v = self.img.u16(addr)
                else:
                    r = self.img.read(addr, 1)
                    v = None if r is None else r[0]
                if v is None:
                    return Deref(addr, width)
                return v
            return None

        pending = {}  # label -> register state carried by an unconditional forward branch
        skipping = False  # after an unconditional branch: unreachable until the next label
        k = i0
        while k < len(self.insns):
            a, typ, jump, ptr, op = self.insns[k]
            if a >= end:
                break
            k += 1
            if a in t.labels:
                skipping = False
                if a in pending:
                    regs = pending.pop(a)
                else:
                    for r in ("r0", "r1", "r2", "r3", "r12", "lr"):
                        regs.pop(r, None)
            elif skipping:
                continue  # literal pool or dead code behind an unconditional branch
            m = RE_ADDFP.match(op)
            if m:
                sp_off = -imm(m.group(1))
                continue
            m = RE_SPFP.match(op)
            if m:
                sp_off = -imm(m.group(1))
                continue
            m = RE_SUBSP.match(op)
            if m:
                sp_off += -imm(m.group(2)) if m.group(1) == "sub" else imm(m.group(2))
                continue
            if op.startswith("push") or op.startswith("pop") or op.startswith("nop"):
                continue
            m = RE_MOV.match(op)
            if m:
                kind, rd, v = m.group(1), reg(m.group(2)), imm(m.group(3)) & 0xFFFFFFFF
                if kind == "mov":
                    regs[rd] = v
                elif kind == "mvn":
                    regs[rd] = (~v) & 0xFFFFFFFF
                elif kind == "movw":
                    regs[rd] = v & 0xFFFF
                else:  # movt
                    cur = regs.get(rd)
                    regs[rd] = ((v & 0xFFFF) << 16) | ((cur if isinstance(cur, int) else 0) & 0xFFFF)
                continue
            m = RE_MOVR.match(op)
            if m:
                rd, rm = reg(m.group(1)), reg(m.group(2))
                regs[rd] = FP(0) if rm == "fp" else FP(sp_off) if rm == "sp" else val(rm)
                continue
            m = RE_LDRPC.match(op)
            if m:
                rd = reg(m.group(1))
                regs[rd] = self.img.u32(ptr) if ptr is not None else None
                continue
            m = RE_ALU3I.match(op)
            if m:
                kind, rd, rn, v = m.group(1), reg(m.group(2)), reg(m.group(3)), imm(m.group(4))
                if rn == "fp":
                    base = FP(0)
                elif rn == "sp":
                    base = FP(sp_off)
                elif rn == "pc":
                    base = a + 8
                else:
                    base = val(rn)
                regs[rd] = self.alu(kind, base, v)
                continue
            m = RE_ALU3R.match(op)
            if m:
                kind, rd, rn, rm = m.group(1), reg(m.group(2)), reg(m.group(3)), reg(m.group(4))
                if rn == "pc":
                    base = a + 8
                elif rn == "fp":
                    base = FP(0)
                elif rn == "sp":
                    base = FP(sp_off)
                else:
                    base = val(rn)
                o = val(rm)
                if m.group(5) and isinstance(o, int):
                    sh = int(m.group(6))
                    o = (o << sh) & 0xFFFFFFFF if m.group(5) == "lsl" else o >> sh
                elif m.group(5):
                    o = None
                regs[rd] = self.alu(kind, base, o)
                continue
            m = RE_EXT.match(op)
            if m:
                kind, rd, rm = m.group(1), reg(m.group(2)), reg(m.group(3))
                v = val(rm)
                if isinstance(v, int):
                    if kind == "uxth":
                        v &= 0xFFFF
                    elif kind == "uxtb":
                        v &= 0xFF
                    elif kind == "sxth":
                        v = s32(((v & 0xFFFF) ^ 0x8000) - 0x8000)
                    else:
                        v = s32(((v & 0xFF) ^ 0x80) - 0x80)
                regs[rd] = v
                continue
            m = RE_MEM.match(op)
            if m:
                kind, rd, rn, off = m.group(1), reg(m.group(2)), m.group(3), m.group(4)
                width = WIDTH[kind]
                if off is None:
                    o = 0
                elif re.match(r"^-?(0x[0-9a-f]+|\d+)$", off):
                    o = imm(off)
                else:
                    o = off  # register name (possibly negated)
                addr = addr_of(reg(rn) if rn not in ("fp", "sp") else rn, o)
                if kind.startswith("ldr"):
                    regs[rd] = load(addr, width) if addr is not None else None
                else:
                    v = val(rd)
                    t.stores.append(Store(a, addr, width, v))
                    if isinstance(addr, FP):
                        stack[addr.off] = (v, width)
                continue
            m = RE_BL.match(op)
            if m:
                target = imm(m.group(1))
                name = self.syms.fname(target)
                args = [val("r0"), val("r1"), val("r2"), val("r3")]
                st = {}
                for n in range(0, 0x100, 4):
                    v = stack.get(sp_off + n)
                    if v is not None:
                        st[n] = v[0]
                t.calls.append(Call(a, name, args, st))
                t.events.append(t.calls[-1])
                regs["r0"] = Ret(name, a)
                for r in ("r1", "r2", "r3", "r12", "lr"):
                    regs.pop(r, None)
                continue
            m = RE_B.match(op)
            if m:
                target = imm(m.group(2))
                br = Branch(a, "b" + (m.group(1) or ""), target, regs.get("_cmp"))
                t.branches.append(br)
                t.events.append(br)
                if m.group(1) is None:
                    if target > a and target < end:
                        pending[target] = dict(regs)
                    skipping = True
                continue
            m = RE_CMP.match(op)
            if m:
                rhs = m.group(3)
                rv = imm(rhs) if re.match(r"^-?(0x[0-9a-f]+|\d+)$", rhs) else val(reg(rhs))
                regs["_cmp"] = (val(reg(m.group(2))), rv)
                continue
            if op.startswith("bx lr") or typ == "ret":
                continue
            # anything else: destination register unknown
            m2 = re.match(r"^\S+\s+" + REG, op)
            if m2 and not op.startswith(("vstr", "vldr", "bx", "blx")):
                regs.pop(reg(m2.group(1)), None)
        return t

    @staticmethod
    def alu(kind, a, b):
        if a is None or b is None:
            return None
        if isinstance(a, FP) and isinstance(b, int):
            b = s32(b)
            if kind == "add":
                return FP(a.off + b)
            if kind == "sub":
                return FP(a.off - b)
            return None
        if isinstance(a, int) and isinstance(b, FP):
            if kind == "add":
                return FP(b.off + s32(a))
            if kind == "rsb":
                return FP(b.off - s32(a))
            return None
        if isinstance(a, int) and isinstance(b, int):
            if kind == "add":
                return (a + b) & 0xFFFFFFFF
            if kind == "sub":
                return (a - b) & 0xFFFFFFFF
            if kind == "rsb":
                return (b - a) & 0xFFFFFFFF
            if kind == "and":
                return a & b
            if kind == "orr":
                return a | b
            if kind == "eor":
                return a ^ b
            if kind == "bic":
                return a & ~b & 0xFFFFFFFF
            if kind == "lsl":
                return (a << b) & 0xFFFFFFFF
            if kind == "lsr":
                return a >> b
            if kind == "asr":
                return s32(a) >> b
        return None


# ------------------------------------------------------------ analysis ---

class Analysis:
    def __init__(self, binary, dump):
        self.dump = dump
        self.img = Image(binary, dump["sections"])
        self.syms = Syms(dump)
        self.insns = dump["insns"]
        self.tr = Tracker(self.img, self.syms, self.insns)
        global GOT_BASE
        GOT_BASE = next(s["vaddr"] for s in dump["sections"] if s["name"] == ".got")
        self._registry = None
        self.obj_by_addr = {va: n for n, (va, sz) in self.syms.objs.items()}

    # -- registration table -------------------------------------------
    def registry(self):
        """goform name -> handler name, from every websDefineAction call."""
        if self._registry is not None:
            return self._registry
        wda = self.syms.funcs["websDefineAction"][0]
        reg = {}
        idx = self.tr.index
        for i, ins in enumerate(self.insns):
            if ins[1] != "call" or ins[2] != wda:
                continue
            # walk back to the enclosing push {.., lr}
            j = i
            while j > 0 and not (self.insns[j][4].startswith("push") and "lr" in self.insns[j][4]):
                j -= 1
            t = self.tr.run(self.insns[j][0], ins[0] + 4)
            c = t.calls[-1]
            name = self.img.cstr(c.args[0]) if isinstance(c.args[0], int) else None
            h = c.args[1]
            hname = h.name if isinstance(h, Sym) else (self.syms.fname(h) if isinstance(h, int) else None)
            if name is None or hname is None:
                raise SystemExit("unresolved websDefineAction @%x: %r %r" % (ins[0], c.args[0], h))
            reg[name] = hname
        self._registry = reg
        return reg

    def handler_range(self, hname):
        if hname not in self.syms.funcs:
            return None
        va, size = self.syms.funcs[hname]
        return va, va + size

    def trace(self, hname):
        r = self.handler_range(hname)
        if r is None:
            return None
        return self.tr.run(*r)

    # -- rendering ----------------------------------------------------
    def show(self, v):
        if v is None:
            return "?"
        if isinstance(v, int):
            if v in self.syms.by_addr:
                return "&" + self.syms.by_addr[v]
            if v in self.obj_by_addr:
                return "&" + self.obj_by_addr[v]
            s = self.img.cstr(v) if self.img.is_string(v) else None
            if s is not None and v >= 0x1000:
                return json.dumps(s)
            if v >= 0x8000 and self.img.sec(v) is not None:
                return "0x%x" % v
            return str(s32(v)) if s32(v) < 0 or v < 0x10000 else "0x%x" % v
        return repr(v)

    VARARGS = {"sscanf": 2, "sprintf": 2, "snprintf": 3, "printf": 1, "fprintf": 2, "cli_printf": 1,
               "websWrite": 2, "memset": 3, "strcpy": 2, "strncpy": 3, "strcmp": 2, "strcat": 2,
               "atoi": 1, "strlen": 1, "strtok_r": 3, "strtok": 2, "strstr": 2, "strchr": 2,
               "cJSON_AddStringToObject": 3, "cJSON_AddNumberToObject": 4, "cJSON_AddItemToObject": 3,
               "cJSON_AddItemToArray": 2, "cJSON_CreateObject": 0, "cJSON_CreateArray": 0,
               "cJSON_Print": 1, "cJSON_Delete": 1, "cJSON_GetObjectItem": 2, "cJSON_Parse": 1,
               "cJSON_CreateString": 1, "cJSON_GetString": 3, "cJSON_GetInt": 3,
               "outputToWebs": 2, "outputResultToWebs": 2, "websGetVar": 3, "free": 1,
               "getCmdResultWebService": 4, "setCmdResultWebServiceWithString": 3,
               "setCmdResultWebService": 3, "formQuickParamToBuf": 5, "formGetListCommon": 9,
               "web_service_cmd": 4, "http_cmd_config_execute": 3, "ParseWebsDate": 1,
               "formQuickDebug": 6, "tickGet": 0, "base64_encode": 3, "base64_decode": 3,
               "formQuickListStrToJson": 5, "formQuickStrToJson": 5, "cJSON_AddTrueToObject": 2,
               "cJSON_AddFalseToObject": 2, "cJSON_GetArraySize": 1, "cJSON_GetArrayItem": 2,
               "strncmp": 3, "memcpy": 3, "strcasecmp": 2, "atol": 1, "strtol": 3, "strtoul": 3,
               "nonprint_replace_space": 1, "outputResultToWebs": 2, "ParseWebsDate": 1,
               "cJSON_free": 1, "pal_time_sec2tm": 2, "convertNameToPortNumber": 2,
               "convertPortNumberToName": 2, "cJSON_GetObjectItem": 2}

    FMT_CONV = re.compile(r"%(?:[-+ #0]*\d*(?:\.\d+)?)?(?:hh|h|ll|l|L|z|j|t)?(\[[^\]]*\]|[a-zA-Z%])")

    def nargs(self, c):
        n = self.VARARGS.get(c.name)
        if n is None:
            return 4
        if c.name in ("sscanf", "sprintf", "snprintf", "printf", "fprintf", "cli_printf"):
            fmtarg = {"sscanf": 1, "sprintf": 1, "snprintf": 2, "printf": 0, "fprintf": 1, "cli_printf": 0}[c.name]
            f = c.arg(fmtarg)
            fs = self.img.cstr(f) if isinstance(f, int) and self.img.is_string(f) else None
            if fs is None:
                return 8
            convs = [m for m in self.FMT_CONV.findall(fs) if m != "%" and not m.startswith("*")]
            if c.name == "sscanf":
                convs = [m for m in convs if m != "%*"]
            return n + len(convs)
        return n

    def render_call(self, c):
        n = self.nargs(c)
        args = [self.show(c.arg(i)) for i in range(n)]
        return "%s(%s)" % (c.name, ", ".join(args))

    def render_trace(self, hname):
        t = self.trace(hname)
        if t is None:
            return "  (no symbol %s)" % hname
        out = []
        for ev in t.events:
            if isinstance(ev, Call):
                out.append("  %06x  %s" % (ev.addr, self.render_call(ev)))
            else:
                cmp = ""
                if ev.cmp:
                    cmp = "  [cmp %s, %s]" % (self.show(ev.cmp[0]), self.show(ev.cmp[1]))
                out.append("  %06x  %s -> %06x%s" % (ev.addr, ev.op, ev.target, cmp))
        # frame stores that are not plain argument staging; runs of zero
        # stores are folded into one "zero" line (struct = {0} style init)
        st = []
        run = None  # [first_addr, lo_off, hi_off]
        def flush():
            if run is not None:
                st.append("  %06x  zero fp%+#x .. fp%+#x (%d bytes)" % (run[0], run[1], run[2], run[2] - run[1]))
        for s in t.stores:
            if not isinstance(s.dest, FP) or s.val is None or isinstance(s.val, (Ret, Deref)):
                continue
            if s.val == 0:
                lo, hi = s.dest.off, s.dest.off + s.width
                if run is not None and (lo == run[2] or hi == run[1]):
                    run[1], run[2] = min(run[1], lo), max(run[2], hi)
                    continue
                flush()
                run = [s.addr, lo, hi]
                continue
            flush()
            run = None
            st.append("  %06x  store%d %s <- %s" % (s.addr, s.width, s.dest, self.show(s.val)))
        flush()
        return "\n".join(out + ["  -- constant frame stores:"] + st)

    def render_disasm(self, hname):
        """Raw instructions with literal / string / GOT annotations."""
        r = self.handler_range(hname)
        if r is None:
            return "  (no symbol %s)" % hname
        start, end = r
        out = []
        regs = {}
        for k in range(self.tr.index[start], len(self.insns)):
            a, typ, jump, ptr, op = self.insns[k]
            if a >= end:
                break
            note = ""
            m = RE_LDRPC.match(op)
            if m and ptr is not None:
                v = self.img.u32(ptr)
                regs[reg(m.group(1))] = v
                note = "= 0x%x" % v if v is not None else ""
            else:
                m = RE_ALU3R.match(op)
                if m and m.group(1) == "add" and m.group(3) == "pc":
                    v = regs.get(reg(m.group(4)))
                    if isinstance(v, int):
                        va = (a + 8 + v) & 0xFFFFFFFF
                        note = self.show(va)
                        regs[reg(m.group(2))] = va
                else:
                    m = RE_MEM.match(op)
                    if m and m.group(1) == "ldr" and reg(m.group(3)) == "r4" and m.group(4) and m.group(4).startswith("r"):
                        v = regs.get(reg(m.group(4)))
                        if isinstance(v, int) and GOT_BASE + v in self.syms.relocs:
                            note = "GOT " + self.syms.relocs[GOT_BASE + v]
                    elif typ == "call" and jump is not None:
                        note = self.syms.fname(jump)
            if jump is not None and typ in ("cjmp", "jmp"):
                note = ""
            out.append("  %06x  %-36s %s" % (a, op, note))
        return "\n".join(out)


    # -- row getters ----------------------------------------------------
    ROW_OK_CMP = ("cJSON_CreateObject", "cJSON_CreateArray", "cJSON_Print")

    def row_spec(self, name, hname, t):
        """Recover a declarative spec for the common list getter shape:
        one daemon request, one strtok loop, one sscanf per line, one JSON
        object per line. Returns (spec, None) or (None, reason)."""
        calls = t.calls
        gets = [c for c in calls if c.name == "getCmdResultWebService"]
        if len(gets) != 1:
            return None, "getCmdResultWebService calls: %d" % len(gets)
        g = gets[0]
        msg, buf, bufsize, sock = g.arg(0), g.arg(1), g.arg(2), g.arg(3)
        if not (isinstance(msg, FP) and isinstance(buf, FP) and isinstance(bufsize, int)
                and isinstance(sock, int) and self.img.is_string(sock)):
            return None, "unresolved getCmdResultWebService args"
        sock = self.img.cstr(sock)
        # request body
        codes = [st for st in t.stores if st.width == 2 and st.dest == msg]
        if len(codes) != 1 or not isinstance(codes[0].val, int):
            return None, "message code stores: %d" % len(codes)
        code = codes[0].val
        spec = {"Name": name, "Handler": hname, "Socket": sock, "Code": code, "Buf": bufsize,
                "Vars": None, "Param": None, "U16": []}
        param_len = None
        for st in t.stores:
            if not isinstance(st.dest, FP) or st.addr == codes[0].addr:
                continue
            if msg.off <= st.dest.off < msg.off + 0x43a:
                if st.val == 0:
                    continue
                if st.width == 2 and isinstance(st.val, int):
                    spec["U16"].append([st.dest.off - msg.off, st.val])
                    continue
                if st.width == 2 and isinstance(st.val, Ret) and st.val.callee == "sprintf" \
                        and st.dest.off - msg.off == 34:
                    param_len = st.val.site  # strlen(value) stored as u16 at +34
                    continue
                return None, "unexpected store into message at +%d" % (st.dest.off - msg.off)
        for c in calls:
            if c.addr >= g.addr:
                break
            if c.name == "formQuickParamToBuf":
                if not (c.arg(0) == Arg(0) and c.arg(1) == 0 and isinstance(c.arg(2), int)
                        and isinstance(c.arg(3), int) and c.arg(4) == msg):
                    return None, "formQuickParamToBuf shape"
                spec["Vars"] = self.ptr_table(c.arg(2), c.arg(3))
            elif c.name in ("sprintf", "strcpy", "strncpy", "snprintf", "memcpy", "strcat"):
                d = c.arg(0)
                if isinstance(d, FP) and msg.off <= d.off < msg.off + 0x43a:
                    if c.name != "sprintf":
                        return None, "%s into message" % c.name
                    fmt = c.arg(1)
                    v = c.arg(2)
                    if not (isinstance(fmt, int) and self.img.cstr(fmt) == "%s" and isinstance(v, Ret)
                            and v.callee == "websGetVar"):
                        return None, "sprintf into message with %s" % self.show(v)
                    wg = [x for x in calls if x.addr == v.site][0]
                    if not (isinstance(wg.arg(1), int) and self.img.is_string(wg.arg(1))
                            and isinstance(wg.arg(2), int) and self.img.is_string(wg.arg(2))):
                        return None, "websGetVar args"
                    spec["Param"] = [self.img.cstr(wg.arg(1)), self.img.cstr(wg.arg(2)), d.off - msg.off,
                                     param_len == c.addr]
            elif c.name == "websGetVar":
                pass
            elif c.name in ("memset", "cJSON_CreateObject", "cJSON_CreateArray", "cJSON_AddItemToObject",
                            "formQuickDebug", "tickGet"):
                pass
            else:
                return None, "call before request: %s" % c.name
        # JSON skeleton: root object, list array, AddItemToObject(root, key, list)
        objs = [c for c in calls if c.name == "cJSON_CreateObject"]
        arrs = [c for c in calls if c.name == "cJSON_CreateArray"]
        adds = [c for c in calls if c.name == "cJSON_AddItemToObject"]
        if not objs or len(arrs) != 1 or len(adds) != 1:
            return None, "JSON skeleton (objects=%d arrays=%d addItem=%d)" % (len(objs), len(arrs), len(adds))
        root, lst, add = objs[0], arrs[0], adds[0]
        if not (isinstance(add.arg(0), Ret) and add.arg(0).site == root.addr and isinstance(add.arg(2), Ret)
                and add.arg(2).site == lst.addr):
            return None, "AddItemToObject args"
        key = add.arg(1)
        if not (isinstance(key, int) and self.img.is_string(key)):
            return None, "list key"
        spec["ListKey"] = self.img.cstr(key)
        after = [c for c in calls if c.addr > max(g.addr, add.addr)]
        toks = [c for c in after if c.name == "strtok_r"]
        if len(toks) != 1:
            return None, "strtok_r calls: %d" % len(toks)
        tok = toks[0]
        delim = tok.arg(1)
        if not (isinstance(delim, int) and self.img.is_string(delim)):
            return None, "strtok delimiter"
        spec["Delim"] = self.img.cstr(delim)
        # loop body = [back-edge target, strtok_r call)
        back = [b for b in t.branches if b.addr > tok.addr and b.op == "bne" and b.cmp
                and isinstance(b.cmp[0], Ret) and b.cmp[0].callee == "strtok_r"]
        if len(back) != 1:
            return None, "loop back-edge"
        body_lo, body_hi = back[0].target, tok.addr
        spec["ErrorEmpty"] = False
        for b in t.branches:
            if b.op == "b":
                continue
            c = b.cmp
            if b.addr == back[0].addr:
                continue
            if b.op == "beq" and c and isinstance(c[0], Ret) and c[0].callee in self.ROW_OK_CMP and c[1] == 0:
                continue
            if b.op == "beq" and c and isinstance(c[0], Ret) and c[0].callee == "strcmp" and c[1] == 0:
                sc = [x for x in calls if x.addr == c[0].site][0]
                if sc.arg(0) == buf and isinstance(sc.arg(1), int) and self.img.cstr(sc.arg(1)) == "ERROR":
                    spec["ErrorEmpty"] = True
                    continue
            return None, "branch %s@%x on %s" % (b.op, b.addr, self.show(c[0]) if c else "?")
        body = [c for c in after if body_lo <= c.addr < body_hi]
        outside = [c for c in after if not (body_lo <= c.addr < body_hi) and c.addr != tok.addr]
        for c in outside:
            if c.name not in ("cJSON_Print", "cJSON_Delete", "outputToWebs", "free", "cJSON_free",
                              "outputResultToWebs", "strcmp", "formQuickDebug", "tickGet", "cli_printf"):
                return None, "call outside loop: %s" % c.name
        # body
        spec["RowZero"] = []
        spec["Cols"] = []
        counter = None
        scan = None
        row = None
        for c in body:
            if c.name == "memset":
                d = c.arg(0)
                if not (isinstance(d, FP) and c.arg(1) == 0 and isinstance(c.arg(2), int)):
                    return None, "memset in body"
                spec["RowZero"].append([d.off, c.arg(2)])  # memset(fp+off, 0, n)
            elif c.name == "sscanf":
                if scan is not None or c.arg(0) != buf and not isinstance(c.arg(0), Deref):
                    pass
                if scan is not None:
                    return None, "two sscanf"
                fmt = c.arg(1)
                if not (isinstance(fmt, int) and self.img.is_string(fmt)):
                    return None, "sscanf format"
                fs = self.img.cstr(fmt)
                n = self.nargs(c) - 2
                offs = []
                for i in range(n):
                    v = c.arg(2 + i)
                    if not isinstance(v, FP):
                        return None, "sscanf arg %d unresolved" % i
                    offs.append(v.off)
                scan = [fs, offs]
                spec["Fmt"], spec["Offs"] = fs, offs
            elif c.name == "cJSON_CreateObject":
                row = c
            elif c.name == "cJSON_AddItemToArray":
                if not (isinstance(c.arg(0), Ret) and c.arg(0).site == lst.addr and isinstance(c.arg(1), Ret)
                        and row is not None and c.arg(1).site == row.addr):
                    return None, "AddItemToArray args"
            elif c.name == "sprintf":
                if not (isinstance(c.arg(0), FP) and isinstance(c.arg(1), int) and self.img.cstr(c.arg(1)) == "%d"
                        and c.arg(2) == 1 and counter is None):
                    return None, "sprintf in body"
                counter = c.arg(0).off
            elif c.name == "cJSON_AddStringToObject":
                if not (isinstance(c.arg(0), Ret) and row is not None and c.arg(0).site == row.addr):
                    return None, "AddString target"
                k, v = c.arg(1), c.arg(2)
                if not (isinstance(k, int) and self.img.is_string(k)):
                    return None, "AddString key"
                col = {"Key": self.img.cstr(k)}
                if isinstance(v, FP):
                    if counter is not None and v.off == counter:
                        col["Counter"] = True
                        col["Off"] = v.off
                    else:
                        col["Off"] = v.off
                elif isinstance(v, int) and self.img.is_string(v):
                    col["Const"] = self.img.cstr(v)
                else:
                    return None, "AddString value %s" % self.show(v)
                spec["Cols"].append(col)
            elif c.name in ("formQuickDebug", "tickGet"):
                pass
            else:
                return None, "call in body: %s" % c.name
        if scan is None or row is None or not spec["Cols"]:
            return None, "body incomplete"
        # no literal bytes may be written into the row buffers by the body
        for st in t.stores:
            if body_lo <= st.addr < body_hi and isinstance(st.dest, FP) and isinstance(st.val, int) \
                    and st.val != 0 and (st.width < 4 or st.dest.off in spec["Offs"]):
                return None, "literal store in body at %s" % st.dest
        # the zero runs inside the body are per-row too
        zeros = []
        run = None
        for st in t.stores:
            if not (body_lo <= st.addr < body_hi) or not isinstance(st.dest, FP) or st.val != 0:
                continue
            lo, hi = st.dest.off, st.dest.off + st.width
            if run is not None and (lo == run[1] or hi == run[0]):
                run = [min(run[0], lo), max(run[1], hi)]
                continue
            if run is not None:
                zeros.append(run)
            run = [lo, hi]
        if run is not None:
            zeros.append(run)
        for lo, hi in zeros:
            if hi - lo <= 4 and not any(lo <= o < hi for o in spec["Offs"]):
                continue  # a loop variable (strtok cursor, counter), not a text buffer
            spec["RowZero"].append([lo, hi - lo])  # memset(fp+lo, 0, hi-lo)
        spec["RowZero"].sort(key=lambda z: z[0])
        spec["Counter"] = counter
        frame = max([abs(o) for o in spec["Offs"]] + [abs(z[0]) for z in spec["RowZero"]] + [abs(buf.off), abs(msg.off)])
        spec["Frame"] = frame
        return spec, None

    def listquick_spec(self, name, hname, t):
        """Getters that call formQuickListStrToJson themselves (same JSON
        shape as formGetListCommon, own socket / buffer size)."""
        calls = t.calls
        gets = [c for c in calls if c.name == "getCmdResultWebService"]
        lq = [c for c in calls if c.name == "formQuickListStrToJson"]
        if len(gets) != 1 or len(lq) != 1:
            return None, "calls"
        g, q = gets[0], lq[0]
        msg, buf, bufsize, sock = g.arg(0), g.arg(1), g.arg(2), g.arg(3)
        if not (isinstance(msg, FP) and isinstance(buf, FP) and isinstance(bufsize, int)
                and isinstance(sock, int) and self.img.is_string(sock)):
            return None, "unresolved getCmdResultWebService args"
        codes = [st for st in t.stores if st.width == 2 and st.dest == msg]
        if len(codes) != 1 or not isinstance(codes[0].val, int):
            return None, "message code stores: %d" % len(codes)
        for st in t.stores:
            if isinstance(st.dest, FP) and msg.off <= st.dest.off < msg.off + 0x43a and st.val != 0 \
                    and st.addr != codes[0].addr:
                return None, "unexpected store into message at +%d" % (st.dest.off - msg.off)
        vars_ = None
        for c in calls:
            if c.addr >= g.addr:
                break
            if c.name == "formQuickParamToBuf":
                if not (c.arg(0) == Arg(0) and c.arg(1) == 0 and isinstance(c.arg(2), int)
                        and isinstance(c.arg(3), int) and c.arg(4) == msg):
                    return None, "formQuickParamToBuf shape"
                vars_ = self.ptr_table(c.arg(2), c.arg(3))
            elif c.name in ("memset", "ParseWebsDate", "cJSON_GetString", "formQuickDebug", "tickGet"):
                pass
            elif c.name in ("sprintf", "strcpy", "strncpy", "snprintf", "memcpy", "strcat"):
                return None, "%s before request" % c.name
            else:
                return None, "call before request: %s" % c.name
        objs = [c for c in calls if c.name == "cJSON_CreateObject"]
        if len(objs) != 1 or not (isinstance(q.arg(1), Ret) and q.arg(1).site == objs[0].addr):
            return None, "root object"
        if q.arg(0) != buf or not isinstance(q.arg(2), int) or q.arg(2) == 0:
            return None, "formQuickListStrToJson args"
        delim = q.arg(4)
        if delim not in (0, None):
            if not (isinstance(delim, int) and self.img.is_string(delim)):
                return None, "delimiter"
            delim = self.img.cstr(delim)
        else:
            delim = ","
        dsym = [(n, sz) for n, (va, sz) in self.syms.objs.items() if va == q.arg(2)]
        if not dsym:
            return None, "desc table symbol"
        dname, dsize = dsym[0]
        for b in t.branches:
            if b.op == "b":
                continue
            c = b.cmp
            if c and isinstance(c[0], Ret) and c[1] == 0 and (
                    (b.op == "beq" and c[0].callee in self.ROW_OK_CMP) or
                    (b.op == "bne" and c[0].callee == "formQuickListStrToJson")):
                continue
            return None, "branch %s@%x" % (b.op, b.addr)
        for c in calls:
            if c.addr > q.addr and c.name not in ("cJSON_Print", "cJSON_Delete", "outputToWebs", "free",
                                                  "cJSON_free", "outputResultToWebs", "formQuickDebug"):
                return None, "call after conversion: %s" % c.name
        return {"Name": name, "Handler": hname, "Code": codes[0].val, "Socket": self.img.cstr(sock),
                "Buf": bufsize, "Vars": vars_ or [], "Desc": self.ptr_table(q.arg(2), dsize // 4),
                "DescOverflow": self.ptr_table(q.arg(2) + dsize, 8), "Delim": delim}, None

    # -- table recovery -----------------------------------------------
    def ptr_table(self, va, count):
        out = []
        for i in range(count):
            p = self.img.u32(va + 4 * i)
            s = self.img.cstr(p) if p is not None and self.img.is_string(p) else None
            out.append(s)
        return out

    def listcommon_spec(self, name, hname, t):
        calls = [c for c in t.calls if c.name == "formGetListCommon"]
        if len(calls) != 1:
            return None
        c = calls[0]
        code, vars_p, nvars, desc_p, flags, extra = c.arg(3), c.arg(4), c.arg(5), c.arg(6), c.arg(7), c.arg(8)
        if not all(isinstance(x, int) for x in (code, vars_p, nvars, desc_p, flags)):
            return None
        vars_ = self.ptr_table(vars_p, nvars)
        desc, overflow = None, []
        if desc_p:
            dsym = [(n, sz) for n, (va, sz) in self.syms.objs.items() if va == desc_p]
            if not dsym:
                return None
            dname, dsize = dsym[0]
            desc = self.ptr_table(desc_p, dsize // 4)
            overflow = self.ptr_table(desc_p + dsize, 8)
        return {"Name": name, "Handler": hname, "Code": code, "Vars": vars_, "Desc": desc,
                "DescOverflow": overflow, "PonPortList": bool(flags & 1), "Extra": extra,
                "Debug": any(c.name == "formQuickDebug" for c in t.calls)}

    def quicksetter_spec(self, name, hname, t):
        q = [c for c in t.calls if c.name == "formQuickParamToBuf"]
        s = [c for c in t.calls if c.name == "setCmdResultWebServiceWithString"]
        if len(q) != 1 or len(s) != 1:
            return None
        qc, sc = q[0], s[0]
        names_p, count, msg = qc.arg(2), qc.arg(3), qc.arg(4)
        sock = sc.arg(2)
        if not (isinstance(names_p, int) and isinstance(count, int) and isinstance(msg, FP)
                and isinstance(sock, int) and self.img.is_string(sock)):
            return None
        if qc.arg(0) != 0 or not isinstance(qc.arg(1), Ret) or qc.arg(1).callee != "ParseWebsDate":
            return None
        if sc.arg(1) != msg:
            return None
        # the command code: the one 16-bit store at the message start
        codes = [st.val for st in t.stores if st.width == 2 and st.dest == msg]
        if len(codes) != 1 or not isinstance(codes[0], int):
            return None
        # no other constant store may land inside the message
        others = [st for st in t.stores if isinstance(st.dest, FP) and msg.off < st.dest.off < msg.off + 0x464
                  and st.addr not in [x.addr for x in t.stores if x.dest == msg]]
        if others:
            return None
        return {"Name": name, "Handler": hname, "Code": codes[0], "Socket": self.img.cstr(sock),
                "Vars": self.ptr_table(names_p, count)}

    def classify(self, name, hname):
        t = self.trace(hname)
        if t is None:
            return "no-symbol", t
        names = [c.name for c in t.calls]
        if "formGetListCommon" in names:
            return "listcommon", t
        if "formQuickParamToBuf" in names and "setCmdResultWebServiceWithString" in names:
            return "quicksetter", t
        if "http_cmd_config_execute" in names or "web_service_cmd" in names:
            return "cli-line", t
        if "setCmdResultWebServiceWithString" in names:
            return "setter-handbuilt", t
        if "setCmdResultWebService" in names:
            return "setter-plain", t
        if "getCmdResultWebService" in names:
            return "getter-bespoke", t
        return "local", t


# ---------------------------------------------------------------- main ---

def gostrs(lst):
    if lst is None:
        return "nil"
    return "[]string{" + ", ".join(json.dumps(x) for x in lst) + "}"


def emit_tables(an):
    reg = an.registry()
    getters, setters = [], []
    for name, hname in reg.items():
        kind, t = an.classify(name, hname)
        if kind == "listcommon":
            sp = an.listcommon_spec(name, hname, t)
            if sp is None:
                print("// UNRESOLVED listcommon %s (%s)" % (name, hname), file=sys.stderr)
                continue
            getters.append(sp)
        elif kind == "quicksetter":
            sp = an.quicksetter_spec(name, hname, t)
            if sp is None:
                print("// UNRESOLVED quicksetter %s (%s)" % (name, hname), file=sys.stderr)
                continue
            setters.append(sp)
    quick, rows = [], []
    for name, hname in reg.items():
        kind, t = an.classify(name, hname)
        if kind != "getter-bespoke":
            continue
        sp, why = an.listquick_spec(name, hname, t)
        if sp is not None:
            quick.append(sp)
            continue
        sp, why = an.row_spec(name, hname, t)
        if sp is not None:
            rows.append(sp)
    getters.sort(key=lambda s: s["Name"])
    setters.sort(key=lambda s: s["Name"])
    quick.sort(key=lambda s: s["Name"])
    rows.sort(key=lambda s: s["Name"])
    out = []
    out.append("// Code generated from webserver (app.live-20261123, md5 ebc0a80aed7c5d74830e011c6394c8ba)")
    out.append("// by tools/oltre (r2dump.py + oltre.py tables); DO NOT EDIT by hand.")
    out.append("//")
    out.append("// listCommonSpecs: the argument set each vendor goform wrapper passes to")
    out.append("// formGetListCommon. quickSetterSpecs: formQuickParamToBuf +")
    out.append("// setCmdResultWebServiceWithString setters. listQuickSpecs: getters that")
    out.append("// call formQuickListStrToJson themselves (own socket and buffer size).")
    out.append("// rowSpecs: getters of the one-request / strtok loop / sscanf-per-line /")
    out.append("// one-object-per-line shape, with the vendor's stack-frame offsets.")
    out.append("")
    out.append("package endpoints")
    out.append("")
    out.append("var listCommonSpecs = []listCommonSpec{")
    for s in getters:
        delim = ""
        if isinstance(s["Extra"], int) and s["Extra"] != 0:
            # the wrapper's 5th stack word: a token delimiter other than ","
            d = an.img.cstr(s["Extra"]) if an.img.is_string(s["Extra"]) else None
            if d is None:
                print("// UNRESOLVED delimiter for %s" % s["Name"], file=sys.stderr)
                continue
            delim = ", Delim: %s" % json.dumps(d)
        out.append("\t{Name: %s, Handler: %s, Code: %d, Vars: %s, Desc: %s, DescOverflow: %s, PonPortList: %s%s}," % (
            json.dumps(s["Name"]), json.dumps(s["Handler"]), s["Code"], gostrs(s["Vars"]),
            gostrs(s["Desc"]), gostrs(s["DescOverflow"] if s["Desc"] is not None else []),
            "true" if s["PonPortList"] else "false", delim))
    out.append("}")
    out.append("")
    out.append("var quickSetterSpecs = []quickSetterSpec{")
    for s in setters:
        out.append("\t{Name: %s, Handler: %s, Code: %d, Socket: %s, Vars: %s}," % (
            json.dumps(s["Name"]), json.dumps(s["Handler"]), s["Code"], json.dumps(s["Socket"]), gostrs(s["Vars"])))
    out.append("}")
    out.append("")
    out.append("var listQuickSpecs = []listCommonSpec{")
    for s in quick:
        out.append("\t{Name: %s, Handler: %s, Code: %d, Socket: %s, Buf: %d, Vars: %s, Desc: %s, DescOverflow: %s, Delim: %s}," % (
            json.dumps(s["Name"]), json.dumps(s["Handler"]), s["Code"], json.dumps(s["Socket"]), s["Buf"],
            gostrs(s["Vars"]), gostrs(s["Desc"]), gostrs(s["DescOverflow"]), json.dumps(s["Delim"])))
    out.append("}")
    out.append("")
    out.append("var rowSpecs = []rowSpec{")
    for s in rows:
        cols = []
        for c in s["Cols"]:
            if c.get("Counter"):
                cols.append("{Key: %s, Counter: true}" % json.dumps(c["Key"]))
            elif "Const" in c:
                cols.append("{Key: %s, Const: %s, IsConst: true}" % (json.dumps(c["Key"]), json.dumps(c["Const"])))
            else:
                cols.append("{Key: %s, Off: %#x}" % (json.dumps(c["Key"]), -c["Off"]))
        zero = ", ".join("{%#x, %d}" % (-z[0], z[1]) for z in s["RowZero"])
        offs = ", ".join("%#x" % -o for o in s["Offs"])
        u16 = ", ".join("{%d, %d}" % (u[0], u[1]) for u in s["U16"])
        param = "nil"
        if s["Param"]:
            param = "&legacyParam{Name: %s, Default: %s, Off: %d, Len: %s}" % (
                json.dumps(s["Param"][0]), json.dumps(s["Param"][1]), s["Param"][2], "true" if s["Param"][3] else "false")
        out.append("\t{Name: %s, Handler: %s, Socket: %s, Code: %d, Buf: %d, Frame: %#x, Vars: %s, Param: %s, U16: []u16Field{%s}, ListKey: %s, Delim: %s, ErrorEmpty: %s, RowZero: []zeroRegion{%s}, Fmt: %s, Offs: []int{%s}, Counter: %#x, Cols: []rowCol{%s}}," % (
            json.dumps(s["Name"]), json.dumps(s["Handler"]), json.dumps(s["Socket"]), s["Code"], s["Buf"], s["Frame"],
            gostrs(s["Vars"]) if s["Vars"] is not None else "nil", param, u16, json.dumps(s["ListKey"]), json.dumps(s["Delim"]),
            "true" if s["ErrorEmpty"] else "false", zero, json.dumps(s["Fmt"]), offs,
            -s["Counter"] if s["Counter"] is not None else 0, ", ".join(cols)))
    out.append("}")
    return "\n".join(out) + "\n", getters, setters, quick, rows


def main():
    if len(sys.argv) < 4:
        sys.exit(__doc__)
    binary, dump, cmd = sys.argv[1], sys.argv[2], sys.argv[3]
    an = Analysis(binary, json.load(open(dump)))
    if cmd == "registry":
        for n, h in sorted(an.registry().items()):
            print("%-40s %s" % (n, h))
    elif cmd == "tables":
        text, g, s, q, r = emit_tables(an)
        sys.stdout.write(text)
        print("listcommon=%d quicksetters=%d listquick=%d rows=%d" % (len(g), len(s), len(q), len(r)), file=sys.stderr)
    elif cmd == "classify":
        reg = an.registry()
        names = sys.argv[4:] or sorted(reg)
        for n in names:
            h = reg.get(n)
            if h is None:
                print("%-36s NOT-REGISTERED" % n)
                continue
            kind, t = an.classify(n, h)
            ipc = [c.name for c in t.calls if c.name in ("getCmdResultWebService", "setCmdResultWebServiceWithString",
                                                          "setCmdResultWebService", "web_service_cmd",
                                                          "http_cmd_config_execute", "formQuickParamToBuf",
                                                          "formGetListCommon")] if t else []
            print("%-36s %-18s %-36s %s" % (n, kind, h, ",".join(ipc)))
    elif cmd == "rows":
        reg_ = an.registry()
        names = sys.argv[4:] or sorted(reg_)
        ok = 0
        for n in names:
            h = reg_.get(n)
            if h is None:
                continue
            kind, t = an.classify(n, h)
            if kind != "getter-bespoke":
                continue
            sp, why = an.row_spec(n, h, t)
            if sp is None:
                print("%-32s NO   %s" % (n, why))
            else:
                ok += 1
                print("%-32s OK   %s code=%d buf=%d cols=%d zero=%d delim=%r vars=%s param=%s u16=%s" % (
                    n, sp["Socket"], sp["Code"], sp["Buf"], len(sp["Cols"]), len(sp["RowZero"]), sp["Delim"],
                    sp["Vars"], sp["Param"], sp["U16"]))
        print("row-shaped getters: %d" % ok)
    elif cmd == "disasm":
        reg_ = an.registry()
        for n in sys.argv[4:]:
            h = reg_.get(n, n)
            print("== %s -> %s" % (n, h))
            print(an.render_disasm(h))
    elif cmd == "trace":
        reg = an.registry()
        for n in sys.argv[4:]:
            h = reg.get(n, n)
            print("== %s -> %s" % (n, h))
            print(an.render_trace(h))
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
