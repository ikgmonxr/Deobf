#!/usr/bin/env python3
"""Luraph AI Deobfuscator v8.0 — Optimized"""
import sys, os, re, base64, json, time, traceback

try:
    from groq import Groq
    GROQ = True
except ImportError:
    GROQ = False

RE_XOR = re.compile(r'bit32\.bxor|bit\.bxor|bxor')
RE_LUAU = re.compile(rb'^\x1bLua')
RE_KV = re.compile(r'(\w+)\s*=\s*(0x[0-9a-fA-F]+|\d+)')
RE_LOCAL_FN = re.compile(r'local\s+function\s+(\w+)\s*\(([^)]*)\)')
RE_GLOBAL_FN = re.compile(r'function\s+(\w+)\s*\(([^)]*)\)')
RE_RETURN_TABLE = re.compile(r'return\s*\(\{(.*?)\}\)\s*:\s*\w+\s*\(', re.DOTALL)
RE_OPCODE_HANDLER = re.compile(r'if\s+opcode\s*==\s*(\d+)\s+then', re.DOTALL)
RE_HEX_TABLE = re.compile(r'\{([^}]*0x[0-9a-fA-F]{2}[^}]*)\}')
RE_HEX_BYTE = re.compile(r'0x([0-9a-fA-F]{2})')
RE_BASE64_LONG = re.compile(r'["\']([A-Za-z0-9+/=_-]{100,})["\']')
RE_STR_TABLE = re.compile(r'(?:string_table|str_table|strings|str)\s*=\s*\{([^}]*)\}', re.DOTALL)
RE_STR_ENTRY = re.compile(r'\[(\d+)\]\s*=\s*"((?:[^"\\]|\\.)*)"')
RE_CONST_TABLE = re.compile(r'(?:constants|consts|K)\s*=\s*\{([^}]*)\}', re.DOTALL)
RE_CONST_ENTRY = re.compile(r'\[(\d+)\]\s*=\s*([^,)]+)')
RE_HANDLER_BLOCK = re.compile(r'if\s+opcode\s*==\s*(\d+)\s+then\s*(.*?)(?=elseif|else|end)', re.DOTALL)
RE_FN_BODY = re.compile(r'\blocal\s+function\s+(\w+)\s*\(([^)]*)\)\s*(.*?)\s*end(?=\s*(?:local\s+)?function|\Z)', re.DOTALL)

def esc(s):
    return s.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n').replace('\r', '\\r')

def b64d(s):
    try:
        s = s.replace('_', '/').replace('-', '+')
        return base64.b64decode(s + '=' * ((4 - len(s) % 4) % 4))
    except: return b''

def xor_decrypt(data, key, method=0):
    out = bytearray(len(data))
    if method == 0:
        for i, b in enumerate(data):
            out[i] = b ^ ((key >> ((i % 4) * 8)) & 0xFF)
    elif method == 1:
        c = 0
        for i, b in enumerate(data):
            out[i] = b ^ ((key + c + i) & 0xFF)
            c = (c + 1) % 256
    elif method == 2:
        rk = key
        for i, b in enumerate(data):
            out[i] = b ^ ((rk >> ((i % 4) * 8)) & 0xFF)
            rk = (rk * 1103515245 + 12345) & 0xFFFFFFFF
    return bytes(out)

def score_decrypt(data):
    if not data: return 0
    s = 100 if data[:4] == b'\x1bLua' else 0
    if len(data) > 12 and 0x51 <= data[4] <= 0x55: s += 20
    if len(data) > 6 and data[6] in (0, 1): s += 10
    n = min(len(data), 1000)
    printable = sum(1 for b in data[:n] if 32 <= b <= 126 or b in (9, 10, 13))
    s += (printable / max(n, 1)) * 40
    return s

def try_decrypt(data, key=0xDEADBEEF):
    if not data or len(data) < 8: return data
    best, best_score, best_m = data, 0, -1
    for m in range(3):
        r = xor_decrypt(data, key, m)
        sc = score_decrypt(r)
        if sc > best_score:
            best, best_score, best_m = r, sc, m
    if best_score > 10: return best
    return data

class Devirtualizer:
    OP_NAMES = {
        0: "NOP", 1: "LOADK", 2: "LOADBOOL", 3: "LOADNIL", 4: "GETUPVAL",
        5: "GETGLOBAL", 6: "GETTABLE", 7: "SETGLOBAL", 8: "SETUPVAL", 9: "SETTABLE",
        10: "NEWTABLE", 11: "SELF", 12: "ADD", 13: "SUB", 14: "MUL", 15: "DIV",
        16: "MOD", 17: "POW", 18: "UNM", 19: "NOT", 20: "LEN", 21: "CONCAT",
        22: "JMP", 23: "EQ", 24: "LT", 25: "LE", 26: "TEST", 27: "TESTSET",
        28: "CALL", 29: "TAILCALL", 30: "RETURN", 31: "FORLOOP", 32: "FORPREP",
        33: "TFORLOOP", 34: "SETLIST", 35: "CLOSURE", 36: "VARARG", 37: "EXTRAARG",
    }

    def __init__(self, debug=False, api_key=None):
        self.debug = debug
        self.ai = None
        self.ai_model = "llama-3.3-70b-versatile"
        if GROQ and api_key:
            try:
                self.ai = Groq(api_key=api_key)
            except: pass

    def log(self, msg, tag="*"):
        if msg and (self.debug or tag != "D"):
            print(f"[{tag}] {msg}")

    def ai_analyze(self, data: dict) -> str:
        """Use Groq AI to analyze extracted obfuscation data and suggest deobfuscation strategies."""
        if not self.ai:
            return ""
        try:
            info_lines = [
                f"Obfuscator version: {data.get('version', 'Unknown')}",
                f"Functions found: {len(data.get('functions', {}))}",
                f"Strings found: {len(data.get('strings', {}))}",
                f"Constants found: {len(data.get('constants', {}))}",
                f"VM opcodes detected: {len(data.get('opcodes', {}))}",
                f"VM handler blocks: {len(data.get('vm_handlers', {}))}",
                f"Decrypted bytecode size: {len(data.get('encrypted', b''))} bytes",
                f"Instructions decoded: {len(data.get('instructions', []))}",
            ]
            prompt = (
                "You are a Lua obfuscation analysis expert. Analyze the following extracted data from a Luraph-obfuscated Lua script.\n"
                "Provide:\n"
                "1. What type of obfuscation is present (VM, string encryption, control flow, etc.)\n"
                "2. Key observations about the structure\n"
                "3. Suggested deobfuscation approach\n"
                "4. Any patterns that indicate specific obfuscator version or technique\n\n"
                "Extracted data:\n" + "\n".join(info_lines)
            )
            resp = self.ai.chat.completions.create(
                model=self.ai_model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=500,
                temperature=0.3,
            )
            return resp.choices[0].message.content.strip()
        except Exception as ex:
            self.log(f"AI analysis failed: {ex}", "!")
            return ""

    def extract_all(self, script):
        """Single-pass extraction of all data from script."""
        result = {
            'version': 'Unknown', 'encrypted': b'', 'key': None, 'functions': {},
            'strings': {}, 'constants': {}, 'vm_handlers': {}, 'opcodes': {},
            'instructions': [], 'success': False,
        }

        # Version
        m = re.search(r'Luraph Obfuscator v(\d+)', script)
        if m: result['version'] = m.group(1) + '.x'

        # Key
        for m in RE_KV.finditer(script):
            n, v = m.group(1).lower(), m.group(2)
            if any(k in n for k in ['key', 'xor', 'crypt', 'enc', 'dec', 'k']):
                try:
                    result['key'] = int(v, 16) if v.startswith('0x') else int(v)
                    break
                except: pass

        # Strings table
        m = RE_STR_TABLE.search(script)
        if m:
            for idx, val in RE_STR_ENTRY.findall(m.group(1)):
                try: result['strings'][int(idx)] = val
                except: pass

        # Constants table
        m = RE_CONST_TABLE.search(script)
        if m:
            for idx, val in RE_CONST_ENTRY.findall(m.group(1)):
                v = val.strip()
                if v.startswith('"'): v = v[1:-1]
                elif v == 'true': v = True
                elif v == 'false': v = False
                elif v == 'nil': v = None
                elif v.startswith('0x'): v = int(v, 16)
                elif v.isdigit(): v = int(v)
                try: result['constants'][int(idx)] = v
                except: pass

        # Encrypted data
        for m in RE_BASE64_LONG.finditer(script):
            d = b64d(m.group(1))
            if len(d) > 20:
                result['encrypted'] = d
                break
        if not result['encrypted']:
            for m in RE_HEX_TABLE.finditer(script):
                hv = RE_HEX_BYTE.findall(m.group(1))
                if len(hv) > 10:
                    result['encrypted'] = bytes(int(h, 16) for h in hv)
                    break

        # Opcodes
        for m in RE_OPCODE_HANDLER.finditer(script):
            op = int(m.group(1))
            if op not in result['opcodes']:
                result['opcodes'][op] = self.OP_NAMES.get(op, f"OP_{op}")

        # VM handler blocks
        for m in RE_HANDLER_BLOCK.finditer(script):
            op = int(m.group(1))
            body = m.group(2)[:200]
            result['vm_handlers'][op] = len(body)

        # Functions
        for m in RE_LOCAL_FN.finditer(script):
            result['functions'][m.group(1)] = {'type': 'local', 'params': m.group(2).split(',') if m.group(2) else []}
        for m in RE_GLOBAL_FN.finditer(script):
            n = m.group(1)
            if n not in result['functions']:
                result['functions'][n] = {'type': 'global', 'params': m.group(2).split(',') if m.group(2) else []}

        result['success'] = True
        return result

    def devirtualize(self, script):
        start = time.time()
        self.log("=" * 50, "=")
        self.log("LPH DEVIRTUALIZER v8", "+")

        data = self.extract_all(script)

        # Decrypt
        if data['encrypted']:
            data['encrypted'] = try_decrypt(data['encrypted'], data['key'] or 0xDEADBEEF)

        # Decode instructions from decrypted bytecode
        bc = data['encrypted']
        if bc and len(bc) > 8 and not RE_LUAU.match(bc[:4]):
            pc = 0
            while pc + 4 <= len(bc):
                op = bc[pc]
                args = [bc[pc + i] for i in range(1, 4) if pc + i < len(bc) and bc[pc + i] != 0]
                data['instructions'].append({
                    'opcode': op,
                    'args': args,
                    'name': self.OP_NAMES.get(op, f"OP_{op}"),
                    'pc': pc,
                })
                pc += 4

        # Run AI analysis
        ai_insights = self.ai_analyze(data)
        data['ai_analysis'] = ai_insights

        # Generate output
        out = []
        out.append(f"-- [[ LPH DEVIRTUALIZER v8 ]]")
        out.append(f"-- Version: {data['version']} | Instructions: {len(data['instructions'])}")
        out.append("")

        if ai_insights:
            out.append("-- [AI ANALYSIS]")
            for line in ai_insights.split("\n"):
                out.append(f"--   {line.strip()}")
            out.append("")

        if data['strings']:
            out.append("-- [STRINGS]")
            for k, v in sorted(data['strings'].items()):
                out.append(f'local STR_{k} = "{esc(v)}"')
            out.append("")

        if data['constants']:
            out.append("-- [CONSTANTS]")
            for k, v in sorted(data['constants'].items()):
                if isinstance(v, str): out.append(f'local CONST_{k} = "{esc(v)}"')
                elif v is None: out.append(f'local CONST_{k} = nil')
                elif isinstance(v, bool): out.append(f'local CONST_{k} = {str(v).lower()}')
                else: out.append(f'local CONST_{k} = {v}')
            out.append("")

        if data['opcodes']:
            out.append("-- [OPCODES]")
            for op in sorted(data['opcodes']):
                out.append(f"--   {data['opcodes'][op]:12} ({op})")
            out.append("")

        if data['functions']:
            out.append("-- [FUNCTIONS]")
            for n, info in data['functions'].items():
                p = ', '.join(info['params'])
                out.append(f"--   {info['type']:6} {n}({p})")
            out.append("")

        if data['instructions']:
            out.append("-- [BYTECODE]")
            for i, instr in enumerate(data['instructions']):
                a = ', '.join(str(a) for a in instr['args'])
                out.append(f"-- {i:4d}: {instr['name']:12} ({a})")
            out.append("")

        out.append(f"-- Deobfuscated in {time.time()-start:.2f}s")
        if data['success']: out.append("-- Successfully devirtualized!")
        else: out.append("-- Devirtualization incomplete")

        data['lua_source'] = '\n'.join(out)
        data['elapsed'] = time.time() - start
        return data


def main():
    print("\n" + "=" * 50)
    print("  LPH DEVIRTUALIZER v8 — 6Vms")
    print("=" * 50)

    args = sys.argv[1:]
    debug = '-d' in args or '--debug' in args
    input_file = output_file = None

    for i, a in enumerate(args):
        if not a.startswith('-') and not input_file: input_file = a
        elif a in ('-o', '--output') and i + 1 < len(args): output_file = args[i + 1]

    if not input_file:
        print("Enter path to obfuscated Lua file:")
        input_file = input("> ").strip().strip('"').strip("'")

    if not input_file or not os.path.exists(input_file):
        print("[X] File not found"); input("Press Enter..."); sys.exit(1)

    with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
        script = f.read()

    base = os.path.splitext(input_file)[0]
    if not output_file: output_file = f"{base}.deobf.lua"

    # Get API key
    api_key = None
    for a in args:
        if a.startswith('--groq-key='):
            api_key = a.split('=', 1)[1]
    if not api_key: api_key = os.environ.get('GROQ_API_KEY')

    dev = Devirtualizer(debug=debug, api_key=api_key)
    result = dev.devirtualize(script)
    src = result.get('lua_source', '-- No output')

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(src)

    if result.get('instructions'):
        with open(f"{base}.instructions.json", 'w', encoding='utf-8') as f:
            json.dump(result['instructions'], f)

    if result.get('ai_analysis'):
        with open(f"{base}.analysis.txt", 'w', encoding='utf-8') as f:
            f.write(result['ai_analysis'])

    print(f"\n[*] Output: {output_file}")
    print(f"[*] Functions: {len(result['functions'])} | Strings: {len(result['strings'])} | Instructions: {len(result['instructions'])}")
    print(f"[*] AI: {'yes' if result.get('ai_analysis') else 'no (no API key)'}")
    print(f"[*] Time: {result.get('elapsed', 0):.2f}s")
    print("[+] Done!")
    input("Press Enter...")


if __name__ == "__main__":
    main()
