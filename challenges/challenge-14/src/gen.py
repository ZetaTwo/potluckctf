# for the record the emulator in this file does not work lol, just needed to debug some things in the chall and this worked well enough for that
from types import CodeType, FunctionType
from builtins import *
import marshal
import tempfile
import sys
from dis import _inline_cache_entries
from code import InteractiveConsole
from opcode import opmap, opname
from importlib ._bootstrap_external import MAGIC_NUMBER, _pack_uint32
import readline
import rlcompleter
from os.path import exists, expanduser
import atexit
opmap.update({"<17>": 17})
histfile = expanduser("~/.python_gdb_history")
interact_vars = globals()
interact_vars.update(locals())
readline.set_completer(rlcompleter.Completer(interact_vars).complete)
readline.parse_and_bind("bind ^I rl_complete")
if not exists(histfile):
    open(histfile, 'w').close()
else:
    try:
        readline.read_history_file(histfile)
    except:
        pass
def savehist():
    readline.write_history_file(histfile)
def interact(local=interact_vars):
    console = InteractiveConsole(local)
    console.interact()
atexit.register(savehist)

CODE_TO_CACHE = {}
for op in opmap:
    try:
        CODE_TO_CACHE[op] = _inline_cache_entries[opmap[op]]
    except:
        pass

SPLICE_SIZE = CODE_TO_CACHE["LOAD_ATTR"] - 2 - 1
class DummyCode:
    def __init__(self, bc):
        self.co_code = bc

        
def code_to_asm(code):
    for i in range(0, len(code.co_code), 2):
        yield [opname[code.co_code[i]], code.co_code[i+1]]

# splice bytecode into instructions of length SPLICE_SIZE, make sure a function and it's caches are in the same splice
def splice_code(asm):
    if asm[0][0] == "RESUME":
        asm = asm[1:]
    asm_copy = asm.copy()
    instrs = []
    while len(asm_copy):
        instr = [asm_copy.pop(0)]
        while len(asm_copy) and asm_copy[0][0] == "CACHE":
            instr.append(asm_copy.pop(0))
        instrs.append(instr)
    # concat consecutive instructions such that group size is at max SPLICE_SIZE
    instrs_copy = instrs
    splices = []
    while len(instrs_copy):
        nex = instrs_copy.pop(0)
        if len(nex) > SPLICE_SIZE:
            splices.append(nex)
            continue
        while True:
            if not len(instrs_copy) or (len(instrs_copy[0]) + len(nex) > SPLICE_SIZE):
                break
            nex.extend(instrs_copy.pop(0))
        splices.append(nex)
    return splices

def obfuscate_asm(splice, new_asm=[], c=0, index_table={}, names=[0,2]):
    new_asm.append(["LOAD_NAME", names[0]])
    new_asm.append(["LOAD_ATTR", names[1]])
    new_asm.append(["<17>", 0])
    new_asm.append(["POP_TOP", 0])
    for instr in splice:
        new_asm.append(instr)
        index_table[c] = len(new_asm) - 1
        c += 1
    new_asm.append(["JUMP_FORWARD_P", SPLICE_SIZE - len(splice) + 1])
    for _ in range(SPLICE_SIZE - len(splice)):
        new_asm.append(["CACHE", 0])
    new_asm.append(["JUMP_BACKWARD_P", 9])
    return new_asm, c, index_table

def get_ith_jump(asm, num_jump):
    seen = 0
    for x in range(len(asm)):
        if "JUMP" in asm[x][0] or asm[x][0] == "FOR_ITER":
            if seen == num_jump:
                return x
            seen += 1
    return -1

def obfuscate(asm, names=[0,2]):
    splices = splice_code(asm)
    new_asm = []
    c = 0
    index_table = {}
    for splice in splices:
        if len(splice) > SPLICE_SIZE:
            for instr in splice:
                new_asm.append(instr)
                index_table[c] = len(new_asm) - 1
                c += 1
        else:
            new_asm, c, index_table = obfuscate_asm(splice, new_asm = new_asm, c = c, index_table = index_table, names=names)
    jumps = 0
    for idx in range(len(new_asm)):
        x = new_asm[idx]
        if ("JUMP" in x[0] or x[0] == "FOR_ITER") and x[0] not in ["JUMP_FORWARD_P", "JUMP_BACKWARD_P"]:
            i = get_ith_jump(asm, jumps)
            if i == -1:
                raise Exception("Jump not found")
            jumps += 1
            if "BACKWARD" in x[0]:
                target = i - x[1] + 1
            elif "FORWARD" in x[0] or x[0] == "FOR_ITER":
                target = i + x[1] - 1 
            else:
                target = i + x[1] - 1
            new_target = index_table[target]
            new_asm[idx][1] = abs(new_target - idx)
            if "BACKWARD" in x[0]:
                new_asm[idx][1] = new_asm[idx][1] + 2
    for x in new_asm:
        if x[0][-2:] == "_P":
            x[0] = x[0][:-2]
    return new_asm

class NULL:
    def __repr__(self):
        return "<NULL>"
class KWNAMES:
    pass

class Stack:
    def __init__(self):
        self.stack = []
        self.str_stack = []
    
    def append(self, item, str_item=None):
        self.stack = [item] + self.stack
        if str_item:
            self.str_stack = [f"{str_item}"] + self.str_stack
        else:
            self.str_stack = [f"{item}"] + self.str_stack

    def pop(self):
        self.str_stack.pop(0)
        return self.stack.pop(0)

    def pop_str(self):
        self.stack.pop(0)
        return self.str_stack.pop(0)
    
    def pop_both(self):
        return self.str_stack.pop(0), self.stack.pop(0)
    
    def __getitem__(self, item):
        return self.stack[item]
    
    def __setitem__(self, item, value, str_value=None):
        self.stack[item] = value
        if str_value:
            self.str_stack[item] = f"{str_value}"
        else:
            self.str_stack[item] = f"{value}"
    
    def copy(self):
        return self.stack.copy()
    
    def copy_str_stack(self):
        return self.str_stack.copy()

class GDB:
    def __init__(self, bytecode=b"", asm=[], co_names=tuple(), co_consts=tuple(), co_varnames=tuple()):
        if bytecode == b"" and asm == []:
            raise ValueError("must provide either bytecode or asm")
        if asm == []:
            asm = GDB.bytecode_to_asm(bytecode)
        if b"" == bytecode:
            bytecode = GDB.asm_to_bytecode(asm)
        self.co_code = bytecode
        self.asm = asm
        self.co_names = list(co_names)
        self.co_consts = list(co_consts)
        self.co_varnames = list(co_varnames)
        self.stack = Stack()
        self.index = 0
        self.processing = True
        self.globals = globals().copy()
        self.stdout_f = tempfile.NamedTemporaryFile()
        self.stdout = open(self.stdout_f.name, 'r+')
    
    @staticmethod
    def print_asm(asm, co_consts = [], co_names = [], co_varnames = [], show_caches=False):
        pad_to = len(max([x[0] for x in asm], key=lambda x:len(x))) + 3
        numbers = [str(x) for x in range(len(asm))]
        num_pad_to = len(max([x for x in asm], key=lambda x:len(x)))
        numbers = [(x + " "*(num_pad_to - len(x))) for x in numbers]
        args = [str(x[1]) for x in asm]
        arg_pad_to = len(max([x for x in args], key=lambda x:len(x)))
        args = [(" "*(arg_pad_to - len(x))+ x) for x in args]
        for i in range(len(args)):
            try:
                match asm[i][0]:
                    case "LOAD_NAME":
                        args[i] = f"{args[i]} ({co_names[asm[i][1]]})"
                    case "LOAD_ATTR":
                        args[i] = f"{args[i]} ({co_names[asm[i][1]>>1]})"
                    case "STORE_NAME":
                        args[i] = f"{args[i]} ({co_names[asm[i][1]]})"
                    case "LOAD_CONST":
                        args[i] = f"{args[i]} ({co_consts[asm[i][1]]})"
                    case "RETURN_CONST":
                        args[i] = f"{args[i]} ({co_consts[asm[i][1]]})"
                    case "LOAD_GLOBAL":
                        args[i] = f"{args[i]} ({globals()[co_names[asm[i][1]]]})"
                    # jumps
                    case "JUMP_FORWARD":
                        args[i] = f"{args[i]} (to {i + asm[i][1] + 1})"
                    case "JUMP_BACKWARD":
                        args[i] = f"{args[i]} (to {i - asm[i][1] + 1})"
                    case _ if "JUMP" in asm[i][0]:
                        args[i] = f"{args[i]} (to {i + asm[i][1] + 1})"
                    case "FOR_ITER":
                        args[i] = f"{args[i]} (to {i + asm[i][1] + 1})"
            except:
                pass
        for i in range(len(asm)):
            op = asm[i]
            if op[0] == "CACHE" and not show_caches:
                continue
            padding = pad_to - len(op[0])
            print(f"{numbers[i]}: {op[0]}{' '*padding}{args[i]}")
    
    @staticmethod
    def bytecode_to_asm(bytecode):
        asm = []
        for i in range(0, len(bytecode), 2):
            opcode = bytecode[i]
            arg = bytecode[i+1]
            if type(arg) == bytes:
                arg = arg[0]
            asm.append([opname[opcode], arg])
        return asm
    
    @staticmethod
    def inst(opc, arg=0):
        # yoinked from fredds code
        nb = max(1,-(-arg.bit_length()//8))
        ab = arg.to_bytes(nb, 'big')
        ext_arg = opmap['EXTENDED_ARG']
        inst = bytearray()
        for i in range(nb-1):
            inst.append(ext_arg)
            inst.append(ab[i])
        inst.append(opmap[opc])
        inst.append(ab[-1])    
        return bytes(inst)
    
    @staticmethod
    def asm_to_bytecode(asm):
        bc = b""
        for instr in asm:
            bc += GDB.inst(instr[0], instr[1])
        return bc
    
    
    def CACHE(self, arg=0):
        self.index += 1
    
    
    def RESUME(self, arg=0):
        self.index += 1
    
    
    def NOP(self, arg=0):
        self.index += 1
    
    
    def POP_TOP(self, arg=0):
        self.stack.pop()
        self.index += 1
    
    def GET_ITER(self, arg=0):
        self.stack[-1] = iter(self.stack[-1])
        self.index += 1
    def FOR_ITER(self, arg=0):
        try:
            self.stack.append(next(self.stack[-1]))
            self.index += 1
        except StopIteration:
            self.stack.append(StopIteration())
            self.index += arg + 1
    def JUMP_FORWARD(self, arg=0):
        self.index += arg
        self.index += 1
    
    def JUMP_BACKWARD(self, arg=0):
        self.index -= arg
        self.index += 1
    def POP_JUMP_IF_FALSE(self, arg=0):
        if not self.stack.pop():
            self.index += arg
        self.index += 1
    def IMPORT_NAME(self, arg=0):
        self.stack.append(__import__(self.co_names[arg]))
        self.index += 1
    
    def STORE_NAME(self, arg=0):
        self.globals[self.co_names[arg]] = self.stack.pop()
        self.index += 1

    
    def MAKE_FUNCTION(self, arg=0):
        code = self.stack.pop()
        self.stack.append(FunctionType(code, globals=self.globals), str_item="<FUNCTION>")
        self.index += 1

    
    def LOAD_ATTR(self, arg=0):
        str_obj, obj = self.stack.pop_both()
        attr = self.co_names[arg>>1]
        self.stack.append(getattr(obj, attr), str_item=f"{str_obj}.{attr}")
        self.index += 1
    
    
    def LOAD_CONST(self, arg=0):
        const = self.co_consts[arg]
        if type(const) == CodeType:
            self.stack.append(const, str_item=f"<CODE_{arg}>")
        else:
            self.stack.append(self.co_consts[arg])
        self.index += 1

    @staticmethod
    def from_code(code):
        return GDB(code.co_code, [], code.co_names, code.co_consts, code.co_varnames)
    @staticmethod
    def clear_load_attrs(asm):
        # clear instances of [["LOAD_NAME", 0], ["LOAD_ATTR", 2], ["POP_TOP", 0], ...]
        exclude = [["LOAD_NAME", 0], ["LOAD_ATTR", 2]]
        exclude.append(["POP_TOP", 0])
        new_asm = []
        i = 0
        while i < len(asm):
            if asm[i:i+len(exclude)] == exclude:
                i += len(exclude)
            else:
                new_asm.append(asm[i])
                i += 1
        return new_asm

    
    def LOAD_NAME(self, arg=0):
        self.stack.append(self.globals[self.co_names[arg]], str_item=self.co_names[arg])
        self.index += 1
    
    def COMPARE_OP(self, arg=0):
        match arg:
            case 2:
                self.stack.append(self.stack.pop() < self.stack.pop())
            case 26:
                self.stack.append(self.stack.pop() <= self.stack.pop())
            case 40:
                self.stack.append(self.stack.pop() == self.stack.pop())
            case 55:
                self.stack.append(self.stack.pop() != self.stack.pop())
            case 68:
                self.stack.append(self.stack.pop() > self.stack.pop())
            case 92:
                self.stack.append(self.stack.pop() >= self.stack.pop())
        self.index += 1
    def PUSH_NULL(self, arg=0):
        self.stack.append(NULL())
        self.index += 1

    
    def CALL(self, arg=0):
        argc = arg
        args = []
        kwargs = {}
        if argc != 0:
            first = self.stack.pop()
            if type(first) == KWNAMES:
                argc -= first.arg_count
                args = []
                kwargs = first.kwargs
            else:
                args = [first]
                argc -= 1
                kwargs = {}
            for _ in range(argc):
                args = [self.stack.pop()] + args
        if type(self.stack[1]) == NULL:
            func = self.stack.pop()
            self.stack.pop()
            self.stack.append(func(*args, **kwargs))
        else:
            _self = self.stack.pop()
            func = self.stack.pop()
            self.stack.append(func(_self, *args, **kwargs))
        self.index += 1
    
    
    def RETURN_CONST(self, arg=0):
        self.stack.append(self.co_consts[arg])
        self.processing = False
        self.index += 1
    
    def set_std(self):
        sys.stdout = self.stdout
    
    def unset_std(self, print_std=True):
        sys.stdout = sys.__stdout__
        if print_std:
            old = self.stdout.tell()
            self.stdout.seek(0)
            data = self.stdout.read().strip()
            if data:
                print("STDOUT:")
                print(data)
            self.stdout.seek(old)

    def print_debug(self, unset=False, show_caches=False):
        sys.__stdout__.write("-"*20 + "\n")
        self.unset_std(print_std=True)
        if not unset:
            self.set_std()
        print("STACK:")
        print(self.pretty_print_stack(set_std=False))
        
    def process(self, stop_line=None, debug=False, show_caches=False):
        try:
            self.set_std()
            while self.processing:
                if stop_line and self.index == stop_line:
                    self.print_debug(unset=True, show_caches=show_caches)
                    return
                opcode, arg = self.asm[self.index]
                sys.__stdout__.write(f"Executing line {self.index} ({opcode} with arg {arg})\n")
                if hasattr(self, opcode):
                    getattr(self, opcode)(arg)
                else:
                    raise ValueError("unknown code", opcode)
                if debug:
                    sys.__stdout__.write(self.pretty_print_stack() + "\n")
                if opcode in CODE_TO_CACHE.keys():
                    for _ in range(CODE_TO_CACHE[opcode]):
                        self.CACHE()
            self.print_debug(unset=True, show_caches=show_caches)
            return self.stack.pop()
        except Exception as err:
            sys.__stdout__.write(f"ERROR: {err}\n")
            self.print_debug(unset=True, show_caches=show_caches)
    
    def pretty_print_stack(self, set_std=True):
        self.unset_std(print_std=False)
        stack = self.stack.copy_str_stack()
        if len(stack) == 0:
            return "Stack empty!"
        for i in range(len(stack)):
            if type(stack[i]) != str:
                stack[i] = f"{stack[i]}"
        stack_len = max([len(i) for i in stack])
        
        output = " " + "-" * (stack_len + 2) + "\n"
        for item in stack:
            diff = stack_len - len(item)
            left = diff//2
            right = diff//2 + diff % 2
            output += "| " + ' ' * left + item + ' ' * right + " |\n"
            output += " " + "-" * (stack_len + 2) + "\n"
        if set_std:
            self.set_std()
        return output
    
    def END_FOR(self, arg=0):
        self.stack.pop()
        self.stack.pop()
        self.index += 1

    def to_code(self):
        return CodeType(0, 0, 0, len(self.co_varnames), 0, 0x00000040, self.co_code, tuple(self.co_consts), tuple(self.co_names), tuple(self.co_varnames), "<string>", "main", "main", 1, b"", b"", (), ())
  
    def print_code_asm(code, show_caches=False):
        asm = [*code_to_asm(code),]
        co_consts = code.co_consts
        co_names = code.co_names
        co_varnames = code.co_varnames
        GDB.print_asm(asm=asm, co_consts=co_consts, co_names=co_names, co_varnames=co_varnames, show_caches=show_caches)

def gen_obs_cod(codd):
    codd = "print.__repr__\n" + codd
    cod = compile(codd, "<string>", "exec")
    call_codes = list(code_to_asm(cod))
    obs = [["RESUME", 0]] + obfuscate(call_codes)
    co_code = GDB.asm_to_bytecode(obs)
    co_consts = cod.co_consts
    co_names = cod.co_names
    co_varnames = cod.co_varnames
    return co_code, co_consts, co_names, co_varnames

def gen_obs_cod_obj(codd):
    codd = "print.__repr__\n" + codd
    cod = compile(codd, "<string>", "exec")
    call_codes = list(code_to_asm(cod))
    obs = [["RESUME", 0]] + obfuscate(call_codes)
    co_code = GDB.asm_to_bytecode(obs)
    co_consts = cod.co_consts
    co_names = cod.co_names
    co_varnames = cod.co_varnames
    return to_code_obj(co_code, co_consts, co_names, co_varnames), co_code


def emulate(co_code, co_consts, co_names, co_varnames, stop_line=None, debug=False, show_caches=False):
    gdb = GDB(co_code, [], co_names, co_consts, co_varnames)
    return gdb.process(stop_line=stop_line, debug=debug, show_caches=show_caches)

def to_code_obj(co_code, co_consts, co_names, co_varnames):
    return CodeType(0, 0, 0, len(co_varnames), 0, 0x00000040, co_code, tuple(co_consts), tuple(co_names), tuple(co_varnames), "<string>", "main", "main", 1, b"", b"", (), ())

def obfuscate_code(code, depth=0):
    co_code = code.co_code
    co_consts = code.co_consts
    co_names = code.co_names
    co_varnames = code.co_varnames
    call_codes = list(code_to_asm(code))
    if depth == 0:
        obs = [["RESUME", 0]] + obfuscate(call_codes)
    else:
        obs = obfuscate(call_codes)
    co_code = GDB.asm_to_bytecode(obs)
    c_objects = {}
    for x in range(len(co_consts)):
        if type(co_consts[x]) == CodeType:
            print(f"Obfuscating code object {x} at depth {depth}")
            co_consts = list(co_consts)
            co_consts[x], c_objects = obfuscate_code(co_consts[x], depth=depth+1)
            co_consts = tuple(co_consts)
    c_obj = to_code_obj(co_code, co_consts, co_names, co_varnames)
    c_objects.update({c_obj.co_code: co_code})
    return c_obj, c_objects

def marshal_to_pyc(marshalled: bytes):
    data = bytearray(MAGIC_NUMBER)
    data.extend(_pack_uint32(0))
    data.extend(_pack_uint32(0))
    data.extend(_pack_uint32(0))
    data.extend(marshalled)
    return data

from os import listdir
from os.path import dirname, join, abspath
wd = abspath(dirname(__file__))
fc = join(wd, "flagchecker")

m, m_code = gen_obs_cod_obj(open(join(fc, "m.py"), "r").read())

t_code = open(join(fc, "t.py"), "r").read()
t_code = t_code.replace("m_bytecode", str(m_code))
t_code = t_code.replace("m_co_consts", str(m.co_consts))
t_code = t_code.replace("m_co_names", str(m.co_names))
open(join(fc, "q.py"), "w").write(t_code)
q, q_code = gen_obs_cod_obj(open(join(fc, "q.py"), "r").read())
q_dumped = marshal.dumps(q)
q_dumped = q_dumped.replace(q.co_code, q_code)
q_dumped_pyc = marshal_to_pyc(q_dumped)
open("out.pyc", "wb").write(q_dumped_pyc)
#interact(local=locals())
