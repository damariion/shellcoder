import ctypes    as ct
from typing      import Any
from argparse    import ArgumentParser
from dataclasses import dataclass

# * Assembler Interface {
@dataclass
class IR:
    "intermediate representation of an assembly line"

    bytecode: bytes
    mnemonic: str
    comments: str
class Keystone:
    "compact interface for Keystone interaction"

    class KeystoneException(Exception): ...
    def __inherit_exports(self, dll: ct.CDLL) -> None:
        "make the exports accessible through this class"

        # * instance management
        self.open = dll.ks_open
        self.open.restype, self.open.argtypes = \
        ct.c_int, [                 # ks_err <return>
            ct.c_int,               # ks_arch arch
            ct.c_int,               # ks_mode mode
            ct.POINTER(ct.c_void_p) # ks_engine** ks
        ]

        self.close = dll.ks_close
        self.close.restype, self.close.argtypes = \
        ct.c_int, [     # ks_err <return>
            ct.c_void_p # ks_engine* ks
        ]

        # * exception handling
        self.errno = dll.ks_errno
        self.errno.restype, self.errno.argtypes = \
        ct.c_int, [     # ks_err <return>
            ct.c_void_p # ks_engine* ks
        ]

        self.strerror = dll.ks_strerror
        self.strerror.restype, self.strerror.argtypes = \
        ct.c_char_p, [ # const char* <return>
            ct.c_int   # ks_err code
        ]

        # * resource management
        self.asm = dll.ks_asm
        self.asm.restype, self.asm.argtypes = \
        ct.c_int, [                             # int <return>
            ct.c_void_p,                        # ks_engine* ks
            ct.c_char_p,                        # const char* string
            ct.c_uint64,                        # uint64_t address
            ct.POINTER(ct.POINTER(ct.c_ubyte)), # unsigned char** encoding
            ct.POINTER(ct.c_size_t),            # size_t* encoding_size
            ct.POINTER(ct.c_size_t)             # size_t* stat_count
        ]

        self.free = dll.ks_free
        self.free.restype, self.free.argtypes = \
        None, [                    # void <return>
            ct.POINTER(ct.c_ubyte) # unsigned char* p
        ]

    def __init__(self, path: str) -> None:

        # ? verify accessibility
        try: open(path, 'r').close()
        except PermissionError:
            raise Exception(f"Couldn't open Keystone (access denied)")
        except FileNotFoundError:
            raise Exception(f"Couldn't open Keystone (doesn't exist)")

        self.dll = ct.CDLL(path)
        self.ins = ct.c_void_p()
        self.__inherit_exports(self.dll)

        # ? initialise ks_engine*
        if (errco := self.open(4, 4, ct.byref(self.ins))):
            raise Exception(self.strerror(errco).decode())

    def __enter__(self) -> 'Keystone':
        return self
    def __exit__(self, *args: tuple[object]) -> None:

        # ? close engine if not already closed
        if self.ins and self.close(self.ins):
            raise Exception("Couldn't close Keystone")
        self.ins = ct.c_void_p()
def text_to_bytecode(ks: Keystone, text: str) -> bytes:
    "assemble the provided text using Keystone"

    size = ct.c_size_t()
    stat = ct.c_size_t()
    buff = ct.POINTER(ct.c_ubyte)()

    if ks.asm(

        ks.ins,         # ks_engine ks*
        text.encode(),  # const char* string
        ct.c_uint64(0), # uint64_t address
        ct.byref(buff), # unsigned char **encoding
        ct.byref(size), # size_t* encoding_size
        ct.byref(stat)  # size_t* stat_count

    ): raise Keystone.KeystoneException(
        ks.strerror(ks.errno(ks.ins)).decode())

    # ? capture and immediately free
    result = bytes(buff[:size.value])
    ks.free(buff); return result
def text_to_listofIR(text: str) -> list[IR]:
    "normalise the contents to the intermediate representation"

    output: list[IR] = []

    # ? exclude -t contents
    if '\n' not in text:

        # ! comments aren't supported in text-mode
        for mnemonic in text.split(';'):
            if not mnemonic: continue
            output.append(IR
            (
                mnemonic = mnemonic,
                comments = '',
                bytecode = b''
            ))
        return output

    for line in text.split('\n'):

        # ? capture and filter required elements
        mnemonic = (l := line.split(';'))[0].strip()
        comments = ';'.join(l[1:]).strip()

        if any((mnemonic, comments)):
            output.append(IR
            (
                mnemonic = mnemonic,
                comments = comments,
                bytecode = b''
            ))

    return output
def assemble_IR(ks: Keystone, irs: list[IR]) -> list[IR]:
    "populate the provided irs with their corresponding bytecode"

    # ? join mnemonics in keystone-recognised format
    original = " ; ".join([x.mnemonic for x in irs if x.mnemonic])
    inserted = original.replace(';', ";salc;" * 2) # very uncommon!

    # ? assemble the text (inserted will be used to distinct newlines)
    original = text_to_bytecode(ks, original) # ! explicit cast str -> bytes
    inserted = text_to_bytecode(ks, inserted) # ! explicit cast str -> bytes

    # ? distinct newlines through comparisions
    bytecodes: list[bytes] = []; offset: int = 0
    for line in [x for x in inserted.split(b"\xD6\xD6") if x]:

        # TODO: filter on branching opcodes (size differences)
        bytecodes.append(original[offset:offset+(size:=len(line))])
        offset += size # previous occurance (slice) is exclusive

    # ? populate Line object with bytecode
    output: list[IR] = []; i: int = -1
    for ir in irs:

        # ignore comments and labels
        if (m := ir.mnemonic) and not (':' in m and '[' not in m):
            ir.bytecode = bytecodes[(i := i + 1)]
        output.append(ir);

    return output
def formater_IR(irs: list[IR], name: str, mnemonic_on: bool, comments_on: bool) -> str:
    "format a list of irs conditionally"

    output: list[str] = [f"{name}  = b''"]

    # ? mb = max bytecode, mm = max mnemonic
    mb = len(max(irs, key=lambda x: len(x.bytecode)).bytecode)
    mm = len(max(irs, key=lambda x: len(x.mnemonic)).mnemonic)
    def is_label(i: IR): return i.mnemonic and not i.bytecode
    is_label_present = any(filter(is_label , irs))
    
    # ? format
    for i in irs:

        bytecode = ''
        mnemonic = ''
        comments = ''

        # ? format: bytecode
        if i.bytecode:

            # bytecode
            bytecode = "\\x".join([f"{c:02X}" for c in i.bytecode])
            bytecode = f'{name} += b"' + f'\\x{bytecode}"'

            # whitespace
            if mnemonic_on or comments_on:
                bytecode += ' ' * ((mb*4 + len(name) + 7) - len(bytecode) + 1)

        # ? format: mnemonic
        if i.mnemonic and mnemonic_on:

            # mnemonic
            if i.bytecode:
                mnemonic += '#' + ' ' * (5 if is_label_present else 1)
                mnemonic += i.mnemonic
            else:
                mnemonic += f"{name} += b''" + ' ' * (mb*4 + 1)
                mnemonic += f"# {i.mnemonic}"

            # whitespace
            if i.comments and comments_on:
                if not i.bytecode and is_label_present: 
                    mnemonic += ' ' * 4
                mnemonic += ' ' * (mm - len(i.mnemonic) + 1)

        # ? format: comments
        if i.bytecode and i.comments and comments_on:
            comments += f"{';' if mnemonic_on else '#'} {i.comments}"

        line = bytecode + mnemonic + comments
        (output if line else []).append(line)

    return '\n'.join(output)
# * } Assembler Interface

# * Windows Compatibility {
IS_WINDOWS: bool = hasattr(ct, "windll")
def enable_ansi_mode() -> None:
    "enable ANSI-recognition on archaic Windows systems"

    # ? define the required API headers
    GetStdHandle = ct.CDLL(f"kernel32").GetStdHandle
    GetStdHandle.restype, GetStdHandle.argtypes = \
    ct.c_void_p, [   # HANDLE <return>
        ct.c_uint32  # DWORD nStdHandle
    ]

    GetConsoleMode = ct.CDLL(f"kernel32").GetConsoleMode
    GetConsoleMode.restype, GetConsoleMode.argtypes = \
    ct.c_bool, [     # BOOL <return>
        ct.c_void_p, # HANDLE hConsoleHandle
        ct.c_void_p  # LPDWORD lpMode
    ]

    SetConsoleMode = ct.CDLL(f"kernel32").SetConsoleMode
    SetConsoleMode.restype, SetConsoleMode.argtypes = \
    ct.c_bool, [     # BOOL <return>
        ct.c_void_p, # HANDLE hConsoleHandle
        ct.c_uint32  # DWORD dwMode
    ]

    # ? enable VT processing in the native CMD prompt
    handle, mode = GetStdHandle(-11), ct.c_uint32()
    GetConsoleMode(handle, ct.byref(mode))
    SetConsoleMode(handle, mode.value | 0x4)
def insert_shellcode(code: bytes) -> None:
    "execute the provided bytes through shellcode injection"

    # ? declare the VirtualAlloc header
    VirtualAlloc = ct.CDLL("kernel32.dll").VirtualAlloc
    VirtualAlloc.restype, VirtualAlloc.argtypes = \
    ct.c_void_p, [   # LPVOID <return>
        ct.c_void_p, # LPVOID lpAddress
        ct.c_size_t, # dwSize
        ct.c_int32,  # flAllocationType
        ct.c_int32   # flProtect
    ]

    # ? move shellcode into executable buffer
    buffer = VirtualAlloc(None, len(code), 0x1000, 0x40)
    ct.memmove(buffer, code, len(code))

    # ? execute the shellcode...
    input("Press enter to execute shellcode...")
    ct.CFUNCTYPE(None)(buffer)()
# * } Windows Compatibility

# * { I/O Handling
def parse_arguments() -> "dict[str, Any] | None":
    "parse the CLI-provided arguments using argparse"

    # ? parse CLI-arguments
    parser = ArgumentParser()
    parser.add_argument('-f', "--file",
        action="store", help="assemble contents of a file")
    parser.add_argument('-t', "--text",
        action="store", help="assemble contents of text")
    parser.add_argument('-b', "--bads", default=[],
        action="append", help="bad-characters to highlight (in hex)")
    parser.add_argument('-n', "--name", default="buffer",
        action="store", help="name of the output buffer")
    parser.add_argument('-u', "--util",
        action="store", help="utilise an integrated tool")
    parser.add_argument('-e', "--exec", default=False,
        action="store_true", help="execute the assembly on this system")
    parser.add_argument('-l', "--line", default=False,
        action="store_true", help="render buffer in a single line")
    parser.add_argument('-m', "--mnemonic", default=False,
        action="store_true", help="whether mnemonic info must be rendered")
    parser.add_argument('-c', "--comments", default=False,
        action="store_true", help="whether comments info must be rendered")
    params = parser.parse_args().__dict__

    # ? verify: content (combinations)
    if not any([params["file"], params["text"]]):
        return print("Invalid content (none provided)")
    if all([params["file"], params["text"]]):
        return print("Invalid content (too much provided)")

    # ? verify: content (accessibility)
    if params["file"]:
        try:
            with open(params["file"], 'r') as file:
                params["text"] = file.read()
        except PermissionError:
            return print("Invalid file (access denied)")
        except FileNotFoundError:
            return print("Invalid file (doesn't exist)")

    # ? verify: bad-characters (range and type)
    for char in params["bads"] or '':
        try:
            if not (0x00 <= int(char, 16) <= 0xFF):
                return print(f"Invalid bad-character '{char}' (out of range)")
        except ValueError:
            return print(f"Invalid bad-character '{char}' (not an integer)")

    # ? verify: name (illegal symbols)
    alpha = "1234567890abcdefghijklmnopqrstuvwxyz_"
    if (name := params["name"])[0].isdigit():
        return print(f"Invalid name '{name}' (can't start with digit)")
    for char in params["name"]:
        if char not in [*alpha, *alpha.upper()]:
            return print(f"Invalid name '{name}' (illegal symbol '{char}')")

    # ? verify: utility (existence)
    utils = filter(lambda f: '__' not in f, Utilities.__dict__)
    if (util := params["util"]) and util not in utils:
        return print(f"Invalid utility '{util}' (doesn't exist)")

    # ? verify: exec (operating system)
    if params["exec"] and not hasattr(ct, "windll"):
        return print(f"Invalid option 'exec' (not a Windows system)")

    return {
        "text": params["text"],
        "name": params["name"],
        "util": params["util"],
        "bads": params["bads"],
        "exec": params["exec"],
        "line": params["line"],
        "mnemonic": params["mnemonic"],
        "comments": params["comments"],
    }
def print_shellcode(string: str, bad_characters: list[str]) -> None:

    # ? enable ANSI-support
    if IS_WINDOWS: enable_ansi_mode()

    # ? display with bads coloured red
    for char in bad_characters:

        i: int = int(char, 16)
        string = string.replace(
            f"\\x{i:02X}", 
            f"\033[91m\\x{i:02X}\033[0m"
            )

    print(string)
# * } I/O Handling

class Utilities:

    @staticmethod
    def stackstr(value: str) -> None:

        if value.count('\n') > 0:
            return print("Invalid content (contains whitespace)");

        # split string into segments of 4 where last is truncated
        segments = [value[i:i+4] for i in range(0, len(value), 4)]
        for segment in segments[::-1]:

            # convert each char to hexadecimal variant
            base16 = [f"{ord(char):x}" for char in segment]

            # swap endianness and add null-byte padding
            string = segment.ljust(4, '.')[::-1]
            base16 = ''.join(base16[::-1]).rjust(8, '0')

            print(f"push 0x{base16} ; {string}")

if __name__ == "__main__" and (args := parse_arguments()):

    if util := args["util"]:
        exit(bool(getattr(Utilities, util)(args["text"])))

    # ! this logic only supports Windows (x86) and MacOS (Aarch64) because 
    # ! that's all I personally use, it should be easy to extend though...
    extension: str = "dll" if IS_WINDOWS else "dylib"
    with Keystone(f"include/keystone.{extension}") as ks:

        try:
            irs = text_to_listofIR(args["text"])
            irs = assemble_IR(ks, irs)
            raw = b''.join([c.bytecode for c in irs])
        except Exception as e:
            print(f"Couldn't assemble content: {e}"); exit(1)

    if args["exec"]: out = insert_shellcode(raw)
    if args["line"]: out = "\\x" + "\\x".join([f"{c:02X}" for c in raw])
    else: out = formater_IR(
        irs, 
        args["name"], 
        args["mnemonic"], 
        args["comments"]
        )

    print(f"bytecode size: {len(raw)}")
    print(f"mnemonic size: {len(irs)}")
    print_shellcode('\n' + out, args["bads"])