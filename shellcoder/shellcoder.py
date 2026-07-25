import ctypes as ct
from argparse import ArgumentParser, Namespace

class Instruction:
    "this class is shared with the script, it"
    "isolates only the necessary attributes"

    def __init__(self, address: int, mnemonic: str, bytecode: bytes) -> None:

        # mimic @dataclass
        self.address  = address
        self.mnemonic = mnemonic
        self.bytecode = bytecode

class Multistone:
    "Compact Key- & Capstone wrapper, exposing only required APIs"

    class MultistoneException(Exception): ...
    class __instruction(ct.Structure):
        "structure used to serialise the Capstone's struct<csins>"

        _fields_ = (
            ("id",        ct.c_uint),
            ("address",   ct.c_uint64),
            ("size",      ct.c_uint16),
            ("bytes",     ct.c_ubyte * 16), # 24 on recent capstone
            ("mnemonic",  ct.c_char  * 32), 
            ("op_str",    ct.c_char  * 160),
            ("cs_detail", ct.c_void_p)
        )

    @staticmethod
    def __load_exports(dll: ct.CDLL) -> Namespace:
        "load exports from either Keystone or Capstone (DRY)"

        # ? resolve the DLL name (tested on MacOS and Windows 10)
        name = dll._name[(i := dll._name.rfind(".")) - 8:i]

        if (name := name.lower()) not in ("keystone", "capstone"):
            raise Exception(f"Invalid name parsed: {name}")

        # ? load commonly typed exports
        open = getattr(dll, f"{name[0]}s_open")
        open.restype, open.argtypes = \
        ct.c_int, [                 # *s_err <return>
            ct.c_int,               # *s_arch arch
            ct.c_int,               # *s_mode mode
            ct.POINTER(ct.c_void_p) # csh* handle / ks_engine** ks
        ]

        errno = getattr(dll, f"{name[0]}s_errno")
        errno.restype, errno.argtypes = \
        ct.c_int, [     # cs_err <return>
            ct.c_void_p # csh handle
        ]

        strerror = getattr(dll, f"{name[0]}s_strerror")
        strerror.restype, strerror.argtypes = \
        ct.c_char_p, [ # const char* <return>
            ct.c_int   # cs_err code
        ]

        # ? load uniquely typed exports
        match name:

            case "keystone":

                apply = dll.ks_asm
                apply.restype, apply.argtypes = \
                ct.c_int, [                             # int <return>
                    ct.c_void_p,                        # ks_engine* ks
                    ct.c_char_p,                        # const char* string
                    ct.c_uint64,                        # uint64_t address
                    ct.POINTER(ct.POINTER(ct.c_ubyte)), # unsigned char** encoding
                    ct.POINTER(ct.c_size_t),            # size_t* encoding_size
                    ct.POINTER(ct.c_size_t)             # size_t* stat_count
                ]

                free = dll.ks_free
                free.restype, free.argtypes = \
                None, [                    # void <return>
                    ct.POINTER(ct.c_ubyte) # unsigned char* p
                ]

                close = dll.ks_close
                close.restype, close.argtypes = \
                ct.c_int, [     # ks_err <return>
                    ct.c_void_p # ks_engine* ks
                ]

            case "capstone":

                apply = dll.cs_disasm
                apply.restype, apply.argtypes = \
                ct.c_size_t, [   # size_t <return>
                    ct.c_void_p, # csh handle
                    ct.c_char_p, # const uint8_t* code
                    ct.c_size_t, # size_t code_size
                    ct.c_uint64, # uint64_t address
                    ct.c_size_t, # size_t count
                                 # cs_insn** insn
                    ct.POINTER(ct.POINTER(Multistone.__instruction))
                ]

                free = dll.cs_free
                free.restype, free.argtypes = \
                None, [                                    # void <return>
                    ct.POINTER( Multistone.__instruction), # cs_insn* insn,
                    ct.c_size_t                            # size_t count
                ]

                close = dll.cs_close
                close.restype, close.argtypes = \
                ct.c_int, [                 # cs_err <return>
                    ct.POINTER(ct.c_void_p) # csh* handle
                ]

        # ? return an identically labeled namespace
        return Namespace(
            open     = open,
            free     = free,
            close    = close,
            apply    = apply,
            errno    = errno,
            strerror = strerror
            )

    def __last_error(self) -> str:

        # ? determine faulty operation uniformly
        if (code := self.ks.errno(self.ks.engine)):
            return self.ks.strerror(code).decode()
        if (code := self.cs.errno(self.cs.engine)):
            return self.cs.strerror(code).decode()

        # this message is identical between modules
        return "No error: everything was fine"

    def asm(self, text: str) -> bytes:

        # ? initialise values
        size = ct.c_size_t()
        stat = ct.c_size_t()
        buff = ct.POINTER(ct.c_ubyte)()

        # ? perform the assembly through Keystone
        if self.ks.apply(

            self.ks.engine, # ks_engine ks*
            text.encode(),  # const char* string
            ct.c_uint64(0), # uint64_t address
            ct.byref(buff), # unsigned char **encoding
            ct.byref(size), # size_t* encoding_size
            ct.byref(stat)  # size_t* stat_count

        ): raise self.MultistoneException(
            f"Couldn't assemble text: {self.__last_error()}")

        # ? capture and immediately free
        result = bytes(buff[:size.value])
        self.ks.free(buff); return result

    def dis(self, code: bytes) -> tuple[Instruction, ...]:

        # ? perform the disassembly through Capstone
        array = ct.POINTER(self.__instruction)()
        count = self.cs.apply(

            self.cs.engine,         # csh handle
            code,                   # const uint8_t* code
            ct.c_size_t(len(code)), # size_t code_size
            ct.c_uint64(0),         # uint64_t address
            ct.c_size_t(0),         # size_t count
            ct.byref(array)         # cs_insn** insn

            )

        # ? capture and immediately free
        result: list[Instruction] = []
        for i in range(count):

            mnemonic = array[i].mnemonic.decode()
            operands = array[i].op_str.decode()
            bytecode = array[i].bytes

            result.append(
                Instruction(
                    array[i].address,               # e.g. 0x2f
                    f"{mnemonic} {operands}",       # e.g. xor eax, eax
                    bytes(bytecode)[:array[i].size] # e.g. b'1\xc0'
                )
            )

        self.cs.free(array, count)

        # ? prevent Cs from ignoring instructions silently
        if sum(len(x.bytecode) for x in result) < len(code):
            raise self.MultistoneException(
                f"Couldn't disassemble code: {self.__last_error()}")

        return (*result,)

    def __init__(self, ks_dll: ct.CDLL, cs_dll: ct.CDLL) -> None:

        # ? load exports
        self.ks = self.__load_exports(ks_dll)
        self.cs = self.__load_exports(cs_dll)
        self.ks.engine, self.cs.engine = ct.c_void_p(), ct.c_void_p()

        if (code := self.ks.open(4, 4, ct.byref(self.ks.engine))):
            text = self.ks.strerror(code).decode()
            raise self.MultistoneException(f"Couldn't open Keystone: {text}")

        if (code := self.cs.open(3, 4, ct.byref(self.cs.engine))):
            text = self.cs.strerror(code).decode()
            raise self.MultistoneException(f"Couldn't open Capstone: {text}")

    def __enter__(self) -> 'Multistone':
        return self
    def __exit__(self, *args: tuple[object]) -> None:

        # ? prevent double release
        if  (not self.ks.engine) \
        and (not self.cs.engine): return

        # ? free the engines individually
        if self.ks.close(self.ks.engine):
            raise self.MultistoneException(
                f"Couldn't close Keystone: {self.__last_error()}")
        if self.cs.close(self.cs.engine):
            raise self.MultistoneException(
                f"Couldn't close Capstone: {self.__last_error()}")

        # ? enable double release protection
        self.cs.engine = self.ks.engine = ct.c_void_p()

def parse_arguments() -> Namespace | None:
    "parse and validate CLI-provided arguments"

    # ? parse through the built-in argument handler
    parser = ArgumentParser()
    parser.add_argument('-f', "--file", required=False, default='',
        action="store", help="assemble contents of a file")
    parser.add_argument('-t', "--text", required=False, default='',
        action="store", help="assemble contents of a text")
    parser.add_argument('-b', "--bads", required=False, default="0",
        action="store", help="bad-characters to highlight (in hex)")
    parser.add_argument('-n', "--name", required=False, default="buffer",
        action="store", help="name of the output buffer")
    parser.add_argument('-e', "--exec", required=False, default=False,
        action="store_true", help="execute the assembly on this system")
    parser.add_argument('-k', "--keystone", required=False, default="./keystone.dll",
        action="store", help="path of the keystone library")
    parser.add_argument('-c', "--capstone", required=False, default="./capstone.dll",
        action="store", help="path of the capstone library")
    params = parser.parse_args()

    # ? ensure at least one source for content
    if not any([params.text, params.file]):
        raise ValueError("No contents provided")

    # ? convert bad-characters (if exist) to integers
    characters: list[int] = []
    for char in params.bads.split(','):

        try:

            if not char: 
                continue
            if not (0 <= (xchar := int(char, 16)) <= 0xFF):
                raise OverflowError

            characters.append(xchar)

        except ValueError:
            raise ValueError(f"Invalid bad-character: '{char}' (invalid hex)")
        except OverflowError:
            raise OverflowError(f"Invalid bad-character: '{char}' (range: 0-FF)")
    params.bads = characters #! explicit type-convertion (str -> list[int])

    # ? read contents of the provided file, only if no text is present
    try:

        if not params.file:
            return params

        with open(params.file, 'r') as file:

            # remove comments and newlines to match Keystone syntax
            nocoms = [x.split(';')[0].strip() for x in file.readlines()]
            params.text = ';'.join(nocoms); return params

    except PermissionError:
        raise PermissionError("Couldn't open file (insufficient permissions)")
    except FileNotFoundError:
        raise FileNotFoundError("Couldn't open file (non-existent path)")


def create_skeleton(crln: tuple[Instruction, ...], name: str) -> list[str]:
    "generate the individual lines (skeleton) of the buffer"

    # ? define the metadata required for alignment
    align_com = max(crln, key=lambda x: len(x.bytecode))
    align_com = len(align_com.bytecode) * 4 + 7
    align_num = len(f"{crln[-1].address:x}") + 1

    # ? construct the output-string (without any highlights)
    lines: list[str] = [f"{name}  = b''"]
    for line in crln:

        # <name> += b"<bytes>" # <offset> | <text>
        lines.append('%s += b"\\x%s"%s#%s%s | %s' \
            % (
                name,
                '\\x'.join([f'{n:02X}' for n in line.bytecode]),
                ' ' * (align_com - (len(line.bytecode) * 4 + 6)),
                ' ' * (align_num - len(f"{line.address:x}")),
                f"{line.address:x}",
                line.mnemonic
            ))   

    return lines

def execute_shellcode(code: bytes) -> None:

    # ? declare the VirtualAlloc header
    alloc = ct.CDLL("kernel32.dll").VirtualAlloc
    alloc.restype, alloc.argtypes = \
    ct.c_void_p, [   # LPVOID <return>
        ct.c_void_p, # LPVOID lpAddress
        ct.c_size_t, # dwSize
        ct.c_int32,  # flAllocationType
        ct.c_int32   # flProtect
    ]

    # ? move shellcode into executable buffer
    buffer = alloc(None, len(code), 0x1000, 0x40)
    ct.memmove(buffer, code, len(code))

    # ? execute the shellcode...
    input("Press enter to execute shellcode...")
    ct.CFUNCTYPE(None)(buffer)()

def printf(skeleton: list[str], chars: list[int]) -> None:
    "display all lines on the terminal in a colour-coded manner"

    # TODO: enable ANSI for colour support in native CMD
    ...

    # ? insert the highlighting of bad-characters
    characters: list[str] = [f"\\x{n:02X}" for n in chars]
    for index, line in enumerate(skeleton):

        # proceed if line does not contain bad-characters
        if not any([char in line for char in characters]):
            continue

        # colour mnemonical instruction
        edge = line.find("|") + 1
        skeleton[index] = line[:edge] + "\033[31m" + \
                          line[edge:] + "\033[0m " + '<!>'

    # colour individual instances
    output: str = '\n'.join(skeleton)
    for char in characters:
        output = output.replace(char, f"\033[31m{char}\033[0m")

    print(output)

if __name__ == "__main__":

    try:

        # ? parse CLI-provided arguments
        if not (args := parse_arguments()):
            raise Exception()

        # ? convert text to common representation (CR)
        ks_dll = ct.CDLL(args.keystone)
        cs_dll = ct.CDLL(args.capstone)

        with Multistone(ks_dll, cs_dll) as ms:

            code = ms.asm(args.text)
            crln = ms.dis(code)

        # ? utilise CR for flagged functionality
        if args.exec: 
            execute_shellcode(code)
        else:
            print(f"bytecode size: {len(code)}")
            print(f"mnemonic size: {len(crln)}", end='\n\n')
            printf(create_skeleton(crln, args.name), args.bads)

    except Exception as e: print(str(e))
