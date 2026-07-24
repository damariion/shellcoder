from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CsInsn
from argparse import ArgumentParser, Namespace
from ctypes   import (
    CDLL,     POINTER,  byref,
    c_int,    c_void_p, c_char_p, 
    c_size_t, c_uint64, c_ubyte,
)

"""
* Keystone and Capstone haven't been properly type-annotated, which results
* in many errors when Pylance is configured in strict-mode. The wrappers
* below are meant to make the rest of the source code more readable.
"""
def cs_dis(cs: Cs, code: bytes) -> list[CsInsn] : return [*cs.disasm(code, 0)]

class Keystone:
    "Compact Keystone wrapper, exposing only required APIs"

    class KeystoneException(Exception): ...

    def __declare_exports(self) -> None:
        "map DLL exports to this class (self)"

        # https://github.com/keystone-engine/keystone/
        # blob/master/include/keystone/keystone.h#L244
        self.__open = self.dll.ks_open
        self.__open.restype, self.__open.argtypes = \
        c_int, [              # ks_err <return>
            c_int,            # ks_arch arch
            c_int,            # int mode
            POINTER(c_void_p) # ks_engine** ks
        ]

        # https://github.com/keystone-engine/keystone/
        # blob/master/include/keystone/keystone.h#L260
        self.__close = self.dll.ks_close
        self.__close.restype, self.__close.argtypes = \
        c_int, [     # ks_err <return>
            c_void_p # ks_engine* ks
        ]

        # https://github.com/keystone-engine/keystone/blob/
        # master/include/keystone/keystone.h#L326C1-L330C29
        self.__asm = self.dll.ks_asm
        self.__asm.restype, self.__asm.argtypes = \
        c_int, [                       # int <return>
            c_void_p,                  # ks_engine* ks
            c_char_p,                  # const char* string
            c_uint64,                  # uint64_t address
            POINTER(POINTER(c_ubyte)), # unsigned char** encoding
            POINTER(c_size_t),         # size_t* encoding_size
            POINTER(c_size_t)          # size_t* stat_count
        ]

        # https://github.com/keystone-engine/keystone/
        # blob/master/include/keystone/keystone.h#L339
        self.__free = self.dll.ks_free
        self.__free.restype, self.__free.argtypes = \
        None, [              # void <return>
            POINTER(c_ubyte) # unsigned char* p
        ]

        # https://github.com/keystone-engine/keystone/
        # blob/master/include/keystone/keystone.h#L272
        self.__errno = self.dll.ks_errno
        self.__errno.restype, self.__errno.argtypes = \
        c_int, [     # ks_err <return>
            c_void_p # ks_engine* ks
        ]

        # https://github.com/keystone-engine/keystone/
        # blob/master/include/keystone/keystone.h#L284
        self.__strerror = self.dll.ks_strerror
        self.__strerror.restype, self.__strerror.argtypes = \
        c_char_p, [ # const char* <return>
            c_int   # ks_err code
        ]

    def __get_last_error(self) -> str:
        "retrieve the last registered error in string format"

        # no explicit exception-handling
        # to use the OS invoked exception
        code = self.__errno(self.engine)
        text = self.__strerror(code)

        return text.decode()

    def __init__(self, path: str) -> None:

        # ? load DLL and exports
        self.dll = CDLL(path)
        self.__declare_exports()
        self.engine = c_void_p()

        # ? start the engine in x86 32-bit mode
        if (code := self.__open(4, 4, self.engine)):
            raise self.KeystoneException(self.__strerror(code).decode())

    def assemble(self, text: str) -> bytes:
        "assemble the provided text into bytecode"

        size = c_size_t()
        stat = c_size_t()
        buff = POINTER(c_ubyte)()

        # this function call is entirely direct and no sanitisation 
        # is performed, exceptions are also blatantly returned in a 
        # generic Exception object

        if self.__asm(

            self.engine,   # ks_engine ks*
            text.encode(), # const char* string
            c_uint64(0),   # uint64_t address
            byref(buff),   # unsigned char **encoding
            byref(size),   # size_t* encoding_size
            byref(stat)    # size_t* stat_count

        ): raise self.KeystoneException(self.__get_last_error())

        # ? capture and immediately free
        result = bytes(buff[:size.value])
        self.__free(buff); return result

    def release(self) -> None:
        "release the engine and initialised resources"

        if not self.engine:
            return

        # ! don't use APIs after release
        if self.__close(self.engine):
            raise self.KeystoneException(self.__get_last_error())

        # ensure release terminates safely
        self.engine = c_void_p()

def parse_arguments() -> Namespace | None:
    """
    parse and validate the CLI-arguments.<br>
    **returns**: Namespace<text: str, bads: list[int], name: str\\>
    """

    # ? parse through the built-in argument handler
    parser = ArgumentParser()
    parser.add_argument('-f', "--file", required=False, default='',
        action="store", help="assemble contents of a file")
    parser.add_argument('-t', "--text", required=False, default='',
        action="store", help="assemble contents of a text")
    parser.add_argument('-b', "--bads", required=False, default="0",
        action="store", help="bad-characters to highlight (hex)")
    parser.add_argument('-n', "--name", required=False, default="buffer",
        action="store", help="name of the output buffer")
    parser.add_argument('-e', "--exec", required=False, default=False,
        action="store_true", help="execute the assembly on this system")
    params = parser.parse_args()

    # ? ensure at least one source for content
    if not any([params.text, params.file]):
        return print("No contents provided.")
    
    if all([params.text, params.file]):
        return print("Too many contents provided.")

    # ? convert bad-characters (if exist) to integers
    characters: list[int] = []
    for char in params.bads.split(','):

        if not char: 
            continue
        try:
            if not (0 <= (xchar := int(char, 16)) <= 0xFF):
                raise OverflowError
            characters.append(xchar)

        except ValueError:
            return print(f"Invalid bad-character: '{char}' (invalid hex)")
        except OverflowError:
            return print(f"Invalid bad-character: '{char}' (range: 0-FF)")
    params.bads = characters #! explicit type-convertion (str -> list[int])

    # ! text has priority!
    if not params.file:
        return params
    
    # ? read contents from file if path is provided
    try:

        with open(params.file, 'r') as file:

            # remove comments and newlines to match Keystone syntax
            nocoms = [x.split(';')[0].strip() for x in file.readlines()]
            params.text = ';'.join(nocoms); return params

    except PermissionError:
        return print("Couldn't open file (insufficient permissions)")
    except FileNotFoundError:
        return print("Couldn't open file (non-existent path)")

def convert_to_CR(
        text    : str, 
        ks_path : str = "keystone.dll",
        cs_path : str = "capstone.dll"
        ) -> list[CsInsn] | None:
    """
    convert the assembly-contents to an common representation (CsInsn)<br>
    **returns**: list<capstone.CsInsn\\>
    """

    ks, cs = None, None
    def release(ks: Keystone | None, cs: Cs | None) -> None:

        if ks: ks.release()
        if cs: ...

    try:

        # ? initialise external DLLs
        ks = Keystone(ks_path)
        cs = Cs(CS_ARCH_X86, CS_MODE_32)

        # ? perform the conversion
        code = ks.assemble(text)
        cscr = cs_dis(cs, bytes(code))

        # prevents Cs from ignoring instructions silently
        if sum(len(i.bytes) for i in cscr) != len(code):
            return print("Couldn't assemble all instructions")

        release(ks, cs); return cscr

    except Keystone.KeystoneException as e:
        release(ks, cs); return print(f"Keystone caused an exception: {e}")
    except Exception as e:
        release(ks, cs); return print(f"Couldn't (dis)assemble text: {e}")

def create_thread(bytecode: bytes) -> None:

    ... # TODO

def create_buffer(cr: list[CsInsn], name: str) -> list[str]:
    """
    generate every line that will eventually be output, these lines<br>
    follow the format: <name\\> += b"<bytes\\>" # <offset\\> | <text\\><br>
    **returns**: list<lines\\>
    """

    # metadata required for neat alignment
    align_com = max(cr, key=lambda x: len(x.bytes))
    align_com = len(align_com.bytes) * 4 + 7
    align_num = len(f"{cr[-1].address:x}") + 1

    # ? construct the output-string (without any highlights)
    lines: list[str] = [f"{name}  = b''"]
    for line in cr:

        # <name> += b"<bytes>" # <offset> | <text>
        lines.append('%s += b"\\x%s"%s#%s%s | %s' \
            % (
                name,
                '\\x'.join([f'{n:02X}' for n in line.bytes]),
                ' ' * (align_com - (len(line.bytes) * 4 + 6)),
                ' ' * (align_num - len(f"{line.address:x}")),
                f"{line.address:x}",
                f"{line.mnemonic} {line.op_str}"
            ))   

    return lines

def to_stdout(lines: list[str], chars: list[int]) -> None:
    "display all lines on the terminal in a colour-coded manner"

    characters: list[str] = [f"\\x{n:02X}" for n in chars]

    # ? insert the highlighting of bad-characters
    for index, line in enumerate(lines):

        # proceed if line does not contain bad-characters
        if not any([char in line for char in characters]):
            continue

        # colour mnemonical instruction
        edge = line.find("|") + 1
        lines[index] = line[:edge] + "\033[31m" + \
                       line[edge:] + "\033[0m " + '<!>'

    # colour individual instances
    output: str = '\n'.join(lines)
    for char in characters:
        output = output.replace(char, f"\033[31m{char}\033[0m")

    print(output)

if __name__ == "__main__" and (args := parse_arguments()):

    if not (cr := convert_to_CR(args.text, "external/libkeystone.dylib")):
        exit(1) # if the conversion doesn't work, nothing will...

    if args.exec:
        create_thread(b''.join([x.bytes for x in cr]))
    else:
        to_stdout(create_buffer(cr, args.name), args.bads)