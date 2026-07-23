from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CsInsn
from keystone import Ks, KS_ARCH_X86, KS_MODE_32
from argparse import ArgumentParser, Namespace

"""
* Keystone and Capstone haven't been properly type-annotated, which results
* in many errors when Pylance is configured in strict-mode. The wrappers
* below are meant to make the rest of the source code more readable.
"""
def ks_asm(ks: Ks, content: str) -> bytes       : return ks.asm(content, 0)[0]
def cs_dis(cs: Cs, code: bytes) -> list[CsInsn] : return [*cs.disasm(code, 0)]

def parse_arguments() -> Namespace | None:
    """
    parse and validate the CLI-arguments.<br>
    **returns**: Namespace<text: str, bads: list[int], name: str\\>
    """

    # ? parse through the built-in argument handler
    parser = ArgumentParser()
    parser.add_argument('-f', "--file", required=False,
        action="store", help="assemble contents of a file")
    parser.add_argument('-t', "--text", required=False,
        action="store", help="assemble contents of a text")
    parser.add_argument('-b', "--bads", required=False, default="0",
        action="store", help="bad-characters to highlight (hex)")
    parser.add_argument('-n', "--name", required=False, default="buffer",
        action="store", help="name of the output buffer")
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

    # text has priority!
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

def convert_to_CR(content: str) -> list[CsInsn] | None:
    """
    convert the assembly-contents to an common representation (CsInsn)<br>
    **returns**: list<capstone.CsInsn\\>
    """

    ks = Ks(KS_ARCH_X86, KS_MODE_32)
    cs = Cs(CS_ARCH_X86, CS_MODE_32)

    # ? pass through both KS and CS to reach CR (aka: CsInsn)
    try:

        code = ks_asm(ks, content)
        text = cs_dis(cs, bytes(code))

        # prevents Cs from ignoring instructions silently
        if sum(len(i.bytes) for i in text) != len(code):
            return print("Couldn't assemble all instructions")

        return text
    
    except Exception as e:
        return print(f"Couldn't convert to IR: {e}")
    
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

    if (cr := convert_to_CR(args.text)): 
        to_stdout(create_buffer(cr, args.name), args.bads)