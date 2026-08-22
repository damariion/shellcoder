Shellcoder is a portable assembler that utilises Keystone to convert source files into a Python buffer that includes informative comments. It has been designed to utilise the DLL that is shipped with it to ensure usability on all x86 Windows systems, as long as Python 3.9 is installed.

While MSFvenom dumps a block of bytecode after its payload generation, Shellcoder formats its buffer to match the original assembly code, providing useful details when debugging your payload. Additionally, it features routine enhancements such as bad-character highlighting, size annotations and commonly used CLI utilities.

Below is an example of its usage, where we make use of the payload that resolves `kernel32.dll` by walking the Process Environment Block (PEB):

![example](example.png)

This script is meant to be run on Windows 10 (x86). To support this expectation, the following design choices have been made during its development:

- The DLL is compiled in 32-bit mode;
- The code has been tested on Python 3.9;
- VT processing is enabled for colour support;

Finally, I'd like to mention that this script does not contain any intelligent features; it merely attempts to minimise tedium.