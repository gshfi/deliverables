from pwn import *

os.environ["LIBC_FATAL_STDERR_"] = "1"

buffer_overflow_length = 0

# Send a string of increasing length to the second prompt until "stack smashing detected" error
for i in range(1, 101):  # We'll start from 1 and go up to 500
    p = process("./dungeon5")
    try:        
        print(f"Fuzzing with {i} characters...")  # Print progress
        print(p.recvline())
        p.sendline(b'prompt1')
        print(p.recvline())
	
        # Fuzz the second prompt
        payload = b"A" * i
        p.sendline(payload)

        p.recvall()  # Wait for all output; program will likely crash here if it's going to

    except EOFError:  # Catch error when the process is forcibly closed
        # The EOFError will be thrown when the process is forcibly closed
        # Check for "stack smashing detected" in the last few lines of output
        if b"stack smashing detected" in p.stderr.read():
            print(f"Buffer overflow detected at {i} characters.")
            buffer_overflow_length = i
            break

    finally:
        p.close()

if buffer_overflow_length == 0:
    print("No buffer overflow detected within the range.")
else:
    print(f"The input buffer overflows after {buffer_overflow_length} characters.")
