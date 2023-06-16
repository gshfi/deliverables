import subprocess

for i in range(30, 101):
    a_str = "A" * i
    result = subprocess.run(f"echo {a_str} | ./dungeon3", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if "segmentation fault" in result.stderr.decode():
        print(f"Found value that caused segmentation fault: {a_str}")
        break
