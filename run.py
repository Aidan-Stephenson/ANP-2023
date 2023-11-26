import os
import sys
import argparse
import subprocess
import time
from datetime import datetime
from termcolor import colored
from pwn import *

# Set cwd to project root
os.chdir(sys.path[0])

DEBUG_DIR = datetime.now().strftime("debug/%H%M_%d%m%Y/")
os.system("mkdir debug 2>/dev/null")
os.system(f"mkdir {DEBUG_DIR}")

def build():
    os.system("cmake .")
    os.system("make -j")
    os.system("make install")

def run(args):
    if args.run == "tcp":
        subprocess.call(["/bin/bash", "sh-setup-arpserver.sh"], cwd="./bin")    # Setup network stack
        subprocess.Popen(["./anp_server"], cwd="./build", stdout=subprocess.DEVNULL)
        custom_env = {
                    'LD_PRELOAD': '/usr/local/lib/libanpnetstack.so'
                }
        if args.no_gdb:
            p = process(["./build/anp_client", "-a", "10.110.0.5", "-w"], env=custom_env)
            if not args.no_wireshark:
                with open(f"{DEBUG_DIR}/capture.pcap", "w") as pcap:
                    subprocess.Popen(["tcpdump", "-U", "-i", "tap0", "-w", "-"], stdout=pcap)
                    time.sleep(2)   # Give it a second to startup
            p.sendline()
            print_program_output(p)
            p.wait()
        else:
            p = gdb.debug(["./build/anp_client", "-a", "10.110.0.5", "-w"], gdbscript='c\n', env=custom_env)
            if not args.no_wireshark:
                with open(f"{DEBUG_DIR}/capture.pcap", "w") as pcap:
                    subprocess.Popen(["tcpdump", "-U", "-i", "tap0", "-w", "-"], stdout=pcap)
                    time.sleep(2)   # Give it a second to startup
            p.sendline()
            print_program_output(p)
            p.wait()


def print_program_output(p):
    history = ""
    while True:
        try:
            line = p.recvline().decode().strip()
            if not line:
                break
            print(line)
            history += line + "\n"
        except EOFError:
            print(line)
            history += line
            break
    with open(f"{DEBUG_DIR}/output.txt", "w") as f:
        f.write(history)



parser = argparse.ArgumentParser(description='Build and test ANP project.')
parser.add_argument('--no-gdb', action='store_true', help='Do not use GDB')
parser.add_argument('--no-wireshark', action='store_true', help='Do not use Wireshark (only works with gdb)')
parser.add_argument('run', type=str, help='Specify the task to run')

args = parser.parse_args()

if __name__ == "__main__":
    build()
    run(args)

    print(colored(f"Debug run: {DEBUG_DIR}", "red"))
