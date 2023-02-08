#!/usr/bin/env python3
#
# AI-instrument-lqwrm, 2023
#
# This fuzzer uses the subprocess module to run the target binary with a
# different file argument in each test case. It generates a random string
# and write it to a file, then it uses that file as the argument for the
# binary, and then it deletes the file after the test case is done. It also
# uses a try-except block to catch any exceptions that may occur when running
# the binary, and it prints a message if an exception is caught.
#
# This is a simple fuzzer that can be used to test a blackbox windows binary
# that takes one argument.
#

import subprocess
import random
import string

# Set the path to the target binary
binary = "C:\\path\\binary.exe"
#binary = "/usr/bin/file" #nix

# Set the number of test cases to run
num_tests = 251

# Set the length of the random strings to generate
string_length = 125

for i in range(num_tests):
    # Generate a random string to use as the file argument
    random_string = ''.join(random.choice(string.printable) for _ in range(string_length))
    file_name = "test_file_"+str(i)+".txt"
    with open(file_name, "w") as f:
        f.write(random_string)
    try:
        subprocess.run([binary, file_name], check=True, timeout=5)
    except Exception as e:
        print(f"Test case {i} caused an exception: {e}")
    finally:
        #subprocess.run(["rm",file_name]) #nix
        subprocess.run(["del",file_name])

print("Fuzzing complete!")
