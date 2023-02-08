#!/usr/bin/env python3
#
# AI-instrument-lqwrm, 2023
#
# This fuzzer uses the os.urandom() function to generate random bytes, which it
# writes to a file. It then runs the target binary with the file as an argument
# and uses a try-except block to catch any exceptions that may occur when running
# the binary. It also records the time each test case takes, in case the binary
# crashes or hangs on a specific input.
#
# This fuzzer is more advanced than the previous one as it generates random binary
# data, which is more likely to cause unexpected behavior in the target binary and
# it also records the time taken for each test case.
#

import os
import random
import subprocess
import time

# Set the path to the target binary
binary = "C:\\path\\binary.exe"

# Set the number of test cases to run
num_tests = 251

# Set the length of the random bytes to generate
num_bytes = 125

# Set the directory to store the test cases
dir_name = "fuzz_cases"

# Create the directory if it doesn't exist
if not os.path.exists(dir_name):
    os.mkdir(dir_name)

for i in range(num_tests):
    # Generate random bytes
    random_bytes = os.urandom(num_bytes)
    # Write the bytes to a file
    #file_name = f"{dir_name}\\fuzz_case_{i}.bin"
    file_name = f"{dir_name}/fuzz_case_{i}.bin"
    with open(file_name, "wb") as f:
        f.write(random_bytes)
    # Run the binary with the file as the argument
    try:
        start_time = time.time()
        subprocess.run([binary, file_name], check=True, timeout=5)
        end_time = time.time()
    except Exception as e:
        print(f"Test case {i} caused an exception: {e}")
        print(f"Test case {i} took {end_time - start_time} seconds")
    finally:
        subprocess.run(["del",file_name])
        print

print("Fuzzing complete!")
