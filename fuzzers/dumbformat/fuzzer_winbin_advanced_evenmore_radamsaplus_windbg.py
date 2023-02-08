#!/usr/bin/env python3
#
# AI-instrument-lqwrm, 2023
#
# Fuzzer win binary 1 arg, radamsa mutated, test case, windbg.
#


import os
import subprocess
import time

# Set the path to the target binary
binary = "C:\\path\\to\\binary.exe"

# Set the number of test cases to run
num_tests = 251

# Set the directory to store the test cases
dir_name = "fuzz_cases"

# Set the path to the radamsa binary
radamsa_path = "C:\\path\\radamsa.exe"

# Set the path to the test case file
test_case_file = "test_case.bin"

# Seed for radamsa
seed = 0

# Set mutation option for radamsa
mutation = "havoc"

# Set the directory to store the crash reports
crash_dir = "crashes"

# Create the directory if it doesn't exist
if not os.path.exists(dir_name):
    os.mkdir(dir_name)

if not os.path.exists(crash_dir):
    os.mkdir(crash_dir)

for i in range(num_tests):
    # Generate a fuzzed test case using radamsa
    fuzzed_file = f"{dir_name}\\fuzz_case_{i}.bin"
    subprocess.run([radamsa_path, "-o", fuzzed_file, "-s", str(seed), "-n", mutation, test_case_file], check=True)
    seed += 1

    # Run the binary with the fuzzed file as the argument using Windbg
    try:
        start_time = time.time()
        windbg_command = f"sxe av; g; .logopen {crash_dir}\\fuzz_case_{i}.log; g; .logclose"
        subprocess.run(["windbg.exe", "-c", windbg_command, binary, fuzzed_file], check=True, timeout=5)
        end_time = time.time()
    except Exception as e:
        print(f"Test case {i} caused an exception: {e}")
        print(f"Test case {i} took {end_time - start_time} seconds")
    finally:
        subprocess.run(["del",fuzzed_file])

print("Fuzzing complete!")
