#!/usr/bin/env python3
#
# AI-instrument-lqwrm 2023
#
# The fuzzer includes an injection point, specified by the injection_offset
# variable, which is set to 2, and the injection_string variable, which is
# set to b"{t00t}". In each iteration of the loop, the fuzzer generates random
# bytes using the os.urandom() function, and then it splices the bytes at
# the injection offset using python string slicing, and then it inserts the
# injection string at that point and then it writes the modified bytes to a
# file.
#
# Then it runs the target binary with the file as an argument and uses
# a try-except block to catch any exceptions that may occur when running the
# binary. It also records the time each test case takes, in case the binary
# crashes or hangs on a specific input. You can adjust the injection offset
# and the injection string to suit your needs and test the binary with different
# variations at that location, you can also adjust the number of bytes generated
# to fit the size of the file format you're testing.


import os
import random
import subprocess
import time

# Set the path to the target binary
binary = "C:\\path\\binary.exe"
#binary = "/usr/bin/file" #nix

# Set the number of test cases to run
num_tests = 251

# Set the length of the random bytes to generate
num_bytes = 125

# Set the directory to store the test cases
dir_name = "fuzz_cases"

# Create the directory if it doesn't exist
if not os.path.exists(dir_name):
    os.mkdir(dir_name)

# Set the injection point
injection_offset = 2
injection_string = b"{t00t}" # offset
#
# type fuzz_cases\fuzz_case_0.bin
# AA{t00t}AAAAAAAA%
#

for i in range(num_tests):
    # Generate random bytes
    random_bytes = os.urandom(num_bytes)
    #random_bytes = b"AAAAAAAAAA"
    # Insert the injection string at the specified offset
    random_bytes = random_bytes[:injection_offset] + injection_string + random_bytes[injection_offset:]
    # Write the bytes to a file
    file_name = f"{dir_name}\\fuzz_case_{i}.bin"
    #file_name = f"{dir_name}/fuzz_case_{i}.bin" #nix

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
        #subprocess.run(["rm",file_name]) #nix
        print

print("Fuzzing complete!")
