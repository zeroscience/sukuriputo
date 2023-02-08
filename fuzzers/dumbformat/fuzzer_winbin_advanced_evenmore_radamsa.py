#!/usr/bin/env python3
#
# AI-instrument-lqwrm, 2023
#
# This fuzzer uses Radamsa as a mutator to create new test cases. Radamsa
# is a popular open-source fuzzer and it can be used to generate new test
# cases by mutating existing ones. In this example, the fuzzer uses the
# subprocess.run() function to run the Radamsa binary and pass it the test
# case file and the output file, which is the fuzzed test case. The output
# file is then passed as the argument to the target binary and the results
# are recorded. 
#
# It's important to note that you will have to install Radamsa on your system
# and adjust the path to the Radamsa binary in the code accordingly. Also, this
# code will only work on windows systems, as the "del" command is used to delete
# the files after the test case is done. On other systems, you will have to
# use the appropriate command for deleting files. Keep in mind that this is
# just a basic example, and Radamsa has many options that you can use to customize
# the mutation process. You can refer to Radamsa documentation for more information.
#

import os
import subprocess
import time

# Set the path to the target binary
binary = "C:\\path\\binary.exe"

# Set the number of test cases to run
num_tests = 251

# Set the directory to store the test cases
dir_name = "fuzz_cases"

# Set the path to the radamsa binary
radamsa_path = "C:\\path\radamsa.exe"

# Set the path to the test case file
test_case_file = "test_case.bin"

# Create the directory if it doesn't exist
if not os.path.exists(dir_name):
    os.mkdir(dir_name)

for i in range(num_tests):
    # Generate a fuzzed test case using radamsa
    fuzzed_file = f"{dir_name}\\fuzz_case_{i}.bin"
    subprocess.run([radamsa_path, "-o", fuzzed_file, test_case_file], check=True)

    # Run the binary with the fuzzed file as the argument
    try:
        start_time = time.time()
        subprocess.run([binary, fuzzed_file], check=True, timeout=5)
        end_time = time.time()
    except Exception as e:
        print(f"Test case {i} caused an exception: {e}")
        print(f"Test case {i} took {end_time - start_time} seconds")
    finally:
        #subprocess.run(["del",fuzzed_file])
        print

print("Fuzzing complete!")
