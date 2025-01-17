#!/bin/bash

# Perform a clean build
echo "Performing make clean ..."
make clean

echo "Performing make ..."
make

# Check if make was successful
if [ $? -ne 0 ]; then
    echo "Build failed. Exiting."
    exit 1
fi

# Loop over each .pcap file in trace_files directory
for pcap in trace_files/*.pcap; do
    # Extract base name without extension
    base=$(basename "$pcap" .pcap)
    
    # Define output and expected file paths
    test_output="test${base}.out"
    expected="trace_files/${base}.out"
    
    echo "Running test for ${pcap} ..."
    
    # Run the trace program and capture output
    ./trace "$pcap" > "$test_output"
    
    # Compare the generated output with the expected output
    if diff "$test_output" "$expected" > /dev/null; then
        echo "Test for ${base}: PASSED"
    else
        echo "Test for ${base}: FAILED"
        echo "Differences (with line numbers):"
        # Customize the diff output
        diff -u "$test_output" "$expected" | sed \
            -e 's/^+/\tactual: /' \
            -e 's/^-/\texpected: /'
    fi
    
    echo # Print an empty line for readability
done
