#!/bin/bash

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
        diff -u "$test_output" "$expected"
    fi
    
    echo # Print an empty line for readability
done
