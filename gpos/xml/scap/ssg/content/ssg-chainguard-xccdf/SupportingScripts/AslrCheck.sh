#!/bin/sh

aslr_value=$(sysctl kernel.randomize_va_space | awk '{print $3}')

if [ $aslr_value -eq 2 ]; then
    return $XCCDF_RESULT_PASS
else 
    echo "ASLR not configured correctly"
    return $XCCDF_RESULT_FAIL
fi