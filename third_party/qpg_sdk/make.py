#! /usr/bin/env python3
'''Python wrapper to call make based builds within the SDK
'''
import subprocess
import sys

subprocess.run(['make', '-j'] + sys.argv[1:], check=True)
