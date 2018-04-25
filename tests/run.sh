#!/bin/bash

set -e

CURRENT="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd $CURRENT

# Compile POSIX binaries
for FPATH in posix/*.c; do
	test -f $FPATH.testbin || gcc $FPATH -o $FPATH.testbin
done

# Download some windows binary
test -f ./win32/ru.exe.testbin || wget --quiet https://live.sysinternals.com/ru.exe -O ./win32/ru.exe.testbin

test -f ./win32/livekd64.exe.testbin || wget --quiet https://live.sysinternals.com/livekd64.exe -O ./win32/livekd64.exe.testbin

python3 -m unittest discover .

