Codepaths
========

Codepaths is a binary reversing tool to find all possible code paths between two functions.

It is a command line tool built on Python3 and r2pipe which supports the formats and architectures that radare2 supports.

The tool gives you a brief overview on how to hit interesting parts of the code in preparation for the manual reverse engineering process. It is particularly useful for simple scenarios like finding paths between functions that handles user-provided input to functions that invoke `exec()`-like function.

Usage
-----

Different mode of operations can be specified through arguments.

* `from-to`: Find the code paths between functions passed in `--from` and `--to` arguments. Omitting `--from` starts searching from the binary entry point.
* `to-exec`: Find the code paths between `--from` function and a list of `exec()`-like functions. Omitting `--from` starts searching from the binary entry point.
* `list-func`: List the functions in the binary. Same as radare2 `afl`.
* `list-exec`: List the `exec()`-like functions in the binary.

Arguments `--from` and `--to` accept both function name format used by radare2 (i.e. `sym.*`, `sub.*`, `entry0`) and addresses in the `0x` format. Customise what's considered notable `exec()`-like function in the `SINKS` variable in the script.

Requirements
------------

Follow the official documentation on installing the latest version of  [radare2](https://github.com/radare/radare2).

```
$ git clone https://github.com/radare/radare2
$ cd radare/
$ sudo sys/install.sh
```

Then install r2pipe binding for Python 3.

```
$ sudo pip3 install r2pipe
```

Examples
--------

### `from-to`

Find all the paths between the entry point and `socket()` call in `/bin/cat` binary.

```
$ ./codepaths.py from-to --to sym.imp.socket /bin/cat

[+] Analyzing all referenced code with radare2
[+] Finding paths betwen 1 sources and 1 sinks..
[+] Path 1 of 1 between sym.imp.socket and entry0

▶ 0x100001590 entry0
| 0x1000016cc call sym.func.100001728
▶ 0x100001728 sym.func.100001728
| 0x100001857 call sym.imp.socket
▶ 0x100001d8c sym.imp.socket
```

### `to-exec`

Find all the paths between the entry point and any `exec()`-like call in `/usr/bin/jar` binary.

```
$ ./codepaths.py to-exec /usr/bin/jar

[+] Analyzing all referenced code with radare2
[+] Finding paths betwen 1 sources and 1 sinks..
[+] Path 1 of 1 between sym.imp.execv and entry0

▶ 0x10000090d entry0
| 0x100000aea call sym.func.100001146
▶ 0x100001146 sym.func.100001146
| 0x10000120a call sym.imp.execv
▶ 0x100001876 sym.imp.execv
```

### `list-exec`

List all the `exec()`-like functions in the `/usr/bin/find` binary.

```
$ ./codepaths.py list-exec /usr/bin/find

[+] Analyzing all referenced code with radare2
0x100005a4c sym.imp.execvp
```

### `list-exec` 

List all the functions in the `/bin/ls` binary.

```
$ ./codepaths.py list-func /bin/ls

[+] Analyzing all referenced code with radare2
0x100000f20 sym.func.100000f20
0x100000f32 sym.func.100000f32
0x100000f47 sym.func.100000f47
...
```

Known issues
------------

- Codepaths could be run from radare2 command line terminal, but it currently triggers [this](https://github.com/radare/radare2-r2pipe/issues/57) error. This will be updated when fixed.
- Dictionary of sinks `SINKS` would benefit from additional categories and functions. 
