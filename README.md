# memrepl

`memrepl` is a `frida` based script that aims to help a researcher in the task of exploitation of memory corruption related bugs.

The idea is that the researcher can perform database like `queries` to get information about the contents and layout of the memory of a program. To perform these queries, `memrepl` exposes several global functions listed bellow:

- `memory_list`: query current memory segments.
- `memory_search`: search for a given value.
- `memory_read`: read from a memory address.
- `memory_write`: write to a memory address.
- `memory_search_pointer`: search any pointers starting from a given address.

## Installation

```
# Install `pip` if not installed.
$ easy_install pip

# Install `virtualenv` if not installed.
$ pip install virtualenv

# Create a virtual python environment.
$ virtualenv venv_memrepl

# Activate the environment (POSIX system).
$ source ./venv_memrepl/bin/activate

# Install `memrepl` into the virtual environment.
$ python setup.py install

```
### Dependencies
All the requirements will be installed automatically using python's `setuptools`.
- `python`
- `pip`
- `virtualenv (optional)`
- `frida`
- `ipython`
- `hexdump`

## Usage

Execute `memrepl` with `-h` to get help:

```
$ memrepl -h
usage: memrepl [-h] [-V] (-p PROC_PID | -n PROC_NAME | -l) [-d DEVICE]
               [-m MOD_NAMES]

Memory Grip.

optional arguments:
  -h, --help     show this help message and exit
  -V, --version  show program's version number and exit
  -p PROC_PID    Process PID.
  -n PROC_NAME   Process name (follows unix wildcard patterns).
  -l             Display running processes.
  -d DEVICE      Select a device by ID. Specify `list` to get a list of
                 available devices.
  -m MOD_NAMES   Specify zero or more modules that need to be loaded in the
                 target process.
```

### Attaching to a process by pid

```
$ memrepl -p 39718
Using device Device(id="local", name="Local System", type='local').
Attaching to process pid `39718`.
Attaching to process `39718`.

 ____________________
< Welcome to MemREPL >
 --------------------
        \   ^__^
         \  (oo)\_______
            (__)\       )\/\
                ||----w |
                ||     ||

Avaliable commands:

memory_list: list memory regions in the attached program
memory_search: search for a given value
memory_read: read from a given address
memory_write: write to a given address

Use help(command_name) to see how to use the command.


In [1]:
```

## Getting help while on the REPL loop

Each exported function has a help message defined that can be read by using python's `help` function. Each help messages contains usage examples.

```
In [10]: help(memory_read)
Help on function memory_read in module memrepl:

memory_read(value_format, address, size=32)
    Examples:
    memory_read("u8", 0xcafecafe)
    memory_read("u16", 0xcafecafe)
    memory_read("u32", 0xcafecafe)
    memory_read("u64", 0xcafecafe)
    memory_read("hex", 0xcafecafe, 4)
    memory_read("bytes", 0xcafecafe, 4)
    memory_read("BBII", 0xcafecafe)
```

## Listing memory

**Exported function signature:** `memory_list(protection="---")`

### Listing all segments
To list all the segments present in the target process use the `memory_list` function without an argument:
```
In [5]: memory_list()
  0: 0x000000010a4f5000 - 0x000000010a4f6000 (      4096 / 0x00001000) next=0x0000000000000000 r-x
  1: 0x000000010a4f6000 - 0x000000010a4f7000 (      4096 / 0x00001000) next=0x0000000000000000 rw-
  2: 0x000000010a4f7000 - 0x000000010a4fa000 (     12288 / 0x00003000) next=0x0000000000000000 r--
  3: 0x000000010a4fa000 - 0x000000010a4fc000 (      8192 / 0x00002000) next=0x0000000000000000 rw-
  ...
```

`memory_list` allows a `permission` agument that serves as a match filter, allowing the researcher to filter those segments he is interested in. For instance:

### Executable segments
```
In [7]: memory_list("x")
 0: 0x000000010a4f5000 - 0x000000010a4f6000 (      4096 / 0x00001000) next=0x0000000000007000 r-x
 1: 0x000000010a4fd000 - 0x000000010a4fe000 (      4096 / 0x00001000) next=0x000000000000a000 r-x
 2: 0x000000010a508000 - 0x000000010a738000 (   2293760 / 0x00230000) next=0x0000000000037000 r-x
 3: 0x000000010a76f000 - 0x000000010a78c000 (    118784 / 0x0001d000) next=0x0000000000091000 r-x
...
```

### RWX segments

```
In [8]: memory_list("rwx")
0: 0x00007fffe8dac000 - 0x00007fffe8dad000 (      4096 / 0x00001000) next=0x000000000001c000 rwx /private/var/db/dyld/dyld_shared_cache_x86_64h
1: 0x00007fffe8dc9000 - 0x00007fffe8dca000 (      4096 / 0x00001000) next=0x00000000000bc000 rwx /private/var/db/dyld/dyld_shared_cache_x86_64h
2: 0x00007fffe8e86000 - 0x00007fffe8e87000 (      4096 / 0x00001000) next=0x0000000000000000 rwx /private/var/db/dyld/dyld_shared_cache_x86_64h
```

## Searching memory

**Exported function signature:** `memory_search(value_format, value, out_format="hex", out_size=32)`

### Example search expressions

```
memory_search("u8", 0xca)
memory_search("u16", 0xcafe)
memory_search("u32", 0xcafedead)
memory_search("u64", 0xcafecafecafecafe)
memory_search("hex", "ca fe ca fe")
memory_search("bytes", "\xca\xfe\xca\xfe")
```

### Example search

```
# Search for the string "CAFE" repeated 8 times.
In [12]: memory_search("bytes", "CAFE" * 8)
Found @ 0x000026412eceeeb0
00000000: 43 41 46 45 43 41 46 45  43 41 46 45 43 41 46 45  CAFECAFECAFECAFE
00000010: 43 41 46 45 43 41 46 45  43 41 46 45 43 41 46 45  CAFECAFECAFECAFE
...
Got 203 results.

# Search for a pointer to the found string.
In [13]: string_address = 0x000026412eceeeb0
In [14]: memory_search("u64", string_address)
Found @ 0x0000000115f1b6d8
00000000: B0 EE CE 2E 41 26 00 00  50 01 00 00 E5 E5 E5 E5  ....A&..P.......
00000010: B8 2B 7C 19 01 00 00 00  00 14 A1 2E 41 26 00 00  .+|.........A&..
```

## Reading memory

**Exported function signature:** `memory_read(value_format, address, size=32)`

```
# Reading possible object that points to our address.
In [15]: object_address = 0x0000000115f1b6d8

# Read a couple QWORDs before the object to see whats there.
In [16]: memory_read("hex", object_address - 8 * 4)
Read @ 0x0000000115f1b6b8
00000000: B8 2B 7C 19 01 00 00 00  40 14 A1 2E 41 26 00 00  .+|.....@...A&..
00000010: 40 00 00 00 E5 E5 E5 E5  B8 2B 7C 19 01 00 00 00  @........+|.....

# Looks like the format is pointer|pointer|uint32|uint32|pointer
In [17]: memory_read("PPIIP", object_address - 8 * 4)
Read @ 0x0000000115f1b6b8
0x00000001197c2bb8 0x000026412ea11440 0x00000040 0xe5e5e5e5 0x00000001197c2bb8
```

## Searching for pointers

**Exported function signature:** `memory_search_pointer(address, protection)`

The main usage of this function is to search for things to overwrite. Basically one can search for pointers to things that may be useful while exploiting bugs. Two cases come to mind:

- Pointers to data (to create infoleaks)
- Pointers to code (to get code execution)

### Example: looking for the position of a function pointer to overwrite.

```
In [18]: memory_search_pointer(object_address, "x")
Found pointer @ 0x0000000115f36e48 = 0x00000001192bfde8 to segment 0x0000000117cbf000 - 0x0000000119598000 r-x

In [19]: 0x0000000115f36e48 - object_address
Out[19]: 112496

In [20]: function_pointer_address = 0x0000000115f36e48
```

## Writing memory

**Exported function signature:** `memory_write(value_format, address, value)`

```
In [21]: memory_write("u64", function_pointer_address, 0xdeadbeef)

# In another console with `lldb` attached:
(lldb) c
Process 39718 resuming
Process 39718 stopped
* thread #1, queue = 'com.apple.main-thread', stop reason = EXC_BAD_ACCESS (code=1, address=0xdeadbeef)

(lldb) register read rip
     rip = 0x00000000deadbeef
```