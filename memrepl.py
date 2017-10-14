import sys
import struct
import fnmatch
import binascii
import argparse
import collections

import frida
import hexdump
import IPython

parser = argparse.ArgumentParser(description="Memory Grip.")

# Show the program version.
parser.add_argument('-V', '--version', action="version",
                    version="%(prog)s 0.1")

# Required, mutually exclusive options.
group = parser.add_mutually_exclusive_group(required=True)

# Specify the process to which we will attach by PID.
group.add_argument("-p", action="store",
                   dest="proc_pid", type=int, help="Process PID.")

# Specify the process to which we will attach by NAME.
group.add_argument("-n", action="store", dest="proc_name",
                   help="Process name (follows unix wildcard patterns).")

# List running processes.
group.add_argument("-l", action="store_true",
                   dest="show_processes", help="Display running processes.")

# Add an option to select a device.
parser.add_argument("-d", action="store", dest="device", default="local",
                    help="Select a device by ID. Specify `list` to get a list of available devices.")

# Specify zero or mode modules.
parser.add_argument("-m", action="append", dest="mod_names", default=[],
                    help="Specify zero or more modules that need to be loaded in the target process.")

# Parse command line arguments.
args = parser.parse_args()

# Show available devices.
if args.device == "list":
    print "Available devices:"
    print "  %-10s %s" % ("ID", "Name")
    for device in frida.enumerate_devices():
        print "  %-10s %s" % (device.id, device.name)

    sys.exit()

# Lookup the desired device.
if args.device:
    devs = [dev.id for dev in frida.enumerate_devices()]
    if args.device not in devs:
        print "Invalid device id `%s`." % args.device
        sys.exit(-1)

    # Get the device.
    device = frida.get_device(args.device)

    print "Using device %r." % device

# Show processes.
if args.show_processes:
    # Enumerate process and sort them by pid in ascending order.
    processes = sorted(device.enumerate_processes(), reverse=True)

    # Show a tabel with the devices processes.
    print "Local processes list:"
    print "  %-6s %s" % ("PID", "Name")
    for process in processes:
        print "  %-6d %s" % (process.pid, process.name)

    sys.exit()

# Select the correct process to attach.
if args.proc_pid:
    print "Attaching to process pid `%d`." % args.proc_pid
    target_process = args.proc_pid

elif args.proc_name:
    # Get the list of local processes.
    processes = sorted(device.enumerate_processes(), reverse=True)

    # Filter processes that match our name.
    processes = [proc for proc in processes if fnmatch.fnmatch(
        proc.name, args.proc_name)]

    # Process name does not match any running processes.
    if len(processes) == 0:
        print "Invalid process name `%s`." % args.proc_name
        sys.exit(-1)

    # More than one process is available.
    if len(processes) > 1:
        print "Multiple processes (%d) available." % len(processes)

    # Found a single module to attach to.
    found = False

    # Find which module
    for proc in processes:
        if not args.mod_names:
            break

        # Temporarily attach to the process to get a module list.
        session = frida.attach(proc.pid)

        # Search if one of the specified modules is loaded in the target.
        modules = [str(module.name) for module in session.enumerate_modules()]
        if any(mod_name in modules for mod_name in args.mod_names):
            print "Process `%s:%d` matches module list." % (proc.name, proc.pid)
            target_process = proc.pid
            found = True
            break

        session.detach()

    if not found:
        proc = processes[0]
        print "Defaulting to first process `%s:%d`." % (proc.name, proc.pid)
        target_process = proc.pid

else:
    print "I need either a PID or a process name."
    parser.print_usage()
    sys.exit(-1)


def string_to_int(value):
    try:
        ret = int(value)

    except ValueError:
        ret = int(value, 16)

    return ret


def string_to_hex(value):
    # Convert to hex form.
    value = binascii.hexlify(value)
    return " ".join(value[i:i + 2] for i in range(0, len(value), 2))


def format_size(format, size=-1):
    if format == "u8":
        return 1
    elif format == "u16":
        return 2
    elif format == "u32":
        return 4
    elif format == "u64":
        return 8
    elif format in ["hex", "bytes"]:
        return size

    return struct.calcsize(format)


def format_value(format, value):
    if format == "u8":
        return struct.pack("B", value)
    elif format == "u16":
        return struct.pack("H", value)
    elif format == "u32":
        return struct.pack("I", value)
    elif format == "u64":
        return struct.pack("Q", value)
    elif format == "hex":
        return binascii.unhexlify(value.replace(" ", ""))

    return value


def format_string(data, format):
    if format == "hex":
        return hexdump.hexdump(data, result="return")

    elif format == "u8":
        format = "B"

    elif format == "u16":
        format = "H"

    elif format == "u32":
        format = "I"

    elif format == "u64":
        format = "Q"

    out = []
    unpacked_data = struct.unpack(format, data)
    for d, f in zip(unpacked_data, format):
        size = struct.calcsize(f)
        if isinstance(d, int) or isinstance(d, long):
            if size == 1:
                out.append("0x%.2x" % d)
            elif size == 2:
                out.append("0x%.4x" % d)
            elif size == 4:
                out.append("0x%.8x" % d)
            elif size == 8:
                out.append("0x%.16x" % d)

        else:
            out.append(str(d))

    return " ".join(out)


script_code = """
'use strict';

function searchMemory(pattern) {
    var results = [];
    var ranges = Process.enumerateRangesSync({ protection: 'rw-', coalesce: true });
    for (var i = 0; i < ranges.length; i++) {
        var range = ranges[i];
        var matches = Memory.scanSync(range.base, range.size, pattern);
        for (var r = 0; r < matches.length; r++) {
            results.push(matches[r].address);
        }
    }

    return results;
}

function readMemory(address, size) {
    return Memory.readByteArray(ptr(address), size);
}

function writeMemory(address, value) {
    Memory.writeByteArray(ptr(address), value)
}

function listMemory(protection) {
    return Process.enumerateRangesSync({
        protection: protection,
        coalesce: true
    });
}

rpc.exports = {
    searchMemory: searchMemory,
    readMemory: readMemory,
    writeMemory: writeMemory,
    listMemory: listMemory
};
"""

__banner__ = """
 ____________________
< Welcome to MemREPL >
 --------------------
        \\   ^__^
         \\  (oo)\\_______
            (__)\\       )\\/\\
                ||----w |
                ||     ||
"""

__header__ = "Avaliable commands:\n\n"
__header__ += "\n".join([
    "memory_list: list memory regions in the attached program",
    "memory_search: search for a given value",
    "memory_read: read from a given address",
    "memory_write: write to a given address"
])

__header__ += "\n\nUse help(command_name) to see how to use the command.\n"


class MemoryGrip:
    def __init__(self, target_process):
        # Attach to the target process.
        self.session = frida.attach(target_process)

        # Load the script in the target process.
        self.script = self.session.create_script(script_code)
        self.script.load()

    def memory_list(self, protection):
        def convert(segment):
            out = {}
            out["start"] = string_to_int(segment["base"])
            out["size"] = segment["size"]
            out["end"] = out["start"] + out["size"]
            out["protection"] = segment["protection"]

            try:
                out["filename"] = segment["file"]["path"]

            except KeyError:
                out["filename"] = "-"

            return out

        return map(convert, self.script.exports.list_memory(protection))

    def memory_search(self, value):
        # Frida expects the values to be in "hex" format.
        value = string_to_hex(value)
        return map(string_to_int, self.script.exports.search_memory(value))

    def memory_read(self, address, size):
        return self.script.exports.read_memory(address, size)

    def memory_write(self, address, value):
        value = map(ord, list(value))
        return self.script.exports.write_memory(address, value)

    def run(self):
        IPython.embed(header=__header__, banner1=__banner__)

        # Detach from the process.
        print "Detaching from the target process."
        self.session.detach()
        return


# Global instance of our class.
memory_grip = None


def memory_list(protection="---"):
    """

    """
    global memory_grip

    results = memory_grip.memory_list(protection)
    n = len(str(len(results)))
    for i, result in enumerate(results):
        start = result["start"]
        size = result["size"]
        end = result["end"]
        prot = result["protection"]
        filename = result["filename"]

        try:
            next_result = results[i + 1]
            next_start = next_result["start"]

        except IndexError:
            next_start = end

        # Calculate the gap
        gap = next_start - end

        prefix = "{i:{width}d}:".format(width=n, i=i)

        print "%s 0x%.16x - 0x%.16x (%10u / 0x%.8x) next=0x%.16x %3s %s " % (
            prefix, start, end, size, size, gap, prot, filename
        )

    print "Got %u results." % len(results)


def memory_search(value_format, value, out_format="hex", out_size=32):
    """
    Examples:
    memory_search("u8", 0xca)
    memory_search("u16", 0xcafe)
    memory_search("u32", 0xcafedead)
    memory_search("u64", 0xcafecafecafecafe)
    memory_search("hex", "ca fe ca fe")
    memory_search("bytes", "\xca\xfe\xca\xfe")
    """
    global memory_grip

    # Convert the value to the right representation.
    value = format_value(value_format, value)
    results = memory_grip.memory_search(value)

    # Calculate the number of bytes we need to represent the output.
    size = format_size(out_format, out_size)

    # Collect results offsets.
    results_offsets = []

    # For each `result`, dump with the given format.
    for i, result in enumerate(results):
        try:
            next_result_offset = results[i + 1] - result
            results_offsets.append(next_result_offset)

        except IndexError:
            next_result_offset = 0

        # Read `size` bytes from `result` address.
        data = memory_grip.memory_read(result, size)
        print "Address=0x%.16x next_result_offset=0x%.8x" % (result, next_result_offset)
        print format_string(data, out_format)
        print

    print "Got %u results." % len(results)

    print "More common results deltas:"
    for offset, count in collections.Counter(results_offsets).most_common(8):
        if count <= 1:
            break

        print "  offset=0x%.8x count=%u" % (offset, count)


def memory_read(value_format, address, size=32, count=1):
    """
    Examples:
    memory_read("u8", 0xcafecafe)
    memory_read("u16", 0xcafecafe)
    memory_read("u32", 0xcafecafe)
    memory_read("u64", 0xcafecafe)
    memory_read("hex", 0xcafecafe, 4)
    memory_read("bytes", 0xcafecafe, 4)
    memory_read("BBII", 0xcafecafe)
    """
    global memory_grip

    # Calculate the size of the read based on the format string.
    size = format_size(value_format, size)
    for i in xrange(0, count):
        caddr = address + (i * size)
        data = memory_grip.memory_read(caddr, size)
        print "Read @ 0x%.16x:\n%s" % (caddr, format_string(data, value_format))


def memory_write(value_format, address, value, count=1):
    """
    Examples:
    memory_write("u8", 0xdeadbeef, 0xca)
    memory_write("u16", 0xdeadbeef, 0xcafe)
    memory_write("u32", 0xdeadbeef, 0xcafecafe)
    memory_write("u64", 0xdeadbeef, 0xcafecafecafecafe)
    memory_write("hex", 0xdeadbeef, "ca fe ca fe")
    memory_write("bytes", 0xdeadbeef, "\xca\xfe\xca\xfe")
    """
    global memory_grip

    value = format_value(value_format, value)
    size = len(value)
    for i in xrange(0, count):
        caddr = address + (i * size)
        memory_grip.memory_write(caddr, value)


def memory_search_pointer(start_address, protection):
    """
    Start a search from `start_address` looking for pointers to segments with
    `permission`. The search will stop at the end of the segment.

    Searching for function pointers:

        memory_search_pointer(valid_address, "x")
    """
    def compare_protection(p1, p2):
        """
        Check that `p1` contains `p2`.
        """
        p1 = p1.replace("-", "")
        p2 = p2.replace("-", "")
        return set(p2) <= set(p1)

    def get_segment(segments, address):
        """
        Get the segment that contains `address`.
        """
        for segment in segments:
            if address >= segment["start"] and address < segment["end"]:
                return segment

        return None

    # Get all the segments.
    segments = memory_grip.memory_list("")

    # Find the segment that contains `start_address`.
    selected_segment = get_segment(segments, start_address)
    if not selected_segment:
        print "No valid segment was found."
        return

    print "Working on segment %r" % selected_segment

    # Filter target segments.
    segments = [segment for segment in segments if compare_protection(
        segment["protection"], protection)]

    # Read segments data and break it into aligned pointers.
    data = memory_grip.memory_read(
        selected_segment["start"], selected_segment["size"])
    pointer_size = struct.calcsize("P")
    fmt = "P" * (len(data) / pointer_size)
    pointers = struct.unpack(fmt, data)

    # For each pointer, get its segment.
    ret = []
    for i, pointer in enumerate(pointers):
        segment = get_segment(segments, pointer)
        if segment:
            address = selected_segment["start"] + (i * pointer_size)
            ret.append((address, pointer, segment))

    for address, pointer, segment in ret:
        if address < start_address:
            continue

        print "Found pointer @ 0x%.16x = 0x%.16x to segment 0x%.16x - 0x%.16x %3s %s" % (
            address, pointer, segment["start"], segment["end"], segment["protection"], segment["filename"]
        )


def main():
    global memory_grip

    # Attach to the target process and enter the REPL.
    print "Attaching to process `%d`." % target_process
    memory_grip = MemoryGrip(target_process)
    memory_grip.run()
