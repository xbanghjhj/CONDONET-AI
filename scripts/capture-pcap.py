import select
import sys
import time
from ctypes import CDLL, POINTER, Structure, byref, c_char_p, c_int, c_uint, c_void_p
from ctypes import cast, create_string_buffer


class BpfProgram(Structure):
    _fields_ = [("length", c_uint), ("instructions", c_void_p)]


pcap = CDLL("libpcap.so.0.8")
signatures = (
    ("pcap_open_live", c_void_p, (c_char_p, c_int, c_int, c_int, c_char_p)),
    ("pcap_compile", c_int, (c_void_p, POINTER(BpfProgram), c_char_p, c_int, c_uint)),
    ("pcap_setfilter", c_int, (c_void_p, POINTER(BpfProgram))),
    ("pcap_setnonblock", c_int, (c_void_p, c_int, c_char_p)),
    ("pcap_freecode", None, (POINTER(BpfProgram),)),
    ("pcap_get_selectable_fd", c_int, (c_void_p,)),
    ("pcap_geterr", c_char_p, (c_void_p,)),
    ("pcap_dispatch", c_int, (c_void_p, c_int, c_void_p, c_void_p)),
    ("pcap_dump_open", c_void_p, (c_void_p, c_char_p)),
    ("pcap_dump_flush", c_int, (c_void_p,)),
    ("pcap_dump_close", None, (c_void_p,)),
    ("pcap_close", None, (c_void_p,)),
)
for name, result, arguments in signatures:
    function = getattr(pcap, name)
    function.restype = result
    function.argtypes = arguments


def require(condition, error):
    if not condition:
        raise RuntimeError(error().decode(errors="replace"))


def capture(interface, packet_filter, duration):
    error_buffer = create_string_buffer(256)
    handle = pcap.pcap_open_live(interface.encode(), 65535, 0, 100, error_buffer)
    require(handle, lambda: error_buffer.value)
    try:
        def capture_error():
            return pcap.pcap_geterr(handle)

        program = BpfProgram()
        require(pcap.pcap_compile(handle, byref(program), packet_filter.encode(), 1, 0xFFFFFFFF) == 0,
                capture_error)
        try:
            require(pcap.pcap_setfilter(handle, byref(program)) == 0, capture_error)
        finally:
            pcap.pcap_freecode(byref(program))

        require(pcap.pcap_setnonblock(handle, 1, error_buffer) == 0, lambda: error_buffer.value)
        fd = pcap.pcap_get_selectable_fd(handle)
        require(fd >= 0, lambda: b"No selectable capture descriptor")
        output = pcap.pcap_dump_open(handle, b"-")
        require(output, capture_error)
        try:
            require(pcap.pcap_dump_flush(output) == 0, lambda: b"Could not flush PCAP output")
            print(f"listening on {interface}", file=sys.stderr, flush=True)
            dump_packet = cast(pcap.pcap_dump, c_void_p)
            deadline = time.monotonic() + duration
            while (remaining := deadline - time.monotonic()) > 0:
                if select.select([fd], [], [], remaining)[0]:
                    require(pcap.pcap_dispatch(handle, 32, dump_packet, output) >= 0, capture_error)
            require(pcap.pcap_dump_flush(output) == 0, lambda: b"Could not flush PCAP output")
        finally:
            pcap.pcap_dump_close(output)
    finally:
        pcap.pcap_close(handle)


if __name__ == "__main__":
    capture(sys.argv[1], sys.argv[2], float(sys.argv[3]))
