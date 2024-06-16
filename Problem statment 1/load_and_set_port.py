from bcc import BPF
import ctypes
import sys

# Define the default port number
DEFAULT_PORT = 4040

# Load the eBPF program
b = BPF(src_file="drop_tcp_packets.c", cflags=["-I/usr/include", "-I/usr/include/x86_64-linux-gnu"])

# Attach the eBPF program to XDP hook of the network interface (replace eth0 with your interface)
fn = b.load_func("drop_tcp_port", BPF.XDP)
ifname = "eth0"  # Replace with your network interface
b.attach_xdp(ifname, fn, 0)

# Access the BPF map
port_map = b.get_table("port_map")

# Set the default port number in the BPF map
key = ctypes.c_int(0)
port = ctypes.c_int(DEFAULT_PORT)
port_map[key] = port

print(f"Dropping TCP packets on port: {DEFAULT_PORT}")

try:
    while True:
        input_port =
