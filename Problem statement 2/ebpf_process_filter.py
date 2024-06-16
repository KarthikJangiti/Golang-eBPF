from bcc import BPF
import os
import subprocess

bpf_code = """
<Insert the eBPF program code here>
"""

# Load eBPF program
b = BPF(text=bpf_code)
function = b.load_func("xdp_filter", BPF.XDP)

# Attach eBPF program to network interface (e.g., eth0)
b.attach_xdp(dev="eth0", fn=function, flags=0)

# Find the PID of the target process (replace "myprocess" with actual process name)
process_name = "myprocess"
pid = int(subprocess.check_output(["pgrep", "-f", process_name]).decode().strip())

# Update the eBPF map with the target PID
b["allowed_pid_map"].clear()
b["allowed_pid_map"][pid] = pid

print(f"eBPF program loaded and filtering traffic for process '{process_name}' on port {ALLOWED_PORT}.")
