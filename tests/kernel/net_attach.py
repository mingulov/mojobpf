# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Attach a pinned socket-filter program and report per-frame arrival.

Guest-side helper for the kernel-net suite's socket verdict legs
(staged beside the suite, executed inside the disposable guest only).
Opens the bpffs program pin as a file descriptor with the
``BPF_OBJ_GET`` syscall (a plain ``open()`` on a bpffs pin fails
with EIO), attaches it to an AF_PACKET receiver on one end of a
veth pair, transmits each frame file from the peer end, and prints
one ``arrival=`` line per frame on stdout, in frame order
(diagnostics go to stderr). Standard library only (``ctypes``
for the syscall): the guest has no libbpf binding.

Usage: net_attach.py <pinned-prog> <rx-if> <tx-if> <frame> [<frame>...]

Prints ``arrival=yes bytes=N`` when the transmitted frame bytes
arrive verbatim within the timeout (the filter passed it) and
``arrival=no`` on timeout (the filter dropped it). Bringing the
veth pair up emits kernel multicast chatter (MLD reports) that
shares the receiver queue, so received packets are matched by
content: anything that is not the transmitted frame is ignored
as a stray. Each iteration also drains stale queue contents
before sending. Any setup failure raises; tracebacks fail the
leg visibly rather than reporting false drops.
"""

import ctypes
import os
import platform
import socket
import struct
import sys
import time

SO_ATTACH_BPF = 50
ETH_P_ALL = 0x0003
RECV_TIMEOUT = 2.0
BPF_OBJ_GET = 7
_NR_BPF = {"x86_64": 321, "aarch64": 386}


class _ObjGetAttr(ctypes.Structure):
    _fields_ = [("pathname", ctypes.c_uint64),
                ("bpf_fd", ctypes.c_uint32),
                ("file_flags", ctypes.c_uint32)]


def bpf_obj_get(pin):
    """Open a bpffs program pin, returning its file descriptor."""
    machine = platform.machine()
    if machine not in _NR_BPF:
        raise OSError("unsupported guest arch for bpf(): %s" % machine)
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    buf = ctypes.create_string_buffer(pin.encode("utf-8"))
    attr = _ObjGetAttr(pathname=ctypes.addressof(buf),
                       bpf_fd=0, file_flags=0)
    fd = libc.syscall(_NR_BPF[machine], BPF_OBJ_GET,
                      ctypes.byref(attr), ctypes.sizeof(attr))
    if fd < 0:
        err = ctypes.get_errno()
        raise OSError(err, "BPF_OBJ_GET %s failed" % pin)
    return fd


def main(argv):
    if len(argv) < 5:
        raise SystemExit(
            "usage: net_attach.py <pinned-prog> <rx-if> <tx-if> "
            "<frame> [<frame>...]"
        )
    _pin, rx_if, tx_if, frames = argv[1], argv[2], argv[3], argv[4:]
    prog_fd = bpf_obj_get(argv[1])
    rx = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                       socket.htons(ETH_P_ALL))
    rx.bind((rx_if, 0))
    rx.setsockopt(socket.SOL_SOCKET, SO_ATTACH_BPF,
                   struct.pack("i", prog_fd))
    rx.settimeout(RECV_TIMEOUT)
    tx = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    tx.bind((tx_if, 0))
    try:
        for idx, frame_path in enumerate(frames):
            with open(frame_path, "rb") as handle:
                data = handle.read()
            rx.settimeout(0.2)
            try:
                while True:
                    rx.recv(65535)
            except socket.timeout:
                pass
            rx.settimeout(RECV_TIMEOUT)
            sent = tx.send(data)
            if sent != len(data):
                raise AssertionError(
                    "short send on %s: %d of %d"
                    % (frame_path, sent, len(data))
                )
            deadline = time.monotonic() + RECV_TIMEOUT
            arrived = None
            strays = 0
            while arrived is None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    arrived = False
                    break
                rx.settimeout(remaining)
                try:
                    got = rx.recv(65535)
                except socket.timeout:
                    arrived = False
                    break
                if got == data:
                    arrived = True
                else:
                    strays += 1
            if arrived:
                print("arrival=yes bytes=%d" % len(data), flush=True)
            else:
                print("arrival=no", flush=True)
            print("frame %d: sent %d bytes, arrived=%s, strays=%d"
                  % (idx, len(data), arrived, strays),
                  file=sys.stderr)
    finally:
        tx.close()
        rx.close()
        os.close(prog_fd)


if __name__ == "__main__":
    main(sys.argv)
