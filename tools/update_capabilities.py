#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Upstream capability inventory: ``inventory(source_pins) -> CapabilityRegistry``.

This tool generates, validates and diffs the frozen capability registry in
``capabilities/registry.json`` from pinned upstream sources described by
``capabilities/upstream.lock.json``. It uses only the standard library.

Upstream atoms (UAPI enumerators, helper IDs, flags, limits, library symbols,
ELF section conventions and toolchain facts) are each classified exactly once.
Any atom the curated tables do not cover aborts generation with the unknown
list: unknown upstream records fail completeness until they are assigned an
owner and tests. Nothing is silently dropped.

Subcommands::

    refresh  verify staged sources against the lock, then regenerate the registry
    validate check a registry against the schema and the completeness rules
    diff     deterministic difference between two registry documents
    export   write a digest-pinned distribution bundle (registry + schema)

Staging layout for ``refresh --sources DIR`` (paths relative to DIR)::

    uapi/<version>/bpf.h            pinned kernel UAPI, one directory per version
    uapi/<version>/btf.h
    uapi/<version>/bpf_common.h
    uapi/<version>/bpf_perf_event.h
    libbpf-<version>/src/libbpf.h   pinned libbpf source tree
    libbpf-<version>/src/libbpf.map
    libbpf-<version>/src/libbpf.c
    libbpf-<version>/src/bpf.h
    libbpf-<version>/src/btf.h
    libbpf-<version>/src/libbpf_legacy.h
    llvm/facts.json                observed toolchain facts (see the lock file)
    selftests/<tag>/prog_tests.paths
    selftests/<tag>/progs.paths
    selftests/<tag>/verifier.paths

Every staged file is hash-checked against the lock before parsing. ``refresh``
exits 2 on integrity mismatch and 3 on unknown/unclassifiable atoms, printing
the exact offenders. ``--rebase-lock`` accepts staged content as the new pin
and reports the delta instead of aborting; without it, any drift aborts.
"""

import argparse
import hashlib
import json
import os
import re
import sys

TOOL_NAME = "tools/update_capabilities.py"
REGISTRY_VERSION = "capability-registry-v1"
SCHEMA_VERSION = 1
REVISION = 1

EXIT_OK = 0
EXIT_INTEGRITY = 2
EXIT_UNKNOWN = 3
EXIT_INVALID = 4

# ---------------------------------------------------------------------------
# Owning work packages: (id, phase, title). This is the closed owner set;
# every record owner_task must be one of these 65 IDs.
# ---------------------------------------------------------------------------

PACKAGES = [
    ("P0-AUDIT", "P0", "Reconcile repositories and existing stage evidence"),
    ("P0-INVENTORY", "P0", "Pin upstream sources and enumerate the complete capability surface"),
    ("P0-HARNESS", "P0", "Freeze target, fixture, result and evidence contracts"),
    ("P0-COST", "P0", "Define cost metrics and representative paired workloads"),
    ("P0-TARGETS", "P0", "Prepare kernel cohorts and physical/virtual target resources"),
    ("F-ISA", "P1", "Complete ISA lowering and source diagnostics"),
    ("F-CALLS", "P1", "Calls, stack, loops and object composition"),
    ("F-BTF", "P1", "Complete BTF and standard object metadata"),
    ("F-CORE", "P1", "Full CO-RE and target-BTF compatibility"),
    ("F-ENDIAN", "P1", "bpfel and bpfeb artifact generation"),
    ("U-ABI", "P1", "Raw libbpf API and FFI compatibility"),
    ("U-OBJECT", "P1", "Object, program, BTF and owned-resource API"),
    ("U-MAPS", "P1", "Typed/raw map management and operation adapters"),
    ("U-EVENTS", "P1", "Ring/perf/user-ring consumers and callback lifetime"),
    ("U-ATTACH", "P1", "Attachment, link and option adapter foundation"),
    ("U-CONTROL", "P2", "Introspection, delegated control, tokens and build tooling"),
    ("A-X86", "P1", "Physical x86 and isolated hardware-VM lanes"),
    ("A-ARM-PHYSICAL", "P1", "Mandatory physical/native AArch64 lane"),
    ("A-ARM-VM", "P1", "ARM hardware-VM and TCG correctness lanes"),
    ("A-BE", "P1", "Real-kernel big-endian execution lane"),
    ("A-OTHER", "P1", "Remaining upstream JIT/interpreter architectures"),
    ("A-KERNELS", "P1", "LTS, stable, distro, boundary and canary cohorts"),
    ("C-BASELINE", "P1", "Run paired size and practicality baselines"),
    ("C-OPTIMIZE", "P3", "Locate and fix measured expansion"),
    ("T-UP-SINGLE", "P2", "Single userspace probes and ABI/lifecycle behavior"),
    ("T-UP-MULTI", "P2", "Native multi userspace probes"),
    ("T-UP-VARIANTS", "P2", "Sleepable/session userspace probe variants"),
    ("T-USDT", "P2", "USDT arguments and semaphore lifecycle"),
    ("T-KPROBES", "P2", "Kernel probes, syscall wrappers, multi and sessions"),
    ("T-TRACEPOINTS", "P2", "Tracepoint/raw/BTF/writable and perf families"),
    ("T-TRAMPOLINES", "P2", "Typed tracing, return modification and multi/session variants"),
    ("T-FREPLACE", "P2", "Extension and freplace composition"),
    ("S-LSM", "P2", "Global BPF LSM hook support"),
    ("S-LSM-VARIANTS", "P2", "Sleepable and cgroup LSM"),
    ("O-STRUCT", "P2", "struct_ops registration and callback foundation"),
    ("O-CONSUMERS", "P2", "Real struct_ops consumers and updates"),
    ("O-SCX", "P2", "Functional sched_ext support and recovery"),
    ("N-XDP", "P2", "XDP packet/device feature coverage"),
    ("N-TCX", "P2", "TC compatibility, TCX and netkit"),
    ("N-SOCKETS", "P2", "All socket program families"),
    ("N-CGROUPS", "P2", "Every cgroup program and attach variant"),
    ("N-ROUTING", "P2", "Flow dissector, LWT and netfilter"),
    ("N-AFXDP", "P2", "AF_XDP and explicit libxdp integration"),
    ("N-HARDWARE", "P3", "Driver-native, zero-copy and offload qualification"),
    ("N-REMAINDER", "P2", "LIRC, syscall-program and unassigned program-family closure"),
    ("M-KEYED", "P2", "Basic, per-CPU, LRU, trie and bloom maps"),
    ("M-DISPATCH", "P2", "Map composition, dispatch and tail-call maps"),
    ("M-STORAGE", "P2", "Kernel-object local storage"),
    ("M-CHANNELS", "P2", "Buffers, queues, stacks and stream map families"),
    ("M-SPECIAL", "P2", "Arena and every additional special map"),
    ("X-HELPERS", "P2", "Complete typed helper coverage"),
    ("X-KFUNCS", "P2", "Typed kernel/module functions and reference contracts"),
    ("X-ITERATORS", "P2", "Attached, open-coded and helper-driven iterators"),
    ("X-MEMORY", "P2", "Dynptr, kptr, allocator and asynchronous lifetime coverage"),
    ("Q-NATIVE", "P3", "Per-family native x86/AArch64 qualification"),
    ("Q-ENDIAN", "P3", "Per-family big-endian runtime qualification"),
    ("Q-KERNELS", "P3", "Per-family kernel/configuration compatibility closure"),
    ("Q-INTERACTIONS", "P3", "Cross-feature regression and concurrency closure"),
    ("Q-FUZZ", "P3", "Malformed artifacts, fuzzing and controlled stress"),
    ("Q-HARNESS", "P1", "Adversarial validation of the test system"),
    ("D-DEMO", "P4", "Independent installed-package all-Mojo application"),
    ("D-PACKAGE", "P4", "Independent packaging, compatibility and provenance"),
    ("D-SUPPORT", "P4", "Generate public coverage and upstream-delta workflow"),
    ("R-EXISTING-GATE", "P1", "Close the original G5 and initial public gate without widening it"),
    ("R-FULL", "P4", "Close full support for a pinned registry and declared matrix"),
]

PACKAGE_IDS = frozenset(pid for pid, _, _ in PACKAGES)

# ---------------------------------------------------------------------------
# Named upstream families: id -> (title, description, owner, harness cases).
# The first harness case is the default positive/negative test for the
# family's records; further cases are interaction tests.
# ---------------------------------------------------------------------------

FAMILIES = {
    "isa": ("BPF ISA and source expressiveness",
            "Instruction encodings, ISA levels, registers, atomics and "
            "architecture-sensitive codegen constraints.",
            "F-ISA", ["ISA-01"]),
    "calls": ("Calls, stack and object composition",
              "BPF-to-BPF calls, tail calls, bounded loops, linking and "
            "call-depth/stack accounting.",
              "F-CALLS", ["CALL-01", "CALL-02"]),
    "btf": ("BTF and standard object metadata",
            "BTF kinds, function/line records, type layouts and loader-visible "
            "object metadata.",
            "F-BTF", ["OBJ-01"]),
    "core-relocations": ("CO-RE relocations and target compatibility",
                         "CO-RE relocation kinds, field/type existence and size "
                         "queries across target layouts.",
                         "F-CORE", ["CORE-02", "CORE-01"]),
    "object-elf": ("ELF section and loader conventions",
                   "Standard ELF section names, data sections, license "
                   "declarations and loader collection rules.",
                   "F-BTF", ["OBJ-01"]),
    "endian": ("Target endianness",
               "Little- and big-endian BPF targets, encoding and runtime "
               "byte-order behavior.",
               "F-ENDIAN", ["BE-01"]),
    "tracing-uprobe-single": ("Single userspace probes",
                              "uprobe and uretprobe attachment, symbols, "
                              "offsets, cookies and PID scoping.",
                              "T-UP-SINGLE", ["TR-UP-01", "TR-UP-02", "TR-UP-03", "TR-UP-04"]),
    "tracing-uprobe-multi": ("Native multi userspace probes",
                             "Native uprobe_multi and uretprobe_multi "
                             "attachment with symbol arrays and cookies.",
                             "T-UP-MULTI", ["TR-UM-01", "TR-UM-02", "TR-UM-03"]),
    "tracing-uprobe-variants": ("Sleepable and session probe variants",
                                "Sleepable and session userspace probe "
                                "variants and their lifetime rules.",
                                "T-UP-VARIANTS", ["TR-US-01"]),
    "tracing-usdt": ("USDT probes",
                     "USDT argument decoding, semaphores and process "
                     "lifecycle.",
                     "T-USDT", ["TR-UD-01"]),
    "tracing-kprobes": ("Kernel probes and syscall wrappers",
                        "kprobe, kretprobe, multi and session variants and "
                        "kernel syscall wrappers.",
                        "T-KPROBES", ["TR-KP-01"]),
    "tracing-tracepoints": ("Tracepoints and BTF tracepoints",
                            "Tracepoint, raw tracepoint, writable and BTF "
                            "tracepoint programs.",
                            "T-TRACEPOINTS", ["TR-TP-01"]),
    "tracing-trampolines": ("Typed tracing trampolines",
                            "fentry, fexit, fmod_ret, fsession and their "
                            "multi variants.",
                            "T-TRAMPOLINES", ["TR-BTF-01"]),
    "tracing-freplace": ("Extension and freplace composition",
                         "freplace extension programs and target replacement "
                         "semantics.",
                         "T-FREPLACE", ["TR-EXT-01"]),
    "tracing-perf": ("Perf-event programs",
                     "Perf-event sampling programs and lost-event "
                     "accounting.",
                     "T-TRACEPOINTS", ["TR-PERF-01"]),
    "security-lsm": ("LSM programs",
                     "Linux Security Module hook programs, typed parameters "
                     "and allow/deny policy.",
                     "S-LSM", ["SEC-LSM-01"]),
    "security-lsm-variants": ("Sleepable and cgroup LSM",
                              "Sleepable LSM contexts and cgroup-scoped LSM "
                              "attachment.",
                              "S-LSM-VARIANTS", ["SEC-LSM-02"]),
    "structops-core": ("struct_ops registration foundation",
                       "struct_ops maps, typed callbacks, registration and "
                       "teardown.",
                       "O-STRUCT", ["OPS-01"]),
    "structops-consumers": ("Real struct_ops consumers",
                            "Kernel subsystems consuming struct_ops maps, "
                            "updates and module lifetime.",
                            "O-CONSUMERS", ["OPS-02"]),
    "sched-ext": ("sched_ext scheduler support",
                  "Minimal functional scheduler through the kernel "
                  "sched_ext interface with recovery.",
                  "O-SCX", ["SCX-01"]),
    "net-xdp": ("XDP and device paths",
                "XDP programs, actions, fragments, redirect and "
                "device/cpumap dispatch.",
                "N-XDP", ["NET-XDP-01", "NET-XDP-02"]),
    "net-tcx": ("TC compatibility, TCX and netkit",
                "TC classifier/action programs, TCX ingress/egress and "
                "netkit endpoints.",
                "N-TCX", ["NET-TCX-01"]),
    "net-sockets": ("Socket programs",
                    "Socket filter, sockops, sk_msg, sk_skb, sockmap links, "
                    "sk_lookup and reuseport selection.",
                    "N-SOCKETS", ["NET-SOCK-01"]),
    "net-cgroups": ("Cgroup programs",
                    "Cgroup skb, socket lifecycle, address hooks, sockopt, "
                    "sysctl and device policy.",
                    "N-CGROUPS", ["NET-CGRP-01"]),
    "net-routing": ("Routing and netfilter",
                    "Flow dissector, LWT encapsulation and netfilter "
                    "programs.",
                    "N-ROUTING", ["NET-ROUTE-01"]),
    "net-afxdp": ("AF_XDP integration",
                  "XSKMAP, socket/UMEM lifecycle, rings and zero-copy "
                  "paths.",
                  "N-AFXDP", ["NET-XSK-01"]),
    "net-hardware": ("Driver and device qualification",
                     "Device-bound programs, driver-native paths, zero-copy "
                     "and offload behavior.",
                     "N-HARDWARE", ["NET-XDP-02"]),
    "net-remainder": ("Remaining program families",
                      "LIRC, syscall programs and any other registry program "
                      "family with a real kernel consumer.",
                      "N-REMAINDER", ["MISC-01"]),
    "maps-keyed": ("Keyed maps",
                   "Arrays, hashes, per-CPU variants, LRU, LPM tries and "
                   "bloom filters.",
                   "M-KEYED", ["MAP-01"]),
    "maps-dispatch": ("Dispatch and composition maps",
                      "Program arrays, map-in-map, cgroup arrays, devmap, "
                      "cpumap, XSKMAP, sockmap and reuseport arrays.",
                      "M-DISPATCH", ["MAP-02"]),
    "maps-storage": ("Kernel-object local storage",
                     "Socket, task, inode and cgroup storage maps and their "
                     "automatic lifetimes.",
                     "M-STORAGE", ["MAP-02"]),
    "maps-channels": ("Buffers, queues and stream maps",
                      "Ringbuf, user ringbuf, perf-event arrays, stack-trace "
                      "maps, queues and stacks.",
                      "M-CHANNELS", ["MAP-01", "BUF-01"]),
    "maps-special": ("Special allocation maps",
                     "Arena maps and every additional special map present in "
                     "the pinned upstream source.",
                     "M-SPECIAL", ["MAP-02"]),
    "helpers": ("BPF helper functions",
                "Typed helper prototypes and their valid program, attach "
                "and context combinations.",
                "X-HELPERS", ["ISA-01"]),
    "kfuncs": ("Typed kernel functions",
               "Kernel and module kfunc resolution, references, lifetimes "
               "and sleepability.",
               "X-KFUNCS", ["KFUNC-01"]),
    "iterators": ("Iterators",
                  "Attached BPF iterators, open-coded iterators, numeric "
                  "iteration and helper loop callbacks.",
                  "X-ITERATORS", ["ITER-01"]),
    "memory": ("Managed memory and concurrency",
               "Dynptr, kptr, allocation, arenas, lists, timers, "
               "workqueues, locks and atomics.",
               "X-MEMORY", ["MEM-01"]),
    "userspace-abi": ("Raw userspace ABI surface",
                      "Raw bpf() syscall commands, feature probing, CO-RE "
                      "field access and library utilities.",
                      "U-ABI", ["ABI-01"]),
    "userspace-object": ("Object and program management",
                         "Object open/load, program and BTF handling, "
                         "pinning and owned resources.",
                         "U-OBJECT", ["LIFE-01"]),
    "userspace-maps": ("Map management",
                       "Map lookup/update/delete, batches, mmap, freezing "
                       "and per-CPU access.",
                       "U-MAPS", ["MAP-03"]),
    "userspace-events": ("Event consumption",
                         "Ring-buffer, perf-buffer and user-ring consumers "
                         "and callback lifetimes.",
                         "U-EVENTS", ["BUF-01"]),
    "userspace-attach": ("Attachment and links",
                         "Program attachment, links, attach options and "
                         "link lifecycle.",
                         "U-ATTACH", ["LIFE-01"]),
    "userspace-control": ("Introspection and control",
                          "Program test-run, object introspection, tokens "
                          "and delegated control.",
                          "U-CONTROL", ["LIFE-01"]),
}

# Required target cells per family. Tokens name execution classes, not
# specific machines; the target manifest binds them to real lanes later.
FAMILY_TARGETS = {
    "endian": ["linux-aarch64-physical", "linux-bpfeb", "linux-x86-64"],
    "net-hardware": ["linux-aarch64-physical", "linux-x86-64-device"],
}
DEFAULT_TARGETS = ["linux-aarch64-physical", "linux-x86-64"]

# ---------------------------------------------------------------------------
# Curated family assignments. Keys are upstream enumerator short names
# (bpf_prog_type members without the BPF_PROG_TYPE_ prefix, and so on).
# Any upstream member missing here aborts generation: that is the
# completeness gate, not a gap to paper over with a default family.
# ---------------------------------------------------------------------------

PROG_FAMILY = {
    "SOCKET_FILTER": "net-sockets",
    "KPROBE": "tracing-kprobes",
    "SCHED_CLS": "net-tcx",
    "SCHED_ACT": "net-tcx",
    "TRACEPOINT": "tracing-tracepoints",
    "XDP": "net-xdp",
    "PERF_EVENT": "tracing-perf",
    "CGROUP_SKB": "net-cgroups",
    "CGROUP_SOCK": "net-cgroups",
    "LWT_IN": "net-routing",
    "LWT_OUT": "net-routing",
    "LWT_XMIT": "net-routing",
    "SOCK_OPS": "net-sockets",
    "SK_SKB": "net-sockets",
    "CGROUP_DEVICE": "net-cgroups",
    "SK_MSG": "net-sockets",
    "RAW_TRACEPOINT": "tracing-tracepoints",
    "CGROUP_SOCK_ADDR": "net-cgroups",
    "LWT_SEG6LOCAL": "net-routing",
    "LIRC_MODE2": "net-remainder",
    "SK_REUSEPORT": "net-sockets",
    "FLOW_DISSECTOR": "net-routing",
    "CGROUP_SYSCTL": "net-cgroups",
    "RAW_TRACEPOINT_WRITABLE": "tracing-tracepoints",
    "CGROUP_SOCKOPT": "net-cgroups",
    "TRACING": "tracing-trampolines",
    "STRUCT_OPS": "structops-core",
    "EXT": "tracing-freplace",
    "LSM": "security-lsm",
    "SK_LOOKUP": "net-sockets",
    "SYSCALL": "net-remainder",
    "NETFILTER": "net-routing",
}

ATTACH_FAMILY = {
    "BPF_CGROUP_INET_INGRESS": "net-cgroups",
    "BPF_CGROUP_INET_EGRESS": "net-cgroups",
    "BPF_CGROUP_INET_SOCK_CREATE": "net-cgroups",
    "BPF_CGROUP_INET_SOCK_RELEASE": "net-cgroups",
    "BPF_CGROUP_INET4_BIND": "net-cgroups",
    "BPF_CGROUP_INET6_BIND": "net-cgroups",
    "BPF_CGROUP_INET4_CONNECT": "net-cgroups",
    "BPF_CGROUP_INET6_CONNECT": "net-cgroups",
    "BPF_CGROUP_INET4_POST_BIND": "net-cgroups",
    "BPF_CGROUP_INET6_POST_BIND": "net-cgroups",
    "BPF_CGROUP_UDP4_SENDMSG": "net-cgroups",
    "BPF_CGROUP_UDP6_SENDMSG": "net-cgroups",
    "BPF_CGROUP_UDP4_RECVMSG": "net-cgroups",
    "BPF_CGROUP_UDP6_RECVMSG": "net-cgroups",
    "BPF_CGROUP_INET4_GETPEERNAME": "net-cgroups",
    "BPF_CGROUP_INET6_GETPEERNAME": "net-cgroups",
    "BPF_CGROUP_INET4_GETSOCKNAME": "net-cgroups",
    "BPF_CGROUP_INET6_GETSOCKNAME": "net-cgroups",
    "BPF_CGROUP_UNIX_CONNECT": "net-cgroups",
    "BPF_CGROUP_UNIX_SENDMSG": "net-cgroups",
    "BPF_CGROUP_UNIX_RECVMSG": "net-cgroups",
    "BPF_CGROUP_UNIX_GETPEERNAME": "net-cgroups",
    "BPF_CGROUP_UNIX_GETSOCKNAME": "net-cgroups",
    "BPF_CGROUP_SOCK_OPS": "net-sockets",
    "BPF_CGROUP_DEVICE": "net-cgroups",
    "BPF_CGROUP_SYSCTL": "net-cgroups",
    "BPF_CGROUP_GETSOCKOPT": "net-cgroups",
    "BPF_CGROUP_SETSOCKOPT": "net-cgroups",
    "BPF_SK_SKB_STREAM_PARSER": "net-sockets",
    "BPF_SK_SKB_STREAM_VERDICT": "net-sockets",
    "BPF_SK_SKB_VERDICT": "net-sockets",
    "BPF_SK_MSG_VERDICT": "net-sockets",
    "BPF_SK_LOOKUP": "net-sockets",
    "BPF_SK_REUSEPORT_SELECT": "net-sockets",
    "BPF_SK_REUSEPORT_SELECT_OR_MIGRATE": "net-sockets",
    "BPF_FLOW_DISSECTOR": "net-routing",
    "BPF_NETFILTER": "net-routing",
    "BPF_LIRC_MODE2": "net-remainder",
    "BPF_TRACE_RAW_TP": "tracing-tracepoints",
    "BPF_TRACE_FENTRY": "tracing-trampolines",
    "BPF_TRACE_FEXIT": "tracing-trampolines",
    "BPF_MODIFY_RETURN": "tracing-trampolines",
    "BPF_TRACE_FSESSION": "tracing-trampolines",
    "BPF_TRACE_FENTRY_MULTI": "tracing-trampolines",
    "BPF_TRACE_FEXIT_MULTI": "tracing-trampolines",
    "BPF_TRACE_FSESSION_MULTI": "tracing-trampolines",
    "BPF_TRACE_ITER": "iterators",
    "BPF_TRACE_KPROBE_MULTI": "tracing-kprobes",
    "BPF_TRACE_KPROBE_SESSION": "tracing-kprobes",
    "BPF_TRACE_UPROBE_MULTI": "tracing-uprobe-multi",
    "BPF_TRACE_UPROBE_SESSION": "tracing-uprobe-variants",
    "BPF_LSM_MAC": "security-lsm",
    "BPF_LSM_CGROUP": "security-lsm-variants",
    "BPF_STRUCT_OPS": "structops-core",
    "BPF_XDP": "net-xdp",
    "BPF_XDP_DEVMAP": "net-xdp",
    "BPF_XDP_CPUMAP": "net-xdp",
    "BPF_TCX_INGRESS": "net-tcx",
    "BPF_TCX_EGRESS": "net-tcx",
    "BPF_NETKIT_PRIMARY": "net-tcx",
    "BPF_NETKIT_PEER": "net-tcx",
    "BPF_PERF_EVENT": "tracing-perf",
}

LINK_FAMILY = {
    "RAW_TRACEPOINT": "tracing-tracepoints",
    "TRACING": "tracing-trampolines",
    "CGROUP": "net-cgroups",
    "ITER": "iterators",
    "NETNS": "net-routing",
    "XDP": "net-xdp",
    "PERF_EVENT": "tracing-perf",
    "KPROBE_MULTI": "tracing-kprobes",
    "STRUCT_OPS": "structops-core",
    "NETFILTER": "net-routing",
    "TCX": "net-tcx",
    "UPROBE_MULTI": "tracing-uprobe-multi",
    "NETKIT": "net-tcx",
    "SOCKMAP": "net-sockets",
    "TRACING_MULTI": "tracing-trampolines",
}

MAP_FAMILY = {
    "HASH": "maps-keyed",
    "ARRAY": "maps-keyed",
    "PERCPU_HASH": "maps-keyed",
    "PERCPU_ARRAY": "maps-keyed",
    "LRU_HASH": "maps-keyed",
    "LRU_PERCPU_HASH": "maps-keyed",
    "LPM_TRIE": "maps-keyed",
    "BLOOM_FILTER": "maps-keyed",
    "PROG_ARRAY": "maps-dispatch",
    "CGROUP_ARRAY": "maps-dispatch",
    "ARRAY_OF_MAPS": "maps-dispatch",
    "HASH_OF_MAPS": "maps-dispatch",
    "DEVMAP": "maps-dispatch",
    "DEVMAP_HASH": "maps-dispatch",
    "SOCKMAP": "maps-dispatch",
    "SOCKHASH": "maps-dispatch",
    "CPUMAP": "maps-dispatch",
    "XSKMAP": "maps-dispatch",
    "REUSEPORT_SOCKARRAY": "maps-dispatch",
    "SK_STORAGE": "maps-storage",
    "INODE_STORAGE": "maps-storage",
    "TASK_STORAGE": "maps-storage",
    "CGROUP_STORAGE": "maps-storage",
    "CGROUP_STORAGE_DEPRECATED": "maps-storage",
    "PERCPU_CGROUP_STORAGE": "maps-storage",
    "PERCPU_CGROUP_STORAGE_DEPRECATED": "maps-storage",
    "CGRP_STORAGE": "maps-storage",
    "PERF_EVENT_ARRAY": "maps-channels",
    "STACK_TRACE": "maps-channels",
    "QUEUE": "maps-channels",
    "STACK": "maps-channels",
    "RINGBUF": "maps-channels",
    "USER_RINGBUF": "maps-channels",
    "STRUCT_OPS": "structops-core",
    "ARENA": "maps-special",
    "INSN_ARRAY": "maps-special",
    "RHASH": "maps-special",
}

# Channel maps whose positive test is the stream case rather than MAP-01.
MAP_POSITIVE_OVERRIDE = {
    "RINGBUF": "BUF-01",
    "USER_RINGBUF": "BUF-01",
    "PERF_EVENT_ARRAY": "BUF-01",
}

# Syscall commands owned by the introspection/control surface; every other
# command belongs to the raw ABI surface.
CMD_CONTROL = frozenset({
    "BPF_PROG_TEST_RUN",
    "BPF_PROG_RUN",
    "BPF_PROG_STREAM_READ_BY_FD",
    "BPF_TASK_FD_QUERY",
    "BPF_ENABLE_STATS",
    "BPF_TOKEN_CREATE",
    "BPF_OBJ_GET_INFO_BY_FD",
    "BPF_BTF_GET_FD_BY_ID",
    "BPF_BTF_GET_NEXT_ID",
    "BPF_LINK_GET_FD_BY_ID",
    "BPF_LINK_GET_NEXT_ID",
    "BPF_PROG_GET_NEXT_ID",
    "BPF_MAP_GET_NEXT_ID",
    "BPF_PROG_GET_FD_BY_ID",
    "BPF_MAP_GET_FD_BY_ID",
    "BPF_ITER_CREATE",
    "BPF_PROG_QUERY",
    "BPF_RAW_TRACEPOINT_OPEN",
})

# Flag members (exact name -> family). Helper-call argument flags stay with
# the helpers family; map/program/attach/test flags stay with the surface
# they qualify. Anything missing aborts generation.
FLAG_FAMILY = {
    # Attach option flags.
    "BPF_F_ALLOW_OVERRIDE": "userspace-attach",
    "BPF_F_ALLOW_MULTI": "userspace-attach",
    "BPF_F_REPLACE": "userspace-attach",
    "BPF_F_BEFORE": "userspace-attach",
    "BPF_F_AFTER": "userspace-attach",
    "BPF_F_ID": "userspace-attach",
    "BPF_F_PREORDER": "userspace-attach",
    "BPF_F_LINK": "userspace-attach",
    # Program load/verify flags.
    "BPF_F_STRICT_ALIGNMENT": "isa",
    "BPF_F_ANY_ALIGNMENT": "isa",
    "BPF_F_TEST_RND_HI32": "isa",
    "BPF_F_TEST_STATE_FREQ": "isa",
    "BPF_F_SLEEPABLE": "isa",
    "BPF_F_TEST_REG_INVARIANTS": "isa",
    "BPF_F_XDP_HAS_FRAGS": "net-xdp",
    "BPF_F_XDP_DEV_BOUND_ONLY": "net-hardware",
    "BPF_F_NETFILTER_IP_DEFRAG": "net-routing",
    # Test-run and query flags.
    "BPF_F_QUERY_EFFECTIVE": "userspace-control",
    "BPF_F_TEST_RUN_ON_CPU": "userspace-control",
    "BPF_F_TEST_XDP_LIVE_FRAMES": "userspace-control",
    "BPF_F_TEST_SKB_CHECKSUM_COMPLETE": "userspace-control",
    # Multi-attach selection flags.
    "BPF_F_KPROBE_MULTI_RETURN": "tracing-kprobes",
    "BPF_F_UPROBE_MULTI_RETURN": "tracing-uprobe-multi",
    "BPF_F_UPROBE_MULTI_PATH_FD": "tracing-uprobe-multi",
    # Map update flags.
    "BPF_ANY": "maps-keyed",
    "BPF_NOEXIST": "maps-keyed",
    "BPF_EXIST": "maps-keyed",
    "BPF_F_LOCK": "maps-keyed",
    "BPF_F_CPU": "maps-keyed",
    "BPF_F_ALL_CPUS": "maps-keyed",
    # Map create flags.
    "BPF_F_NO_PREALLOC": "maps-keyed",
    "BPF_F_NO_COMMON_LRU": "maps-keyed",
    "BPF_F_NUMA_NODE": "maps-keyed",
    "BPF_F_RDONLY": "maps-keyed",
    "BPF_F_WRONLY": "maps-keyed",
    "BPF_F_ZERO_SEED": "maps-keyed",
    "BPF_F_RDONLY_PROG": "maps-keyed",
    "BPF_F_WRONLY_PROG": "maps-keyed",
    "BPF_F_CLONE": "maps-keyed",
    "BPF_F_MMAPABLE": "maps-keyed",
    "BPF_F_PRESERVE_ELEMS": "maps-keyed",
    "BPF_F_PATH_FD": "maps-keyed",
    "BPF_F_VTYPE_BTF_OBJ_FD": "maps-keyed",
    "BPF_F_TOKEN_FD": "maps-keyed",
    "BPF_F_SEGV_ON_FAULT": "maps-keyed",
    "BPF_F_NO_USER_CONV": "maps-keyed",
    "BPF_F_INNER_MAP": "maps-dispatch",
    "BPF_F_STACK_BUILD_ID": "maps-channels",
    "BPF_F_RB_OVERWRITE": "maps-channels",
    # Storage accessor flags.
    "BPF_LOCAL_STORAGE_GET_F_CREATE": "maps-storage",
    "BPF_SK_STORAGE_GET_F_CREATE": "maps-storage",
    # Ring-buffer policy and query flags.
    "BPF_RB_NO_WAKEUP": "maps-channels",
    "BPF_RB_FORCE_WAKEUP": "maps-channels",
    "BPF_RB_AVAIL_DATA": "maps-channels",
    "BPF_RB_RING_SIZE": "maps-channels",
    "BPF_RB_CONS_POS": "maps-channels",
    "BPF_RB_PROD_POS": "maps-channels",
    "BPF_RB_OVERWRITE_POS": "maps-channels",
    # BTF loader flags.
    "BTF_F_COMPACT": "btf",
    "BTF_F_NONAME": "btf",
    "BTF_F_PTR_RAW": "btf",
    "BTF_F_ZERO": "btf",
    # kfunc call flags.
    "BPF_F_PAD_ZEROS": "kfuncs",
    # Timer flags.
    "BPF_F_TIMER_ABS": "memory",
    "BPF_F_TIMER_CPU_PIN": "memory",
    # Sysctl helper flags.
    "BPF_F_SYSCTL_BASE_NAME": "net-cgroups",
    # Flow-dissector program flags.
    "BPF_FLOW_DISSECTOR_F_PARSE_1ST_FRAG": "net-routing",
    "BPF_FLOW_DISSECTOR_F_STOP_AT_FLOW_LABEL": "net-routing",
    "BPF_FLOW_DISSECTOR_F_STOP_AT_ENCAP": "net-routing",
    # Sock-ops callback request flags.
    "BPF_SOCK_OPS_RTO_CB_FLAG": "net-sockets",
    "BPF_SOCK_OPS_RETRANS_CB_FLAG": "net-sockets",
    "BPF_SOCK_OPS_STATE_CB_FLAG": "net-sockets",
    "BPF_SOCK_OPS_RTT_CB_FLAG": "net-sockets",
    "BPF_SOCK_OPS_PARSE_ALL_HDR_OPT_CB_FLAG": "net-sockets",
    "BPF_SOCK_OPS_PARSE_UNKNOWN_HDR_OPT_CB_FLAG": "net-sockets",
    "BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG": "net-sockets",
    "BPF_SOCK_OPS_ALL_CB_FLAGS": "net-sockets",
    "SK_BPF_CB_TX_TIMESTAMPING": "net-sockets",
    "SK_BPF_CB_MASK": "net-sockets",
    # LSM helper flags.
    "BPF_F_BPRM_SECUREEXEC": "security-lsm",
}

# Helper-call argument flags default to the helpers family. Only flags NOT
# in FLAG_FAMILY may match these prefixes; anything else aborts.
FLAG_HELPER_PREFIXES = (
    "BPF_F_RECOMPUTE_CSUM",
    "BPF_F_INVALIDATE_HASH",
    "BPF_F_HDR_FIELD_MASK",
    "BPF_F_PSEUDO_HDR",
    "BPF_F_MARK_MANGLED_0",
    "BPF_F_MARK_ENFORCE",
    "BPF_F_IPV6",
    "BPF_F_TUNINFO_IPV6",
    "BPF_F_SKIP_FIELD_MASK",
    "BPF_F_USER_STACK",
    "BPF_F_FAST_STACK_CMP",
    "BPF_F_REUSE_STACKID",
    "BPF_F_USER_BUILD_ID",
    "BPF_F_ZERO_CSUM_TX",
    "BPF_F_DONT_FRAGMENT",
    "BPF_F_SEQ_NUMBER",
    "BPF_F_NO_TUNNEL_KEY",
    "BPF_F_TUNINFO_FLAGS",
    "BPF_F_INDEX_MASK",
    "BPF_F_CURRENT_CPU",
    "BPF_F_CTXLEN_MASK",
    "BPF_F_CURRENT_NETNS",
    "BPF_F_ADJ_ROOM_",
    "BPF_F_GET_BRANCH_RECORDS_SIZE",
    "BPF_F_INGRESS",
    "BPF_F_BROADCAST",
    "BPF_F_EXCLUDE_INGRESS",
    "BPF_F_REDIRECT_FLAGS",
    "BPF_F_MTU_CHK_SEGS",
    "BPF_MTU_CHK_SEGS",
    "BPF_SK_LOOKUP_F_",
    "BPF_FIB_LOOKUP_",
)

# Context-only members (exact name or prefix -> records that consume them).
# Context-only values are carried inside a capability's buffers and calls;
# they are never standalone features, but they must stay traceable.
CTX_RECORDS_EXACT = {
    "BPF_MAY_GOTO": ["isa:BPF_JCOND"],
    "BPF_ADDR_SPACE_CAST": ["isa:BPF_ALU64"],
    "BPF_ADJ_ROOM_ENCAP_L2_MASK": ["helper:skb_adjust_room"],
    "BPF_ADJ_ROOM_ENCAP_L2_SHIFT": ["helper:skb_adjust_room"],
    "BPF_OK": ["prog:SCHED_CLS", "prog:SCHED_ACT"],
    "BPF_DROP": ["prog:SCHED_CLS", "prog:SCHED_ACT"],
    "BPF_REDIRECT": ["prog:SCHED_CLS", "prog:SCHED_ACT"],
    "BPF_LWT_REROUTE": ["prog:LWT_IN", "prog:LWT_OUT", "prog:LWT_XMIT"],
    "BPF_FLOW_DISSECTOR_CONTINUE": ["prog:FLOW_DISSECTOR"],
    "BPF_SKB_TSTAMP_DELIVERY_MONO": ["helper:skb_set_tstamp"],
    "BPF_SKB_CLOCK_REALTIME": ["helper:skb_set_tstamp"],
    "BPF_SKB_CLOCK_MONOTONIC": ["helper:skb_set_tstamp"],
    "BPF_SKB_CLOCK_TAI": ["helper:skb_set_tstamp"],
    "BPF_STATS_RUN_TIME": ["cmd:ENABLE_STATS"],
    "BPF_STACK_BUILD_ID_EMPTY": ["helper:get_stackid"],
    "BPF_STACK_BUILD_ID_VALID": ["helper:get_stackid"],
    "BPF_STACK_BUILD_ID_IP": ["helper:get_stackid"],
    "BPF_STREAM_STDOUT": ["cmd:PROG_STREAM_READ_BY_FD"],
    "BPF_STREAM_STDERR": ["cmd:PROG_STREAM_READ_BY_FD"],
    "BPF_MTU_CHK_RET_SUCCESS": ["helper:check_mtu"],
    "BPF_MTU_CHK_RET_FRAG_NEEDED": ["helper:check_mtu"],
    "BPF_MTU_CHK_RET_SEGS_TOOBIG": ["helper:check_mtu"],
    "BPF_FD_TYPE_RAW_TRACEPOINT": ["cmd:TASK_FD_QUERY"],
    "BPF_FD_TYPE_TRACEPOINT": ["cmd:TASK_FD_QUERY"],
    "BPF_FD_TYPE_KPROBE": ["cmd:TASK_FD_QUERY"],
    "BPF_FD_TYPE_KRETPROBE": ["cmd:TASK_FD_QUERY"],
    "BPF_FD_TYPE_UPROBE": ["cmd:TASK_FD_QUERY"],
    "BPF_FD_TYPE_URETPROBE": ["cmd:TASK_FD_QUERY"],
    "BPF_ADJ_ROOM_NET": ["helper:skb_adjust_room"],
    "BPF_ADJ_ROOM_MAC": ["helper:skb_adjust_room"],
    "BPF_HDR_START_MAC": ["helper:skb_load_bytes"],
    "BPF_HDR_START_NET": ["helper:skb_load_bytes"],
    "BPF_LWT_ENCAP_SEG6": ["helper:lwt_push_encap"],
    "BPF_LWT_ENCAP_SEG6_INLINE": ["helper:lwt_push_encap"],
    "BPF_LWT_ENCAP_IP": ["helper:lwt_push_encap"],
    "BPF_CGROUP_ITER_SELF_ONLY": ["attach:TRACE_ITER"],
    "BPF_CGROUP_ITER_DESCENDANTS_PRE": ["attach:TRACE_ITER"],
    "BPF_CGROUP_ITER_DESCENDANTS_POST": ["attach:TRACE_ITER"],
    "BPF_CGROUP_ITER_ANCESTORS_UP": ["attach:TRACE_ITER"],
    "BPF_CGROUP_ITER_CHILDREN": ["attach:TRACE_ITER"],
    "BPF_PERF_EVENT_UPROBE": ["prog:PERF_EVENT"],
    "BPF_PERF_EVENT_URETPROBE": ["prog:PERF_EVENT"],
    "BPF_PERF_EVENT_KPROBE": ["prog:PERF_EVENT"],
    "BPF_PERF_EVENT_KRETPROBE": ["prog:PERF_EVENT"],
    "BPF_PERF_EVENT_TRACEPOINT": ["prog:PERF_EVENT"],
    "BPF_PERF_EVENT_EVENT": ["prog:PERF_EVENT"],
    "BTF_INT_SIGNED": ["btf:INT"],
    "BTF_INT_CHAR": ["btf:INT"],
    "BTF_INT_BOOL": ["btf:INT"],
    "BTF_FUNC_STATIC": ["btf:FUNC"],
    "BTF_FUNC_GLOBAL": ["btf:FUNC"],
    "BTF_FUNC_EXTERN": ["btf:FUNC"],
    "BTF_VAR_STATIC": ["btf:VAR"],
    "BTF_VAR_GLOBAL_ALLOCATED": ["btf:VAR"],
    "BTF_VAR_GLOBAL_EXTERN": ["btf:VAR"],
}

CTX_RECORDS_PREFIX = (
    ("BPF_REG_", ["isa:registers"]),
    ("BPF_CSUM_LEVEL_", ["helper:csum_level"]),
    ("XDP_", ["prog:XDP"]),
    ("TCX_", ["prog:SCHED_CLS"]),
    ("SK_DROP", ["prog:SK_SKB"]),
    ("SK_PASS", ["prog:SK_SKB"]),
    ("BPF_SOCK_OPS_", ["prog:SOCK_OPS"]),
    ("BPF_TCP_", ["prog:SOCK_OPS"]),
    ("TCP_BPF_", ["prog:SOCK_OPS"]),
    ("SK_BPF_CB_FLAGS", ["prog:SOCK_OPS"]),
    ("SK_BPF_BYPASS_PROT_MEM", ["prog:SOCK_OPS"]),
    ("BPF_LOAD_HDR_", ["prog:SOCK_OPS"]),
    ("BPF_WRITE_HDR_", ["prog:SOCK_OPS"]),
    ("BPF_DEVCG_", ["prog:CGROUP_DEVICE"]),
    ("BPF_FIB_LKUP_RET_", ["helper:fib_lookup"]),
    ("BPF_RINGBUF_", ["map:RINGBUF"]),
)

# Reserved sentinels: never capabilities, always classified. Besides these
# exact and pattern rules, any same-enum duplicate value is an alias of the
# first-seen name.
SENTINEL_EXACT = frozenset({
    "BPF_PROG_TYPE_UNSPEC",
    "BPF_MAP_TYPE_UNSPEC",
    "BPF_LINK_TYPE_UNSPEC",
    "BPF_PERF_EVENT_UNSPEC",
    "BPF_CGROUP_ITER_ORDER_UNSPEC",
    "BPF_SKB_TSTAMP_UNSPEC",
    "BTF_KIND_UNKN",
    "BPF_SOCK_OPS_VOID",
    "__BPF_FUNC_MAX_ID",
    "__MAX_BPF_REG",
    "__MAX_BPF_CMD",
    "__MAX_BPF_MAP_TYPE",
    "__MAX_BPF_PROG_TYPE",
    "__MAX_BPF_ATTACH_TYPE",
    "__MAX_BPF_LINK_TYPE",
    "MAX_BPF_REG",
    "MAX_BPF_ATTACH_TYPE",
    "MAX_BPF_LINK_TYPE",
})


def is_versioned_bound(name):
    """True for sentinels and limits whose values may legitimately drift.

    Count sentinels and structural bounds grow as upstream enums grow;
    they are recorded with their newest value plus the per-version map.
    """
    return (name in SENTINEL_EXACT or name in LIMIT_EXACT
            or name.startswith("__MAX") or name.startswith("MAX_BPF_"))

# Structural constants and bounds: enumerated with values, no record needed.
LIMIT_EXACT = frozenset({
    "BPF_TAG_SIZE",
    "BPF_OBJ_NAME_LEN",
    "BPF_BUILD_ID_SIZE",
    "BPF_MAXINSNS",
    "BPF_COMMON_ATTRS",
    "BTF_MAGIC",
    "BTF_VERSION",
    "BTF_MAX_KIND",
    "BTF_MAX_TYPE",
    "BTF_MAX_NAME_OFFSET",
    "BTF_MAX_VLEN",
    "NR_BTF_KINDS",
    "BTF_KIND_MAX",
    "BPF_TCP_MAX_STATES",
})

# Internal preprocessor machinery and accessor macros: enumerated so the
# traversal is complete, then excluded with a reason. Function-like macros
# and include guards are excluded by rule and need no entry here.
EXCLUDED_EXACT = {
    "___BPF_FUNC_MAPPER": "helper-ID mapper machinery, not a capability",
    "__BPF_FUNC_MAPPER": "helper-ID mapper machinery, not a capability",
    "__BPF_FUNC_MAPPER_APPLY": "helper-ID mapper machinery, not a capability",
    "__BPF_ENUM_FN": "helper-ID mapper machinery, not a capability",
    "dummy": "unused LLVM BPF feature bit",
    "dwarfris": "LLVM debug relocation control, not a BPF capability",
}

# ISA opcode defines that own the calls family (call/return mechanics);
# every other opcode or classic-BPF define owns the isa family.
CALLS_ISA = frozenset({
    "BPF_CALL",
    "BPF_EXIT",
    "BPF_PSEUDO_CALL",
    "BPF_PSEUDO_FUNC",
})

# True #define aliases (name -> canonical). Unlike same-enum duplicate
# values, colliding define values across opcode classes are NOT aliases:
# each opcode keeps its own record.
DEFINE_ALIAS = {
    "BPF_XADD": "BPF_ATOMIC",
    "BPF_FROM_LE": "BPF_TO_LE",
    "BPF_FROM_BE": "BPF_TO_BE",
}

# The kfunc call pseudo-instruction belongs to the kfunc family.
KFUNC_ISA = frozenset({
    "BPF_PSEUDO_KFUNC_CALL",
})

# ELF section pattern prefixes (ordered, longest match wins) -> family.
SECTION_FAMILY = (
    ("struct_ops", "structops-core"),
    ("lsm_cgroup", "security-lsm-variants"),
    ("lsm", "security-lsm"),
    ("uprobe.session", "tracing-uprobe-variants"),
    ("uprobe.multi.s", "tracing-uprobe-variants"),
    ("uretprobe.multi.s", "tracing-uprobe-variants"),
    ("uprobe.multi", "tracing-uprobe-multi"),
    ("uretprobe.multi", "tracing-uprobe-multi"),
    ("uprobe.s", "tracing-uprobe-variants"),
    ("uretprobe.s", "tracing-uprobe-variants"),
    ("uprobe", "tracing-uprobe-single"),
    ("uretprobe", "tracing-uprobe-single"),
    ("kprobe", "tracing-kprobes"),
    ("kretprobe", "tracing-kprobes"),
    ("ksyscall", "tracing-kprobes"),
    ("kretsyscall", "tracing-kprobes"),
    ("usdt", "tracing-usdt"),
    ("tracepoint", "tracing-tracepoints"),
    ("raw_tracepoint", "tracing-tracepoints"),
    ("raw_tp", "tracing-tracepoints"),
    ("tp_btf", "tracing-tracepoints"),
    ("tp", "tracing-tracepoints"),
    ("fentry", "tracing-trampolines"),
    ("fexit", "tracing-trampolines"),
    ("fmod_ret", "tracing-trampolines"),
    ("fsession", "tracing-trampolines"),
    ("freplace", "tracing-freplace"),
    ("iter", "iterators"),
    ("syscall", "net-remainder"),
    ("socket", "net-sockets"),
    ("sockops", "net-sockets"),
    ("sk_skb", "net-sockets"),
    ("sk_msg", "net-sockets"),
    ("sk_reuseport", "net-sockets"),
    ("sk_lookup", "net-sockets"),
    ("xdp", "net-xdp"),
    ("tc", "net-tcx"),
    ("tcx", "net-tcx"),
    ("classifier", "net-tcx"),
    ("action", "net-tcx"),
    ("netkit", "net-tcx"),
    ("perf_event", "tracing-perf"),
    ("lwt_", "net-routing"),
    ("lirc_mode2", "net-remainder"),
    ("flow_dissector", "net-routing"),
    ("netfilter", "net-routing"),
    ("cgroup", "net-cgroups"),
)

# Library symbol prefixes (ordered) -> family. Exact overrides win over
# prefixes; anything unmatched aborts generation.
API_FAMILY_PREFIX = (
    ("bpf_program__attach", "userspace-attach"),
    ("bpf_program__", "userspace-object"),
    ("bpf_object__", "userspace-object"),
    ("bpf_map__", "userspace-maps"),
    ("bpf_map_", "userspace-maps"),
    ("bpf_link__", "userspace-attach"),
    ("bpf_link_", "userspace-attach"),
    ("bpf_prog_attach", "userspace-attach"),
    ("bpf_prog_detach", "userspace-attach"),
    ("bpf_prog_test_run", "userspace-control"),
    ("bpf_prog_run_opts", "userspace-control"),
    ("bpf_prog_query", "userspace-control"),
    ("bpf_prog_get_", "userspace-control"),
    ("bpf_prog_load", "userspace-object"),
    ("bpf_prog_bind_map", "userspace-object"),
    ("bpf_prog_", "userspace-control"),
    ("bpf_obj_pin", "userspace-object"),
    ("bpf_obj_get_info", "userspace-control"),
    ("bpf_obj_get", "userspace-object"),
    ("bpf_btf_", "userspace-object"),
    ("btf_ext__", "userspace-object"),
    ("btf_dump__", "userspace-object"),
    ("btf__", "userspace-object"),
    ("btf_", "userspace-object"),
    ("ring_buffer__", "userspace-events"),
    ("perf_buffer__", "userspace-events"),
    ("user_ring_buffer__", "userspace-events"),
    ("ring__", "userspace-events"),
    ("bpf_usdt_", "tracing-usdt"),
    ("bpf_xdp_", "net-xdp"),
    ("bpf_tc_", "net-tcx"),
    ("bpf_netfilter_", "net-routing"),
    ("bpf_insn_", "userspace-abi"),
    ("bpf_probe_", "userspace-abi"),
    ("bpf_token_", "userspace-control"),
    ("bpf_core_", "userspace-abi"),
    ("bpf_", "userspace-abi"),
    ("libbpf_", "userspace-abi"),
)

# Helper positive-test overrides: exact names, then longest-prefix match.
# The default is the helpers family case.
HELPER_TEST_EXACT = {
    "tail_call": "CALL-02",
    "loop": "CALL-02",
    "trace_printk": "TR-TP-01",
    "trace_vprintk": "TR-TP-01",
    "override_return": "TR-BTF-01",
    "get_func_ip": "TR-BTF-01",
    "get_func_arg": "TR-BTF-01",
    "get_func_ret": "TR-BTF-01",
    "get_func_arg_cnt": "TR-BTF-01",
    "get_retval": "TR-BTF-01",
    "set_retval": "TR-BTF-01",
    "get_attach_cookie": "TR-BTF-01",
    "sys_bpf": "LIFE-01",
    "sys_close": "LIFE-01",
    "for_each_map_elem": "ITER-01",
}

HELPER_TEST_PREFIX = (
    ("ringbuf_", "BUF-01"),
    ("perf_event_", "BUF-01"),
    ("get_stack", "BUF-01"),
    ("get_task_stack", "BUF-01"),
    ("skb_output", "BUF-01"),
    ("xdp_output", "BUF-01"),
    ("user_ringbuf_", "BUF-01"),
    ("timer_", "MEM-01"),
    ("dynptr_", "MEM-01"),
    ("kptr_", "MEM-01"),
    ("map_", "MAP-01"),
    ("sk_storage_", "MAP-02"),
    ("inode_storage_", "MAP-02"),
    ("task_storage_", "MAP-02"),
    ("cgrp_storage_", "MAP-02"),
    ("get_local_storage", "MAP-02"),
)

# Opcode and pseudo-instruction defines in bpf.h that own ISA records.
# Any other bpf.h object-like define must be a flag, limit, sentinel,
# alias or excluded entry; anything else aborts generation.
ISA_DEFINES = frozenset({
    "BPF_JMP32", "BPF_ALU64", "BPF_DW", "BPF_MEMSX", "BPF_ATOMIC",
    "BPF_MOV", "BPF_ARSH", "BPF_END", "BPF_TO_LE", "BPF_TO_BE",
    "BPF_JNE", "BPF_JLT", "BPF_JLE", "BPF_JSGT", "BPF_JSGE",
    "BPF_JSLT", "BPF_JSLE", "BPF_JCOND", "BPF_CALL", "BPF_EXIT",
    "BPF_FETCH", "BPF_XCHG", "BPF_CMPXCHG", "BPF_LOAD_ACQ",
    "BPF_STORE_REL", "BPF_PSEUDO_MAP_FD", "BPF_PSEUDO_MAP_IDX",
    "BPF_PSEUDO_MAP_VALUE", "BPF_PSEUDO_MAP_IDX_VALUE",
    "BPF_PSEUDO_BTF_ID", "BPF_PSEUDO_FUNC", "BPF_PSEUDO_CALL",
    "BPF_PSEUDO_KFUNC_CALL",
})


class InventoryError(Exception):
    """Fatal inventory failure with an exit status."""

    def __init__(self, message, status=EXIT_UNKNOWN):
        super().__init__(message)
        self.status = status


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def dump_canonical(document):
    return json.dumps(document, indent=2, sort_keys=True) + "\n"


def strip_comments(text):
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def strip_pp_lines(text):
    return "\n".join(
        line for line in text.splitlines()
        if not line.lstrip().startswith("#")
    )


_CONSTEXPR_TOKEN = re.compile(r"""
    (?P<num>0[xX][0-9a-fA-F]+[uUlL]*|\d+[uUlL]*)
  | (?P<ident>[A-Za-z_]\w*)
  | (?P<op><<|>>|[()|&^~+\-*/%])
  | (?P<space>\s+)
  | (?P<bad>.)
""", re.VERBOSE)


def eval_constexpr(expr, known):
    """Evaluate a simple C integer constant expression.

    Returns the integer value, or None when the expression references an
    unknown name, calls a macro, or uses unsupported syntax. ``known``
    maps already-resolved names to values.
    """
    tokens = []
    for match in _CONSTEXPR_TOKEN.finditer(expr):
        kind = match.lastgroup
        word = match.group()
        if kind == "space":
            continue
        if kind == "bad":
            return None
        tokens.append((kind, word))

    pos = 0

    def peek():
        return tokens[pos] if pos < len(tokens) else (None, None)

    def parse_or():
        nonlocal pos
        value = parse_xor()
        if value is None:
            return None
        while True:
            kind, word = peek()
            if kind == "op" and word == "|":
                pos += 1
                rhs = parse_xor()
                if rhs is None:
                    return None
                value |= rhs
            else:
                return value

    def parse_xor():
        nonlocal pos
        value = parse_and()
        if value is None:
            return None
        while True:
            kind, word = peek()
            if kind == "op" and word == "^":
                pos += 1
                rhs = parse_and()
                if rhs is None:
                    return None
                value ^= rhs
            else:
                return value

    def parse_and():
        nonlocal pos
        value = parse_shift()
        if value is None:
            return None
        while True:
            kind, word = peek()
            if kind == "op" and word == "&":
                pos += 1
                rhs = parse_shift()
                if rhs is None:
                    return None
                value &= rhs
            else:
                return value

    def parse_shift():
        nonlocal pos
        value = parse_add()
        if value is None:
            return None
        while True:
            kind, word = peek()
            if kind == "op" and word in ("<<", ">>"):
                pos += 1
                rhs = parse_add()
                if rhs is None:
                    return None
                value = value << rhs if word == "<<" else value >> rhs
            else:
                return value

    def parse_add():
        nonlocal pos
        value = parse_unary()
        if value is None:
            return None
        while True:
            kind, word = peek()
            if kind == "op" and word in ("+", "-"):
                pos += 1
                rhs = parse_unary()
                if rhs is None:
                    return None
                value = value + rhs if word == "+" else value - rhs
            else:
                return value

    def parse_unary():
        nonlocal pos
        kind, word = peek()
        if kind == "op" and word in ("+", "-", "~"):
            pos += 1
            value = parse_unary()
            if value is None:
                return None
            return {"+": value, "-": -value, "~": ~value}[word]
        return parse_primary()

    def parse_primary():
        nonlocal pos
        kind, word = peek()
        if kind == "num":
            pos += 1
            return int(re.sub(r"[uUlL]+$", "", word), 0)
        if kind == "ident":
            pos += 1
            # A following paren means a macro call: not evaluable here.
            nxt_kind, nxt_word = peek()
            if nxt_kind == "op" and nxt_word == "(":
                return None
            return known.get(word)
        if kind == "op" and word == "(":
            pos += 1
            value = parse_or()
            kind2, word2 = peek()
            if kind2 != "op" or word2 != ")":
                return None
            pos += 1
            return value
        return None

    try:
        value = parse_or()
    except (RecursionError, ArithmeticError):
        return None
    if pos != len(tokens):
        return None
    return value


def parse_defines(text):
    """Return [(name, value_text_or_None, is_function_like, lineno)]."""
    defines = []
    lines = text.splitlines()
    index = 0
    while index < len(lines):
        line = lines[index]
        match = re.match(r"\s*#\s*define\s+([A-Za-z_]\w*)(\()?", line)
        if not match:
            index += 1
            continue
        name = match.group(1)
        is_function_like = match.group(2) == "("
        rest = line[match.end():]
        lineno = index + 1
        while rest.rstrip().endswith("\\") and index + 1 < len(lines):
            index += 1
            rest = rest.rstrip()[:-1] + " " + lines[index]
        value = strip_comments(rest).strip()
        defines.append((name, value or None, is_function_like, lineno))
        index += 1
    return defines


def parse_enums(text):
    """Return [(enum_name_or_None, [(member, value_text_or_None)], lineno)]."""
    clean = strip_pp_lines(strip_comments(text))
    enums = []
    for match in re.finditer(r"\benum\s+(\w+)?\s*\{(.*?)\};", clean, re.S):
        body = match.group(2)
        members = []
        for piece in body.split(","):
            piece = piece.strip()
            if not piece:
                continue
            name_match = re.match(r"([A-Za-z_]\w*)(.*)$", piece, re.S)
            if not name_match:
                continue
            name = name_match.group(1)
            tail = name_match.group(2).strip()
            value_text = None
            if tail.startswith("="):
                value_text = tail[1:].strip() or None
            elif tail:
                # Macro invocation inside the enum (helper mapper): keep
                # the head identifier so the traversal stays complete.
                value_text = tail
            members.append((name, value_text))
        lineno = clean.count("\n", 0, match.start()) + 1
        enums.append((match.group(1), members, lineno))
    return enums


def enum_values(members, known):
    """Compute C enum values. Returns {name: (value_or_None, value_text)}."""
    result = {}
    next_value = 0
    scope = dict(known)
    for name, value_text in members:
        if value_text is None:
            value = next_value
        else:
            value = eval_constexpr(value_text, scope)
        result[name] = (value, value_text)
        if value is not None:
            scope[name] = value
            next_value = value + 1
    return result


def parse_helpers(text):
    """Return [(helper_name, helper_id)] from the FUNC_MAPPER macro."""
    match = re.search(
        r"#define ___BPF_FUNC_MAPPER\(FN, ctx\.\.\.\)(.*?)(?=\n#define |\n/\*|\nenum )",
        text,
        re.S,
    )
    if not match:
        return []
    entries = re.findall(r"FN\((\w+),\s*(\d+)", match.group(1))
    return [(name, int(number)) for name, number in entries]


def parse_libbpf_map(text):
    """Return [(version_node, [symbols])] from a linker version script."""
    nodes = []
    for match in re.finditer(r"^(\w[\w.]*)\s*\{\s*global:(.*?)\}",
                             text, re.S | re.M):
        body = match.group(2)
        symbols = re.findall(r"^\s*([A-Za-z_]\w*)\s*;", body, re.M)
        nodes.append((match.group(1), symbols))
    return nodes


def parse_sec_defs(text):
    """Return [(pattern, prog_short, attach_or_None, flags, attach_fn)]."""
    match = re.search(
        r"struct bpf_sec_def section_defs\[\] = \{(.*?)\n\};",
        text,
        re.S,
    )
    if not match:
        return []
    entries = []
    pattern = re.compile(
        r'SEC_DEF\(\s*"([^"]+)"\s*,\s*(\w+)\s*,\s*'
        r"(\w+)\s*,\s*([^,)]+)(\s*,\s*(\w+))?\s*\)"
    )
    for sec in pattern.finditer(match.group(1)):
        attach = sec.group(3)
        entries.append((
            sec.group(1),
            sec.group(2),
            None if attach == "0" else attach,
            sec.group(4).strip(),
            sec.group(6),
        ))
    return entries


def parse_declarations(text):
    """Return the set of function names declared or defined in C text."""
    clean = strip_comments(text)
    names = set()
    for match in re.finditer(r"\b([A-Za-z_]\w*)\s*\(", clean):
        names.add(match.group(1))
    return names


# ---------------------------------------------------------------------------
# Source staging
# ---------------------------------------------------------------------------

UAPI_FILES = ("bpf.h", "btf.h", "bpf_common.h", "bpf_perf_event.h")
LIBBPF_FILES = (
    "src/libbpf.h",
    "src/libbpf.map",
    "src/libbpf.c",
    "src/bpf.h",
    "src/btf.h",
    "src/libbpf_legacy.h",
)
LIBBPF_DECL_HEADERS = (
    "src/libbpf.h",
    "src/bpf.h",
    "src/btf.h",
    "src/libbpf_legacy.h",
)
SELFTEST_LISTS = ("prog_tests.paths", "progs.paths", "verifier.paths")


def read_text(path):
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


def verify_staging(sources_dir, lock, rebase=False):
    """Hash-check every staged file against the lock.

    Returns the (possibly rebased) expected map. Aborts with exit 2 on
    any missing or drifting file unless ``rebase`` is set, in which case
    the lock dict is updated in place and the delta is reported.
    """
    expected = lock.get("expected", {})
    problems = []
    for relpath in sorted(expected):
        staged = os.path.join(sources_dir, relpath)
        if not os.path.isfile(staged):
            problems.append("missing staged file: %s" % relpath)
            continue
        actual = sha256_file(staged)
        if actual != expected[relpath]:
            problems.append(
                "hash drift: %s expected %s actual %s"
                % (relpath, expected[relpath], actual)
            )
    if problems and not rebase:
        raise InventoryError(
            "source integrity failure:\n  " + "\n  ".join(problems),
            status=EXIT_INTEGRITY,
        )
    if rebase:
        delta = []
        for relpath in sorted(expected):
            staged = os.path.join(sources_dir, relpath)
            if not os.path.isfile(staged):
                delta.append("MISSING %s (kept old pin)" % relpath)
                continue
            actual = sha256_file(staged)
            if actual != expected[relpath]:
                delta.append(
                    "UPDATE %s %s -> %s"
                    % (relpath, expected[relpath], actual)
                )
                expected[relpath] = actual
        return delta
    return []


def load_staging(sources_dir, lock):
    """Read and parse every staged source. Returns a Staging bundle."""
    uapi_versions = list(lock["uapi_versions"])
    uapi = {}
    for version in uapi_versions:
        per_file = {}
        for filename in UAPI_FILES:
            path = os.path.join(sources_dir, "uapi", version, filename)
            per_file[filename] = read_text(path)
        uapi[version] = per_file
    libbpf_version = lock["libbpf_version"]
    libbpf = {}
    for filename in LIBBPF_FILES:
        path = os.path.join(
            sources_dir, "libbpf-%s" % libbpf_version, filename
        )
        libbpf[filename] = read_text(path)
    llvm_facts = load_json(os.path.join(sources_dir, "llvm", "facts.json"))
    selftests = {}
    tag = lock["selftests_tag"]
    for name in SELFTEST_LISTS:
        path = os.path.join(sources_dir, "selftests", tag, name)
        with open(path, "r", encoding="utf-8") as handle:
            selftests[name] = [
                line.strip() for line in handle if line.strip()
            ]
    return {
        "uapi_versions": uapi_versions,
        "uapi": uapi,
        "libbpf_version": libbpf_version,
        "libbpf": libbpf,
        "llvm": llvm_facts,
        "selftests_tag": tag,
        "selftests": selftests,
    }


# ---------------------------------------------------------------------------
# Union and classification
# ---------------------------------------------------------------------------

class Atom:
    """One upstream atom merged across pinned versions."""

    def __init__(self, name):
        self.name = name
        self.kinds = set()
        self.enums = set()
        self.files = set()
        self.present_in = []
        self.values = {}
        self.value_texts = {}
        self.function_like = False
        self.helper_id = None

    def add(self, version, kind, enum, filename, value, value_text,
            function_like=False):
        self.kinds.add(kind)
        if enum:
            self.enums.add(enum)
        self.files.add(filename)
        self.present_in.append(version)
        self.values[version] = value
        self.value_texts[version] = value_text
        self.function_like = self.function_like or function_like


def collect_uapi_atoms(staging):
    """Parse every pinned UAPI version into merged atoms.

    Returns (atoms_by_name, conflicts). Value or shape conflicts across
    versions are returned for the caller to fail loudly on.
    """
    per_version = {}
    seen_anon = set()
    for version in staging["uapi_versions"]:
        occ = {}
        files = staging["uapi"][version]
        for filename in UAPI_FILES:
            text = files[filename]
            for enum_name, members, _ in parse_enums(text):
                if enum_name is None:
                    # Anonymous enums shift file positions across
                    # versions; key them by first member, which the
                    # append-only UAPI never renames.
                    first = members[0][0] if members else "empty"
                    enum_key = "<anon-first:%s>" % first
                    seen_key = (version, filename, enum_key)
                    if seen_key in seen_anon:
                        raise InventoryError(
                            "duplicate anonymous enum key %s in %s@%s"
                            % (enum_key, filename, version)
                        )
                    seen_anon.add(seen_key)
                else:
                    enum_key = enum_name
                for name, value_text in members:
                    occ.setdefault(name, []).append({
                        "kind": "enum",
                        "enum": enum_key,
                        "file": filename,
                        "value_text": value_text,
                    })
                    # A macro invocation inside an enum body hides the
                    # members that follow it on the same piece; recover
                    # every identifier from the invocation tail.
                    if value_text and not value_text.startswith("=") and \
                            "(" in value_text and name.startswith("_"):
                        for extra in re.findall(r"[A-Za-z_]\w*", value_text):
                            if extra != name:
                                occ.setdefault(extra, []).append({
                                    "kind": "enum",
                                    "enum": enum_key,
                                    "file": filename,
                                    "value_text": None,
                                })
            for name, value_text, func_like, _ in parse_defines(text):
                occ.setdefault(name, []).append({
                    "kind": "define",
                    "enum": None,
                    "file": filename,
                    "value_text": value_text,
                    "function_like": func_like,
                })
        # Resolve enum values first (enums are self-contained), then
        # defines against defines plus all enum values.
        known = {}
        for filename in UAPI_FILES:
            for enum_name, members, _ in parse_enums(files[filename]):
                for name, (value, _) in enum_values(members, known).items():
                    if value is not None:
                        known[name] = value
        for name, entries in occ.items():
            for entry in entries:
                if entry["kind"] == "define" and not entry["function_like"] \
                        and entry["value_text"]:
                    entry["value"] = eval_constexpr(
                        entry["value_text"], known
                    )
                else:
                    entry["value"] = None
        # Second pass: defines may reference later defines.
        for _ in range(2):
            for name, entries in occ.items():
                for entry in entries:
                    if entry["kind"] == "define" and entry["value"] is None \
                            and entry["value_text"]:
                        entry["value"] = eval_constexpr(
                            entry["value_text"], known
                        )
                    if entry.get("value") is not None:
                        known[name] = entry["value"]
        for filename in UAPI_FILES:
            for enum_name, members, _ in parse_enums(files[filename]):
                if enum_name is None:
                    first = members[0][0] if members else "empty"
                    enum_key = "<anon-first:%s>" % first
                else:
                    enum_key = enum_name
                values = enum_values(members, known)
                for name, (value, _) in values.items():
                    for entry in occ.get(name, []):
                        if entry["kind"] == "enum" and \
                                entry["enum"] == enum_key and \
                                entry["file"] == filename:
                            entry["value"] = value
        per_version[version] = occ

    atoms = {}
    conflicts = []
    for version in staging["uapi_versions"]:
        for name, entries in per_version[version].items():
            atom = atoms.setdefault(name, Atom(name))
            for entry in entries:
                atom.add(
                    version, entry["kind"], entry["enum"], entry["file"],
                    entry.get("value"), entry.get("value_text"),
                    entry.get("function_like", False),
                )
    for name in sorted(atoms):
        atom = atoms[name]
        if len(atom.files) > 1:
            conflicts.append(
                "file conflict for %s: %s"
                % (name, ", ".join(sorted(atom.files)))
            )
        valued = sorted({v for v in atom.values.values() if v is not None})
        if len(valued) > 1 and not is_versioned_bound(name):
            conflicts.append(
                "value conflict for %s: %s"
                % (name, ", ".join(
                    "%s=%s" % (ver, atom.values[ver])
                    for ver in sorted(atom.values)
                ))
            )
        shapes = set()
        for version in staging["uapi_versions"]:
            for entry in per_version[version].get(name, []):
                shapes.add((entry["kind"], entry["enum"], entry["file"]))
        if len(shapes) > 1 and not is_versioned_bound(name):
            # Multi-shape atoms merge only when every occurrence that
            # carries a value agrees on it: a self-referential no-value
            # define plus a valued enum member, or internal machinery
            # with no value at all.
            distinct = set()
            for version in staging["uapi_versions"]:
                for entry in per_version[version].get(name, []):
                    if entry.get("value") is not None:
                        distinct.add(entry["value"])
            if len(distinct) > 1:
                conflicts.append(
                    "shape conflict for %s: %s"
                    % (name, ", ".join(
                        "%s/%s/%s" % s for s in sorted(shapes)
                    ))
                )
    return atoms, conflicts


def longest_prefix_match(table, key):
    best = None
    for prefix, family in table:
        if key.startswith(prefix) and (
                best is None or len(prefix) > len(best[0])):
            best = (prefix, family)
    return best[1] if best else None


def flag_family(name):
    if name in FLAG_FAMILY:
        return FLAG_FAMILY[name]
    for prefix in FLAG_HELPER_PREFIXES:
        if name.startswith(prefix):
            return "helpers"
    return None


def ctx_records(name):
    if name in CTX_RECORDS_EXACT:
        return list(CTX_RECORDS_EXACT[name])
    for prefix, refs in CTX_RECORDS_PREFIX:
        if name.startswith(prefix):
            return list(refs)
    return None


def helper_test_case(name):
    if name in HELPER_TEST_EXACT:
        return HELPER_TEST_EXACT[name]
    best = None
    for prefix, case in HELPER_TEST_PREFIX:
        if name.startswith(prefix) and (
                best is None or len(prefix) > len(best[0])):
            best = (prefix, case)
    return best[1] if best else None


def family_defaults(family):
    """Return (owner, positive, negatives, interactions, targets)."""
    _, _, owner, cases = FAMILIES[family]
    targets = list(FAMILY_TARGETS.get(family, DEFAULT_TARGETS))
    return owner, cases[0], [cases[0]], list(cases[1:]), targets


def base_record(rec_id, family, refs, predicate, next_action,
                compiler_surface, userspace_surface,
                positive=None, interaction=None):
    owner, default_pos, _, default_inter, targets = family_defaults(family)
    pos = positive or default_pos
    return {
        "id": rec_id,
        "family": family,
        "owner_task": owner,
        "scope_required": True,
        "upstream_source_refs": sorted(refs),
        "kernel_registration_refs": [],
        "program_types": [],
        "attach_types": [],
        "link_types": [],
        "elf_sections": [],
        "map_types": [],
        "required_flags": [],
        "btf_requirements": [],
        "helpers_or_kfuncs": [],
        "callable_context_predicates": [],
        "compiler_surface": compiler_surface,
        "userspace_api_surface": userspace_surface,
        "implementation_state": "PLANNED",
        "evidence_level": "none",
        "applicability_predicate": predicate,
        "targets_required": sorted(targets),
        "positive_tests": [pos],
        "negative_tests": [pos],
        "interaction_tests": sorted(interaction if interaction is not None
                                    else default_inter),
        "cost_cases": [],
        "blocker": None,
        "next_action": next_action,
        "evidence_refs": [],
    }


REGISTRATION_BLOCKER = {
    "status": "BLOCKED_UPSTREAM",
    "detail": "Callable program/attach/context registration needs a pinned "
              "kernel source; the UAPI enumerates IDs only and BTF symbol "
              "presence alone never qualifies a call.",
    "next_action": "Pin kernel source, record kernel_registration_refs and "
                   "callable_context_predicates, then re-run refresh.",
}


def uapi_refs(filename, present_in, name):
    return ["linux-uapi:%s@%s#%s" % (filename, ver, name)
            for ver in sorted(present_in)]


def uapi_predicate(name, present_in, rank):
    versions = sorted(present_in)
    oldest = min(present_in, key=lambda ver: rank.get(ver, 0))
    return (
        "kernel UAPI provides %s (first pinned in %s; present in %s) "
        "and the kernel implements the capability"
        % (name, oldest, ", ".join(versions))
    )


def classify_uapi_atom(name, atom, canonical_by_enum):
    """Classify one merged UAPI atom.

    Returns (classification, group, family_or_None, note, canonical).
    ``group`` is the record group for capabilities, else None. Unknown
    atoms return classification ``unknown``.
    """
    if atom.function_like:
        return ("excluded", None, None, "function-like accessor macro", None)
    if name in EXCLUDED_EXACT:
        return ("excluded", None, None, EXCLUDED_EXACT[name], None)
    if name.startswith("_UAPI_") or name.startswith("_LINUX_"):
        return ("excluded", None, None, "header include guard", None)
    if name in SENTINEL_EXACT or name.startswith("__MAX"):
        return ("sentinel", None, None,
                "reserved sentinel; not a capability", None)
    if name in LIMIT_EXACT:
        return ("limit", None, None, "structural bound or constant", None)
    if name in DEFINE_ALIAS:
        return ("alias", None, None, "", DEFINE_ALIAS[name])
    enums = sorted(atom.enums)
    files = sorted(atom.files)
    filename = files[0]
    enum_key = enums[0] if enums else None
    if "enum" in atom.kinds and len(enums) == 1:
        canonical = canonical_by_enum.get((filename, enum_key), {}).get(name)
        if canonical and canonical != name and not (
                canonical in SENTINEL_EXACT or canonical in LIMIT_EXACT):
            # A live name reusing a reserved value is classified on its
            # own merits below, never as an alias of the sentinel.
            return ("alias", None, None, "", canonical)
    # Capability groups by container.
    if enum_key == "bpf_prog_type":
        short = name[len("BPF_PROG_TYPE_"):]
        if short in PROG_FAMILY:
            return ("capability", "prog", PROG_FAMILY[short], "", None)
        return ("unknown", None, None, "unmapped program type", None)
    if enum_key == "bpf_attach_type":
        if name in ATTACH_FAMILY:
            return ("capability", "attach", ATTACH_FAMILY[name], "", None)
        return ("unknown", None, None, "unmapped attach type", None)
    if enum_key == "bpf_link_type":
        short = name[len("BPF_LINK_TYPE_"):]
        if short in LINK_FAMILY:
            return ("capability", "link", LINK_FAMILY[short], "", None)
        return ("unknown", None, None, "unmapped link type", None)
    if enum_key == "bpf_map_type":
        short = name[len("BPF_MAP_TYPE_"):]
        if short in MAP_FAMILY:
            return ("capability", "map", MAP_FAMILY[short], "", None)
        return ("unknown", None, None, "unmapped map type", None)
    if enum_key == "bpf_cmd":
        family = ("userspace-control" if name in CMD_CONTROL
                  else "userspace-abi")
        return ("capability", "cmd", family, "", None)
    if enum_key == "bpf_core_relo_kind":
        return ("capability", "core", "core-relocations", "", None)
    if filename == "btf.h" and name.startswith("BTF_KIND_"):
        return ("capability", "btf", "btf", "", None)
    if filename == "bpf_common.h" and "define" in atom.kinds:
        return ("capability", "isa", "isa", "classic BPF encoding", None)
    if filename == "bpf.h" and name in ISA_DEFINES:
        if name in CALLS_ISA:
            return ("capability", "isa", "calls", "", None)
        if name in KFUNC_ISA:
            return ("capability", "isa", "kfuncs", "", None)
        return ("capability", "isa", "isa", "", None)
    family = flag_family(name)
    if family is not None:
        return ("capability", "flag", family, "", None)
    refs = ctx_records(name)
    if refs is not None:
        return ("context-only", None, None, "", None)
    return ("unknown", None, None, "no classification rule", None)


def container_of(atom):
    filename = sorted(atom.files)[0]
    if "define" in atom.kinds and len(atom.kinds) == 1:
        return "uapi:%s#define" % filename
    enums = sorted(e for e in atom.enums if not e.startswith("<anon"))
    if enums:
        return "uapi:%s#%s" % (filename, enums[0])
    if atom.enums:
        return "uapi:%s#anonymous" % filename
    return "uapi:%s#define" % filename


def canonical_by_enum_newest(staging):
    """Map (file, enum_key) -> {member: canonical_member} for aliases.

    Within one enum, later members sharing the first-seen value are
    aliases of that first name. Scoping is per-enum: identical values
    across different flag words are independent capabilities.
    """
    newest = list(staging["uapi_versions"])[-1]
    files = staging["uapi"][newest]
    canonical = {}
    known = {}
    for filename in UAPI_FILES:
        for enum_name, members, _ in parse_enums(files[filename]):
            key = enum_name or "<anon-first:%s>" % (
                members[0][0] if members else "empty"
            )
            values = enum_values(members, known)
            by_value = {}
            for name in values:
                value, _ = values[name]
                if value is None:
                    continue
                by_value.setdefault(value, []).append(name)
            mapping = {}
            for value, names in by_value.items():
                # First-seen wins, except a deprecated spelling never
                # becomes canonical while a live name shares its value.
                live = [name for name in names
                        if "DEPRECATED" not in name]
                winner = live[0] if live else names[0]
                for name in names:
                    mapping[name] = winner
            canonical[(filename, key)] = mapping
            for name, (value, _) in values.items():
                if value is not None:
                    known[name] = value
    return canonical


def strip_prefix(name, prefix):
    if name.startswith(prefix):
        return name[len(prefix):]
    return name


def inventory(staging, lock):
    """inventory(source_pins) -> CapabilityRegistry.

    Raises InventoryError on any conflict, unknown atom or broken
    cross-reference. On success returns the registry document dict.
    """
    atoms, conflicts = collect_uapi_atoms(staging)
    if conflicts:
        raise InventoryError(
            "upstream union conflicts:\n  " + "\n  ".join(sorted(conflicts))
        )
    version_order = list(staging["uapi_versions"])
    rank = {ver: index for index, ver in enumerate(version_order)}
    newest_uapi = max(version_order, key=lambda ver: rank[ver])
    canonical = canonical_by_enum_newest(staging)

    # Pinned helper IDs, merged across versions.
    helpers = {}
    for version in staging["uapi_versions"]:
        for name, hid in parse_helpers(staging["uapi"][version]["bpf.h"]):
            entry = helpers.setdefault(name, {})
            entry[version] = hid
    for name in sorted(helpers):
        ids = set(helpers[name].values())
        if len(ids) > 1:
            raise InventoryError(
                "helper ID conflict for %s: %s"
                % (name, sorted(helpers[name].items()))
            )

    # Pinned libbpf surface.
    libbpf_version = staging["libbpf_version"]
    map_nodes = parse_libbpf_map(staging["libbpf"]["src/libbpf.map"])
    if not map_nodes:
        raise InventoryError("no version nodes parsed from libbpf.map")
    symbols = {}
    for node, names in map_nodes:
        for name in names:
            symbols.setdefault(name, node)
    declarations = set()
    for header in LIBBPF_DECL_HEADERS:
        declarations |= parse_declarations(staging["libbpf"][header])
    missing_decls = sorted(set(symbols) - declarations)
    if missing_decls:
        raise InventoryError(
            "libbpf.map symbols without header declarations:\n  "
            + "\n  ".join(missing_decls)
        )
    sections = parse_sec_defs(staging["libbpf"]["src/libbpf.c"])
    if not sections:
        raise InventoryError("no SEC_DEF entries parsed from libbpf.c")

    # Pinned LLVM facts, checked against the lock copy.
    llvm = staging["llvm"]
    locked_facts = lock.get("llvm", {}).get("facts", {})
    for key in ("version", "bpf_cpus", "bpf_features", "bpf_targets"):
        if llvm.get(key) != locked_facts.get(key):
            raise InventoryError(
                "llvm facts drift for %r: staged %r locked %r"
                % (key, llvm.get(key), locked_facts.get(key)),
                status=EXIT_INTEGRITY,
            )

    # Pinned selftest index, checked against the lock copy.
    locked_lists = lock.get("selftests", {}).get("lists", {})
    for name in SELFTEST_LISTS:
        if sorted(staging["selftests"][name]) != sorted(
                locked_lists.get(name, [])):
            raise InventoryError(
                "selftest list drift for %s" % name,
                status=EXIT_INTEGRITY,
            )
    selftest_paths = set()
    for name in SELFTEST_LISTS:
        subdir = name[: -len(".paths")]
        for entry in staging["selftests"][name]:
            selftest_paths.add("%s/%s" % (subdir, entry))

    members = []
    records = {}
    unknowns = []

    def add_member(name, container, value, value_text, present_in,
                   classification, record_id=None, canonical_name=None,
                   record_refs=(), note=""):
        members.append({
            "name": name,
            "container": container,
            "value": value,
            "value_text": value_text,
            "present_in": sorted(present_in),
            "classification": classification,
            "record_id": record_id,
            "canonical": canonical_name,
            "record_refs": sorted(record_refs),
            "note": note,
        })

    def add_record(record):
        if record["id"] in records:
            raise InventoryError(
                "duplicate record id %s" % record["id"]
            )
        records[record["id"]] = record

    # -- UAPI atoms ------------------------------------------------------
    for name in sorted(atoms):
        atom = atoms[name]
        filename = sorted(atom.files)[0]
        present = sorted(set(atom.present_in))
        by_age = sorted(present, key=lambda ver: rank.get(ver, 0))
        value = None
        for version in reversed(by_age):
            if atom.values.get(version) is not None:
                value = atom.values[version]
                break
        value_text = None
        for version in reversed(by_age):
            if atom.value_texts.get(version):
                value_text = atom.value_texts[version]
                break
        classification, group, family, note, canonical_name = \
            classify_uapi_atom(name, atom, canonical)
        container = container_of(atom)
        if classification in ("sentinel", "limit"):
            per_version = sorted(
                {atom.values[ver] for ver in present
                 if atom.values.get(ver) is not None}
            )
            if len(per_version) > 1:
                note = (note + "; " if note else "") + "versioned bound: " + (
                    ", ".join("%s=%s" % (ver, atom.values[ver])
                              for ver in by_age
                              if atom.values.get(ver) is not None)
                )
        if classification == "unknown":
            unknowns.append("uapi %s (%s): %s" % (name, container, note))
            continue
        if classification == "context-only":
            refs = ctx_records(name)
            add_member(name, container, value, value_text, present,
                       classification, record_refs=refs,
                       note="consumed by %s" % ", ".join(refs))
            continue
        if classification in ("sentinel", "limit", "excluded"):
            add_member(name, container, value, value_text, present,
                       classification, note=note)
            continue
        if classification == "alias":
            add_member(name, container, value, value_text, present,
                       classification, canonical_name=canonical_name,
                       note="alias of %s" % canonical_name)
            continue
        # Capability: build its record.
        refs = uapi_refs(filename, present, name)
        predicate = uapi_predicate(name, present, rank)
        next_action = "Implement and qualify under %s." % FAMILIES[family][2]
        if group == "prog":
            short = strip_prefix(name, "BPF_PROG_TYPE_")
            rec_id = "prog:" + short
            record = base_record(rec_id, family, refs, predicate, next_action,
                                 "program", "load-attach")
            record["program_types"] = [name]
        elif group == "attach":
            short = strip_prefix(name, "BPF_")
            rec_id = "attach:" + short
            record = base_record(rec_id, family, refs, predicate, next_action,
                                 "not-applicable", "load-attach")
            record["attach_types"] = [name]
        elif group == "link":
            short = strip_prefix(name, "BPF_LINK_TYPE_")
            rec_id = "link:" + short
            record = base_record(rec_id, family, refs, predicate, next_action,
                                 "not-applicable", "load-attach")
            record["link_types"] = [name]
        elif group == "map":
            short = strip_prefix(name, "BPF_MAP_TYPE_")
            rec_id = "map:" + short
            positive = MAP_POSITIVE_OVERRIDE.get(short)
            record = base_record(rec_id, family, refs, predicate, next_action,
                                 "map-type", "map-ops", positive=positive)
            record["map_types"] = [name]
        elif group == "cmd":
            short = strip_prefix(name, "BPF_")
            rec_id = "cmd:" + short
            record = base_record(rec_id, family, refs, predicate, next_action,
                                 "not-applicable", "raw-syscall")
        elif group == "core":
            short = strip_prefix(name, "BPF_CORE_")
            rec_id = "core:" + short
            record = base_record(rec_id, family, refs, predicate, next_action,
                                 "relocation", "not-applicable")
            record["btf_requirements"] = ["target-btf"]
        elif group == "btf":
            short = strip_prefix(name, "BTF_KIND_")
            rec_id = "btf:" + short
            record = base_record(rec_id, family, refs, predicate, next_action,
                                 "btf-type", "not-applicable")
        elif group == "isa":
            rec_id = "isa:" + name
            record = base_record(rec_id, family, refs, predicate, next_action,
                                 "instruction", "not-applicable")
            if family == "kfuncs":
                record["implementation_state"] = "BLOCKED_UPSTREAM"
                record["blocker"] = dict(REGISTRATION_BLOCKER)
        elif group == "flag":
            rec_id = "flag:" + name
            record = base_record(rec_id, family, refs, predicate, next_action,
                                 "flag-option", "option-flag")
            if family == "kfuncs":
                record["implementation_state"] = "BLOCKED_UPSTREAM"
                record["blocker"] = dict(REGISTRATION_BLOCKER)
        else:  # pragma: no cover - guarded by classify_uapi_atom
            raise InventoryError("unhandled group %s" % group)
        add_record(record)
        add_member(name, container, value, value_text, present,
                   "capability", record_id=rec_id, note=note)

    # -- Helpers ---------------------------------------------------------
    for name in sorted(helpers):
        present = sorted(helpers[name])
        hid = helpers[name][present[0]]
        if name == "unspec":
            add_member("BPF_FUNC_unspec", "uapi:bpf.h#helper-mapper", hid,
                       "FN(unspec, 0)", present, "sentinel",
                       note="reserved helper ID 0; not a capability")
            continue
        rec_id = "helper:" + name
        refs = uapi_refs("bpf.h", present, "BPF_FUNC_" + name)
        oldest = min(present, key=lambda ver: rank.get(ver, 0))
        predicate = (
            "kernel UAPI assigns helper ID %d to BPF_FUNC_%s "
            "(first pinned in %s) but callable registration is unpinned"
            % (hid, name, oldest)
        )
        positive = helper_test_case(name) or FAMILIES["helpers"][3][0]
        record = base_record(rec_id, "helpers", refs, predicate,
                             "Pin kernel registration, then implement the "
                             "typed helper intrinsic under X-HELPERS.",
                             "helper-intrinsic", "not-applicable",
                             positive=positive)
        record["helpers_or_kfuncs"] = [{
            "name": "bpf_" + name,
            "kind": "helper",
            "callable": False,
        }]
        record["implementation_state"] = "BLOCKED_UPSTREAM"
        record["blocker"] = dict(REGISTRATION_BLOCKER)
        add_record(record)
        add_member("BPF_FUNC_" + name, "uapi:bpf.h#helper-mapper", hid,
                   "FN(%s, %d)" % (name, hid), present, "capability",
                   record_id=rec_id)

    # -- Library symbols -------------------------------------------------
    for name in sorted(symbols):
        node = symbols[name]
        family = longest_prefix_match(API_FAMILY_PREFIX, name)
        if family is None:
            unknowns.append("libbpf symbol %s: no family rule" % name)
            continue
        rec_id = "api:" + name
        refs = ["libbpf:libbpf.map@%s#%s@%s"
                % (libbpf_version, name, node)]
        predicate = ("libbpf %s exports %s (first version node %s)"
                     % (libbpf_version, name, node))
        record = base_record(
            rec_id, family, refs, predicate,
            "Cover the raw symbol and its typed wrapper under %s."
            % FAMILIES[family][2],
            "not-applicable", "library-symbol")
        add_record(record)
        add_member(name, "libbpf:libbpf.map", None,
                   "%s@%s" % (name, node), [libbpf_version],
                   "capability", record_id=rec_id,
                   note="first exported in %s" % node)

    # -- ELF section conventions ------------------------------------------
    prog_sections = {}
    attach_progs = {}
    for pattern, ptype, atype, flags, _ in sections:
        prog_full = "BPF_PROG_TYPE_" + ptype
        prog_id = "prog:" + ptype
        if prog_id not in records:
            unknowns.append(
                "section %s: program type %s has no record"
                % (pattern, prog_full)
            )
            continue
        if atype is not None and ("attach:" + strip_prefix(atype, "BPF_")
                                  not in records):
            unknowns.append(
                "section %s: attach type %s has no record"
                % (pattern, atype)
            )
            continue
        family = longest_prefix_match(SECTION_FAMILY, pattern)
        if family is None:
            unknowns.append(
                "section %s: no family rule" % pattern
            )
            continue
        rec_id = "section:" + pattern
        refs = ["libbpf:libbpf.c@%s#SEC_DEF(%s)"
                % (libbpf_version, pattern)]
        predicate = (
            "libbpf %s maps ELF section '%s' to %s%s"
            % (libbpf_version, pattern, prog_full,
               (" with attach type " + atype) if atype else "")
        )
        record = base_record(
            rec_id, family, refs, predicate,
            "Qualify the section convention under %s."
            % FAMILIES[family][2],
            "section-convention", "section-convention")
        record["program_types"] = [prog_full]
        record["elf_sections"] = [pattern]
        if atype is not None:
            record["attach_types"] = [atype]
        if "SEC_SLEEPABLE" in flags:
            record["required_flags"] = ["BPF_F_SLEEPABLE"]
        if "SEC_ATTACH_BTF" in flags:
            record["btf_requirements"] = ["attach-btf"]
        add_record(record)
        add_member(pattern, "libbpf:libbpf.c@section_defs", None,
                   "SEC_DEF(%s, %s, %s, %s)"
                   % (pattern, ptype, atype or "0", flags),
                   [libbpf_version], "capability", record_id=rec_id)
        prog_sections.setdefault(prog_id, []).append((pattern, atype))
        if atype is not None:
            attach_progs.setdefault(atype, set()).add(prog_full)

    # Fold section conventions back into program and attach records.
    for prog_id, entries in prog_sections.items():
        record = records[prog_id]
        record["elf_sections"] = sorted(p for p, _ in entries)
        record["attach_types"] = sorted(
            {a for _, a in entries if a is not None})
        for pattern, _ in entries:
            ref = "libbpf:libbpf.c@%s#SEC_DEF(%s)" % (libbpf_version, pattern)
            if ref not in record["upstream_source_refs"]:
                record["upstream_source_refs"].append(ref)
        record["upstream_source_refs"].sort()
    for atype, prog_fulls in attach_progs.items():
        rec_id = "attach:" + strip_prefix(atype, "BPF_")
        if rec_id in records:
            records[rec_id]["program_types"] = sorted(prog_fulls)

    # Program-required flags with certain UAPI evidence.
    if "prog:XDP" in records:
        records["prog:XDP"]["required_flags"] = [
            "BPF_F_XDP_DEV_BOUND_ONLY",
            "BPF_F_XDP_HAS_FRAGS",
        ]

    # -- LLVM toolchain facts ----------------------------------------------
    llvm_version = llvm["version"]
    for cpu in llvm["bpf_cpus"]:
        rec_id = "llvm:cpu-" + cpu
        refs = ["llvm:%s#cpu-%s" % (llvm_version, cpu)]
        record = base_record(
            rec_id, "isa", refs,
            "LLVM %s BPF backend exposes CPU '%s'"
            % (llvm_version, cpu),
            "Qualify codegen for the %s CPU profile under F-ISA." % cpu,
            "instruction", "not-applicable")
        add_record(record)
        add_member("cpu-" + cpu, "llvm:facts", None, cpu,
                   [llvm_version], "capability", record_id=rec_id)
    for feature in llvm["bpf_features"]:
        if feature in EXCLUDED_EXACT:
            add_member("feature-" + feature, "llvm:facts", None, feature,
                       [llvm_version], "excluded",
                       note=EXCLUDED_EXACT[feature])
            continue
        if feature != "alu32":
            unknowns.append("llvm feature %s: no rule" % feature)
            continue
        rec_id = "llvm:feature-alu32"
        record = base_record(
            rec_id, "isa", ["llvm:%s#feature-alu32" % llvm_version],
            "LLVM %s BPF backend exposes the alu32 feature bit"
            % llvm_version,
            "Qualify 32-bit ALU codegen under F-ISA.",
            "instruction", "not-applicable")
        add_record(record)
        add_member("feature-alu32", "llvm:facts", None, "alu32",
                   [llvm_version], "capability", record_id=rec_id)
    for target in llvm["bpf_targets"]:
        family = "endian" if target in ("bpfel", "bpfeb") else "isa"
        rec_id = "llvm:target-" + target
        record = base_record(
            rec_id, family, ["llvm:%s#target-%s" % (llvm_version, target)],
            "LLVM %s registers the %s BPF target" % (llvm_version, target),
            "Qualify %s object generation under %s."
            % (target, FAMILIES[family][2]),
            "not-applicable", "not-applicable")
        add_record(record)
        add_member("target-" + target, "llvm:facts", None, target,
                   [llvm_version], "capability", record_id=rec_id)

    # -- Curated conceptual records -----------------------------------------
    reg_refs = []
    for index in range(11):
        reg_name = "BPF_REG_%d" % index
        if reg_name in atoms:
            reg_refs.extend(uapi_refs(
                "bpf.h", set(atoms[reg_name].present_in), reg_name))
    if reg_refs:
        record = base_record(
            "isa:registers", "isa", reg_refs,
            "kernel UAPI defines the BPF register file r0-r10",
            "Qualify register allocation and calling convention under F-ISA.",
            "instruction", "not-applicable")
        add_record(record)

    elf_records = [
        ("elf:section-conventions",
         ["libbpf:libbpf.c@%s#section_defs" % libbpf_version],
         "libbpf %s section_defs table names every standard ELF section "
         "prefix, program type, attach type and sleepable/BTF flags"
         % libbpf_version,
         "section-convention", "section-convention"),
        ("elf:data-sections",
         ["libbpf:libbpf.c@%s#%s" % (libbpf_version, anchor)
          for anchor in ("MAPS_ELF_SEC", "RODATA_SEC", "KCONFIG_SEC",
                         "KSYMS_SEC", "BTF_ELF_SEC", "BTF_EXT_ELF_SEC")],
         "libbpf %s collects maps, rodata, kconfig, ksyms and BTF "
         "payload sections by fixed ELF section names" % libbpf_version,
         "section-convention", "section-convention"),
        ("elf:license-declaration",
         ["libbpf:libbpf.c@%s#license-section" % libbpf_version],
         "libbpf %s reads the BPF program license from the 'license' "
         "ELF section" % libbpf_version,
         "section-convention", "load-attach"),
    ]
    for rec_id, refs, predicate, compiler, userspace in elf_records:
        record = base_record(
            rec_id, "object-elf", refs, predicate,
            "Qualify standard object layout under F-BTF.",
            compiler, userspace)
        add_record(record)

    if unknowns:
        raise InventoryError(
            "unknown upstream atoms fail completeness; assign an owner "
            "and tests before regenerating:\n  "
            + "\n  ".join(sorted(set(unknowns)))
        )

    # -- Cross-reference checks ----------------------------------------------
    for member in members:
        if member["classification"] == "context-only":
            for ref in member["record_refs"]:
                if ref not in records:
                    raise InventoryError(
                        "context-only %s references missing record %s"
                        % (member["name"], ref)
                    )
        if member["classification"] == "alias":
            target = member["canonical"]
            found = [
                item for item in members
                if item["name"] == target
                and item["container"] == member["container"]
                and item["classification"] in (
                    "capability", "context-only", "limit")
            ]
            if not found:
                raise InventoryError(
                    "alias %s has no classified canonical %s in %s"
                    % (member["name"], target, member["container"])
                )
        if member["classification"] == "capability":
            if member["record_id"] not in records:
                raise InventoryError(
                    "member %s points at missing record %s"
                    % (member["name"], member["record_id"])
                )

    # -- Family-level blockers -------------------------------------------------
    docs = {doc["id"]: doc for doc in lock.get("docs", [])}

    def doc_ref(doc_id):
        doc = docs[doc_id]
        return "%s (sha256 %s)" % (doc["url"], doc["sha256"])

    blockers = []
    struct_ops_tests = [
        "prog_tests/test_struct_ops_module.c",
        "progs/struct_ops_autocreate.c",
    ]
    for path in struct_ops_tests:
        if path not in selftest_paths:
            raise InventoryError(
                "blocker evidence missing from selftest index: %s" % path
            )
    blockers.append({
        "id": "structops-consumers",
        "family": "structops-consumers",
        "status": "BLOCKED_UPSTREAM",
        "detail": "struct_ops consumer registrations (congestion control, "
                  "sched_ext and others in the pinned kernel) need "
                  "kernel-source enumeration; the UAPI pins only the "
                  "STRUCT_OPS program and map types.",
        "source_refs": [
            "linux-uapi:bpf.h@%s#BPF_MAP_TYPE_STRUCT_OPS" % newest_uapi,
            "selftests:%s#%s" % (staging["selftests_tag"],
                                 struct_ops_tests[0]),
            "selftests:%s#%s" % (staging["selftests_tag"],
                                 struct_ops_tests[1]),
        ],
        "next_action": "Pin kernel source, enumerate struct bpf_struct_ops "
                       "registrations per consumer, and bind each to "
                       "qualification tests.",
    })
    if "prog_tests/xsk.c" not in selftest_paths:
        raise InventoryError(
            "blocker evidence missing from selftest index: prog_tests/xsk.c"
        )
    blockers.append({
        "id": "net-afxdp-userspace",
        "family": "net-afxdp",
        "status": "BLOCKED_UPSTREAM",
        "detail": "AF_XDP socket and UMEM userspace lives outside libbpf "
                  "1.7.0, which exports no xsk_* symbols, and outside the "
                  "BPF UAPI; the XSKMAP map record carries the kernel-map "
                  "side only.",
        "source_refs": [
            "selftests:%s#prog_tests/xsk.c" % staging["selftests_tag"],
            "libbpf:libbpf.map@%s (exports no xsk_* symbols)"
            % libbpf_version,
            "linux-uapi:bpf.h@%s#BPF_MAP_TYPE_XSKMAP" % newest_uapi,
        ],
        "next_action": "Bind the explicit companion-socket integration "
                       "and qualify queue, UMEM and zero-copy ownership.",
    })
    sched_hits = sorted(
        path for path in selftest_paths
        if "sched_ext" in path or "/scx" in path or path.startswith("scx")
    )
    if sched_hits:
        raise InventoryError(
            "sched-ext blocker is stale; selftests now cover: %s"
            % ", ".join(sched_hits)
        )
    blockers.append({
        "id": "sched-ext",
        "family": "sched-ext",
        "status": "BLOCKED_UPSTREAM",
        "detail": "The sched_ext interface lives outside the pinned UAPI "
                  "and selftest index; interface shape and stability must "
                  "be pinned from kernel sources before implementation.",
        "source_refs": [
            doc_ref("sched-ext-doc"),
            "selftests:%s#index (contains no sched_ext workload)"
            % staging["selftests_tag"],
        ],
        "next_action": "Pin the sched_ext kernel interface for the target "
                       "cohort and author the minimal-scheduler workload.",
    })
    helper_count = sum(
        1 for item in members
        if item["container"] == "uapi:bpf.h#helper-mapper"
        and item["classification"] == "capability"
    )
    blockers.append({
        "id": "kernel-registration-matrix",
        "family": None,
        "status": "BLOCKED_UPSTREAM",
        "detail": "Helper and kfunc callable program/attach/context "
                  "registration needs a pinned kernel source; %d helper "
                  "IDs are enumerated and zero are registered."
                  % helper_count,
        "source_refs": [
            doc_ref("kfuncs-doc"),
            "linux-uapi:bpf.h@%s#helper-mapper (%d IDs, 0 registered)"
            % (newest_uapi, helper_count),
        ],
        "next_action": "Pin kernel source, extract per-program helper "
                       "prototypes and kfunc registrations, then re-run "
                       "refresh.",
    })
    index_counts = ", ".join(
        "%s %d entries" % (name[: -len(".paths")],
                           len(staging["selftests"][name]))
        for name in SELFTEST_LISTS
    )
    blockers.append({
        "id": "selftest-id-mapping",
        "family": None,
        "status": "PLANNED",
        "detail": "Upstream selftest IDs are pinned but not yet mapped "
                  "onto capability records; records reference project "
                  "harness cases.",
        "source_refs": [
            "selftests:%s#index (%s)"
            % (staging["selftests_tag"], index_counts),
        ],
        "next_action": "Map relevant upstream prog_tests and verifier IDs "
                       "onto records in a later revision.",
    })

    registry = {
        "registry_version": REGISTRY_VERSION,
        "schema_version": SCHEMA_VERSION,
        "revision": REVISION,
        "frozen": True,
        "generated_by": {
            "tool": TOOL_NAME + " refresh",
            "lock_digest": lock["_digest"],
        },
        "packages": [
            {"id": pid, "phase": phase, "title": title}
            for pid, phase, title in PACKAGES
        ],
        "families": [
            {
                "id": fid,
                "title": title,
                "description": description,
                "owner_package": owner,
                "harness_cases": list(cases),
            }
            for fid, (title, description, owner, cases)
            in sorted(FAMILIES.items())
        ],
        "records": [records[rec_id] for rec_id in sorted(records)],
        "enum_members": sorted(
            members, key=lambda item: (item["container"], item["name"])),
        "blockers": sorted(blockers, key=lambda item: item["id"]),
        "notes": [
            "Revision 1 freezes identity, ownership and test mapping; "
            "implementation_state is PLANNED throughout except "
            "registration-gated helpers and kfunc calls.",
            "Implementation assessment reconciles from product evidence "
            "in later revisions; this revision claims no implementation.",
            "The schema and fixture artifact ships at fixed repository "
            "paths and through the export bundle layout.",
        ],
    }
    return registry


# ---------------------------------------------------------------------------
# Schema validation (standard-library subset)
# ---------------------------------------------------------------------------

def _type_matches(value, expected):
    if expected == "null":
        return value is None
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "string":
        return isinstance(value, str)
    if expected == "array":
        return isinstance(value, list)
    if expected == "object":
        return isinstance(value, dict)
    return False


def _check_schema(value, schema, path, errors):
    if not isinstance(schema, dict):
        return
    expected = schema.get("type")
    if expected is not None:
        names = expected if isinstance(expected, list) else [expected]
        if not any(_type_matches(value, name) for name in names):
            errors.append("%s: expected %s" % (path or "document", expected))
            return
    if "const" in schema and value != schema["const"]:
        errors.append("%s: expected const %r" % (path, schema["const"]))
    if "enum" in schema and value not in schema["enum"]:
        errors.append("%s: %r is not an allowed value" % (path, value))
    if isinstance(value, str) and "pattern" in schema:
        if not re.search(schema["pattern"], value):
            errors.append(
                "%s: %r does not match %s" % (path, value, schema["pattern"])
            )
    if isinstance(value, list) and "minItems" in schema:
        if len(value) < schema["minItems"]:
            errors.append(
                "%s: need at least %d items" % (path, schema["minItems"])
            )
    if isinstance(value, list) and "items" in schema:
        for index, item in enumerate(value):
            _check_schema(item, schema["items"],
                          "%s[%d]" % (path, index), errors)
    if isinstance(value, dict):
        for name in schema.get("required", []):
            if name not in value:
                errors.append("%s: missing required %r" % (path, name))
        properties = schema.get("properties", {})
        for name, item in value.items():
            if name in properties:
                _check_schema(item, properties[name],
                              "%s.%s" % (path, name) if path else name,
                              errors)
            elif schema.get("additionalProperties") is False:
                errors.append("%s: unknown field %r" % (path, name))


def validate_schema(document, schema):
    """Return the list of schema violations (empty means valid)."""
    errors = []
    _check_schema(document, schema, "", errors)
    return sorted(errors)


# ---------------------------------------------------------------------------
# Completeness checks
# ---------------------------------------------------------------------------

def check_completeness(registry):
    """Return the list of completeness violations (empty means complete)."""
    errors = []
    packages = registry.get("packages", [])
    package_ids = [entry.get("id") for entry in packages]
    if len(package_ids) != 65 or len(set(package_ids)) != 65:
        errors.append(
            "packages: need exactly 65 unique IDs, found %d (%d unique)"
            % (len(package_ids), len(set(package_ids)))
        )
    package_set = set(package_ids)
    families = {entry.get("id"): entry for entry in registry.get("families", [])}
    records = registry.get("records", [])
    record_ids = [entry.get("id") for entry in records]
    if len(record_ids) != len(set(record_ids)):
        errors.append("records: duplicate record IDs")
    record_set = set(record_ids)
    for entry in records:
        rec_id = entry.get("id", "?")
        owner = entry.get("owner_task")
        if owner not in package_set:
            errors.append("%s: owner %r is not a known package"
                          % (rec_id, owner))
        if entry.get("family") not in families:
            errors.append("%s: family %r is unknown"
                          % (rec_id, entry.get("family")))
        tests = (entry.get("positive_tests", []) + entry.get("negative_tests", [])
                 + entry.get("interaction_tests", []) + entry.get("cost_cases", []))
        if not tests:
            errors.append("%s: no owner tests assigned" % rec_id)
        if not entry.get("upstream_source_refs"):
            errors.append("%s: no upstream source refs" % rec_id)
        if not entry.get("targets_required"):
            errors.append("%s: no required targets" % rec_id)
        if not entry.get("next_action"):
            errors.append("%s: no next action" % rec_id)
        for helper in entry.get("helpers_or_kfuncs", []):
            if helper.get("callable") and not entry.get("kernel_registration_refs"):
                errors.append(
                    "%s: callable %s needs kernel registration refs"
                    % (rec_id, helper.get("name"))
                )
    blockers = registry.get("blockers", [])
    for entry in blockers:
        family = entry.get("family")
        if family is not None and family not in families:
            errors.append("blocker %s: family %r is unknown"
                          % (entry.get("id"), family))
        if not entry.get("source_refs"):
            errors.append("blocker %s: no source refs" % entry.get("id"))
    records_by_family = {}
    for entry in records:
        records_by_family.setdefault(entry.get("family"), []).append(
            entry.get("id"))
    blockers_by_family = {}
    for entry in blockers:
        if entry.get("family"):
            blockers_by_family.setdefault(entry["family"], []).append(
                entry.get("id"))
    for family in sorted(families):
        if not records_by_family.get(family) and not blockers_by_family.get(family):
            errors.append("family %s: no records and no blocker" % family)
    seen_members = set()
    for item in registry.get("enum_members", []):
        key = (item.get("container"), item.get("name"))
        if key in seen_members:
            errors.append("enum_members: %s classified twice" % (key,))
        seen_members.add(key)
        classification = item.get("classification")
        if classification == "capability":
            if item.get("record_id") not in record_set:
                errors.append("%s: capability record %r is missing"
                              % (item.get("name"), item.get("record_id")))
        elif classification == "context-only":
            if not item.get("record_refs"):
                errors.append("%s: context-only value is lost" % item.get("name"))
            for ref in item.get("record_refs", []):
                if ref not in record_set:
                    errors.append("%s: record ref %r is missing"
                                  % (item.get("name"), ref))
        elif classification == "alias":
            if not item.get("canonical"):
                errors.append("%s: alias without canonical" % item.get("name"))
        elif classification in ("sentinel", "limit", "excluded"):
            if item.get("record_id") is not None:
                errors.append("%s: %s must not own a record"
                              % (item.get("name"), classification))
        else:
            errors.append("%s: bad classification %r"
                          % (item.get("name"), classification))
    return sorted(errors)


# ---------------------------------------------------------------------------
# Deterministic diff
# ---------------------------------------------------------------------------

def diff_documents(old, new):
    """Return a deterministic diff dict between two registry documents."""
    diff = {"added": [], "removed": [], "changed": []}
    old_records = {entry["id"]: entry for entry in old.get("records", [])}
    new_records = {entry["id"]: entry for entry in new.get("records", [])}
    for rec_id in sorted(set(new_records) - set(old_records)):
        diff["added"].append(rec_id)
    for rec_id in sorted(set(old_records) - set(new_records)):
        diff["removed"].append(rec_id)
    for rec_id in sorted(set(old_records) & set(new_records)):
        fields = []
        old_entry, new_entry = old_records[rec_id], new_records[rec_id]
        for field in sorted(set(old_entry) | set(new_entry)):
            if old_entry.get(field) != new_entry.get(field):
                fields.append(field)
        if fields:
            diff["changed"].append({"id": rec_id, "fields": fields})

    def member_key(item):
        return (item.get("container"), item.get("name"))

    old_members = {member_key(item): item for item in old.get("enum_members", [])}
    new_members = {member_key(item): item for item in new.get("enum_members", [])}
    diff["members_added"] = sorted(
        "%s#%s" % key for key in set(new_members) - set(old_members)
    )
    diff["members_removed"] = sorted(
        "%s#%s" % key for key in set(old_members) - set(new_members)
    )
    changed_members = []
    for key in sorted(set(old_members) & set(new_members)):
        fields = [
            field for field in sorted(set(old_members[key]) | set(new_members[key]))
            if old_members[key].get(field) != new_members[key].get(field)
        ]
        if fields:
            changed_members.append({"member": "%s#%s" % key, "fields": fields})
    diff["members_changed"] = changed_members
    return diff


def format_diff(diff):
    lines = []
    for rec_id in diff["added"]:
        lines.append("record added: %s" % rec_id)
    for rec_id in diff["removed"]:
        lines.append("record removed: %s" % rec_id)
    for entry in diff["changed"]:
        lines.append("record changed: %s (%s)"
                     % (entry["id"], ", ".join(entry["fields"])))
    for member in diff["members_added"]:
        lines.append("member added: %s" % member)
    for member in diff["members_removed"]:
        lines.append("member removed: %s" % member)
    for entry in diff["members_changed"]:
        lines.append("member changed: %s (%s)"
                     % (entry["member"], ", ".join(entry["fields"])))
    return "\n".join(lines) + ("\n" if lines else "")


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------

def repo_relative(path, anchor):
    if os.path.isabs(path):
        return path
    return os.path.join(anchor, path)


def cmd_refresh(args):
    lock_path = repo_relative(args.lock, args.root)
    lock = load_json(lock_path)
    lock["_digest"] = sha256_file(lock_path)
    try:
        if args.rebase_lock:
            delta = verify_staging(args.sources, lock, rebase=True)
            with open(lock_path, "w", encoding="utf-8") as handle:
                clean = {key: value for key, value in lock.items()
                         if key != "_digest"}
                handle.write(dump_canonical(clean))
            lock["_digest"] = sha256_file(lock_path)
            print("lock rebased: %s" % lock_path)
            for line in delta:
                print("  " + line)
            if not delta:
                print("  no drift; lock unchanged")
        else:
            verify_staging(args.sources, lock)
        staging = load_staging(args.sources, lock)
        registry = inventory(staging, lock)
    except InventoryError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return exc.status
    registry_path = repo_relative(args.registry, args.root)
    with open(registry_path, "w", encoding="utf-8") as handle:
        handle.write(dump_canonical(registry))
    print("wrote %s (%d records, %d members)" % (
        registry_path, len(registry["records"]),
        len(registry["enum_members"])))
    return EXIT_OK


def cmd_validate(args):
    schema = load_json(repo_relative(args.schema, args.root))
    registry = load_json(repo_relative(args.registry, args.root))
    errors = validate_schema(registry, schema)
    errors.extend(check_completeness(registry))
    if errors:
        for line in sorted(set(errors)):
            print("error: %s" % line, file=sys.stderr)
        return EXIT_INVALID
    print("valid: %d records, %d members, %d blockers" % (
        len(registry["records"]), len(registry["enum_members"]),
        len(registry["blockers"])))
    return EXIT_OK


def cmd_diff(args):
    old = load_json(args.old)
    new = load_json(args.new)
    diff = diff_documents(old, new)
    output = format_diff(diff)
    if output:
        print(output, end="")
    else:
        print("no differences")
    return EXIT_OK


def cmd_export(args):
    registry_path = repo_relative(args.registry, args.root)
    schema_path = repo_relative(args.schema, args.root)
    os.makedirs(args.out, exist_ok=True)
    files = {}
    for source, name in ((registry_path, "registry.json"),
                         (schema_path, "capability.schema.json")):
        with open(source, "rb") as handle:
            data = handle.read()
        with open(os.path.join(args.out, name), "wb") as handle:
            handle.write(data)
        files[name] = hashlib.sha256(data).hexdigest()
    bundle = {
        "bundle": REGISTRY_VERSION,
        "revision": REVISION,
        "files": files,
    }
    with open(os.path.join(args.out, "DIGESTS.json"), "w",
              encoding="utf-8") as handle:
        handle.write(dump_canonical(bundle))
    print("exported bundle to %s" % args.out)
    return EXIT_OK


def build_parser():
    parser = argparse.ArgumentParser(
        description="Upstream capability inventory tool.")
    parser.add_argument("--root", default=".",
                        help="repository root for relative paths")
    sub = parser.add_subparsers(dest="command", required=True)
    refresh = sub.add_parser("refresh", help="regenerate the registry")
    refresh.add_argument("--sources", required=True,
                         help="staged upstream sources directory")
    refresh.add_argument("--lock", default="capabilities/upstream.lock.json")
    refresh.add_argument("--registry", default="capabilities/registry.json")
    refresh.add_argument("--rebase-lock", action="store_true",
                         help="accept staged content as the new pin")
    refresh.set_defaults(func=cmd_refresh)
    validate = sub.add_parser("validate", help="validate a registry")
    validate.add_argument("--schema",
                          default="schemas/capability.schema.json")
    validate.add_argument("--registry",
                          default="capabilities/registry.json")
    validate.set_defaults(func=cmd_validate)
    diff = sub.add_parser("diff", help="diff two registries")
    diff.add_argument("old")
    diff.add_argument("new")
    diff.set_defaults(func=cmd_diff)
    export = sub.add_parser("export", help="export a pinned bundle")
    export.add_argument("--out", required=True)
    export.add_argument("--registry", default="capabilities/registry.json")
    export.add_argument("--schema", default="schemas/capability.schema.json")
    export.set_defaults(func=cmd_export)
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
