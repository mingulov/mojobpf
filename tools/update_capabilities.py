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

    refresh  verify staged sources against the lock, regenerate the
             registry, validate it before publishing, and record the
             published digest in the lock
    validate check a registry against the schema, the completeness
             rules and the lock binding (with --sources, also demand
             byte-identity with a fresh inventory run)
    diff     deterministic difference between two registry documents,
             covering records, members, blockers, families, packages
             and revision/provenance metadata
    export   write a digest-pinned distribution bundle (registry + schema)

Staging layout for ``refresh --sources DIR`` (paths relative to DIR)::

    uapi/<version>/bpf.h            pinned kernel UAPI, one directory per version
    uapi/<version>/btf.h
    uapi/<version>/bpf_common.h
    uapi/<version>/bpf_perf_event.h
    linux/<version>/<path>          pinned kernel registration sources
                                    (func_proto tables, verifier ops,
                                    kfunc sets, bpf_types.h, btf.c);
                                    per-version file list in the lock
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
# Registry revisions this tool can generate and read. The revision itself
# comes from the lock file; anything outside this set is rejected.
SUPPORTED_REGISTRY_REVISIONS = frozenset({1})

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
    ("R-EXISTING-GATE", "P1", "Close the original release gate and initial public gate without widening it"),
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

# Upstream selftest ID mapping: (subdir, filename) exact matches win,
# then the longest matching filename-stem prefix. Every pinned selftest
# ID must map onto a record or be cited as blocker evidence; anything
# else aborts generation. Anchors name the most specific record for the
# exercised capability; broad stems anchor the family's central record.
SELFTEST_EXACT = {
    ("prog_tests", "xsk.c"): "map:XSKMAP",
    ("prog_tests", "test_xsk.c"): "map:XSKMAP",
    ("prog_tests", "test_urandom_usdt.c"): "section:usdt+",
    ("prog_tests", "missed.c"): "prog:PERF_EVENT",
    ("prog_tests", "test_bpf_smc.c"): "prog:SYSCALL",
    ("prog_tests", "prepare.c"): "cmd:PROG_LOAD",
    ("progs", "bpf_smc.c"): "prog:SYSCALL",
    ("progs", "prepare.c"): "cmd:PROG_LOAD",
    ("progs", "test_ctx.c"): "prog:SCHED_CLS",
    ("prog_tests", "prog_tests_framework.c"): "api:bpf_object__open",
    ("progs", "test_misc_tcp_hdr_options.c"): "prog:SCHED_CLS",
    ("progs", "twfw.c"): "prog:SCHED_CLS",
    ("progs", "irq.c"): "prog:PERF_EVENT",
    ("progs", "priv_map.c"): "map:HASH",
    ("progs", "priv_prog.c"): "cmd:PROG_LOAD",
    ("progs", "priv_freplace_prog.c"): "section:freplace+",
    ("progs", "test_lirc_mode2_kern.c"): "prog:LIRC_MODE2",
    ("progs", "test_sockhash_kern.c"): "map:SOCKHASH",
    ("progs", "test_stack_map.c"): "map:STACK_TRACE",
    ("progs", "test_assign_reuse.c"): "map:REUSEPORT_SOCKARRAY",
    ("progs", "test_select_reuseport_kern.c"): "prog:SK_REUSEPORT",
    ("progs", "test_send_signal_kern.c"): "helper:send_signal",
    ("progs", "test_btf_decl_tag.c"): "btf:DECL_TAG",
    ("progs", "test_btf_newkv.c"): "btf:STRUCT",
    ("progs", "test_btf_nokv.c"): "btf:STRUCT",
    ("progs", "mmap_inner_array.c"): "map:ARRAY_OF_MAPS",
    ("progs", "test_mmap_inner_array.c"): "map:ARRAY_OF_MAPS",
    ("progs", "update_map_in_htab.c"): "map:HASH_OF_MAPS",
    ("progs", "unsupported_ops.c"): "prog:STRUCT_OPS",
    ("progs", "trace_dummy_st_ops.c"): "prog:STRUCT_OPS",
    ("progs", "test_signed_loader_lsm.c"): "prog:LSM",
    ("progs", "test_signed_loader_map.c"): "cmd:PROG_LOAD",
    ("progs", "test_signed_loader_data.c"): "cmd:PROG_LOAD",
    ("progs", "socket_cookie_prog.c"): "helper:get_socket_cookie",
    ("progs", "get_cgroup_id_kern.c"): "helper:get_current_cgroup_id",
    ("progs", "local_storage_bench.c"): "map:TASK_STORAGE",
    ("progs", "htab_mem_bench.c"): "map:HASH",
}

SELFTEST_PREFIX = (
    # Userspace probes, kernel probes, USDT.
    ("uprobe_multi_session", "attach:TRACE_UPROBE_SESSION"),
    ("uprobe_multi", "attach:TRACE_UPROBE_MULTI"),
    ("uprobe_syscall", "prog:KPROBE"),
    ("uprobe", "section:uprobe+"),
    ("uretprobe", "section:uretprobe+"),
    ("usdt", "section:usdt+"),
    ("test_urandom", "section:usdt+"),
    ("kprobe_multi", "attach:TRACE_KPROBE_MULTI"),
    ("kprobe", "prog:KPROBE"),
    ("kretprobe", "prog:KPROBE"),
    ("ksyscall", "prog:KPROBE"),
    ("ksym", "prog:KPROBE"),
    ("test_ksyms", "prog:KPROBE"),
    ("kretsyscall", "prog:KPROBE"),
    ("missed_kprobe", "prog:KPROBE"),
    ("test_attach_kprobe_sleepable", "prog:KPROBE"),
    ("test_attach_probe", "section:kprobe+"),
    ("attach_probe", "prog:KPROBE"),
    # Tracepoints and perf.
    ("test_tracepoint", "section:tracepoint+"),
    ("tracepoint", "section:tracepoint+"),
    ("test_tp_btf", "section:tp_btf+"),
    ("tp_btf", "section:tp_btf+"),
    ("tp_attach_query", "cmd:PROG_QUERY"),
    ("raw_tracepoint", "section:raw_tp+"),
    ("raw_tp", "section:raw_tp+"),
    ("rcu_tasks_trace_gp", "prog:RAW_TRACEPOINT"),
    ("sleepable_tracepoint", "prog:TRACEPOINT"),
    ("test_sleepable_tracepoint", "prog:TRACEPOINT"),
    ("missed_tp", "prog:TRACEPOINT"),
    ("perf_event_stackmap", "map:STACK_TRACE"),
    ("test_perf_buffer", "map:PERF_EVENT_ARRAY"),
    ("perf_buffer", "map:PERF_EVENT_ARRAY"),
    ("perfbuf_bench", "map:PERF_EVENT_ARRAY"),
    ("test_perf_branches", "prog:PERF_EVENT"),
    ("perf_branches", "prog:PERF_EVENT"),
    ("test_perf_link", "link:PERF_EVENT"),
    ("perf_link", "link:PERF_EVENT"),
    ("test_perf_skip", "prog:PERF_EVENT"),
    ("perf_skip", "prog:PERF_EVENT"),
    ("test_pe_preserve_elems", "prog:PERF_EVENT"),
    ("pe_preserve_elems", "prog:PERF_EVENT"),
    ("test_get_stack_rawtp", "helper:get_stack"),
    ("get_stack_rawtp", "helper:get_stack"),
    ("get_stackid_cannot_attach", "helper:get_stackid"),
    ("get_stack_raw_tp", "helper:get_stack"),
    ("stacktrace", "map:STACK_TRACE"),
    ("test_stacktrace", "map:STACK_TRACE"),
    ("pyperf", "prog:PERF_EVENT"),
    ("profiler", "prog:PERF_EVENT"),
    ("test_profiler", "prog:PERF_EVENT"),
    ("get_branch_snapshot", "helper:get_branch_snapshot"),
    # Typed tracing and freplace.
    ("fmod_ret_freplace", "section:fmod_ret+"),
    ("fmod_ret", "section:fmod_ret+"),
    ("fentry", "section:fentry+"),
    ("fexit", "section:fexit+"),
    ("fsession", "section:fsession+"),
    ("get_func_ip", "helper:get_func_ip"),
    ("get_func_arg", "helper:get_func_arg"),
    ("get_func_ret", "helper:get_func_ret"),
    ("get_attach_cookie", "helper:get_attach_cookie"),
    ("get_retval", "helper:get_retval"),
    ("set_retval", "helper:set_retval"),
    ("modify_return", "attach:MODIFY_RETURN"),
    ("freplace", "section:freplace+"),
    ("summarization", "section:freplace+"),
    ("tracing_multi", "attach:TRACE_FENTRY_MULTI"),
    ("tracing_struct", "prog:TRACING"),
    ("tracing_failure", "prog:TRACING"),
    ("trace_ext", "prog:TRACING"),
    ("test_trace_ext", "prog:TRACING"),
    ("livepatch_trampoline", "prog:TRACING"),
    ("trampoline_count", "prog:TRACING"),
    ("test_trampoline_count", "prog:TRACING"),
    ("test_module_attach", "prog:TRACING"),
    ("module_attach", "prog:TRACING"),
    ("module_fentry_shadow", "prog:TRACING"),
    ("async_stack_depth", "prog:TRACING"),
    ("exceptions", "prog:TRACING"),
    ("exhandler", "prog:TRACING"),
    ("read_vsyscall", "prog:KPROBE"),
    ("wakeup_source", "prog:TRACING"),
    ("test_wakeup_source", "prog:TRACING"),
    ("trace_printk", "helper:trace_printk"),
    ("trace_vprintk", "helper:trace_vprintk"),
    ("legacy_printk", "helper:trace_printk"),
    ("test_legacy_printk", "helper:trace_printk"),
    # XDP.
    ("test_xdp_update_frags", "section:xdp.frags"),
    ("xdp_adjust_frags", "section:xdp.frags"),
    ("xdp_dev_bound_only", "flag:BPF_F_XDP_DEV_BOUND_ONLY"),
    ("xdp_metadata", "prog:XDP"),
    ("test_xdp_meta", "prog:XDP"),
    ("xdp_pull_data", "kfunc:bpf_xdp_pull_data"),
    ("test_xdp_pull_data", "kfunc:bpf_xdp_pull_data"),
    ("test_xdp_do_redirect", "helper:redirect"),
    ("xdp_do_redirect", "helper:redirect"),
    ("test_xdp_with_cpumap", "map:CPUMAP"),
    ("xdp_cpumap_attach", "map:CPUMAP"),
    ("test_xdp_with_devmap", "map:DEVMAP"),
    ("test_xdp_devmap", "map:DEVMAP"),
    ("xdp_devmap_attach", "map:DEVMAP"),
    ("test_xdp_link", "link:XDP"),
    ("xdp_link", "link:XDP"),
    ("test_xdp_context_test_run", "cmd:PROG_TEST_RUN"),
    ("xdp_context_test_run", "cmd:PROG_TEST_RUN"),
    ("xdp_info", "cmd:OBJ_GET_INFO_BY_FD"),
    ("test_xdp_dynptr", "kfunc:bpf_dynptr_from_xdp"),
    ("test_xdp_loop", "helper:loop"),
    ("test_xdp_bpf2bpf", "prog:XDP"),
    ("xdp_bpf2bpf", "prog:XDP"),
    ("test_xdp_veth", "prog:XDP"),
    ("xdp", "prog:XDP"),
    ("xsk", "map:XSKMAP"),
    ("test_xdp", "prog:XDP"),
    ("netif_receive_skb", "prog:XDP"),
    # TC, TCX, netkit, flow dissector, netfilter.
    ("test_tc_change_tail", "helper:skb_change_tail"),
    ("tc_change_tail", "helper:skb_change_tail"),
    ("test_tc_link", "link:TCX"),
    ("tc_links", "link:TCX"),
    ("test_tc_neigh", "section:netkit/primary"),
    ("tc_netkit", "section:netkit/primary"),
    ("test_tunnel", "helper:skb_set_tunnel_key"),
    ("test_tc_tunnel", "helper:skb_set_tunnel_key"),
    ("test_tunnel_kern", "helper:skb_set_tunnel_key"),
    ("test_csum_diff", "helper:csum_diff"),
    ("csum_diff", "helper:csum_diff"),
    ("test_l4lb", "prog:SCHED_CLS"),
    ("l4lb", "prog:SCHED_CLS"),
    ("test_pkt_access", "prog:SCHED_CLS"),
    ("pkt_access", "prog:SCHED_CLS"),
    ("test_pkt_md_access", "prog:SCHED_CLS"),
    ("pkt_md_access", "prog:SCHED_CLS"),
    ("empty_skb", "prog:SCHED_CLS"),
    ("test_skb_ctx", "prog:SCHED_CLS"),
    ("skb_ctx", "prog:SCHED_CLS"),
    ("skb_load_bytes", "helper:skb_load_bytes"),
    ("load_bytes_relative", "helper:skb_load_bytes"),
    ("test_skb_helpers", "helper:skb_load_bytes"),
    ("skb_helpers", "helper:skb_load_bytes"),
    ("test_skb_pkt_end", "prog:SCHED_CLS"),
    ("skb_pkt_end", "prog:SCHED_CLS"),
    ("test_dst_clear", "prog:SCHED_CLS"),
    ("decap_sanity", "prog:SCHED_CLS"),
    ("ctx_rewrite", "prog:SCHED_CLS"),
    ("test_check_mtu", "helper:check_mtu"),
    ("check_mtu", "helper:check_mtu"),
    ("test_seg6_loop", "prog:LWT_SEG6LOCAL"),
    ("test_ctx", "prog:SCHED_CLS"),
    ("cls_redirect", "prog:SCHED_CLS"),
    ("test_cls_redirect", "prog:SCHED_CLS"),
    ("test_tc_edt", "prog:SCHED_CLS"),
    ("test_tc_dtime", "prog:SCHED_CLS"),
    ("test_tc_peer", "prog:SCHED_CLS"),
    ("test_tc_bpf", "prog:SCHED_CLS"),
    ("tc_redirect", "prog:SCHED_CLS"),
    ("tc_bpf", "prog:SCHED_CLS"),
    ("tc_bpf2bpf", "prog:SCHED_CLS"),
    ("tc_dummy", "prog:SCHED_CLS"),
    ("tc_opts", "prog:SCHED_CLS"),
    ("tc_qevent", "prog:SCHED_CLS"),
    ("test_tc_qevent", "prog:SCHED_CLS"),
    ("strobemeta", "prog:SCHED_CLS"),
    ("test_btf_skc_cls_ingress", "prog:SCHED_CLS"),
    ("btf_skc_cls_ingress", "prog:SCHED_CLS"),
    ("bpf_flow", "prog:FLOW_DISSECTOR"),
    ("flow_dissector", "prog:FLOW_DISSECTOR"),
    ("test_bpf_nf", "prog:NETFILTER"),
    ("bpf_nf", "prog:NETFILTER"),
    ("test_netfilter_link_attach", "prog:NETFILTER"),
    ("netfilter_link_attach", "prog:NETFILTER"),
    ("ip_check_defrag", "flag:BPF_F_NETFILTER_IP_DEFRAG"),
    # Sockets, sockmap, sockops, reuseport, lookup.
    ("test_sockmap", "map:SOCKMAP"),
    ("bench_sockmap_prog", "map:SOCKMAP"),
    ("sockmap", "map:SOCKMAP"),
    ("mptcp", "map:SOCKMAP"),
    ("sock_iter_batch", "attach:TRACE_ITER"),
    ("sockmap_parse_prog", "prog:SK_MSG"),
    ("sockmap_tcp_msg_prog", "prog:SK_MSG"),
    ("sockmap_verdict_prog", "prog:SK_MSG"),
    ("test_tcpbpf_kern", "prog:SOCK_OPS"),
    ("tcpbpf_user", "prog:SOCK_OPS"),
    ("test_tcp_custom_syncookie", "prog:SOCK_OPS"),
    ("tcp_custom_syncookie", "prog:SOCK_OPS"),
    ("test_tcp_estats", "prog:SOCK_OPS"),
    ("tcp_estats", "prog:SOCK_OPS"),
    ("test_tcp_hdr_options", "prog:SOCK_OPS"),
    ("tcp_hdr_options", "prog:SOCK_OPS"),
    ("test_parse_tcp_hdr_opt", "prog:SOCK_OPS"),
    ("parse_tcp_hdr_opt", "prog:SOCK_OPS"),
    ("tcp_rtt", "prog:SOCK_OPS"),
    ("test_tcpnotify_kern", "prog:SOCK_OPS"),
    ("sock_ops_get_sk", "prog:SOCK_OPS"),
    ("net_timestamping", "prog:SOCK_OPS"),
    ("tcp_ca", "prog:STRUCT_OPS"),
    ("bpf_cc_cubic", "prog:STRUCT_OPS"),
    ("bpf_cubic", "prog:STRUCT_OPS"),
    ("bpf_dctcp", "prog:STRUCT_OPS"),
    ("bpf_tcp_ca", "prog:STRUCT_OPS"),
    ("bpf_tcp_nogpl", "prog:STRUCT_OPS"),
    ("sockopt_qos_to_cc", "prog:CGROUP_SOCKOPT"),
    ("test_sk_lookup", "prog:SK_LOOKUP"),
    ("sk_lookup", "prog:SK_LOOKUP"),
    ("vrf_socket_lookup", "prog:SK_LOOKUP"),
    ("test_sk_assign", "helper:sk_assign"),
    ("sk_assign", "helper:sk_assign"),
    ("test_skmsg_load_helpers", "prog:SK_MSG"),
    ("sk_msg", "prog:SK_MSG"),
    ("sk_skb", "prog:SK_SKB"),
    ("sk_storage", "map:SK_STORAGE"),
    ("test_sk_storage", "map:SK_STORAGE"),
    ("sk_bypass_prot_mem", "prog:SOCK_OPS"),
    ("test_skc_to_unix_sock", "prog:CGROUP_SOCK_ADDR"),
    ("skc_to_unix_sock", "prog:CGROUP_SOCK_ADDR"),
    ("socket_cookie", "helper:get_socket_cookie"),
    ("sendmsg", "prog:CGROUP_SOCK_ADDR"),
    ("recvmsg", "prog:CGROUP_SOCK_ADDR"),
    ("connect", "prog:CGROUP_SOCK_ADDR"),
    ("bind", "prog:CGROUP_SOCK_ADDR"),
    ("getpeername", "prog:CGROUP_SOCK_ADDR"),
    ("getsockname", "prog:CGROUP_SOCK_ADDR"),
    ("sock_addr", "prog:CGROUP_SOCK_ADDR"),
    ("xfrm_info", "prog:CGROUP_SOCK_ADDR"),
    ("sock_create", "prog:CGROUP_SOCK"),
    ("sock_post_bind", "prog:CGROUP_SOCK"),
    ("sock_destroy", "prog:CGROUP_SOCK"),
    ("test_migrate_reuseport", "prog:SK_REUSEPORT"),
    ("migrate_reuseport", "prog:SK_REUSEPORT"),
    ("test_select_reuseport", "prog:SK_REUSEPORT"),
    ("select_reuseport", "prog:SK_REUSEPORT"),
    ("assign_reuse", "map:REUSEPORT_SOCKARRAY"),
    ("setget_sockopt", "prog:CGROUP_SOCKOPT"),
    ("sockopt_inherit", "prog:CGROUP_SOCKOPT"),
    ("sockopt_multi", "prog:CGROUP_SOCKOPT"),
    ("sockopt_sk", "prog:CGROUP_SOCKOPT"),
    ("sockopt", "prog:CGROUP_SOCKOPT"),
    ("connect_force_port", "prog:CGROUP_SOCK_ADDR"),
    ("connect_ping", "prog:CGROUP_SOCK_ADDR"),
    ("bind_perm", "prog:CGROUP_SOCK_ADDR"),
    ("cgroup_getset_retval", "prog:CGROUP_SOCKOPT"),
    # Cgroup skb/device/sysctl/sockopt, LWT.
    ("cgroup_skb", "prog:CGROUP_SKB"),
    ("cgroup_tcp_skb", "prog:CGROUP_SKB"),
    ("cgroup_device", "prog:CGROUP_DEVICE"),
    ("cgroup_dev", "prog:CGROUP_DEVICE"),
    ("dev_cgroup", "prog:CGROUP_DEVICE"),
    ("test_sysctl", "prog:CGROUP_SYSCTL"),
    ("cgroup_sysctl", "prog:CGROUP_SYSCTL"),
    ("test_sysctl_loop", "prog:CGROUP_SYSCTL"),
    ("test_sysctl_prog", "prog:CGROUP_SYSCTL"),
    ("cgroup_sockopt", "prog:CGROUP_SOCKOPT"),
    ("cgrp_local_storage", "map:CGRP_STORAGE"),
    ("cgrp_ls", "map:CGRP_STORAGE"),
    ("cg_storage_multi", "map:CGRP_STORAGE"),
    ("cgroup_storage", "map:CGROUP_STORAGE"),
    ("cgrp_kfunc", "kfunc:bpf_cgroup_acquire"),
    ("cgroup_iter", "attach:TRACE_ITER"),
    ("test_cgroup_link", "link:CGROUP"),
    ("cgroup_link", "link:CGROUP"),
    ("cgroup_mprog", "flag:BPF_F_ALLOW_MULTI"),
    ("cgroup_preorder", "flag:BPF_F_PREORDER"),
    ("cgroup_attach_autodetach", "cmd:PROG_DETACH"),
    ("cgroup_attach_multi", "flag:BPF_F_ALLOW_MULTI"),
    ("cgroup_attach_override", "flag:BPF_F_ALLOW_OVERRIDE"),
    ("cgroup_attach", "cmd:PROG_ATTACH"),
    ("cgroup_ancestor", "cmd:PROG_ATTACH"),
    ("cgroup_v1v2", "cmd:PROG_ATTACH"),
    ("test_cgroup1_hierarchy", "cmd:PROG_ATTACH"),
    ("cgroup1_hierarchy", "cmd:PROG_ATTACH"),
    ("cgroup_hierarchical_stats", "prog:CGROUP_SKB"),
    ("cgroup_xattr", "prog:CGROUP_SKB"),
    ("read_cgroupfs_xattr", "prog:CGROUP_SKB"),
    ("cgroup_read_xattr", "prog:CGROUP_SKB"),
    ("cgroup_get_current_cgroup_id", "helper:get_current_cgroup_id"),
    ("netcnt", "prog:CGROUP_SKB"),
    ("udp_limit", "prog:CGROUP_SKB"),
    ("sock_fields", "prog:CGROUP_SKB"),
    ("test_sock_fields", "prog:CGROUP_SKB"),
    ("lwt_seg6local", "prog:LWT_SEG6LOCAL"),
    ("test_lwt_seg6local", "prog:LWT_SEG6LOCAL"),
    ("lwt_redirect", "prog:LWT_XMIT"),
    ("test_lwt_redirect", "prog:LWT_XMIT"),
    ("lwt_reroute", "prog:LWT_XMIT"),
    ("test_lwt_reroute", "prog:LWT_XMIT"),
    ("lwt_ip_encap", "helper:lwt_push_encap"),
    ("test_lwt_ip_encap", "helper:lwt_push_encap"),
    ("lwt_misc", "prog:LWT_IN"),
    ("lwt", "prog:LWT_XMIT"),
    # Maps.
    ("map_in_map", "map:ARRAY_OF_MAPS"),
    ("test_map_in_map", "map:ARRAY_OF_MAPS"),
    ("access_map_in_map", "map:ARRAY_OF_MAPS"),
    ("map_excl", "helper:map_lookup_elem"),
    ("test_map_init", "cmd:MAP_CREATE"),
    ("map_init", "cmd:MAP_CREATE"),
    ("map_kptr", "helper:kptr_xchg"),
    ("test_map_lock", "flag:BPF_F_LOCK"),
    ("map_lock", "flag:BPF_F_LOCK"),
    ("test_map_lookup_percpu_elem", "helper:map_lookup_percpu_elem"),
    ("map_lookup_percpu_elem", "helper:map_lookup_percpu_elem"),
    ("test_map_ops", "cmd:MAP_UPDATE_ELEM"),
    ("map_ops", "cmd:MAP_UPDATE_ELEM"),
    ("map_ptr", "cmd:MAP_LOOKUP_ELEM"),
    ("map_btf", "btf:STRUCT"),
    ("normal_map_btf", "btf:STRUCT"),
    ("test_btf_map_in_map", "btf:STRUCT"),
    ("btf_map_in_map", "btf:STRUCT"),
    ("map_percpu_stats", "map:PERCPU_ARRAY"),
    ("test_lookup_and_delete", "map:HASH"),
    ("lookup_and_delete", "map:HASH"),
    ("test_lookup_key", "map:HASH"),
    ("lookup_key", "map:HASH"),
    ("inner_array_lookup", "map:ARRAY_OF_MAPS"),
    ("fd_htab_lookup", "map:HASH"),
    ("htab_update", "map:HASH"),
    ("htab_reuse", "map:HASH"),
    ("htab", "map:HASH"),
    ("test_hash_large_key", "map:HASH"),
    ("hash_large_key", "map:HASH"),
    ("hashmap", "map:HASH"),
    ("bpf_hashmap", "map:HASH"),
    ("lru_bug", "map:LRU_HASH"),
    ("lru_lock_nmi", "map:LRU_HASH"),
    ("lru", "map:LRU_HASH"),
    ("lpm_trie", "map:LPM_TRIE"),
    ("percpu_array_inner_map", "map:PERCPU_ARRAY"),
    ("percpu", "map:PERCPU_ARRAY"),
    ("bloom_filter", "map:BLOOM_FILTER"),
    ("rhash", "map:RHASH"),
    ("test_queue_map", "map:QUEUE"),
    ("queue_stack_map", "map:QUEUE"),
    ("test_ringbuf", "map:RINGBUF"),
    ("ringbuf", "map:RINGBUF"),
    ("user_ringbuf", "map:USER_RINGBUF"),
    ("arena", "map:ARENA"),
    ("libarena", "map:ARENA"),
    ("stream", "cmd:PROG_STREAM_READ_BY_FD"),
    ("test_task_local_data", "map:TASK_STORAGE"),
    ("task_local_data", "map:TASK_STORAGE"),
    ("test_local_storage", "map:TASK_STORAGE"),
    ("local_storage", "map:TASK_STORAGE"),
    ("bench_local_storage_create", "map:TASK_STORAGE"),
    ("task_local_storage", "map:TASK_STORAGE"),
    ("task_ls_recursion", "map:TASK_STORAGE"),
    ("task_ls_uptr", "map:TASK_STORAGE"),
    ("task_local_storage_exit_creds", "map:TASK_STORAGE"),
    ("task_storage_nodeadlock", "map:TASK_STORAGE"),
    ("percpu_alloc", "kfunc:bpf_percpu_obj_new"),
    ("test_bpf_ma", "kfunc:bpf_obj_new"),
    ("preempted_bpf_ma_op", "kfunc:bpf_obj_new"),
    ("fd_array", "map:PROG_ARRAY"),
    ("test_prog_array_init", "map:PROG_ARRAY"),
    ("prog_array_init", "map:PROG_ARRAY"),
    ("test_pinning_devmap", "map:DEVMAP"),
    ("pinning_devmap", "map:DEVMAP"),
    ("test_pinning_htab", "map:HASH"),
    ("pinning_htab", "map:HASH"),
    ("test_pinning", "cmd:OBJ_PIN"),
    ("pinning", "cmd:OBJ_PIN"),
    ("test_link_pinning", "cmd:OBJ_PIN"),
    ("link_pinning", "cmd:OBJ_PIN"),
    ("bpf_obj_pinning", "cmd:OBJ_PIN"),
    ("test_bpffs", "cmd:OBJ_PIN"),
    ("test_rdonly_maps", "flag:BPF_F_RDONLY"),
    ("rdonly_maps", "flag:BPF_F_RDONLY"),
    ("test_mmap", "flag:BPF_F_MMAPABLE"),
    ("mmap", "flag:BPF_F_MMAPABLE"),
    ("test_global_data", "map:ARRAY"),
    ("global_data", "map:ARRAY"),
    ("test_global_map_resize", "map:ARRAY"),
    ("global_map_resize", "map:ARRAY"),
    ("set_global_vars", "map:ARRAY"),
    ("metadata", "elf:data-sections"),
    ("test_global_func", "isa:BPF_PSEUDO_CALL"),
    ("global_func", "isa:BPF_PSEUDO_CALL"),
    ("test_subprogs", "isa:BPF_PSEUDO_CALL"),
    ("subprogs", "isa:BPF_PSEUDO_CALL"),
    ("linked_funcs", "api:bpf_linker__new"),
    ("linked_maps", "api:bpf_linker__new"),
    ("linked_vars", "api:bpf_linker__new"),
    ("test_static_linked", "api:bpf_object__open"),
    ("static_linked", "api:bpf_object__open"),
    ("bpf_insn_array", "map:INSN_ARRAY"),
    # Memory, timers, iterators, kfuncs.
    ("free_timer", "helper:timer_init"),
    ("timer", "helper:timer_init"),
    ("wq", "kfunc:bpf_wq_start"),
    ("rcu_read_lock", "kfunc:bpf_rcu_read_lock"),
    ("rcu_tasks_trace", "prog:RAW_TRACEPOINT"),
    ("test_spin_lock", "helper:spin_lock"),
    ("spin_lock", "helper:spin_lock"),
    ("res_spin_lock", "helper:spin_lock"),
    ("linked_list", "kfunc:bpf_list_push_front"),
    ("rbtree", "kfunc:bpf_rbtree_add"),
    ("cpumask", "kfunc:bpf_cpumask_first"),
    ("cpu_mask", "kfunc:bpf_cpumask_first"),
    ("test_kfunc_dynptr_param", "kfunc:bpf_dynptr_from_skb"),
    ("kfunc_dynptr_param", "kfunc:bpf_dynptr_from_skb"),
    ("dynptr", "helper:dynptr_read"),
    ("test_d_path", "helper:d_path"),
    ("d_path", "helper:d_path"),
    ("kptr_xchg", "helper:kptr_xchg"),
    ("local_kptr_stash", "helper:kptr_xchg"),
    ("refcounted_kptr", "helper:kptr_xchg"),
    ("test_task_work", "kfunc:bpf_task_work_schedule_signal"),
    ("task_work", "kfunc:bpf_task_work_schedule_signal"),
    ("bpf_iter_bpf", "attach:TRACE_ITER"),
    ("bpf_iter_ipv6_route", "attach:TRACE_ITER"),
    ("bpf_iter_ksym", "attach:TRACE_ITER"),
    ("bpf_iter_map_elem", "attach:TRACE_ITER"),
    ("bpf_iter_netlink", "attach:TRACE_ITER"),
    ("bpf_iter_setsockopt", "attach:TRACE_ITER"),
    ("bpf_iter_sockmap", "attach:TRACE_ITER"),
    ("bpf_iter_task", "attach:TRACE_ITER"),
    ("bpf_iter_tcp", "attach:TRACE_ITER"),
    ("bpf_iter_test_kern", "attach:TRACE_ITER"),
    ("bpf_iter_udp", "attach:TRACE_ITER"),
    ("bpf_iter_unix", "attach:TRACE_ITER"),
    ("bpf_iter_vma_offset", "attach:TRACE_ITER"),
    ("bpf_iter", "attach:TRACE_ITER"),
    ("iters", "attach:TRACE_ITER"),
    ("iter_buf_null_fail", "attach:TRACE_ITER"),
    ("for_each", "helper:for_each_map_elem"),
    ("kmem_cache_iter", "attach:TRACE_ITER"),
    ("dmabuf_iter", "attach:TRACE_ITER"),
    ("btf_field_iter", "attach:TRACE_ITER"),
    ("crypto", "kfunc:bpf_crypto_ctx_create"),
    ("sha256", "kfunc:bpf_crypto_ctx_create"),
    ("test_strncmp", "helper:strncmp"),
    ("strncmp", "helper:strncmp"),
    ("string_kfuncs", "kfunc:bpf_strcmp"),
    ("task_kfunc", "kfunc:bpf_task_acquire"),
    ("test_get_xattr", "kfunc:bpf_get_file_xattr"),
    ("test_set_remove_xattr", "kfunc:bpf_get_file_xattr"),
    ("test_sig_in_xattr", "kfunc:bpf_get_file_xattr"),
    ("test_fsverity", "kfunc:bpf_get_file_xattr"),
    ("fs_kfuncs", "kfunc:bpf_get_file_xattr"),
    ("kfunc_implicit_args", "kfunc:bpf_obj_new"),
    ("kfunc_module_order", "kfunc:bpf_obj_new"),
    ("kfunc_param_nullable", "kfunc:bpf_obj_new"),
    ("test_kfunc_param_nullable", "kfunc:bpf_obj_new"),
    ("verifier_kfunc_prog_types", "kfunc:bpf_obj_new"),
    ("kfunc_call", "isa:BPF_PSEUDO_KFUNC_CALL"),
    ("nested_trust", "kfunc:bpf_refcount_acquire"),
    ("nested_acquire", "kfunc:bpf_refcount_acquire"),
    ("cb_refs", "kfunc:bpf_refcount_acquire"),
    ("kfree_skb", "kfunc:bpf_kfree_skb"),
    ("find_vma", "helper:find_vma"),
    ("task_pt_regs", "helper:task_pt_regs"),
    ("test_task_pt_regs", "helper:task_pt_regs"),
    ("test_task_under_cgroup", "helper:current_task_under_cgroup"),
    ("task_under_cgroup", "helper:current_task_under_cgroup"),
    ("task_fd_query", "cmd:TASK_FD_QUERY"),
    ("test_ns_current_pid_tgid", "helper:get_current_pid_tgid"),
    ("ns_current_pid_tgid", "helper:get_current_pid_tgid"),
    ("netns_cookie", "helper:get_netns_cookie"),
    ("fib_lookup", "helper:fib_lookup"),
    ("send_signal", "helper:send_signal"),
    ("signal_pending", "helper:send_signal"),
    ("snprintf_btf", "helper:snprintf_btf"),
    ("snprintf", "helper:snprintf"),
    ("test_snprintf", "helper:snprintf"),
    ("skb_output", "helper:skb_output"),
    ("xdp_output", "helper:xdp_output"),
    # BTF, CO-RE, objects, loader surface.
    ("btf_dump", "api:btf_dump__new"),
    ("btf__core_reloc", "core:FIELD_EXISTS"),
    ("test_core_reloc", "core:FIELD_EXISTS"),
    ("test_core_autosize", "core:TYPE_SIZE"),
    ("core_autosize", "core:TYPE_SIZE"),
    ("test_core_extern", "core:TYPE_EXISTS"),
    ("core_extern", "core:TYPE_EXISTS"),
    ("test_core_retro", "core:FIELD_EXISTS"),
    ("core_retro", "core:FIELD_EXISTS"),
    ("test_core_read_macros", "core:FIELD_EXISTS"),
    ("core_read_macros", "core:FIELD_EXISTS"),
    ("test_core_kern", "core:FIELD_EXISTS"),
    ("core_kern", "core:FIELD_EXISTS"),
    ("core_reloc", "core:FIELD_EXISTS"),
    ("resolve_btfids", "api:bpf_object__open"),
    ("test_subskeleton", "api:bpf_object__open"),
    ("subskeleton", "api:bpf_object__open"),
    ("test_skeleton", "api:bpf_object__open"),
    ("skeleton", "api:bpf_object__open"),
    ("test_autoload", "api:bpf_object__load"),
    ("autoload", "api:bpf_object__load"),
    ("test_autoattach", "api:bpf_object__load"),
    ("autoattach", "api:bpf_object__load"),
    ("test_uprobe_autoattach", "api:bpf_object__load"),
    ("test_uprobe", "section:uprobe+"),
    ("test_usdt", "section:usdt+"),
    ("uprobe_autoattach", "api:bpf_object__load"),
    ("test_custom_sec_handlers", "elf:section-conventions"),
    ("custom_sec_handlers", "elf:section-conventions"),
    ("section_names", "elf:section-conventions"),
    ("test_vmlinux", "btf:STRUCT"),
    ("vmlinux", "btf:STRUCT"),
    ("test_verify_pkcs7_sig", "cmd:PROG_LOAD"),
    ("verify_pkcs7_sig", "cmd:PROG_LOAD"),
    ("test_signed_loader", "cmd:PROG_LOAD"),
    ("signed_loader", "cmd:PROG_LOAD"),
    ("test_veristat", "cmd:PROG_LOAD"),
    ("test_build_id", "elf:data-sections"),
    ("build_id", "elf:data-sections"),
    ("btf", "btf:STRUCT"),
    ("test_btf", "btf:STRUCT"),
    ("varlen", "btf:STRUCT"),
    ("test_varlen", "btf:STRUCT"),
    # LSM, syscalls, LIRC, misc.
    ("test_lsm", "prog:LSM"),
    ("lsm", "prog:LSM"),
    ("test_bprm_opts", "prog:LSM"),
    ("bprm_opts", "prog:LSM"),
    ("test_ima", "prog:LSM"),
    ("ima", "prog:LSM"),
    ("token_lsm", "prog:LSM"),
    ("file_reader", "prog:LSM"),
    ("security_bpf_map", "prog:LSM"),
    ("test_deny_namespace", "prog:LSM"),
    ("deny_namespace", "prog:LSM"),
    ("bpf_syscall_macro", "prog:SYSCALL"),
    ("test_bpf_syscall_macro", "prog:SYSCALL"),
    ("syscall", "prog:SYSCALL"),
    ("exe_ctx", "prog:SYSCALL"),
    ("lirc", "prog:LIRC_MODE2"),
    ("sysctl", "prog:CGROUP_SYSCTL"),
    # Loops, tails, ISA checks.
    ("tailcall", "helper:tail_call"),
    ("epilogue", "isa:BPF_EXIT"),
    ("pro_epilogue", "isa:BPF_EXIT"),
    ("pyperf600_bpf_loop", "helper:loop"),
    ("strobemeta_bpf_loop", "helper:loop"),
    ("bpf_loop_bench", "helper:loop"),
    ("test_bpf_loop", "helper:loop"),
    ("bpf_loop", "helper:loop"),
    ("loop", "helper:loop"),
    ("test_ldsx_insn", "isa:BPF_MEMSX"),
    ("bpf_gotox", "isa:BPF_JCOND"),
    ("jeq_infer_not_null", "isa:BPF_JCOND"),
    ("jump", "isa:BPF_JCOND"),
    ("jset", "isa:BPF_ALU64"),
    ("test_verif_scale", "cmd:PROG_LOAD"),
    ("bpf_verif_scale", "cmd:PROG_LOAD"),
    ("verif_stats", "cmd:ENABLE_STATS"),
    ("test_enable_stats", "cmd:ENABLE_STATS"),
    ("enable_stats", "cmd:ENABLE_STATS"),
    ("test_overhead", "cmd:ENABLE_STATS"),
    ("test_log_buf", "cmd:PROG_LOAD"),
    ("log_buf", "cmd:PROG_LOAD"),
    ("test_log_fixup", "cmd:PROG_LOAD"),
    ("log_fixup", "cmd:PROG_LOAD"),
    ("arg_parsing", "cmd:PROG_LOAD"),
    ("bpf_attr_size", "cmd:PROG_LOAD"),
    ("bpf_mod_race", "cmd:PROG_LOAD"),
    ("test_helper_restricted", "cmd:PROG_LOAD"),
    ("helper_restricted", "cmd:PROG_LOAD"),
    ("test_kernel_flag", "cmd:PROG_LOAD"),
    ("kernel_flag", "cmd:PROG_LOAD"),
    ("stack_var_off", "cmd:PROG_LOAD"),
    ("test_stack_var_off", "cmd:PROG_LOAD"),
    ("stack_arg", "isa:BPF_PSEUDO_CALL"),
    ("btf__stack_arg_precision", "isa:BPF_PSEUDO_CALL"),
    ("btf__verifier_stack_arg_order", "isa:BPF_PSEUDO_CALL"),
    ("ptr_untrusted", "cmd:PROG_LOAD"),
    ("test_ptr_untrusted", "cmd:PROG_LOAD"),
    ("mem_rdonly_untrusted", "cmd:PROG_LOAD"),
    ("recursion", "cmd:PROG_LOAD"),
    ("reference_tracking", "cmd:PROG_LOAD"),
    ("reg_bounds", "cmd:PROG_LOAD"),
    ("compute_live_registers", "cmd:PROG_LOAD"),
    ("type_cast", "cmd:PROG_LOAD"),
    ("uninit_stack", "cmd:PROG_LOAD"),
    ("test_unpriv_bpf_disabled", "cmd:PROG_LOAD"),
    ("unpriv_bpf_disabled", "cmd:PROG_LOAD"),
    ("uptr", "cmd:PROG_LOAD"),
    ("preempt_lock", "cmd:PROG_LOAD"),
    ("verifier", "cmd:PROG_LOAD"),
    ("recursive_attach", "section:fentry+"),
    ("atomic", "isa:BPF_ATOMIC"),
    ("calls", "isa:BPF_CALL"),
    ("bpf_st_mem", "isa:BPF_ALU64"),
    ("bpf_loop_inline", "helper:loop"),
    ("ctx_skb", "prog:SCHED_CLS"),
    ("ctx_sk_lookup", "prog:SK_LOOKUP"),
    ("dead_code", "cmd:PROG_LOAD"),
    ("direct_value_access", "map:ARRAY"),
    ("event_output", "helper:perf_event_output"),
    ("jit", "llvm:target-bpfel"),
    ("jit_probe_mem", "llvm:target-bpfel"),
    ("jmp32", "isa:BPF_JMP32"),
    ("junk_insn", "cmd:PROG_LOAD"),
    ("ld_abs", "prog:SOCKET_FILTER"),
    ("ld_dw", "isa:BPF_DW"),
    ("ld_imm64", "isa:BPF_DW"),
    ("map_kptr", "helper:kptr_xchg"),
    ("perf_event_sample_period", "prog:PERF_EVENT"),
    ("precise", "cmd:PROG_LOAD"),
    ("scale", "cmd:PROG_LOAD"),
    ("sleepable", "flag:BPF_F_SLEEPABLE"),
    ("wide_access", "cmd:PROG_LOAD"),
    ("value", "cmd:PROG_LOAD"),
    ("stack", "cmd:PROG_LOAD"),
    ("bounds", "cmd:PROG_LOAD"),
    ("basic", "cmd:PROG_LOAD"),
    ("align", "cmd:PROG_LOAD"),
    ("array_access", "map:ARRAY"),
    ("async_cb_context", "prog:TRACING"),
    ("basic_stack", "cmd:PROG_LOAD"),
    ("bitfield_write", "cmd:PROG_LOAD"),
    ("bits_iter", "attach:TRACE_ITER"),
    ("bounds_deduction", "cmd:PROG_LOAD"),
    ("error", "cmd:PROG_LOAD"),
    # Object, link, token, misc userspace surface.
    ("token", "cmd:TOKEN_CREATE"),
    ("obj_name", "api:bpf_object__name"),
    ("test_obj_id", "cmd:PROG_GET_NEXT_ID"),
    ("bpf_obj_id", "cmd:PROG_GET_NEXT_ID"),
    ("test_libbpf_get_fd_by_id_opts", "api:bpf_prog_get_fd_by_id"),
    ("libbpf_get_fd_by_id_opts", "api:bpf_prog_get_fd_by_id"),
    ("libbpf_probes", "api:libbpf_probe_bpf_prog_type"),
    ("libbpf_str", "api:libbpf_strerror"),
    ("bpftool", "cmd:MAP_GET_NEXT_ID"),
    ("prog_run_opts", "cmd:PROG_TEST_RUN"),
    ("test_raw_tp_test_run", "cmd:PROG_TEST_RUN"),
    ("raw_tp_test_run", "cmd:PROG_TEST_RUN"),
    ("raw_tp_writable", "section:raw_tp.w+"),
    ("trigger_bench", "cmd:PROG_TEST_RUN"),
    ("bpf_nop_bench", "cmd:PROG_TEST_RUN"),
    ("test_fill_link_info", "api:bpf_link_get_info_by_fd"),
    ("fill_link_info", "api:bpf_link_get_info_by_fd"),
    ("test_bpf_cookie", "helper:get_attach_cookie"),
    ("bpf_cookie", "helper:get_attach_cookie"),
    ("clone_attach_btf_id", "cmd:LINK_CREATE"),
    ("test_probe_read_user_str", "helper:probe_read_user_str"),
    ("probe_read_user_str", "helper:probe_read_user_str"),
    ("test_probe_user", "helper:probe_read_user"),
    ("probe_user", "helper:probe_read_user"),
    ("time_tai", "helper:ktime_get_tai_ns"),
    ("test_time_tai", "helper:ktime_get_tai_ns"),
    ("test_struct_ops", "prog:STRUCT_OPS"),
    ("struct_ops", "prog:STRUCT_OPS"),
    ("bad_struct_ops", "prog:STRUCT_OPS"),
    ("dummy_st_ops", "prog:STRUCT_OPS"),
    ("bpf_qdisc", "prog:STRUCT_OPS"),
    ("endian", "llvm:target-bpfeb"),
    ("test_endian", "llvm:target-bpfeb"),
)


def selftest_target(subdir, filename):
    """Return the record ID for a selftest file, or None if unmapped."""
    if (subdir, filename) in SELFTEST_EXACT:
        return SELFTEST_EXACT[(subdir, filename)]
    stem = filename[:-2] if filename.endswith(".c") else filename
    best = None
    for prefix, rec_id in SELFTEST_PREFIX:
        if stem.startswith(prefix) and (
                best is None or len(prefix) > len(best[0])):
            best = (prefix, rec_id)
    return best[1] if best else None


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


# Lock section recording the last published registry. It is excluded
# from the lock digest (otherwise publishing could never settle: the
# registry embeds the lock digest while the lock embeds the registry
# digest). Tampering with either side is still caught: validate checks
# the registry digest, counts and revision against this section and the
# lock digest against everything else.
PUBLISHED_KEY = "published"


def lock_digest_of(lock):
    """Return the binding digest of a lock dict (minus ``published``)."""
    trimmed = {key: value for key, value in lock.items()
               if key != PUBLISHED_KEY and not key.startswith("_")}
    return hashlib.sha256(
        dump_canonical(trimmed).encode("utf-8")).hexdigest()


def check_binding(registry, lock, registry_digest):
    """Return lock/registry binding violations (empty means bound)."""
    errors = []
    if lock.get("registry_revision") not in SUPPORTED_REGISTRY_REVISIONS:
        errors.append(
            "lock registry_revision %r is not supported (supports %s)"
            % (lock.get("registry_revision"),
               sorted(SUPPORTED_REGISTRY_REVISIONS)))
    if registry.get("revision") != lock.get("registry_revision"):
        errors.append(
            "registry revision %r does not match lock revision %r"
            % (registry.get("revision"), lock.get("registry_revision")))
    generated = registry.get("generated_by", {})
    if generated.get("lock_digest") != lock_digest_of(lock):
        errors.append("registry lock_digest does not match the lock file")
    published = lock.get(PUBLISHED_KEY, {})
    if published.get("registry_digest") != registry_digest:
        errors.append("registry digest does not match lock published pin")
    if published.get("records") != len(registry.get("records", [])):
        errors.append("registry record count does not match lock pin")
    if published.get("members") != len(registry.get("enum_members", [])):
        errors.append("registry member count does not match lock pin")
    if published.get("revision") != registry.get("revision"):
        errors.append("registry revision does not match lock pin")
    return sorted(errors)


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


def c_brace_body(text, open_pos):
    """Return the brace-delimited body starting at ``open_pos``.

    ``text[open_pos]`` must be ``{``. String and character literals are
    skipped so braces inside them do not confuse the depth count; run
    ``strip_comments`` first so comment braces cannot either.
    """
    depth = 0
    pos = open_pos
    literal = None
    while pos < len(text):
        char = text[pos]
        if literal is not None:
            if char == "\\":
                pos += 2
                continue
            if char == literal:
                literal = None
        elif char in "\"'":
            literal = char
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[open_pos:pos + 1]
        pos += 1
    raise InventoryError("unbalanced braces in kernel source")


def parse_bpf_types(text):
    """Return [(BPF_PROG_TYPE_*, short_name)] from bpf_types.h."""
    return re.findall(
        r"BPF_PROG_TYPE\(\s*(BPF_PROG_TYPE_\w+)\s*,\s*(\w+)", text)


def parse_func_protos(text):
    """Return {name: (cases, calls)} for kernel func_proto definitions.

    Any top-level definition returning ``struct bpf_func_proto *``
    with first parameter ``enum bpf_func_id`` is kept, whatever its
    name; sub-dispatchers need not be called ``*func_proto*``.
    ``cases`` are the ``BPF_FUNC_*`` IDs with a ``case`` label in the
    function body (brace-matched, so labels in neighboring functions
    cannot leak in). ``calls`` are the functions the body delegates
    to with ``(func_id, ...)``; indirect member calls such as
    ``reg->get_func_proto(func_id, ...)`` are target-dependent and
    excluded, as are C keywords such as ``switch (func_id)``.
    """
    clean = strip_comments(text)
    protos = {}
    for match in re.finditer(
            r"(?m)^(?:static\s+)?(?:const\s+)?struct bpf_func_proto\s*\*"
            r"\s*\**\s*(\w+)\s*\(", clean):
        name = match.group(1)
        signature = clean[match.end():match.end() + 60]
        if not re.match(r"\s*enum\s+bpf_func_id\b", signature):
            continue
        brace = clean.find("{", match.end())
        if brace == -1 or brace - match.end() > 600:
            continue
        if clean.find(";", match.end(), brace) != -1:
            continue
        body = c_brace_body(clean, brace)
        cases = set(re.findall(r"case\s+(BPF_FUNC_\w+)", body))
        calls = set()
        for call in re.finditer(r"(\w+)\s*\(\s*func_id", body):
            if call.group(1) in ("switch", "if", "while", "for",
                                  "return", "sizeof"):
                continue
            before = body[max(0, call.start() - 2):call.start()]
            if before.endswith("->") or before.endswith("."):
                continue
            if call.group(1) != name:
                calls.add(call.group(1))
        if name in protos:
            protos[name][0].update(cases)
            protos[name][1].update(calls)
        else:
            protos[name] = (set(cases), set(calls))
    return protos


def parse_verifier_ops(text):
    """Return {ops_name: get_func_proto_fn_or_None} from kernel text."""
    clean = strip_comments(text)
    ops = {}
    for match in re.finditer(
            r"struct bpf_verifier_ops\s+(\w+)\s*=\s*\{", clean):
        body = c_brace_body(clean, match.end() - 1)
        fns = re.findall(r"\.get_func_proto\s*=\s*(\w+)", body)
        ops[match.group(1)] = fns[0] if fns else None
    return ops


_KFUNC_BLOCK_RES = (
    re.compile(r"BTF_KFUNCS_START\((\w+)\)(.*?)BTF_KFUNCS_END\(\1\)",
               re.S),
    re.compile(r"BTF_SET8_START\((\w+)\)(.*?)BTF_SET8_END\(\1\)", re.S),
    re.compile(r"BTF_SET_START\((\w+)\)(.*?)BTF_SET_END\(\1\)", re.S),
)


def parse_kfunc_blocks(text):
    """Return {block: [(name, flags_or_None)]} for candidate ID blocks.

    Every ``BTF_KFUNCS_*``/``BTF_SET8_*``/``BTF_SET_*`` block is returned;
    the caller keeps only blocks referenced by a ``btf_kfunc_id_set``,
    which is what distinguishes kfunc registrations from hook and
    allowlist blocks sharing the same spelling.
    """
    blocks = {}
    for regex in _KFUNC_BLOCK_RES:
        for match in regex.finditer(text):
            members = re.findall(
                r"BTF_ID(?:_FLAGS)?\(\s*func\s*,\s*(\w+)"
                r"\s*(?:,([^)]*))?\)",
                match.group(2),
            )
            cleaned = [(name, flags.strip() if flags else None)
                       for name, flags in members]
            if match.group(1) in blocks:
                raise InventoryError(
                    "duplicate kfunc block %s" % match.group(1))
            blocks[match.group(1)] = cleaned
    return blocks


def parse_kfunc_id_sets(text):
    """Return [(var, block, filter)] for ``btf_kfunc_id_set`` defs.

    ``filter`` is the ``.filter`` callback name, or None when the set
    carries no filter. A set without ``.set`` is malformed and reported
    with a None block so the caller can fail the registration closed.
    """
    clean = strip_comments(text)
    found = []
    for match in re.finditer(
            r"struct btf_kfunc_id_set\s+(\w+)\s*=\s*\{", clean):
        body = c_brace_body(clean, match.end() - 1)
        set_match = re.search(r"\.set\s*=\s*&(\w+)", body)
        filter_match = re.search(r"\.filter\s*=\s*(\w+)", body)
        found.append((
            match.group(1),
            set_match.group(1) if set_match else None,
            filter_match.group(1) if filter_match else None,
        ))
    return found


def parse_kfunc_registers(text):
    """Return [(BPF_PROG_TYPE_*, var)] for register calls."""
    return re.findall(
        r"register_btf_kfunc_id_set\s*\(\s*(BPF_PROG_TYPE_\w+)\s*,"
        r"\s*&(\w+)\s*\)",
        text,
        re.S,
    )


def parse_fmodret_registers(text):
    """Return [var] for ``register_btf_fmodret_id_set`` calls.

    Fmodret sets name modify_return attach targets, not callable
    kfuncs; the verifier consults them on the attach path only.
    """
    return re.findall(
        r"register_btf_fmodret_id_set\s*\(\s*&(\w+)\s*\)", text)


def parse_kfunc_hook_switch(text):
    """Return {BPF_PROG_TYPE_*: hook} from btf.c's hook switch."""
    clean = strip_comments(text)
    match = re.search(
        r"bpf_prog_type_to_kfunc_hook\s*\([^)]*\)\s*\{", clean)
    if not match:
        raise InventoryError(
            "bpf_prog_type_to_kfunc_hook is missing from btf.c")
    body = c_brace_body(clean, match.end() - 1)
    groups = {}
    for chunk in re.finditer(
            r"((?:case\s+BPF_PROG_TYPE_\w+\s*:\s*)+)"
            r"return\s+(BTF_KFUNC_HOOK_\w+)\s*;",
            body):
        types = re.findall(r"case\s+(BPF_PROG_TYPE_\w+)", chunk.group(1))
        for prog_type in types:
            groups[prog_type] = chunk.group(2)
    return groups


def check_kfunc_common_first(text):
    """True when btf.c consults the COMMON kfunc hook for every program."""
    clean = strip_comments(text)
    match = None
    for entry in ("btf_kfunc_is_allowed", "btf_kfunc_id_set_contains"):
        match = re.search(
            r"(?<![\w_])%s\s*\([^)]*\)\s*\{" % entry, clean)
        if match:
            break
    if not match:
        raise InventoryError(
            "no kfunc allow-check entry in btf.c")
    body = c_brace_body(clean, match.end() - 1)
    common = body.find("BTF_KFUNC_HOOK_COMMON")
    typed = body.find("bpf_prog_type_to_kfunc_hook(prog_type)")
    return common != -1 and typed != -1 and common < typed


# ---------------------------------------------------------------------------
# kfunc filter (.filter) classification
# ---------------------------------------------------------------------------

_MEMBERSHIP_CALLS = frozenset({
    "btf_id_set_contains", "btf_id_set8_contains",
})


def c_function_body(clean, name):
    """Return (params, body) for the definition of ``name``, or None.

    ``clean`` must be comment-stripped. Only true definitions (with a
    brace body, not a ``;`` declaration) match; the first definition
    wins.
    """
    for match in re.finditer(r"\b%s\s*\(" % re.escape(name), clean):
        pos = match.end() - 1
        depth = 0
        end = None
        for index in range(pos, len(clean)):
            char = clean[index]
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    end = index
                    break
        if end is None:
            continue
        params = clean[pos + 1:end]
        brace = clean.find("{", end)
        if brace == -1 or brace - end > 600:
            continue
        if clean.find(";", end, brace) != -1:
            continue
        return params, c_brace_body(clean, brace)
    return None


def _filter_prog_param(params, fn_name, version):
    """Return the ``struct bpf_prog *`` parameter name of a filter."""
    match = re.search(r"struct\s+bpf_prog\s*\*\s*(\w+)", params)
    if not match:
        raise InventoryError(
            "kfunc filter %s@%s has no bpf_prog parameter"
            % (fn_name, version))
    return match.group(1)


def _cond_tokenize(text):
    """Split a filter condition into tokens."""
    tokens = []
    pos = 0
    while pos < len(text):
        char = text[pos]
        if char.isspace():
            pos += 1
            continue
        two = text[pos:pos + 2]
        if two in ("==", "!=", "&&", "||", "->"):
            tokens.append(two)
            pos += 2
            continue
        if char in "!()&,":
            tokens.append(char)
            pos += 1
            continue
        match = re.match(r"[A-Za-z_]\w*|0[xX][0-9a-fA-F]+|\d+", text[pos:])
        if match:
            tokens.append(match.group(0))
            pos += len(match.group(0))
            continue
        raise InventoryError(
            "cannot parse filter condition near %r" % text[pos:pos + 20])
    return tokens


def _cond_parse(tokens):
    """Parse condition tokens into an AST over caller atoms.

    Returns (node, opaque) where opaque maps placeholder names to the
    original subexpression text for anything outside the supported
    atom shapes (bit tests, unknown calls, foreign member access).
    Bound nodes are ("const", bool), ("not", sub), ("and"/"or",
    [subs]), ("type_cmp"/"attach_cmp"/"stops_cmp", op, value),
    ("member", set), ("stops_null",) or ("opaque", placeholder).
    """

    opaque = {}
    counter = [0]

    def take_opaque(node_tokens):
        counter[0] += 1
        name = "__opaque_%d" % counter[0]
        opaque[name] = " ".join(node_tokens)
        return ("opaque", name)

    pos = [0]

    def peek():
        return tokens[pos[0]] if pos[0] < len(tokens) else None

    def parse_or():
        subs = [parse_and()]
        while peek() == "||":
            pos[0] += 1
            subs.append(parse_and())
        if len(subs) == 1:
            return subs[0]
        return ("or", subs)

    def parse_and():
        subs = [parse_cmp()]
        while peek() == "&&":
            pos[0] += 1
            subs.append(parse_cmp())
        if len(subs) == 1:
            return subs[0]
        return ("and", subs)

    def parse_cmp():
        start = pos[0]
        left = parse_unary()
        if peek() in ("==", "!="):
            op = peek()
            pos[0] += 1
            right = parse_unary()
            return ("cmp", left, op, right, start, pos[0])
        return left

    def parse_unary():
        if peek() == "!":
            pos[0] += 1
            return ("not", parse_unary())
        if peek() == "(":
            pos[0] += 1
            node = parse_or()
            if peek() != ")":
                raise InventoryError(
                    "cannot parse filter condition: unbalanced paren")
            pos[0] += 1
            return node
        return parse_atom()

    def parse_atom():
        start = pos[0]
        token = peek()
        if token is None:
            raise InventoryError(
                "cannot parse filter condition: truncated")
        if token == "&":
            pos[0] += 1
            name = peek()
            if name is None or not re.match(r"[A-Za-z_]", name):
                raise InventoryError(
                    "cannot parse filter condition near '&'")
            pos[0] += 1
            return ("addr", name)
        if re.match(r"\d", token):
            pos[0] += 1
            return ("number", token)
        if not re.match(r"[A-Za-z_]", token):
            raise InventoryError(
                "cannot parse filter condition near %r" % token)
        pos[0] += 1
        if peek() == "(":
            pos[0] += 1
            depth = 1
            args = []
            current = []
            while True:
                tok = peek()
                if tok is None:
                    raise InventoryError(
                        "cannot parse filter condition: truncated call")
                if tok == "(":
                    depth += 1
                elif tok == ")":
                    depth -= 1
                    if depth == 0:
                        pos[0] += 1
                        break
                if tok == "," and depth == 1:
                    args.append(current)
                    current = []
                    pos[0] += 1
                    continue
                current.append(tok)
                pos[0] += 1
            args.append(current)
            if token in _MEMBERSHIP_CALLS and len(args) == 2 and \
                    args[0] and args[0][0] == "&" and len(args[0]) == 2:
                return ("member", args[0][1])
            return take_opaque(tokens[start:pos[0]])
        node = [token]
        while peek() == "->":
            pos[0] += 1
            field = peek()
            if field is None or not re.match(r"[A-Za-z_]", field):
                raise InventoryError(
                    "cannot parse filter condition near '->'")
            node.append(field)
            pos[0] += 1
        if len(node) == 1:
            return ("ident", token)
        return ("field", tuple(node))

    node = parse_or()
    if pos[0] != len(tokens):
        raise InventoryError("cannot parse filter condition tail")
    return node, opaque, tokens


def _opaque_for(opaque, tokens, text):
    """Register an opaque leaf, returning its placeholder name."""
    counter = [0]
    for key in opaque:
        match = re.match(r"__opaque_(\d+)$", key)
        if match:
            counter[0] = max(counter[0], int(match.group(1)))
    name = "__opaque_%d" % (counter[0] + 1)
    opaque[name] = text if text is not None else " ".join(tokens)
    return name


def _bind_condition(node, prog_param, aliases, protected_members,
                    opaque, tokens, fn_name):
    """Bind raw atoms to typed condition leaves.

    Field comparisons against ``prog`` become typed comparison
    leaves; membership aliases resolve to set tests; anything else
    becomes an opaque leaf carrying its original text.
    """
    kind = node[0]
    if kind in ("const", "member", "opaque", "stops_null"):
        return node
    if kind == "not":
        return ("not", _bind_condition(
            node[1], prog_param, aliases, protected_members,
            opaque, tokens, fn_name))
    if kind in ("and", "or"):
        return (kind, [_bind_condition(
            sub, prog_param, aliases, protected_members,
            opaque, tokens, fn_name)
            for sub in node[1]])
    if kind == "ident":
        name = node[1]
        if name in aliases:
            return ("member", aliases[name])
        if name in protected_members:
            return ("member", protected_members[name])
        if name in opaque:
            return ("opaque", name)
        if name in ("true", "TRUE"):
            return ("const", True)
        if name in ("false", "FALSE"):
            return ("const", False)
        return ("opaque", _opaque_for(opaque, tokens, name))
    if kind in ("addr", "number"):
        return ("opaque", _opaque_for(
            opaque, tokens,
            ("&" if kind == "addr" else "") + node[1]))
    if kind == "field":
        path = node[1]
        if path[0] == prog_param and path[1:] == ("aux", "st_ops"):
            return ("stops_null",)
        return ("opaque", _opaque_for(opaque, tokens, "->".join(path)))
    if kind == "cmp":
        _, left, op, right, start, end = node
        value = None
        if right[0] == "ident":
            value = right[1]
        elif right[0] == "addr":
            value = "&" + right[1]
        elif right[0] == "number":
            value = right[1]
        else:
            return ("opaque", _opaque_for(
                opaque, tokens, " ".join(tokens[start:end])))
        if left[0] == "field" and left[1][0] == prog_param:
            rest = left[1][1:]
            if rest == ("type",) and value.startswith("BPF_PROG_TYPE_"):
                return ("type_cmp", op, value)
            if rest == ("expected_attach_type",) and \
                    value.startswith("BPF_"):
                return ("attach_cmp", op, value)
            if rest == ("aux", "st_ops") and value.startswith("&"):
                return ("stops_cmp", op, value[1:])
        # Mirrored comparison (constant on the left).
        if right[0] == "field" and right[1][0] == prog_param:
            rest = right[1][1:]
            if left[0] == "ident":
                if rest == ("type",) and \
                        left[1].startswith("BPF_PROG_TYPE_"):
                    return ("type_cmp", op, left[1])
                if rest == ("expected_attach_type",) and \
                        left[1].startswith("BPF_"):
                    return ("attach_cmp", op, left[1])
        return ("opaque", _opaque_for(
            opaque, tokens, " ".join(tokens[start:end])))
    raise InventoryError(
        "cannot parse filter %s condition" % fn_name)


def _protect_condition_atoms(text):
    """Replace opaque-prone groups with placeholders.

    Membership calls become ``__member_<set>`` idents and paren groups
    holding a lone ``&`` (attach-context bit tests, never address-of
    or ``&&``) become ``__opaque_<n>`` idents. Returns (rewritten,
    members, opaque) with the placeholder back-maps.
    """
    members = {}
    opaque = {}

    def protect_member(match):
        name = "__member_%s" % match.group(1)
        members[name] = match.group(1)
        return name

    rewritten = re.sub(
        r"btf_id_set8?_contains\s*\(\s*&(\w+)\s*,\s*\w+\s*\)",
        protect_member, text)
    counter = [0]

    def has_lone_and(group):
        return re.search(r"(?<![&|])&(?![&=|])", group) is not None

    while True:
        match = None
        for candidate in re.finditer(r"\([^()]*\)", rewritten):
            if has_lone_and(candidate.group(0)):
                match = candidate
                break
        if match is None:
            break
        counter[0] += 1
        name = "__bitop_%d" % counter[0]
        opaque[name] = re.sub(
            r"\s+", " ", match.group(0)).strip()
        rewritten = (rewritten[:match.start()] + " " + name + " "
                     + rewritten[match.end():])
    return rewritten, members, opaque


def _parse_condition(text, prog_param, aliases, pred_exprs, fn_name):
    """Parse and bind one filter condition for simulation.

    Predicate calls over ``prog`` are inlined one level from
    ``pred_exprs``; membership aliases resolve to set tests. Returns
    (node, opaque) with opaque mapping placeholders to original text.
    """
    expanded = text
    for pred, expr in sorted(pred_exprs.items()):
        expanded = re.sub(
            r"\b%s\s*\(\s*%s\s*\)" % (re.escape(pred),
                                      re.escape(prog_param)),
            "(%s)" % expr, expanded)
    expanded, protected_members, protected_opaque = \
        _protect_condition_atoms(expanded)
    node, opaque, tokens = _cond_parse(_cond_tokenize(expanded))
    opaque.update(protected_opaque)
    return _bind_condition(
        node, prog_param, aliases, protected_members,
        opaque, tokens, fn_name), opaque


def _split_filter_body(body, fn_name, version):
    """Split a filter body into simulation statements.

    Returns (aliases, stmts) where aliases maps local idents to kfunc
    set names and stmts holds ("if", cond, kind) with kind allow/deny,
    ("allow", None, None), ("deny", None, None) or ("end", None,
    None) for the terminal return. Bare compound blocks are parsed
    recursively, so a nested denying block denies instead of being
    silently skipped. Anything outside the supported statement shapes
    fails the registration closed.
    """
    inner = body.strip()
    if inner.startswith("{") and inner.endswith("}"):
        inner = inner[1:-1]
    aliases = {}
    for match in re.finditer(
            r"\bbool\s+(\w+)\s*=\s*btf_id_set8?_contains\s*"
            r"\(\s*&(\w+)\s*,", inner):
        aliases[match.group(1)] = match.group(2)
    stmts = []
    _split_filter_stmts(inner, fn_name, version, stmts)
    return aliases, stmts


def _split_filter_stmts(inner, fn_name, version, stmts):
    """Append one statement list's simulation statements to ``stmts``.

    Straight-line declarations, assignments and calls carry no verdict
    and are skipped; ``if``/``return`` shapes become simulation
    statements and bare ``{ ... }`` blocks recurse so nested returns
    keep their control-flow meaning. Anything else fails closed.
    """
    pos = 0
    end = len(inner)
    while pos < end:
        match = re.match(r"\s*", inner[pos:])
        pos += match.end()
        if pos >= end:
            break
        if re.match(r"if\b", inner[pos:]):
            cond_start = inner.find("(", pos)
            depth = 0
            cond_end = None
            for index in range(cond_start, end):
                char = inner[index]
                if char == "(":
                    depth += 1
                elif char == ")":
                    depth -= 1
                    if depth == 0:
                        cond_end = index
                        break
            if cond_end is None:
                raise InventoryError(
                    "cannot parse filter %s@%s: unbalanced if"
                    % (fn_name, version))
            cond = inner[cond_start + 1:cond_end]
            rest = inner[cond_end + 1:]
            then = None
            if re.match(r"\s*\{", rest):
                brace = inner.find("{", cond_end + 1)
                block = c_brace_body(inner, brace)
                returns = re.findall(r"\breturn\b", block)
                if len(returns) != 1 or \
                        re.search(r"\b(if|for|while|switch|goto)\b",
                                  block):
                    raise InventoryError(
                        "cannot parse filter %s@%s: complex branch"
                        % (fn_name, version))
                then = block[block.find("return"):block.rfind("}")].strip()
                pos = brace + len(block)
            else:
                semi = inner.find(";", cond_end + 1)
                if semi == -1:
                    raise InventoryError(
                        "cannot parse filter %s@%s: truncated branch"
                        % (fn_name, version))
                then = inner[cond_end + 1:semi].strip()
                pos = semi + 1
            if re.match(r"\s*else\b", inner[pos:]):
                raise InventoryError(
                    "cannot parse filter %s@%s: else branch"
                    % (fn_name, version))
            kind = _classify_return(then, fn_name, version)
            if kind is None:
                continue
            stmts.append(("if", cond, kind))
            continue
        if re.match(r"return\b", inner[pos:]):
            semi = inner.find(";", pos)
            if semi == -1:
                raise InventoryError(
                    "cannot parse filter %s@%s: truncated return"
                    % (fn_name, version))
            kind = _classify_return(
                inner[pos:semi].strip(), fn_name, version)
            if kind is None:
                raise InventoryError(
                    "cannot parse filter %s@%s: empty return"
                    % (fn_name, version))
            stmts.append((kind[0], kind[1], kind[2]))
            pos = semi + 1
            continue
        if re.match(r"(for|while|switch|goto|do|else)\b", inner[pos:]):
            raise InventoryError(
                "cannot parse filter %s@%s: unsupported statement"
                % (fn_name, version))
        if inner[pos] == "{":
            block = c_brace_body(inner, pos)
            _split_filter_stmts(
                block[1:-1], fn_name, version, stmts)
            pos += len(block)
            continue
        semi = inner.find(";", pos)
        if semi == -1:
            raise InventoryError(
                "cannot parse filter %s@%s: trailing text"
                % (fn_name, version))
        if re.search(r"\breturn\b", inner[pos:semi]):
            raise InventoryError(
                "cannot parse filter %s@%s: hidden return"
                % (fn_name, version))
        pos = semi + 1


def _classify_return(text, fn_name, version):
    """Classify a return statement for simulation.

    Returns ("allow"/"deny", None, None), ("ternary", cond, allow_first)
    or None when the text is not a return at all.
    """
    match = re.match(r"\s*return\b(.*)$", text, re.S)
    if not match:
        return None
    expr = match.group(1).strip()
    if expr.endswith(";"):
        expr = expr[:-1].strip()
    if expr == "0":
        return ("allow", None, None)
    if re.match(r"-\s*[A-Za-z_]\w*$", expr) or \
            re.match(r"-\s*\d+$", expr) or re.match(r"[1-9]\d*$", expr):
        return ("deny", None, None)
    if "?" in expr:
        depth = 0
        question = None
        for index, char in enumerate(expr):
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
            elif char == "?" and depth == 0:
                question = index
                break
        if question is None:
            raise InventoryError(
                "cannot parse filter %s@%s return %r"
                % (fn_name, version, expr[:40]))
        cond = expr[:question].strip()
        if cond.startswith("(") and cond.endswith(")"):
            cond = cond[1:-1]
        arms = expr[question + 1:]
        depth = 0
        colon = None
        for index, char in enumerate(arms):
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
            elif char == ":" and depth == 0:
                colon = index
                break
        if colon is None:
            raise InventoryError(
                "cannot parse filter %s@%s return %r"
                % (fn_name, version, expr[:40]))
        first = arms[:colon].strip()
        second = arms[colon + 1:].strip()
        if first == "0" and second != "0":
            return ("ternary", cond, True)
        if second == "0" and first != "0":
            return ("ternary", cond, False)
    raise InventoryError(
        "cannot parse filter %s@%s return %r"
        % (fn_name, version, expr[:40]))


def _fold_condition(node, prog_type, member, membersets):
    """Fold type/membership leaves for one caller and member.

    Returns the simplified node: ("const", bool), possibly with
    attach/stops/opaque leaves remaining.
    """
    kind = node[0]
    if kind == "const":
        return node
    if kind == "member":
        return ("const", member in membersets.get(node[1], set()))
    if kind == "type_cmp":
        _, op, value = node
        matched = prog_type == value
        return ("const", matched if op == "==" else not matched)
    if kind in ("attach_cmp", "stops_cmp", "opaque", "stops_null"):
        return node
    if kind == "not":
        sub = _fold_condition(node[1], prog_type, member, membersets)
        if sub[0] == "const":
            return ("const", not sub[1])
        if sub[0] == "not":
            return sub[1]
        return ("not", sub)
    if kind == "and":
        subs = []
        for sub in node[1]:
            folded = _fold_condition(
                sub, prog_type, member, membersets)
            if folded == ("const", False):
                return ("const", False)
            if folded != ("const", True):
                subs.append(folded)
        if not subs:
            return ("const", True)
        if len(subs) == 1:
            return subs[0]
        return ("and", subs)
    if kind == "or":
        subs = []
        for sub in node[1]:
            folded = _fold_condition(
                sub, prog_type, member, membersets)
            if folded == ("const", True):
                return ("const", True)
            if folded != ("const", False):
                subs.append(folded)
        if not subs:
            return ("const", False)
        if len(subs) == 1:
            return subs[0]
        return ("or", subs)
    raise InventoryError("cannot evaluate filter condition")


def _negate_condition(node):
    """Push a negation through to the leaves (De Morgan)."""
    kind = node[0]
    if kind == "const":
        return ("const", not node[1])
    if kind == "not":
        return node[1]
    if kind == "and":
        return ("or", [_negate_condition(sub) for sub in node[1]])
    if kind == "or":
        return ("and", [_negate_condition(sub) for sub in node[1]])
    if kind in ("attach_cmp", "stops_cmp"):
        _, op, value = node
        return (kind, "!=" if op == "==" else "==", value)
    return ("not", node)


def _narrow_union(left, right):
    """Union two allow-narrows from disjunctive requirements."""
    attach_l, stops_l, notes_l, _ = left
    attach_r, stops_r, notes_r, _ = right
    if attach_l is None or attach_r is None:
        attach = None
    else:
        attach = attach_l | attach_r
    if stops_l is None or stops_r is None:
        stops = None
    else:
        stops = stops_l | stops_r
    notes = set(notes_l) | set(notes_r)
    notes = _union_notes(notes, attach, "requires expected_attach_type ",
                         "attach requirements vary by binding context")
    notes = _union_notes(notes, stops, "requires struct_ops attachment to ",
                         "struct_ops requirements vary by binding context")
    return (attach, stops, notes, False)


def _union_notes(notes, union, prefix, varied):
    """Render one dimension of a disjunctive requirement honestly.

    A union of several required values is an either/or, so the
    per-branch "requires X" notes collapse into a single "one of"
    note; a union widened to unconstrained by one branch keeps no
    blanket requirement.
    """
    bare = set(note for note in notes if not note.startswith(prefix))
    if union is None:
        if bare != notes:
            bare.add(varied)
        return bare
    if len(union) > 1:
        bare.add("requires %sone of: %s"
                 % (prefix[len("requires "):], ", ".join(sorted(union))))
        return bare
    return notes


def _require_folded(node, opaque, fn_name, version):
    """Evaluate a folded allow-requirement into a narrow.

    Returns (attach_or_None, stops_or_None, notes, deny) where None
    sets mean unconstrained and deny means unsatisfiable. Opaque
    caller atoms fail the registration closed: a denial the inventory
    cannot scope is not a permission it may claim.
    """
    kind = node[0]
    if kind == "const":
        if node[1]:
            return (None, None, set(), False)
        return (set(), set(), set(), True)
    if kind == "attach_cmp":
        _, op, value = node
        if op == "==":
            return ({value}, None,
                    {"requires expected_attach_type %s" % value}, False)
        return (None, None,
                {"excludes expected_attach_type %s" % value}, False)
    if kind == "stops_cmp":
        _, op, value = node
        if op == "==":
            return (None, {value},
                    {"requires struct_ops attachment to %s" % value},
                    False)
        return (None, None,
                {"rejected when attached to %s" % value}, False)
    if kind == "and":
        attach, stops, notes = None, None, set()
        for sub in node[1]:
            sub_attach, sub_stops, sub_notes, deny = _require_folded(
                sub, opaque, fn_name, version)
            if deny:
                return (set(), set(), sub_notes, True)
            if sub_attach is not None:
                attach = sub_attach if attach is None \
                    else attach & sub_attach
            if sub_stops is not None:
                stops = sub_stops if stops is None \
                    else stops & sub_stops
            notes |= sub_notes
        return (attach, stops, notes, False)
    if kind == "or":
        result = None
        for sub in node[1]:
            branch = _require_folded(sub, opaque, fn_name, version)
            if branch[3]:
                continue
            result = branch if result is None \
                else _narrow_union(result, branch)
        if result is None:
            return (set(), set(), set(), True)
        return result
    if kind == "opaque":
        raise InventoryError(
            "kfunc filter %s@%s denies on an unrecognized condition %r; "
            "cannot scope the denial" % (fn_name, version,
                                         opaque[node[1]][:60]))
    raise InventoryError(
        "kfunc filter %s@%s has an unsupported requirement"
        % (fn_name, version))


def _opaque_notes(node, opaque, fn_name):
    """Render restriction notes for an opaque allow-alternative."""
    texts = set()

    def visit(current):
        kind = current[0]
        if kind == "opaque":
            texts.add(opaque[current[1]])
        elif kind in ("and", "or"):
            for sub in current[1]:
                visit(sub)
        elif kind == "not":
            visit(current[1])

    visit(node)
    notes = set()
    for text in texts:
        consts = sorted(set(re.findall(
            r"SCX_KF_ALLOW_\w+|QDISC_OPS_KF_\w+|[A-Z][A-Z0-9_]*"
            r"(?=\s*\)|\s|$)", text)))
        consts = [item for item in consts
                  if item not in ("EACCES",)]
        if consts and "&" in text:
            for const in consts:
                notes.add("requires %s attach context (via %s)"
                          % (const, fn_name))
        else:
            notes.add("additionally restricted by %s (%s)"
                      % (fn_name, re.sub(r"\s+", " ", text)[:80]))
    return notes


def _collect_pred_exprs(texts, fn_name, version):
    """Collect single-return predicate bodies callable from a filter.

    Returns {name: return-expression} for every ``static bool`` style
    helper in the version texts. Only one level of inlining is
    supported; anything else stays opaque at the call site.
    """
    exprs = {}
    for relpath in sorted(texts):
        clean = texts[relpath]
        for match in re.finditer(
                r"\b(\w+)\s*\(\s*(?:const\s+)?struct\s+bpf_prog\s*\*"
                r"\s*\w+\s*\)\s*\{", clean):
            name = match.group(1)
            if name == fn_name:
                continue
            try:
                body = c_brace_body(clean, match.end() - 1)
            except InventoryError:
                continue
            inner = body.strip()[1:-1].strip()
            ret = re.match(r"\s*return\b(.*);\s*$", inner, re.S)
            if ret and "?" not in ret.group(1) and \
                    ";" not in ret.group(1):
                expr = ret.group(1).strip()
                if name in exprs and exprs[name] != expr:
                    raise InventoryError(
                        "kfunc filter helper %s@%s is defined twice"
                        % (name, version))
                exprs[name] = expr
    return exprs


def _condition_sets(node):
    """Yield every ID-block name a bound condition consults."""
    kind = node[0]
    if kind == "member":
        yield node[1]
    elif kind in ("and", "or"):
        for sub in node[1]:
            for name in _condition_sets(sub):
                yield name
    elif kind == "not":
        for name in _condition_sets(node[1]):
            yield name


def simulate_kfunc_filter(fn_name, texts, version, members, membersets,
                          hook_types):
    """Simulate one ``.filter`` callback over callers and members.

    ``texts`` maps relpaths to comment-stripped version sources,
    ``members`` lists the governed set members, ``membersets`` maps
    every ID-block name to its member set and ``hook_types`` lists
    the candidate caller program types. Returns {member: verdict}
    where each verdict holds the allowed program types ("types", a
    subset of ``hook_types``), the unioned attach/stops value sets
    and restriction notes ("attach"/"stops"/"notes"), the per-caller
    alternative lists ("by_caller": {caller: [(attach, stops,
    notes)]}) and the caller-grouped scoped alternatives
    ("alternatives": [{callers, attach, stops, notes}]). Program-type
    atoms decide directly; attach and struct_ops atoms narrow the
    context without deciding, since the pinned load path
    default-allows unexpected attach pairings and struct_ops values
    are not statically known. Unknown denying shapes fail the
    registration closed.
    """
    found = None
    for relpath in sorted(texts):
        hit = c_function_body(texts[relpath], fn_name)
        if hit is not None:
            if found is not None:
                raise InventoryError(
                    "kfunc filter %s@%s is defined twice"
                    % (fn_name, version))
            found = hit
    if found is None:
        raise InventoryError(
            "kfunc filter %s@%s is not defined in the pinned sources"
            % (fn_name, version))
    params, body = found
    prog_param = _filter_prog_param(params, fn_name, version)
    aliases, stmts = _split_filter_body(body, fn_name, version)
    pred_exprs = _collect_pred_exprs(texts, fn_name, version)
    for alias, target in sorted(aliases.items()):
        if target not in membersets:
            raise InventoryError(
                "kfunc filter %s@%s consults unknown ID block %s"
                % (fn_name, version, target))
    parsed = []
    for kind, cond, extra in stmts:
        if cond is None:
            parsed.append((kind, None, extra, {}))
            continue
        node, opaque = _parse_condition(
            cond, prog_param, aliases, pred_exprs, fn_name)
        if kind == "if" and extra[0] == "ternary":
            inner_node, inner_opaque = _parse_condition(
                extra[1], prog_param, aliases, pred_exprs, fn_name)
            extra = ("ternary", (inner_node, inner_opaque), extra[2])
            check_nodes = (node, inner_node)
        else:
            check_nodes = (node,)
        for check in check_nodes:
            for block in _condition_sets(check):
                if block not in membersets:
                    raise InventoryError(
                        "kfunc filter %s@%s consults unknown ID block %s"
                        % (fn_name, version, block))
        parsed.append((kind, node, extra, opaque))
    results = {}
    for member in members:
        by_caller = {}
        for prog_type in hook_types:
            alts = _simulate_filter_caller(
                parsed, prog_type, member, membersets,
                fn_name, version)
            by_caller[prog_type] = _normalize_alts(alts)
        allowed = set(
            prog_type for prog_type, alts in by_caller.items() if alts)
        attach_union = set()
        stops_union = set()
        notes_union = set()
        for alts in by_caller.values():
            for attach, stops, notes in alts:
                attach_union |= set(attach)
                stops_union |= set(stops)
                notes_union |= set(notes)
        results[member] = {
            "types": allowed,
            "attach": attach_union,
            "stops": stops_union,
            "notes": sorted(notes_union),
            "by_caller": {
                prog_type: [(set(attach), set(stops), set(notes))
                            for attach, stops, notes in alts]
                for prog_type, alts in by_caller.items()
            },
            "alternatives": _group_alternatives(by_caller),
        }
    return results


def _normalize_alts(alts):
    """Normalize alternative triples and prune dominated ones.

    Each entry becomes (frozenset, frozenset, frozenset); exact
    duplicates collapse, and an unconditional alternative dominates
    its caller's conditional ones since it grants everything they do.
    """
    seen = []
    for attach, stops, notes in alts:
        triple = (frozenset(attach or ()), frozenset(stops or ()),
                  frozenset(notes or ()))
        if triple not in seen:
            seen.append(triple)
    uncond = (frozenset(), frozenset(), frozenset())
    if uncond in seen:
        return [uncond]
    return seen


def _group_alternatives(by_caller):
    """Group {caller: [alternatives]} into scoped alternatives.

    Callers sharing identical requirements merge into one
    alternative; branch alternatives with different requirements
    stay distinct. Returns [{callers, attach, stops, notes}] with
    sorted lists in deterministic order.
    """
    groups = {}
    for caller in sorted(by_caller):
        for triple in by_caller[caller]:
            groups.setdefault(triple, set()).add(caller)
    alts = []
    for (attach, stops, notes), callers in groups.items():
        alts.append({
            "callers": sorted(callers),
            "attach": sorted(attach),
            "stops": sorted(stops),
            "notes": sorted(notes),
        })
    alts.sort(key=lambda alt: (alt["callers"], alt["attach"],
                               alt["stops"], alt["notes"]))
    return alts


def _merge_hook_alts(per_filt):
    """AND-combine one alternative list per hook filter.

    Returns the cartesian product with conjoined requirements as
    frozenset triples; contradictory combinations drop out, and an
    empty result means the hook denies this caller.
    """
    acc = [(None, None, set())]
    for alts in per_filt:
        merged = []
        for base in acc:
            for attach, stops, notes in alts:
                out = _merge_alt_reqs(
                    base, (set(attach) or None, set(stops) or None,
                           set(notes)))
                if out is not None:
                    merged.append(out)
        acc = merged
        if not acc:
            break
    return [(frozenset(attach or ()), frozenset(stops or ()),
             frozenset(notes))
            for attach, stops, notes in acc]


def _merge_alt_reqs(base, extra):
    """Conjoin two requirement triples.

    Each triple is (attach_or_None, stops_or_None, notes) with None
    meaning unconstrained. Returns the merged triple, or None when
    the conjunction is contradictory and can never fire.
    """
    base_attach, base_stops, base_notes = base
    extra_attach, extra_stops, extra_notes = extra
    if base_attach is None:
        merged_attach = extra_attach
    elif extra_attach is None:
        merged_attach = base_attach
    else:
        merged_attach = base_attach & extra_attach
        if merged_attach == set():
            return None
    if base_stops is None:
        merged_stops = extra_stops
    elif extra_stops is None:
        merged_stops = base_stops
    else:
        merged_stops = base_stops & extra_stops
        if merged_stops == set():
            return None
    return (merged_attach, merged_stops,
            set(base_notes) | set(extra_notes))


def _dnf_alternatives(node, opaque, fn_name):
    """Expand a folded allow-condition into alternative conjunctions.

    Returns [(attach_or_None, stops_or_None, notes)] with one entry
    per disjunctive alternative; the empty list means unsatisfiable.
    Conjunctions conjoin their leaves while disjunctions stay
    distinct, so ``A || B`` yields two alternatives rather than the
    empty intersection of both.
    """
    kind = node[0]
    if kind == "const":
        return [(None, None, set())] if node[1] else []
    if kind == "attach_cmp":
        _, op, value = node
        if op == "==":
            return [({value}, None,
                     {"requires expected_attach_type %s" % value})]
        return [(None, None,
                 {"excludes expected_attach_type %s" % value})]
    if kind == "stops_cmp":
        _, op, value = node
        if op == "==":
            return [(None, {value},
                     {"requires struct_ops attachment to %s" % value})]
        return [(None, None,
                 {"rejected when attached to %s" % value})]
    if kind == "stops_null":
        return [(None, None, set())]
    if kind == "opaque":
        return [(None, None, _opaque_notes(node, opaque, fn_name))]
    if kind == "not":
        sub = node[1]
        sub_kind = sub[0]
        if sub_kind == "stops_null":
            # Load-phase leniency while st_ops is unset grants
            # nothing steady-state (fail closed).
            return []
        if sub_kind == "opaque":
            return [(None, None, _opaque_notes(node, opaque, fn_name))]
        if sub_kind in ("attach_cmp", "stops_cmp"):
            _, op, value = sub
            flipped = "!=" if op == "==" else "=="
            return _dnf_alternatives(
                (sub_kind, flipped, value), opaque, fn_name)
        if sub_kind == "not":
            return _dnf_alternatives(sub[1], opaque, fn_name)
        if sub_kind in ("and", "or"):
            return _dnf_alternatives(
                _negate_condition(node), opaque, fn_name)
        if sub_kind == "const":
            return _dnf_alternatives(
                ("const", not sub[1]), opaque, fn_name)
        raise InventoryError(
            "kfunc filter %s has an unsupported requirement" % fn_name)
    if kind == "and":
        acc = [(None, None, set())]
        for sub in node[1]:
            branch = _dnf_alternatives(sub, opaque, fn_name)
            merged = []
            for base in acc:
                for extra in branch:
                    out = _merge_alt_reqs(base, extra)
                    if out is not None:
                        merged.append(out)
            acc = merged
            if not acc:
                break
        return acc
    if kind == "or":
        out = []
        for sub in node[1]:
            out.extend(_dnf_alternatives(sub, opaque, fn_name))
        return out
    raise InventoryError(
        "kfunc filter %s has an unsupported requirement" % fn_name)


def _simulate_filter_caller(stmts, prog_type, member, membersets,
                            fn_name, version):
    """Simulate one filter over a single (caller, member) pair.

    Returns the list of allow-alternatives, each an
    (attach_or_None, stops_or_None, notes) triple giving the context
    requirements under which this caller may call this member. The
    empty list means denied. Alternatives stay distinct: each
    allow-branch conjoins only the deny-narrows accumulated before
    it, and an unconditional allow ends the fall-through path so
    later restrictions cannot leak onto an already granted path.
    """
    conj_attach, conj_stops, conj_notes = None, None, set()
    granted = []

    def snapshot():
        return (conj_attach, conj_stops, set(conj_notes))

    def apply_narrow(narrow):
        nonlocal conj_attach, conj_stops, conj_notes
        sub_attach, sub_stops, sub_notes, deny = narrow
        if deny:
            return True
        merged = _merge_alt_reqs(
            (conj_attach, conj_stops, conj_notes),
            (sub_attach, sub_stops, sub_notes))
        if merged is None:
            # Contradictory requirements prove no permission.
            return True
        conj_attach, conj_stops, conj_notes = merged
        return False

    def allow_half(node, opaque):
        """Grant the conjunction-so-far crossed with this branch.

        Returns True when the fall-through path is dead (the branch
        condition holds unconditionally), in which case later
        statements are unreachable.
        """
        folded = _fold_condition(
            node, prog_type, member, membersets)
        if folded == ("const", True):
            granted.append(snapshot())
            return True
        if folded == ("const", False):
            return False
        if folded == ("not", ("stops_null",)):
            # Load-phase leniency while st_ops is unset: the verifier
            # re-runs the filter once attachment is known, so the
            # transient allow is not a steady-state caller permission
            # and narrowing must still apply below (fail closed).
            return False
        base = snapshot()
        for extra in _dnf_alternatives(folded, opaque, fn_name):
            merged = _merge_alt_reqs(base, extra)
            if merged is not None:
                granted.append(merged)
        return False

    def deny_half(node, opaque):
        folded = _fold_condition(
            node, prog_type, member, membersets)
        if folded == ("const", True):
            return True
        if folded == ("const", False):
            return False
        required = _negate_condition(folded)
        return apply_narrow(_require_folded(
            required, opaque, fn_name, version))

    def run_ternary(inner_node, inner_opaque, allow_first):
        """Decide a ``return (C) ? 0 : -E`` statement.

        Returns the granted alternatives: the allow arm grants while
        the deny arm dies, so only previously granted alternatives
        survive a taken deny arm.
        """
        folded = _fold_condition(
            inner_node, prog_type, member, membersets)
        if folded == ("const", True):
            if allow_first:
                return [snapshot()]
            return list(granted)
        if folded == ("const", False):
            if allow_first:
                return list(granted)
            return [snapshot()]
        if allow_first:
            allow_half(inner_node, inner_opaque)
            deny_half(("not", inner_node), inner_opaque)
        else:
            allow_half(("not", inner_node), inner_opaque)
            deny_half(inner_node, inner_opaque)
        return list(granted)

    for kind, node, extra, opaque in stmts:
        if kind == "allow":
            return [snapshot()]
        if kind == "deny":
            return list(granted)
        if kind == "ternary":
            return run_ternary(node, opaque, extra)
        # kind == "if": the branch kind decides the halves.
        branch, branch_extra, allow_first = extra
        if branch == "allow":
            if allow_half(node, opaque):
                return list(granted)
        elif branch == "deny":
            if deny_half(node, opaque):
                return list(granted)
        else:  # ternary branch under the if condition
            folded_outer = _fold_condition(
                node, prog_type, member, membersets)
            if folded_outer == ("const", False):
                continue
            if folded_outer != ("const", True):
                raise InventoryError(
                    "kfunc filter %s@%s nests a ternary under a "
                    "partial condition; cannot scope it"
                    % (fn_name, version))
            inner_node, inner_opaque = branch_extra
            return run_ternary(inner_node, inner_opaque, allow_first)
    if not granted:
        raise InventoryError(
            "kfunc filter %s@%s falls off the end" % (fn_name, version))
    return list(granted)





# ---------------------------------------------------------------------------
# struct_ops consumer and sched_ext interface parsing
# ---------------------------------------------------------------------------

# Known struct_ops consumer registrations: symbol -> (record slug,
# display title). Any other ``struct bpf_struct_ops`` definition in the
# pinned sources fails generation until it is assigned an owner: an
# unknown consumer is an unknown upstream record, never a silent skip.
STRUCT_OPS_CONSUMERS = {
    "bpf_tcp_congestion_ops": ("tcp-congestion", "TCP congestion control"),
    "bpf_Qdisc_ops": ("qdisc", "queueing discipline"),
    "bpf_hid_bpf_ops": ("hid-bpf", "HID-BPF device handling"),
    "bpf_bpf_dummy_ops": ("dummy", "dummy test consumer"),
    "bpf_smc_hs_ctrl_ops": ("smc-hs", "SMC handshake offload"),
}

# Scheduler endpoint registrations, owned by the sched-ext family
# rather than the generic consumer family.
SCHED_EXT_OPS = ("bpf_sched_ext_ops", "bpf_sched_ext_ops_cid")

# sched_ext operations-table structs: struct -> interface form. The
# cpu form carries per-CPU callbacks, the cid form per-CID callbacks.
SCX_OPS_TABLES = {
    "sched_ext_ops": "cpu-form",
    "sched_ext_ops_cid": "cid-form",
}


def parse_struct_ops_defs(text):
    """Return {name: {"vops", "map_name"}} for struct_ops definitions.

    Only true definitions (``struct bpf_struct_ops <name> = {``) are
    kept; ``extern`` and forward declarations never qualify. The
    ``.verifier_ops`` and ``.name`` initializers are captured when
    present.
    """
    clean = strip_comments(text)
    found = {}
    for match in re.finditer(
            r"struct bpf_struct_ops\s+(\w+)\s*=\s*\{", clean):
        name = match.group(1)
        if name in found:
            raise InventoryError(
                "duplicate struct_ops definition %s" % name)
        body = c_brace_body(clean, match.end() - 1)
        vops = re.search(r"\.verifier_ops\s*=\s*&(\w+)", body)
        label = re.search(r"\.name\s*=\s*\"([^\"]+)\"", body)
        found[name] = {
            "vops": vops.group(1) if vops else None,
            "map_name": label.group(1) if label else None,
        }
    return found


def parse_scx_ops_tables(text):
    """Return {struct: [(callback, rettype, args)]} for sched_ext tables.

    Parses the ``struct sched_ext_ops`` (and cid-form) operations
    tables the pinned guide points at: every function-pointer member
    is one scheduler callback the BPF side may implement. Data
    members are not callbacks and are skipped. Preprocessor lines
    are not evaluated: config-gated callbacks join the union like
    every other versioned shape difference.
    """
    clean = strip_comments(text)
    tables = {}
    for match in re.finditer(
            r"struct\s+(sched_ext_ops(?:_cid)?)\s*\{", clean):
        struct = match.group(1)
        if struct not in SCX_OPS_TABLES:
            continue
        if struct in tables:
            raise InventoryError(
                "duplicate sched_ext ops table %s" % struct)
        body = strip_pp_lines(c_brace_body(clean, match.end() - 1))
        callbacks = []
        for member in re.finditer(
                r"([A-Za-z_]\w*(?:\s*\*)*)\s*\(\s*\*\s*(\w+)\s*\)"
                r"\s*\(([^;]*?)\)\s*;", body):
            if re.search(r"[A-Za-z_]\w*\s+$",
                         body[:member.start()]):
                raise InventoryError(
                    "multi-word return type on sched_ext callback %s"
                    % member.group(2))
            rettype = re.sub(r"\s+", " ", member.group(1)).strip()
            name = member.group(2)
            args = re.sub(r"\s+", " ", member.group(3)).strip()
            callbacks.append((name, rettype, args))
        if not callbacks:
            raise InventoryError(
                "sched_ext ops table %s has no callbacks" % struct)
        seen = set(re.findall(r"\(\s*\*\s*(\w+)\s*\)", body))
        taken = set(name for name, _, _ in callbacks)
        if seen != taken:
            raise InventoryError(
                "sched_ext ops table %s drops callbacks %s"
                % (struct, sorted(seen - taken)))
        tables[struct] = callbacks
    return tables


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


def required_staging_files(lock):
    """Return the exact set of staged paths refresh consumes."""
    required = set()
    for version in lock.get("uapi_versions", []):
        for filename in UAPI_FILES:
            required.add("uapi/%s/%s" % (version, filename))
    for filename in LIBBPF_FILES:
        required.add("libbpf-%s/%s" % (lock["libbpf_version"], filename))
    required.add("llvm/facts.json")
    for name in SELFTEST_LISTS:
        required.add("selftests/%s/%s" % (lock["selftests_tag"], name))
    kernel_files = lock.get("kernel_files", {})
    for version in sorted(kernel_files):
        for relpath in kernel_files[version]:
            required.add("linux/%s/%s" % (version, relpath))
    return required


def _rebase_file_mirror(lock, relpath, digest, delta):
    """Update per-file hashes inside the lock's ``sources`` mirrors."""
    for entry in lock.get("sources", []):
        versions = entry.get("versions")
        if isinstance(versions, list):
            for version in versions:
                for item in version.get("files", []):
                    url = item.get("url", "")
                    name = item.get("name", "")
                    candidate = None
                    if entry.get("id") == "linux-uapi" and url:
                        # urls end with ".../bpf.h?h=v<version>"
                        filename = url.rsplit("/", 1)[-1].split("?")[0]
                        candidate = "uapi/%s/%s" % (
                            version.get("version"), filename)
                    elif entry.get("id") == "linux-kernel" and name:
                        candidate = "linux/%s/%s" % (
                            version.get("version"), name)
                    if candidate == relpath and item.get("sha256") != digest:
                        delta.append(
                            "MIRROR %s sources/%s %s -> %s"
                            % (relpath, entry.get("id"),
                               item.get("sha256"), digest)
                        )
                        item["sha256"] = digest
        elif entry.get("id") == "libbpf":
            for item in entry.get("files", []):
                candidate = "libbpf-%s/%s" % (
                    lock.get("libbpf_version"), item.get("name"))
                if candidate == relpath and item.get("sha256") != digest:
                    delta.append(
                        "MIRROR %s sources/libbpf %s -> %s"
                        % (relpath, item.get("sha256"), digest)
                    )
                    item["sha256"] = digest


def llvm_toolchain_entry(lock):
    """Return the ``sources`` entry pinning the LLVM toolchain, if any."""
    for entry in lock.get("sources", []):
        if entry.get("id") == "llvm-toolchain":
            return entry
    return None


def check_llvm_mirror(lock):
    """Raise when the LLVM facts mirrors inside the lock disagree.

    The lock carries the toolchain facts twice -- under ``llvm.facts``
    and under ``sources``/``llvm-toolchain`` -- so a rebase that moves
    one copy and not the other would silently publish two truths.
    Rebasing heals both copies at once; any other path must fail
    closed here instead of consuming a contradicted pin.
    """
    entry = llvm_toolchain_entry(lock)
    if entry is None or "facts" not in entry:
        return
    facts = lock.get("llvm", {}).get("facts")
    if entry["facts"] != facts:
        raise InventoryError(
            "llvm facts incoherent: sources/llvm-toolchain mirror "
            "differs from llvm.facts; rebase to heal",
            status=EXIT_INTEGRITY,
        )
    if entry.get("version") != (facts or {}).get("version"):
        raise InventoryError(
            "llvm facts incoherent: sources/llvm-toolchain version %r "
            "differs from llvm.facts version %r; rebase to heal"
            % (entry.get("version"), (facts or {}).get("version")),
            status=EXIT_INTEGRITY,
        )


def verify_staging(sources_dir, lock, rebase=False):
    """Hash-check every staged file against the lock.

    Every consumed file must be pinned and every pin must be consumed;
    either gap aborts with exit 2. With ``rebase``, staged content is
    accepted as the new pin: the expected map, the ``sources`` mirrors
    and the llvm/selftest copies are updated in place and the delta is
    reported. Returns the delta (empty without rebase).
    """
    expected = lock.setdefault("expected", {})
    required = required_staging_files(lock)
    problems = []
    for relpath in sorted(set(expected) - required):
        problems.append("stale pin (not consumed): %s" % relpath)
    for relpath in sorted(required - set(expected)):
        problems.append("consumed file without pin: %s" % relpath)
    for relpath in sorted(required & set(expected)):
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
    if not rebase:
        check_llvm_mirror(lock)
        return []
    delta = []
    for relpath in sorted(set(expected) - required):
        delta.append("DROP stale pin %s" % relpath)
        del expected[relpath]
    for relpath in sorted(required):
        staged = os.path.join(sources_dir, relpath)
        if not os.path.isfile(staged):
            raise InventoryError(
                "cannot rebase missing staged file: %s" % relpath,
                status=EXIT_INTEGRITY,
            )
        actual = sha256_file(staged)
        if expected.get(relpath) != actual:
            if relpath in expected:
                delta.append("UPDATE %s %s -> %s"
                             % (relpath, expected[relpath], actual))
            else:
                delta.append("ADD pin %s %s" % (relpath, actual))
            expected[relpath] = actual
        _rebase_file_mirror(lock, relpath, actual, delta)
    staged_facts = load_json(os.path.join(sources_dir, "llvm", "facts.json"))
    if lock.get("llvm", {}).get("facts") != staged_facts:
        delta.append("MIRROR llvm facts from staged copy")
        lock.setdefault("llvm", {})["facts"] = staged_facts
    toolchain = llvm_toolchain_entry(lock)
    if toolchain is not None:
        if toolchain.get("facts") != staged_facts:
            delta.append(
                "MIRROR sources/llvm-toolchain facts from staged copy")
            toolchain["facts"] = staged_facts
        if toolchain.get("version") != staged_facts.get("version"):
            delta.append(
                "MIRROR sources/llvm-toolchain version %r -> %r"
                % (toolchain.get("version"),
                   staged_facts.get("version")))
            toolchain["version"] = staged_facts.get("version")
    staged_lists = {}
    for name in SELFTEST_LISTS:
        path = os.path.join(sources_dir, "selftests",
                            lock["selftests_tag"], name)
        with open(path, "r", encoding="utf-8") as handle:
            staged_lists[name] = sorted(
                line.strip() for line in handle if line.strip())
    if lock.get("selftests", {}).get("lists") != staged_lists:
        delta.append("MIRROR selftest lists from staged copies")
        lock.setdefault("selftests", {})["lists"] = staged_lists
    return delta


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
    kernel = {}
    for version in sorted(lock.get("kernel_files", {})):
        per_file = {}
        for relpath in lock["kernel_files"][version]:
            path = os.path.join(sources_dir, "linux", version, relpath)
            per_file[relpath] = read_text(path)
        kernel[version] = per_file
    return {
        "uapi_versions": uapi_versions,
        "uapi": uapi,
        "libbpf_version": libbpf_version,
        "libbpf": libbpf,
        "llvm": llvm_facts,
        "selftests_tag": tag,
        "selftests": selftests,
        "kernel": kernel,
        "kernel_versions": sorted(kernel),
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


# ---------------------------------------------------------------------------
# Kernel registration tables
# ---------------------------------------------------------------------------

# Kernel source paths with a fixed role. bpf_types.h maps program types to
# verifier-ops names; btf.c maps program types to kfunc hooks and proves
# the COMMON-first matching order.
BPF_TYPES_PATH = "include/linux/bpf_types.h"
BTF_PATH = "kernel/bpf/btf.c"

STRUCT_OPS_TYPE = "BPF_PROG_TYPE_STRUCT_OPS"
EXT_TYPE = "BPF_PROG_TYPE_EXT"


def collect_kernel_registration(staging):
    """Parse pinned kernel sources into per-version registration tables.

    Returns {version: tables} where tables holds ``bpf_types``,
    ``protos`` ({fn: {cases, calls, files}}), ``vops`` ({ops: (fn, file)}),
    ``struct_ops`` ({symbol: {file, vops, map_name}} for consumer and
    scheduler registrations), ``scx_ops`` ({table: {file, callbacks}}
    for the sched_ext operations tables), ``kfunc_sets`` ({block:
    {file, members}} for blocks referenced by a ``btf_kfunc_id_set``),
    ``kfunc_blocks_all`` (every parsed block, including member-only
    sets consulted by filters), ``bindings`` ([(prog, block, file,
    filter)]), ``fmodret_blocks`` (attach-target sets, not callable
    kfuncs), ``hooks`` ({prog: hook}) and ``kernel_texts`` ({file:
    stripped text} for filter simulation). Raises InventoryError on
    any dangling reference, any unknown struct_ops consumer, any
    sched_ext registration without its ops table, or on btf.c
    failing the COMMON-first check.
    """
    versions = staging["kernel_versions"]
    if not versions:
        raise InventoryError(
            "no pinned kernel sources; kernel_files is empty")
    result = {}
    for version in versions:
        files = staging["kernel"][version]
        if BPF_TYPES_PATH not in files:
            raise InventoryError(
                "kernel pin %s is missing %s"
                % (version, BPF_TYPES_PATH))
        if BTF_PATH not in files:
            raise InventoryError(
                "kernel pin %s is missing %s" % (version, BTF_PATH))
        protos = {}
        vops = {}
        blocks = {}
        idvars = {}
        registers = []
        fmodret_registers = []
        struct_ops = {}
        scx_ops = {}
        for relpath in sorted(files):
            text = files[relpath]
            for name, (cases, calls) in \
                    parse_func_protos(text).items():
                slot = protos.setdefault(
                    name, {"cases": set(), "calls": set(),
                           "files": set()})
                slot["cases"].update(cases)
                slot["calls"].update(calls)
                slot["files"].add(relpath)
            for name, fn in parse_verifier_ops(text).items():
                if name in vops and vops[name][0] != fn:
                    raise InventoryError(
                        "verifier ops %s differs across kernel "
                        "files@%s" % (name, version))
                vops[name] = (fn, relpath)
            for name, members in parse_kfunc_blocks(text).items():
                if name in blocks:
                    raise InventoryError(
                        "duplicate kfunc block %s@%s" % (name, version))
                blocks[name] = {"file": relpath, "members": members}
            for var, block, filt in parse_kfunc_id_sets(text):
                if (relpath, var) in idvars:
                    raise InventoryError(
                        "duplicate kfunc id_set %s in %s@%s"
                        % (var, relpath, version))
                idvars[(relpath, var)] = (block, filt)
            for prog, var in parse_kfunc_registers(text):
                registers.append((relpath, prog, var))
            for var in parse_fmodret_registers(text):
                fmodret_registers.append((relpath, var))
            for name, entry in parse_struct_ops_defs(text).items():
                if name in struct_ops:
                    raise InventoryError(
                        "duplicate struct_ops definition %s@%s"
                        % (name, version))
                struct_ops[name] = dict(
                    entry, file=relpath)
            for struct, callbacks in parse_scx_ops_tables(text).items():
                if struct in scx_ops:
                    raise InventoryError(
                        "duplicate sched_ext ops table %s@%s"
                        % (struct, version))
                scx_ops[struct] = {"file": relpath,
                                   "callbacks": callbacks}
        for (relpath, var), (block, _) in sorted(idvars.items()):
            if block not in blocks:
                raise InventoryError(
                    "kfunc id_set %s in %s@%s names unknown block %s"
                    % (var, relpath, version, block))
        bindings = []
        for relpath, prog, var in registers:
            if (relpath, var) not in idvars:
                raise InventoryError(
                    "register_btf_kfunc_id_set(%s) in %s@%s names "
                    "unknown id_set %s" % (prog, relpath, version, var))
            block, filt = idvars[(relpath, var)]
            bindings.append((prog, block, relpath, filt))
        fmodret_blocks = set()
        for relpath, var in fmodret_registers:
            if (relpath, var) not in idvars:
                raise InventoryError(
                    "register_btf_fmodret_id_set in %s@%s names "
                    "unknown id_set %s" % (relpath, version, var))
            fmodret_blocks.add(idvars[(relpath, var)][0])
        hooks = parse_kfunc_hook_switch(files[BTF_PATH])
        if not check_kfunc_common_first(files[BTF_PATH]):
            raise InventoryError(
                "btf.c@%s does not consult the COMMON kfunc hook "
                "first" % version)
        btypes = parse_bpf_types(files[BPF_TYPES_PATH])
        if not btypes:
            raise InventoryError(
                "no program types parsed from %s@%s"
                % (BPF_TYPES_PATH, version))
        referenced = set(block for block, _ in idvars.values())
        for name, entry in sorted(struct_ops.items()):
            if name in STRUCT_OPS_CONSUMERS or name in SCHED_EXT_OPS:
                continue
            raise InventoryError(
                "unknown struct_ops consumer %s in %s@%s; assign an "
                "owner before it can join the inventory"
                % (name, entry["file"], version))
        has_scheduler = any(name in SCHED_EXT_OPS for name in struct_ops)
        if has_scheduler and not scx_ops:
            raise InventoryError(
                "sched_ext registration without an ops table@%s; the "
                "interface enumeration is incomplete" % version)
        if scx_ops and not has_scheduler:
            raise InventoryError(
                "sched_ext ops table without a registration@%s"
                % version)
        result[version] = {
            "bpf_types": btypes,
            "protos": protos,
            "vops": vops,
            "struct_ops": struct_ops,
            "scx_ops": scx_ops,
            "kfunc_sets": {name: blocks[name] for name in referenced},
            "kfunc_blocks_all": dict(blocks),
            "bindings": bindings,
            "fmodret_blocks": fmodret_blocks,
            "hooks": hooks,
            "kernel_texts": {
                relpath: strip_comments(text)
                for relpath, text in files.items()
            },
        }
    return result


def registration_roots(tables, version, prog_types):
    """Return {prog: {"roots": [(fn, ops, file)], "note": str_or_None}}.

    Every program type resolves its verifier-ops root from bpf_types.h.
    STRUCT_OPS additionally collects consumer verifier ops found in the
    pinned files; EXT has deliberately empty ops (the verifier runs the
    extended target's ops) and resolves no helper root.
    """
    btypes = dict(tables["bpf_types"])
    shorts = set(btypes.values())
    protos = tables["protos"]
    vops = tables["vops"]
    for prog in sorted(prog_types):
        if prog not in btypes:
            raise InventoryError(
                "%s has no kernel type entry in %s@%s"
                % (prog, BPF_TYPES_PATH, version))
    roots = {}
    for prog in sorted(prog_types):
        short = btypes[prog]
        ops_name = short + "_verifier_ops"
        if ops_name not in vops:
            raise InventoryError(
                "no verifier ops %s for %s@%s"
                % (ops_name, prog, version))
        fn, vfile = vops[ops_name]
        if fn is None:
            if prog == EXT_TYPE:
                roots[prog] = {"roots": [], "vops": [(ops_name, vfile)],
                               "note": "target-inherited"}
                continue
            if prog == STRUCT_OPS_TYPE:
                roots[prog] = {"roots": [], "vops": [(ops_name, vfile)],
                               "note": "consumers-only"}
                continue
            raise InventoryError(
                "verifier ops %s for %s@%s has no get_func_proto"
                % (ops_name, prog, version))
        if fn not in protos:
            raise InventoryError(
                "verifier ops %s for %s@%s names unparsed %s"
                % (ops_name, prog, version, fn))
        roots[prog] = {"roots": [(fn, ops_name, vfile)],
                       "vops": [(ops_name, vfile)], "note": None}
    for ops_name in sorted(vops):
        stem = ops_name[:-len("_verifier_ops")] \
            if ops_name.endswith("_verifier_ops") else None
        if stem in shorts:
            continue
        fn, vfile = vops[ops_name]
        if fn is not None and fn not in protos:
            raise InventoryError(
                "verifier ops %s@%s names unparsed %s"
                % (ops_name, version, fn))
        # Anything beyond the per-type ops is a struct_ops consumer:
        # only struct_ops extends verifier ops per consumer.
        roots.setdefault(STRUCT_OPS_TYPE,
                         {"roots": [], "vops": [], "note": None})
        roots[STRUCT_OPS_TYPE]["vops"].append((ops_name, vfile))
        if fn is not None:
            roots[STRUCT_OPS_TYPE]["roots"].append((fn, ops_name, vfile))
    for prog, entry in roots.items():
        entry["roots"].sort()
        entry["vops"].sort()
    return roots


def check_proto_edges(tables, version, roots):
    """Validate delegation edges and root reachability for one version."""
    protos = tables["protos"]
    for name in sorted(protos):
        for call in sorted(protos[name]["calls"]):
            if call not in protos:
                raise InventoryError(
                    "%s@%s delegates to unparsed %s"
                    % (name, version, call))
    reachable = set()
    stack = [fn for entry in roots.values() for fn, _, _ in entry["roots"]]
    while stack:
        name = stack.pop()
        if name in reachable or name not in protos:
            continue
        reachable.add(name)
        stack.extend(call for call in protos[name]["calls"]
                     if call in protos)
    lonely = sorted(set(protos) - reachable)
    if lonely:
        raise InventoryError(
            "func_proto without a program root@%s: %s"
            % (version, ", ".join(lonely)))


def helper_contexts(tables, roots):
    """Return {BPF_FUNC_*: set(prog)} over reachable delegation."""
    protos = tables["protos"]
    resolved = {}
    for prog, entry in roots.items():
        seen = set()
        stack = [fn for fn, _, _ in entry["roots"]]
        while stack:
            name = stack.pop()
            if name in seen or name not in protos:
                continue
            seen.add(name)
            stack.extend(call for call in protos[name]["calls"]
                         if call in protos)
        for name in seen:
            for case in protos[name]["cases"]:
                resolved.setdefault(case, set()).add(prog)
    return resolved


def kfunc_callable_types(tables, version, prog_types):
    """Return {kfunc: per-version verdicts} for one version.

    Each verdict holds refs/flags/types/attach/stops/notes plus the
    caller-grouped scoped alternatives ("alternatives") and the
    evaluated registration filters ("filters"). Evaluation follows
    the pinned kernel matching order: each hook owns the union of
    its registered sets and the deduped list of its registration
    filters (btf_populate_kfunc_set), and a caller may call a member
    when the member sits in the COMMON set or its typed hook's set
    and every filter on that hook allows (btf_kfunc_is_allowed).
    Grants via either hook suffice; denials by any hook filter deny
    that hook, including for members of unfiltered sets. Extension
    programs inherit their target and are covered by the prog:EXT
    record, not listed here.
    """
    hooks = tables["hooks"]
    common_hook = hooks.get("BPF_PROG_TYPE_UNSPEC")
    if common_hook is None:
        raise InventoryError(
            "hook switch@%s files no COMMON hook" % version)
    concrete = sorted(prog for prog in prog_types
                      if prog != EXT_TYPE)
    hook_members = {}
    hook_filters = {}
    for prog, block, _, filt in tables["bindings"]:
        if prog == "BPF_PROG_TYPE_UNSPEC":
            hook = common_hook
        elif prog in hooks:
            hook = hooks[prog]
        else:
            raise InventoryError(
                "kfunc set %s@%s is registered for %s with no hook"
                % (block, version, prog))
        info = tables["kfunc_sets"][block]
        hook_members.setdefault(hook, set()).update(
            name for name, _ in info["members"])
        if filt is not None:
            hook_filters.setdefault(hook, set()).add(filt)
    membersets = {
        name: set(member for member, _ in info["members"])
        for name, info in tables["kfunc_blocks_all"].items()
    }
    all_filts = set()
    for filts in hook_filters.values():
        all_filts |= filts
    filter_files = {}
    for filt in sorted(all_filts):
        for relpath in sorted(tables["kernel_texts"]):
            if c_function_body(tables["kernel_texts"][relpath], filt):
                filter_files[filt] = relpath
                break
    all_bound = set()
    for members in hook_members.values():
        all_bound |= members
    sims = {}
    for filt in sorted(all_filts):
        sims[filt] = simulate_kfunc_filter(
            filt, tables["kernel_texts"], version,
            sorted(all_bound), membersets, concrete)
    out = {}
    # A kfunc may sit in several sets per version (for example a COMMON
    # set plus a type-specific one); registration references and flags
    # union across its blocks so no ordering can change the record,
    # while callability is decided per hook below.
    for block in sorted(tables["kfunc_sets"]):
        info = tables["kfunc_sets"][block]
        for name, flags in info["members"]:
            slot = out.setdefault(
                name, {"refs": [], "flags": {}, "types": {},
                       "attach": {}, "stops": {}, "notes": {},
                       "filtered": {}, "filters": {},
                       "alternatives": {}})
            slot["refs"].append((info["file"], block))
            slot["flags"].setdefault(version, set()).add(
                flags if flags is not None else "no flags")
    for name in sorted(out):
        slot = out[name]
        slot["types"].setdefault(version, set())
        slot["attach"].setdefault(version, set())
        slot["stops"].setdefault(version, set())
        slot["notes"].setdefault(version, set())
        slot["filters"].setdefault(version, set())
        slot["alternatives"].setdefault(version, [])
        if name not in all_bound:
            # A referenced but never registered set: present in the
            # source, bound to no program type. Still inventoried,
            # with no callable contexts.
            slot["filtered"][version] = False
            continue
        by_caller = {}
        for caller in concrete:
            hooks_to_try = []
            if name in hook_members.get(common_hook, ()):
                hooks_to_try.append(common_hook)
            typed_hook = hooks.get(caller)
            if typed_hook is not None and typed_hook != common_hook \
                    and name in hook_members.get(typed_hook, ()):
                hooks_to_try.append(typed_hook)
            combined = []
            for hook in hooks_to_try:
                filts = sorted(hook_filters.get(hook, ()))
                if not filts:
                    combined.append(
                        (frozenset(), frozenset(), frozenset()))
                    continue
                per_filt = [sims[filt][name]["by_caller"][caller]
                            for filt in filts]
                if any(not alts for alts in per_filt):
                    # One hook filter denies: no grant via this hook.
                    continue
                combined.extend(_merge_hook_alts(per_filt))
            by_caller[caller] = _normalize_alts(combined)
        slot["alternatives"][version] = _group_alternatives(by_caller)
        for caller, alts in by_caller.items():
            if alts:
                slot["types"][version].add(caller)
            for attach, stops, notes in alts:
                slot["attach"][version] |= set(attach)
                slot["stops"][version] |= set(stops)
                slot["notes"][version] |= set(notes)
        member_hooks = sorted(
            hook for hook, members in hook_members.items()
            if name in members)
        for hook in member_hooks:
            for filt in sorted(hook_filters.get(hook, ())):
                verdict = sims[filt][name]
                if all(alts == [(set(), set(), set())]
                       for alts in verdict["by_caller"].values()):
                    # Short-circuit allow for a foreign member:
                    # no constraint, so no reference.
                    continue
                if filt in filter_files:
                    slot["filters"][version].add(
                        (filt, filter_files[filt]))
        slot["filtered"][version] = bool(not slot["types"][version])
    for slot in out.values():
        for key in slot["flags"]:
            slot["flags"][key] = sorted(slot["flags"][key])
        for key in slot["types"]:
            slot["types"][key] = sorted(slot["types"][key])
        for key in slot["attach"]:
            slot["attach"][key] = sorted(slot["attach"][key])
        for key in slot["stops"]:
            slot["stops"][key] = sorted(slot["stops"][key])
        for key in slot["notes"]:
            slot["notes"][key] = sorted(slot["notes"][key])
        for key in slot["filters"]:
            slot["filters"][key] = sorted(slot["filters"][key])
    return out


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
    check_llvm_mirror(lock)
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

    # Pinned kernel registration, resolved per version.
    if sorted(staging["kernel_versions"]) != sorted(version_order):
        raise InventoryError(
            "kernel pin versions %s do not match UAPI versions %s"
            % (sorted(staging["kernel_versions"]), version_order)
        )
    uapi_prog_types = {}
    for version in version_order:
        typed = []
        for atom_name, atom in atoms.items():
            if version not in atom.present_in:
                continue
            classification, group, _, _, _ = classify_uapi_atom(
                atom_name, atom, canonical)
            if classification == "capability" and group == "prog":
                typed.append(atom_name)
        uapi_prog_types[version] = typed
    registration = collect_kernel_registration(staging)
    helper_sites = {}
    helper_types = {}
    prog_roots = {}
    kfunc_index = {}
    fmodret_index = {}
    uapi_helper_ids = set(
        "BPF_FUNC_" + name for name in helpers if name != "unspec")
    for version in version_order:
        tables = registration[version]
        roots = registration_roots(
            tables, version, uapi_prog_types[version])
        check_proto_edges(tables, version, roots)
        for prog, entry in roots.items():
            prog_roots.setdefault(prog, {})[version] = entry
        for case, progs in helper_contexts(tables, roots).items():
            if case not in uapi_helper_ids:
                raise InventoryError(
                    "kernel@%s registers unknown helper %s"
                    % (version, case))
            helper_types.setdefault(case, {})[version] = sorted(progs)
        for fn, slot in tables["protos"].items():
            for case in slot["cases"]:
                for relpath in sorted(slot["files"]):
                    helper_sites.setdefault(case, []).append(
                        (version, relpath, fn))
        bound = set(block for _, block, _, _ in tables["bindings"])
        for name, slot in kfunc_callable_types(
                tables, version, uapi_prog_types[version]).items():
            dest = kfunc_index.setdefault(
                name, {"refs": [], "flags": {}, "types": {},
                       "attach": {}, "stops": {}, "notes": {},
                       "filtered": {}, "filters": {}, "fmodret": [],
                       "alternatives": {}})
            for relpath, block in slot["refs"]:
                dest["refs"].append((version, relpath, block))
            dest["flags"][version] = slot["flags"][version]
            dest["types"][version] = slot["types"][version]
            dest["attach"][version] = slot["attach"][version]
            dest["stops"][version] = slot["stops"][version]
            dest["notes"][version] = slot["notes"][version]
            dest["filtered"][version] = slot["filtered"][version]
            dest["filters"][version] = slot["filters"][version]
            dest["alternatives"][version] = slot["alternatives"][version]
        for block in tables["fmodret_blocks"]:
            info = tables["kfunc_sets"][block]
            for name, _ in info["members"]:
                if block in bound:
                    dest = kfunc_index.setdefault(
                        name, {"refs": [], "flags": {}, "types": {},
                               "attach": {}, "stops": {}, "notes": {},
                               "filtered": {}, "filters": {},
                               "fmodret": [], "alternatives": {}})
                    dest["fmodret"].append(
                        (version, info["file"], block))
                    continue
                slot = fmodret_index.setdefault(name, [])
                slot.append((version, info["file"], block))
    for name, per_version in sorted(helpers.items()):
        if name == "unspec":
            continue
        full = "BPF_FUNC_" + name
        have = set(ver for ver, _, _ in helper_sites.get(full, []))
        for version in sorted(per_version):
            if version not in have:
                raise InventoryError(
                    "helper %s in UAPI@%s has no kernel registration"
                    % (full, version))
    for version in version_order:
        for prog, _, _, _ in registration[version]["bindings"]:
            if prog == "BPF_PROG_TYPE_UNSPEC":
                continue
            if prog not in uapi_prog_types[version]:
                raise InventoryError(
                    "kfunc binding for unknown %s@%s" % (prog, version))
    # Members seen only in fmodret attach-target sets are not callable
    # kfuncs; they move to the fmodret index (context-only members).
    for name in sorted(kfunc_index):
        slot = kfunc_index[name]
        keep = False
        for version, _, block in slot["refs"]:
            tables = registration[version]
            bound_here = set(bound for _, bound, _, _
                             in tables["bindings"])
            if block in bound_here or \
                    block not in tables["fmodret_blocks"]:
                keep = True
                break
        if not keep:
            del kfunc_index[name]

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
        elif group == "flag":
            rec_id = "flag:" + name
            record = base_record(rec_id, family, refs, predicate, next_action,
                                 "flag-option", "option-flag")
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
        full = "BPF_FUNC_" + name
        contexts = helper_types.get(full, {})
        type_count = len(set(prog for per_version in contexts.values()
                             for prog in per_version))
        predicate = (
            "kernel UAPI assigns helper ID %d to BPF_FUNC_%s "
            "(first pinned in %s); the pinned kernel sources register "
            "it for %d program types"
            % (hid, name, oldest, type_count)
        )
        positive = helper_test_case(name) or FAMILIES["helpers"][3][0]
        record = base_record(rec_id, "helpers", refs, predicate,
                             "Implement the typed helper intrinsic "
                             "under X-HELPERS.",
                             "helper-intrinsic", "not-applicable",
                             positive=positive)
        record["helpers_or_kfuncs"] = [{
            "name": "bpf_" + name,
            "kind": "helper",
            "callable": True,
        }]
        record["kernel_registration_refs"] = sorted(
            "linux:%s@%s#%s" % (relpath, version, fn)
            for version, relpath, fn in helper_sites[full]
        )
        record["callable_context_predicates"] = [
            "callable from %s (%s)" % (", ".join(contexts[version]),
                                       version)
            for version in sorted(contexts)
        ]
        add_record(record)
        add_member("BPF_FUNC_" + name, "uapi:bpf.h#helper-mapper", hid,
                   "FN(%s, %d)" % (name, hid), present, "capability",
                   record_id=rec_id)

    # -- Kernel functions ------------------------------------------------
    for name in sorted(kfunc_index):
        slot = kfunc_index[name]
        call_refs = []
        for version, relpath, block in slot["refs"]:
            tables = registration[version]
            bound = set(bound for _, bound, _, _ in tables["bindings"])
            # Fmodret-only sets are attach targets, not call
            # registrations; they are noted on the predicates below.
            if block in bound or block not in tables["fmodret_blocks"]:
                call_refs.append((version, relpath, block))
        present = sorted(set(version for version, _, _ in call_refs))
        refs = ["linux:%s@%s" % (relpath, version)
                for version in present
                for relpath in sorted(set(
                    rel for ver, rel, _ in call_refs
                    if ver == version))]
        oldest = min(present, key=lambda ver: rank.get(ver, 0))
        type_count = len(set(prog for version in present
                             for prog in slot["types"][version]))
        callable = type_count > 0
        denied = all(slot["filtered"].get(version, False)
                     for version in present)
        if callable:
            predicate = (
                "kernel kfunc %s (first pinned in %s) is registered "
                "for %d program types"
                % (name, oldest, type_count)
            )
            next_action = ("Implement the typed kfunc binding "
                           "under X-KFUNCS.")
        elif denied:
            predicate = (
                "kernel kfunc %s (first pinned in %s) is registered "
                "but its filter denies all contexts"
                % (name, oldest)
            )
            next_action = ("Confirm the denying filter in the pinned "
                           "kernel sources under X-KFUNCS.")
        else:
            predicate = (
                "kernel kfunc %s (first pinned in %s) is present in "
                "a kfunc set but bound to no program type"
                % (name, oldest)
            )
            next_action = ("Confirm the missing program binding in the "
                           "pinned kernel sources under X-KFUNCS.")
        rec_id = "kfunc:" + name
        record = base_record(rec_id, "kfuncs", refs, predicate,
                             next_action, "helper-intrinsic",
                             "not-applicable")
        record["helpers_or_kfuncs"] = [{
            "name": name,
            "kind": "kfunc",
            "callable": callable,
        }]
        reg_refs = [
            "linux:%s@%s#%s" % (relpath, version, block)
            for version, relpath, block in call_refs
        ]
        for version in present:
            for filt, relpath in slot["filters"][version]:
                reg_refs.append(
                    "linux:%s@%s#%s" % (relpath, version, filt))
        record["kernel_registration_refs"] = sorted(set(reg_refs))
        record["attach_types"] = sorted(set(
            attach for version in present
            for attach in slot["attach"][version]))
        predicates = []
        flag_sets = [tuple(slot["flags"][version]) for version in present]
        if len(set(flag_sets)) == 1 and len(flag_sets[0]) == 1:
            predicates.append("kfunc flags: %s" % flag_sets[0][0])
        else:
            for version in present:
                predicates.append("kfunc flags (%s): %s"
                                  % (version,
                                     "; ".join(slot["flags"][version])))
        for version in present:
            types = slot["types"][version]
            alts = slot["alternatives"][version]
            if types:
                if len(alts) == 1:
                    predicates.append(
                        "callable from %s (%s)"
                        % (", ".join(types), version))
                    for note in alts[0]["notes"]:
                        predicates.append(
                            "%s (%s)" % (note, version))
                else:
                    for alt in alts:
                        callers = ", ".join(alt["callers"])
                        phrases = [
                            note[len("requires "):]
                            if note.startswith("requires ") else note
                            for note in alt["notes"]]
                        if alt["attach"] and not any(
                                "expected_attach_type" in phrase
                                for phrase in phrases):
                            phrases.append(
                                "expected_attach_type one of: "
                                + ", ".join(alt["attach"]))
                        if alt["stops"] and not any(
                                "struct_ops attachment" in phrase
                                for phrase in phrases):
                            phrases.append(
                                "struct_ops attachment to one of: "
                                + ", ".join(alt["stops"]))
                        if phrases:
                            predicates.append(
                                "callable from %s when %s (%s)"
                                % (callers, " and ".join(
                                    sorted(phrases)), version))
                        else:
                            predicates.append(
                                "callable from %s (%s)"
                                % (callers, version))
            elif slot["filtered"][version]:
                predicates.append(
                    "registration filter denies all contexts (%s)"
                    % version)
            else:
                predicates.append(
                    "bound to no program type (%s)" % version)
        for version, relpath, block in sorted(slot["fmodret"]):
            predicates.append(
                "also a modify_return attach target (%s@%s#%s)"
                % (relpath, version, block))
        record["callable_context_predicates"] = predicates
        add_record(record)
        newest_flags = "; ".join(slot["flags"][max(
            present, key=lambda ver: rank.get(ver, 0))])
        add_member(name, "linux:kfunc-sets", None, newest_flags,
                   present, "capability", record_id=rec_id,
                   note="sets: " + ", ".join(
                       "%s#%s@%s" % (relpath, block, version)
                       for version, relpath, block
                       in sorted(call_refs)))

    # Fmodret attach targets: traceable, but not callable kfuncs.
    for name in sorted(fmodret_index):
        refs = sorted(fmodret_index[name])
        present = sorted(set(version for version, _, _ in refs))
        add_member(name, "linux:fmodret-ids", None, None, present,
                   "context-only",
                   record_refs=["attach:MODIFY_RETURN"],
                   note="modify_return attach target in " + ", ".join(
                       "%s#%s@%s" % (relpath, block, version)
                       for version, relpath, block in refs))

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
        required = []
        if "SEC_SLEEPABLE" in flags:
            required.append("BPF_F_SLEEPABLE")
        if "SEC_XDP_FRAGS" in flags:
            # Pinned libbpf sets BPF_F_XDP_HAS_FRAGS at load for exactly
            # these sections (libbpf_prepare_prog_load); no other XDP
            # section requires it, and plain XDP programs require no flags.
            required.append("BPF_F_XDP_HAS_FRAGS")
        if required:
            record["required_flags"] = required
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

    # Fold kernel verifier roots into program records.
    for prog_full, per_version in sorted(prog_roots.items()):
        short = strip_prefix(prog_full, "BPF_PROG_TYPE_")
        rec_id = "prog:" + short
        if rec_id not in records:
            continue
        record = records[rec_id]
        refs = []
        predicates = []
        for version in sorted(per_version):
            entry = per_version[version]
            for ops_name, vfile in entry["vops"]:
                refs.append("linux:%s@%s#%s" % (vfile, version, ops_name))
            if entry["note"] == "target-inherited":
                predicates.append(
                    "freplace programs verify under the extended "
                    "target's operations (%s)" % version)
            elif not entry["roots"]:
                predicates.append(
                    "callbacks verify through consumer operations "
                    "with no helper root (%s)" % version)
            else:
                roots = ", ".join(fn for fn, _, _ in entry["roots"])
                predicates.append(
                    "helper calls resolve through %s (%s)"
                    % (roots, version))
        record["kernel_registration_refs"] = sorted(refs)
        record["callable_context_predicates"] = predicates

    # XDP program flags are optional load variants, never universal
    # requirements: the pinned UAPI phrases both BPF_F_XDP_HAS_FRAGS and
    # BPF_F_XDP_DEV_BOUND_ONLY as "if used", and pinned libbpf sets
    # HAS_FRAGS only for SEC_XDP_FRAGS sections (handled above).
    # prog:XDP therefore requires no flags.

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

    # -- struct_ops consumers ------------------------------------------------
    # Every struct_ops registration in the pinned kernel sources owns
    # a record: subsystem consumers land in structops-consumers and
    # the scheduler endpoints in sched-ext. A consumer verifier-ops
    # root without a registration fails generation: half-enumerated
    # consumers are unknown upstream records, never silent skips.
    docs = {doc["id"]: doc for doc in lock.get("docs", [])}

    def doc_ref(doc_id):
        doc = docs[doc_id]
        return "%s (sha256 %s)" % (doc["url"], doc["sha256"])

    for version in version_order:
        tables = registration[version]
        for symbol, entry in sorted(tables["struct_ops"].items()):
            vops = entry["vops"]
            if vops is not None and vops not in tables["vops"]:
                raise InventoryError(
                    "struct_ops %s in %s@%s names unparsed verifier "
                    "ops %s" % (symbol, entry["file"], version, vops))
    for version in sorted(prog_roots.get(STRUCT_OPS_TYPE, {})):
        entry = prog_roots[STRUCT_OPS_TYPE][version]
        defs = registration[version]["struct_ops"]
        for ops_name, _ in entry["vops"]:
            if ops_name == "bpf_struct_ops_verifier_ops":
                continue
            owners = [name for name, info in defs.items()
                      if info["vops"] == ops_name]
            if not owners:
                raise InventoryError(
                    "struct_ops consumer verifier ops %s@%s has no "
                    "registration in the pinned sources"
                    % (ops_name, version))
    consumers_present = {}
    for version in version_order:
        for symbol in registration[version]["struct_ops"]:
            if symbol in STRUCT_OPS_CONSUMERS:
                consumers_present.setdefault(symbol, []).append(version)
    for symbol in sorted(consumers_present):
        slug, title = STRUCT_OPS_CONSUMERS[symbol]
        present = sorted(consumers_present[symbol])
        oldest = min(present, key=lambda ver: rank.get(ver, 0))
        refs = []
        reg_refs = []
        predicates = []
        for version in present:
            entry = registration[version]["struct_ops"][symbol]
            refs.append("linux:%s@%s" % (entry["file"], version))
            reg_refs.append(
                "linux:%s@%s#%s" % (entry["file"], version, symbol))
            if entry["map_name"] is not None:
                predicates.append(
                    "registered under the map name '%s' (%s)"
                    % (entry["map_name"], version))
            if entry["vops"] is not None:
                vfile = registration[version]["vops"][
                    entry["vops"]][1]
                reg_refs.append(
                    "linux:%s@%s#%s" % (vfile, version, entry["vops"]))
                predicates.append(
                    "%s programs verify through %s (%s)"
                    % (title, entry["vops"], version))
            else:
                predicates.append(
                    "registered without verifier-ops overrides (%s)"
                    % version)
        for version in sorted(set(version_order) - set(present)):
            predicates.append(
                "absent from %s (no %s registration in the pins)"
                % (version, symbol))
        rec_id = "structops:" + slug
        record = base_record(
            rec_id, "structops-consumers", refs,
            "kernel subsystem %s consumes struct_ops maps (first "
            "pinned in %s; present in %s)"
            % (title, oldest, ", ".join(present)),
            "Bind the %s consumer to qualification tests under %s."
            % (title, FAMILIES["structops-consumers"][2]),
            "program", "load-attach")
        record["program_types"] = [STRUCT_OPS_TYPE]
        record["kernel_registration_refs"] = sorted(set(reg_refs))
        record["callable_context_predicates"] = predicates
        add_record(record)
        newest = max(present, key=lambda ver: rank.get(ver, 0))
        newest_vops = registration[newest][
            "struct_ops"][symbol]["vops"]
        add_member(symbol, "linux:struct-ops", None, newest_vops,
                   present, "capability", record_id=rec_id,
                   note="consumer registration: " + ", ".join(
                       "%s#%s@%s"
                       % (registration[version]["struct_ops"][
                           symbol]["file"], symbol, version)
                       for version in present))

    # -- sched_ext interface ---------------------------------------------------
    # The scheduler endpoints and every operations-table callback from
    # the pinned kernel sources. The pinned guide names the interface
    # files and documents the ABI instability; the per-version
    # callback lists below come from the tagged sources themselves.
    sched_present = sorted(
        version for version in version_order
        if any(name in SCHED_EXT_OPS
               for name in registration[version]["struct_ops"]))
    if sched_present:
        guide = doc_ref("sched-ext-doc")
        oldest = min(sched_present, key=lambda ver: rank.get(ver, 0))
        refs = [guide]
        reg_refs = []
        predicates = []
        for version in sched_present:
            tables = registration[version]
            pairs = sorted(
                (SCX_OPS_TABLES[struct],
                 len(tables["scx_ops"][struct]["callbacks"]))
                for struct in tables["scx_ops"])
            predicates.append(
                "sched_ext %s interface with %s callbacks (%s)"
                % (" + ".join(form for form, _ in pairs),
                   " + ".join(str(count) for _, count in pairs),
                   version))
            seen_files = set()
            for symbol in sorted(tables["struct_ops"]):
                if symbol not in SCHED_EXT_OPS:
                    continue
                entry = tables["struct_ops"][symbol]
                seen_files.add(entry["file"])
                reg_refs.append(
                    "linux:%s@%s#%s" % (entry["file"], version, symbol))
                if entry["vops"] is not None:
                    vfile = tables["vops"][entry["vops"]][1]
                    reg_refs.append(
                        "linux:%s@%s#%s"
                        % (vfile, version, entry["vops"]))
            for struct in sorted(tables["scx_ops"]):
                seen_files.add(tables["scx_ops"][struct]["file"])
            refs.extend("linux:%s@%s" % (relpath, version)
                        for relpath in sorted(seen_files))
        for version in sorted(set(version_order) - set(sched_present)):
            predicates.append(
                "absent from %s (no sched_ext source at that tag)"
                % version)
        predicates.append(
            "operations carry no stability guarantees "
            "(pinned guide, ABI Instability)")
        record = base_record(
            "scx:sched-ext", "sched-ext", refs,
            "kernel sched_ext scheduler endpoints (first pinned in "
            "%s; present in %s)"
            % (oldest, ", ".join(sched_present)),
            "Author the minimal-scheduler workload under %s."
            % FAMILIES["sched-ext"][2],
            "program", "load-attach")
        record["program_types"] = [STRUCT_OPS_TYPE]
        record["kernel_registration_refs"] = sorted(set(reg_refs))
        record["callable_context_predicates"] = predicates
        add_record(record)
        for symbol in SCHED_EXT_OPS:
            present = sorted(
                version for version in sched_present
                if symbol in registration[version]["struct_ops"])
            if not present:
                continue
            newest = max(present, key=lambda ver: rank.get(ver, 0))
            newest_vops = registration[newest][
                "struct_ops"][symbol]["vops"]
            add_member(symbol, "linux:struct-ops", None,
                       newest_vops, present, "capability",
                       record_id="scx:sched-ext",
                       note="scheduler endpoint: " + ", ".join(
                           "%s#%s@%s"
                           % (registration[version]["struct_ops"][
                               symbol]["file"], symbol, version)
                           for version in present))
        callbacks = {}
        for version in sched_present:
            tables = registration[version]
            for struct in sorted(tables["scx_ops"]):
                info = tables["scx_ops"][struct]
                for name, rettype, args in info["callbacks"]:
                    slot = callbacks.setdefault(name, {})
                    slot.setdefault(version, {})[struct] = (
                        rettype, args, info["file"])
        for name in sorted(callbacks):
            slot = callbacks[name]
            present = sorted(slot)
            sigs = set(
                (rettype, args)
                for per_version in slot.values()
                for rettype, args, _ in per_version.values())
            refs = sorted(set(
                "linux:%s@%s" % (info, version)
                for version, per_version in slot.items()
                for _, _, info in per_version.values()))
            reg_refs = sorted(
                "linux:%s@%s#%s" % (info, version, struct)
                for version, per_version in slot.items()
                for struct, (_, _, info) in per_version.items())
            cb_predicates = []
            if len(sigs) == 1:
                rettype, args = sorted(sigs)[0]
                cb_predicates.append(
                    "callback signature: %s (*%s)(%s)"
                    % (rettype, name, args))
            else:
                for version in present:
                    for struct in sorted(slot[version]):
                        rettype, args, _ = slot[version][struct]
                        cb_predicates.append(
                            "callback signature (%s %s): %s (*%s)(%s)"
                            % (version, SCX_OPS_TABLES[struct],
                               rettype, name, args))
            for struct in SCX_OPS_TABLES:
                having = sorted(
                    version for version in present
                    if struct in slot[version])
                if having:
                    cb_predicates.append(
                        "%s (%s)" % (SCX_OPS_TABLES[struct],
                                     ", ".join(having)))
            rec_id = "scx:" + name
            record = base_record(
                rec_id, "sched-ext", refs,
                "sched_ext scheduler callback %s (present in %s)"
                % (name, ", ".join(present)),
                "Qualify the %s callback under %s."
                % (name, FAMILIES["sched-ext"][2]),
                "program", "load-attach")
            record["program_types"] = [STRUCT_OPS_TYPE]
            record["kernel_registration_refs"] = sorted(set(reg_refs))
            record["callable_context_predicates"] = cb_predicates
            add_record(record)
            newest = max(present, key=lambda ver: rank.get(ver, 0))
            newest_struct = sorted(slot[newest])[0]
            newest_sig = "%s (*%s)(%s)" % (
                slot[newest][newest_struct][0], name,
                slot[newest][newest_struct][1])
            add_member(name, "linux:scx-ops", None, newest_sig,
                       present, "capability", record_id=rec_id,
                       note="scheduler callback in " + ", ".join(
                           "%s#%s@%s" % (info, struct, version)
                           for version in present
                           for struct, (_, _, info)
                           in sorted(slot[version].items())))

    # -- Family-level blockers -------------------------------------------------
    blockers = []
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
    # -- Selftest mapping --------------------------------------------------
    # Every pinned selftest ID maps onto a record or is cited as blocker
    # evidence. Unmapped IDs abort generation: unknown upstream records
    # fail completeness until they are assigned an owner and tests.
    tag = staging["selftests_tag"]
    exempt = set()
    for entry in blockers:
        for ref in entry.get("source_refs", []):
            marker = "selftests:%s#" % tag
            if ref.startswith(marker):
                exempt.add(ref[len(marker):])
    unmapped = []
    for path in sorted(selftest_paths):
        if path in exempt:
            continue
        subdir, filename = path.split("/", 1)
        target = selftest_target(subdir, filename)
        if target is None:
            unmapped.append(path)
            continue
        if target not in records:
            raise InventoryError(
                "selftest rule for %s targets missing record %s"
                % (path, target)
            )
        records[target]["upstream_source_refs"].append(
            "selftests:%s#%s" % (tag, path))
    if unmapped:
        raise InventoryError(
            "unmapped selftest IDs fail completeness; map them onto "
            "capability records:\n  " + "\n  ".join(unmapped)
        )
    for record in records.values():
        record["upstream_source_refs"] = sorted(
            record["upstream_source_refs"])

    revision = lock.get("registry_revision")
    if revision not in SUPPORTED_REGISTRY_REVISIONS:
        raise InventoryError(
            "unsupported registry revision %r (supports %s)"
            % (revision, sorted(SUPPORTED_REGISTRY_REVISIONS))
        )
    registry = {
        "registry_version": REGISTRY_VERSION,
        "schema_version": SCHEMA_VERSION,
        "revision": revision,
        "frozen": True,
        "generated_by": {
            "tool": TOOL_NAME + " refresh",
            "lock_digest": lock_digest_of(lock),
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
            "Revision %d freezes identity, ownership and test mapping; "
            "implementation_state is PLANNED throughout except "
            "records under an explicit blocker." % revision,
            "Helper callability and kfunc membership derive from the "
            "pinned kernel registration sources; every pinned selftest "
            "ID maps onto a record or blocker evidence.",
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
            else:
                target = next(
                    (other for other in registry.get("enum_members", [])
                     if other.get("name") == item.get("canonical")
                     and other.get("container") == item.get("container")
                     and other.get("classification") in (
                         "capability", "context-only", "limit")),
                    None,
                )
                if target is None:
                    errors.append(
                        "%s: alias target %r is missing or unclassified "
                        "in %s" % (item.get("name"), item.get("canonical"),
                                   item.get("container")))
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

def _diff_table(old_list, new_list):
    """Diff [{id, ...}] tables into added/removed/changed-id lists."""
    old_map = {entry["id"]: entry for entry in old_list}
    new_map = {entry["id"]: entry for entry in new_list}
    added = sorted(set(new_map) - set(old_map))
    removed = sorted(set(old_map) - set(new_map))
    changed = []
    for key in sorted(set(old_map) & set(new_map)):
        fields = sorted(
            field for field in set(old_map[key]) | set(new_map[key])
            if old_map[key].get(field) != new_map[key].get(field)
        )
        if fields:
            changed.append({"id": key, "fields": fields})
    return added, removed, changed


def diff_documents(old, new):
    """Return a deterministic diff dict between two registry documents.

    Covers records, members, blockers, families, packages and the
    provenance/revision metadata: no material change is silent.
    """
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
    (diff["blockers_added"], diff["blockers_removed"],
     diff["blockers_changed"]) = _diff_table(
        old.get("blockers", []), new.get("blockers", []))
    (diff["families_added"], diff["families_removed"],
     diff["families_changed"]) = _diff_table(
        old.get("families", []), new.get("families", []))
    (diff["packages_added"], diff["packages_removed"],
     diff["packages_changed"]) = _diff_table(
        old.get("packages", []), new.get("packages", []))
    metadata = []
    for field in ("registry_version", "schema_version", "revision",
                  "frozen", "generated_by", "notes"):
        if old.get(field) != new.get(field):
            metadata.append(field)
    diff["metadata_changed"] = sorted(metadata)
    return diff


def format_diff(diff):
    lines = []
    for field in diff.get("metadata_changed", []):
        lines.append("metadata changed: %s" % field)
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
    for key in diff.get("blockers_added", []):
        lines.append("blocker added: %s" % key)
    for key in diff.get("blockers_removed", []):
        lines.append("blocker removed: %s" % key)
    for entry in diff.get("blockers_changed", []):
        lines.append("blocker changed: %s (%s)"
                     % (entry["id"], ", ".join(entry["fields"])))
    for key in diff.get("families_added", []):
        lines.append("family added: %s" % key)
    for key in diff.get("families_removed", []):
        lines.append("family removed: %s" % key)
    for entry in diff.get("families_changed", []):
        lines.append("family changed: %s (%s)"
                     % (entry["id"], ", ".join(entry["fields"])))
    for key in diff.get("packages_added", []):
        lines.append("package added: %s" % key)
    for key in diff.get("packages_removed", []):
        lines.append("package removed: %s" % key)
    for entry in diff.get("packages_changed", []):
        lines.append("package changed: %s (%s)"
                     % (entry["id"], ", ".join(entry["fields"])))
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
    schema = load_json(repo_relative(args.schema, args.root))
    try:
        if args.rebase_lock:
            delta = verify_staging(args.sources, lock, rebase=True)
            with open(lock_path, "w", encoding="utf-8") as handle:
                handle.write(dump_canonical(lock))
            print("lock rebased: %s" % lock_path)
            for line in delta:
                print("  " + line)
            if not delta:
                print("  no drift; lock unchanged")
        else:
            verify_staging(args.sources, lock)
        staging = load_staging(args.sources, lock)
        registry = inventory(staging, lock)
        gate_errors = validate_schema(registry, schema)
        gate_errors.extend(check_completeness(registry))
        if gate_errors:
            raise InventoryError(
                "generated registry fails validation; not publishing:\n  "
                + "\n  ".join(sorted(set(gate_errors))[:20]),
                status=EXIT_INVALID,
            )
    except InventoryError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return exc.status
    registry_path = repo_relative(args.registry, args.root)
    with open(registry_path, "w", encoding="utf-8") as handle:
        handle.write(dump_canonical(registry))
    lock[PUBLISHED_KEY] = {
        "registry_digest": sha256_file(registry_path),
        "records": len(registry["records"]),
        "members": len(registry["enum_members"]),
        "revision": registry["revision"],
    }
    with open(lock_path, "w", encoding="utf-8") as handle:
        handle.write(dump_canonical(lock))
    print("wrote %s (%d records, %d members)" % (
        registry_path, len(registry["records"]),
        len(registry["enum_members"])))
    return EXIT_OK


def cmd_validate(args):
    schema = load_json(repo_relative(args.schema, args.root))
    registry_path = repo_relative(args.registry, args.root)
    registry = load_json(registry_path)
    registry_digest = sha256_file(registry_path)
    lock = load_json(repo_relative(args.lock, args.root))
    errors = validate_schema(registry, schema)
    errors.extend(check_completeness(registry))
    errors.extend(check_binding(registry, lock, registry_digest))
    if args.sources:
        try:
            verify_staging(args.sources, lock)
            staging = load_staging(args.sources, lock)
            expect = dump_canonical(inventory(staging, lock))
        except InventoryError as exc:
            print("error: %s" % exc, file=sys.stderr)
            return exc.status
        with open(registry_path, "r", encoding="utf-8") as handle:
            actual = handle.read()
        if actual != expect:
            errors.append(
                "registry bytes differ from inventory(staging, lock)")
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
    registry = load_json(registry_path)
    lock = load_json(repo_relative(args.lock, args.root))
    revision = registry.get("revision")
    if revision not in SUPPORTED_REGISTRY_REVISIONS:
        print("error: unsupported registry revision %r (supports %s)"
              % (revision, sorted(SUPPORTED_REGISTRY_REVISIONS)),
              file=sys.stderr)
        return EXIT_INVALID
    if revision != lock.get("registry_revision"):
        print("error: registry revision %r does not match lock revision "
              "%r" % (revision, lock.get("registry_revision")),
              file=sys.stderr)
        return EXIT_INVALID
    schema = load_json(schema_path)
    errors = validate_schema(registry, schema)
    errors.extend(check_completeness(registry))
    errors.extend(check_binding(registry, lock, sha256_file(registry_path)))
    if errors:
        for line in sorted(set(errors)):
            print("error: %s" % line, file=sys.stderr)
        return EXIT_INVALID
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
        "revision": revision,
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
    refresh.add_argument("--schema",
                         default="schemas/capability.schema.json")
    refresh.add_argument("--rebase-lock", action="store_true",
                         help="accept staged content as the new pin")
    refresh.set_defaults(func=cmd_refresh)
    validate = sub.add_parser("validate", help="validate a registry")
    validate.add_argument("--schema",
                          default="schemas/capability.schema.json")
    validate.add_argument("--registry",
                          default="capabilities/registry.json")
    validate.add_argument("--lock",
                          default="capabilities/upstream.lock.json")
    validate.add_argument("--sources", default=None,
                          help="staged upstream sources directory; when "
                          "given, the registry must also be byte-identical "
                          "to inventory(staging, lock)")
    validate.set_defaults(func=cmd_validate)
    diff = sub.add_parser("diff", help="diff two registries")
    diff.add_argument("old")
    diff.add_argument("new")
    diff.set_defaults(func=cmd_diff)
    export = sub.add_parser("export", help="export a pinned bundle")
    export.add_argument("--out", required=True)
    export.add_argument("--registry", default="capabilities/registry.json")
    export.add_argument("--schema", default="schemas/capability.schema.json")
    export.add_argument("--lock",
                        default="capabilities/upstream.lock.json")
    export.set_defaults(func=cmd_export)
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
