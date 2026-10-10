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
#
# The evaluator below understands exactly the FILTER_BODY_GRAMMAR
# documented here. Any filter body containing any construct outside
# that grammar raises FilterNotUnderstood, and the registration
# layer turns that into callable:false plus an explicit
# needs-owner flag on every governed record (default-deny). An
# unrecognized filter never yields permission; the flagged record
# fails completeness until an owner extends the grammar and tests.

_MEMBERSHIP_CALLS = frozenset({
    "btf_id_set_contains", "btf_id_set8_contains",
})


class FilterNotUnderstood(InventoryError):
    """A kfunc filter uses constructs outside the understood grammar.

    A subclass of InventoryError so an unhandled escape still fails
    loudly as an unknown atom; the registration layer catches it per
    filter and records default-deny plus a needs-owner flag instead.
    """


FILTER_BODY_GRAMMAR = """\
Exact filter-body grammar understood by simulate_kfunc_filter.

A filter is a C function ``<int-type> <name>(const struct bpf_prog
*<prog>, u32 <id>)`` (the second parameter name is free; the return
type must be a plain integer type). Its body, after comment
stripping, must consist solely of the statement forms below.
Anything else -- including any construct listed under "Outside" --
raises FilterNotUnderstood and the filter yields no permission.

Statements (in order; statements after an unconditional return are
unreachable and ignored):
  S1  membership alias declaration:
      ``bool`` (or identically ``_Bool``) ``<NAME> =
      btf_id_set8?_contains(&<SET>, <id>);``
      Each <NAME> is declared exactly once in the whole body. The
      initializer must be exactly the bare membership call: any
      leading or trailing operator or expression beyond the call is
      outside the grammar. The declarator may share its
      declaration with other comma declarators, each initializer
      anchoring to its own declarator, and may carry redundant
      parentheses or ``__attribute__`` qualifiers. The alias is
      immutable: any later assignment, compound assignment,
      increment/decrement, address-take or redeclaration
      (shadowing) of <NAME>, and any assignment to or
      redeclaration (shadowing) of the filter parameters, is
      outside the grammar. Shadowing covers every declarator form
      (plain, pointer, array, parenthesized, function-pointer,
      comma, typedef, local enum, struct-suffix, and declarators
      headed by a typedef alias); redundant parentheses around
      the target do not hide the mutation, and cast recognition
      consults local declarations first, so a parenthesized name
      bound as an alias or parameter is never a cast even when it
      spells a typedef. A use ahead of the alias declaration is
      outside the grammar. Other declaration types holding a
      membership result are not aliases; their uses are opaque
      atoms (see Conditions).
  S2  bare block ``{ ... }`` holding statements S1-S5 (recursion).
      A block holding anything else is outside the grammar.
  S3  direct guard: ``if (<COND>) return <RET>;`` or
      ``if (<COND>) { return <RET>; }`` where the braced block holds
      exactly one return and no other control keyword. The branch
      must be a direct return: a nested ``if`` or any other
      non-return statement as the branch is outside the grammar.
  S4  terminal return: ``return <RET>;`` or the ternary form
      ``return (<COND>) ? <A> : <B>;`` where the value (or both
      arms) are constants classified by value after conversion to
      the filter's integer return type (converted zero allows;
      converted nonzero denies; either arm may be the zero arm).
      Identifiers resolve by value against pinned constants,
      file-local constants (enums, object-like macros and
      const-qualified integer objects, evaluated with C
      type/width semantics: enumerators type by value, narrow
      and boolean objects convert their initializer first, only
      macros live after the last active ``#undef`` resolve,
      provably-excluded conditional regions contribute nothing,
      and non-atomic macro bodies expand textually) and, for
      negated arms only, tabled kernel errno values -- never by
      textual shape -- unless the errno name is ``#undef``-killed
      or carries a file-scope binding, which defeats the table;
      and a name bound as a filter local (any declaration form,
      including typedef-headed ones) shadows every constant and
      never classifies, whatever its spelling. Conditional
      inclusion evaluates constant ``#if``/``#elif`` conditions
      (``#ifdef`` and identifier conditions are unproven); a
      consulted name with unproven conditional state, and any
      active ``#undef`` or value-changing redefinition of a
      consulted pipeline or declared name, is outside the
      grammar, as is a conditionally-excluded (or
      unprovably-included) filter definition and any
      preprocessor directive inside a filter body. A
      non-constant arm is outside the grammar. A ternary nested
      under an ``if``
      (form S3 with a ternary return) is understood only when the
      outer condition folds to a constant for the evaluated
      caller and member.
  S5  straight-line statements without verdict effect:
      declarations, assignments, expression statements and calls
      that contain no ``return`` and no control keyword. They are
      skipped, except that alias/parameter mutations (rule S1)
      are still outside the grammar, a later write to a
      provable local discards its value (verdict-relevant uses
      then fail closed, and parenthesized targets count as
      writes); initializers convert to the declared type first
      (unsigned wraparound; signed out-of-range stays unproven)
      and chained initializers resolve through the binding table
      (a bound-but-unproven spelling stays unproven, never a
      spelling-guessed constant); and a write to compared member
      state (an
      assignment to a compared member through any pointer, an
      address-take of a compared member path, or a call
      mentioning the program parameter) is outside the grammar.
      A use ahead of its declaration point is outside the
      grammar. Any preprocessor directive inside a body is
      outside the grammar.
Outside: ``else``, ``for``, ``while``, ``do``, ``switch``,
      ``goto``, labels carrying a ``return``, any ``return`` outside
      forms S3/S4 (empty, void or unrecognized value), and falling
      off the end without a return.

Returns: constants classify by value converted to the filter's
integer return type: converted zero allows; converted nonzero
denies. Negated ``-E<NAME>`` errno macros classify by their tabled
kernel errno value unless ``#undef``-killed or file-bound (rule
S4). Unknown identifiers and non-integer return types are outside
the grammar.

Conditions (<COND>):
  C1  ``!``, ``&&``, ``||`` and parentheses over the atoms below.
      No chained comparisons, no assignments, no ``?:``.
  C2  understood comparisons (either operand order for the first
      two shapes): ``<prog>->type ==/!= BPF_PROG_TYPE_*``,
      ``<prog>->expected_attach_type ==/!= BPF_*``,
      ``<prog>->aux->st_ops ==/!= &<ops>``. Comparisons against any
      other value (including numbers) are opaque atoms. A compared
      name bound as a filter local resolves to the canonical name
      carrying its provable value; a shadow without a provable
      value, or one matching no (unique) canonical name, and any
      st_ops comparison against a filter local's address, is
      outside the grammar.
  C3  membership tests: ``btf_id_set8?_contains(&<SET>, <id>)``
      calls (or their negations) and alias names from rule S1. <SET>
      must be a known ID block; an unknown block is a fatal unknown
      atom, not a default-deny.
  C4  bare ``<prog>->aux->st_ops`` / ``!<prog>->aux->st_ops``.
  C5  predicate calls ``<helper>(<prog>)`` inlined one level when
      the helper is a single ``return <expr>;`` without ``?:`` and
      the inlined expression mentions no name the filter binds
      locally; any other callee is an opaque atom.
  C6  bare boolean constants: ``true``, ``false``, ``TRUE``,
      ``FALSE`` and integer literals in any base, with or without
      ``u``/``l`` suffixes (``0`` is false, any other value is
      true). A spelling bound as a filter local resolves by its
      provable value instead; a bound spelling without a provable
      value is outside the grammar, never a spelling-guessed
      constant.
  C7  anything else -- bit tests such as ``(flags & <FLAG>)``
      (over ``&``, ``|`` or ``^``), unknown calls, foreign member
      access -- is an opaque atom carrying its original text,
      after non-atomic macros splice textually (C preprocessing
      semantics). Only bit-test atoms keep existential permission
      (see rule E2); every other opaque atom in an allow
      requirement is outside the grammar. A group mixing bit tests
      with top-level
      ``&&``/``||`` keeps its logical shape: only the segments
      holding a lone bit operator become opaque atoms, so
      constant segments still fold. Pure integer-literal groups
      fold under C semantics (C operator precedence, C suffix
      widths, unsigned wraparound) to their actual numeric value
      with its width and signedness -- never to Boolean 1 --
      evaluating inside-out with grouping preserved through
      intermediate folds, as does a complete ``&`` expression
      absorbing a literal zero; a ``0 & ...`` prefix before a
      ``|``/``^`` boundary never folds, and a negative-valued
      group declines folding and fails closed downstream.

Evaluation (per caller program type and member):
  E1  Type comparisons and membership tests fold to constants and
      decide directly; attach-type and struct_ops comparisons
      narrow the context without deciding.
  E2  Bit-test atoms in an allow requirement become restriction
      notes (the permission is existential: it holds in some
      further-restricted context). Bit-test notes honor negation
      polarity ("requires <FLAG> attach context" versus "excludes
      <FLAG> attach context"). Bit-test atoms also carry polarity
      constraints, so one operand's flag required and excluded in
      one conjunction contradicts (see rule E5); a bit test
      provably decided against its required polarity grants
      nothing instead of minting permission. A mask with no bits
      below a proven unsigned operand width is provably zero,
      while a wide mask over an operand of unproven width is
      outside the grammar. Every other opaque atom in an allow
      requirement is outside the grammar (an unproven condition
      never yields callable permission). Opaque atoms in a
      deny requirement are outside the grammar (a denial the
      inventory cannot scope is not a permission it may claim),
      except that a provably-decided deny guard narrows vacuously.
  E3  A bare ``!<prog>->aux->st_ops`` allow branch grants nothing
      (load-phase leniency is not a steady-state permission) and
      narrows nothing; any st_ops-null test in a deny requirement
      is outside the grammar.
  E4  Deny narrowings conjoin along the fall-through path;
      allow branches grant the path conjunctions crossed with the
      branch alternatives. Disjunctions split into distinct
      alternative paths, except that a disjunction whose branches
      are identical in every dimension but one positive value set
      merges exactly into that set with a "one of" note.
  E5  ``!=`` requirements are exclusion constraints, not mere
      notes: a conjunction whose exclusions cover every required
      value is contradictory and dropped, within one filter and
      across the conjoined filters of a hook. Bit tests
      canonicalize before constraining (redundant parentheses
      vanish, nested placeholders expand, known constants
      substitute with their widths, commutative operators
      normalize, non-negative mask literals canonicalize across
      signedness/width/spelling), contributing wholeness,
      ``&``-operand and flag-pair facts: one canonical test (or
      one operand/flag sub-test, including ``^``-mixed and subset
      shapes) required and excluded at once is contradictory, as
      is one operand's held mask contained in its excluded mask,
      while independent operands stay satisfiable. Compound bit
      groups prove impossibility over bit algebra (constant
      chains folding to zero, ``x & ~x``, even ``^``
      cancellation); a provably impossible group grants nothing.
      A test mentioning a multi-declared name degrades to
      notes-only. A requirement set that merely overlaps the
      exclusions stays satisfiable.
  E6  A final ``return 0;`` grants the fall-through paths in
      addition to every earlier grant; a final deny grants only
      the earlier ones.

Default-deny: any filter containing any construct outside this
grammar yields no permission; every governed record is
callable:false with an explicit needs-owner flag (a NEEDS-OWNER
predicate and a needs_owner_review entry) and fails completeness
until an owner extends the grammar and tests.
"""



def _c_definition_hits(clean, name):
    """Yield (offset, params, body) for each definition of ``name``.

    ``clean`` must be comment-stripped. Only true definitions (with a
    brace body, not a ``;`` declaration) match, in source order.
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
        yield match.start(), params, c_brace_body(clean, brace)


def c_function_body(clean, name):
    """Return (params, body) for the definition of ``name``, or None.

    ``clean`` must be comment-stripped. Only true definitions (with a
    brace body, not a ``;`` declaration) match; the first definition
    wins.
    """
    for _, params, body in _c_definition_hits(clean, name):
        return params, body
    return None


def _filter_prog_param(params, fn_name, version):
    """Return the ``struct bpf_prog *`` parameter name of a filter."""
    match = re.search(r"struct\s+bpf_prog\s*\*\s*(\w+)", params)
    if not match:
        raise FilterNotUnderstood(
            "kfunc filter %s@%s has no bpf_prog parameter"
            % (fn_name, version))
    return match.group(1)


def _filter_param_names(params, prog_param):
    """Return all filter parameter names for mutation checks."""
    names = [prog_param]
    for name in re.findall(r"\bu32\s+(\w+)", params):
        if name != prog_param and name not in names:
            names.append(name)
    return names


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
        match = re.match(
            r"[A-Za-z_]\w*|0[xX][0-9a-fA-F]+[uUlL]*|\d+[uUlL]*",
            text[pos:])
        if match:
            tokens.append(match.group(0))
            pos += len(match.group(0))
            continue
        raise FilterNotUnderstood(
            "cannot parse filter condition near %r" % text[pos:pos + 20])
    return tokens


def _cond_parse(tokens, id_param):
    """Parse condition tokens into an AST over caller atoms.

    Returns (node, opaque) where opaque maps placeholder names to the
    original subexpression text for anything outside the supported
    atom shapes (bit tests, unknown calls, foreign member access).
    Bound nodes are ("const", bool), ("not", sub), ("and"/"or",
    [subs]), ("type_cmp"/"attach_cmp"/"stops_cmp", op, value),
    ("member", set), ("stops_null",) or ("opaque", placeholder).
    A membership call only binds when its tested argument is exactly
    the filter's id parameter; anything else is opaque.
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
                raise FilterNotUnderstood(
                    "cannot parse filter condition: unbalanced paren")
            pos[0] += 1
            return node
        return parse_atom()

    def parse_atom():
        start = pos[0]
        token = peek()
        if token is None:
            raise FilterNotUnderstood(
                "cannot parse filter condition: truncated")
        if token == "&":
            pos[0] += 1
            name = peek()
            if name is None or not re.match(r"[A-Za-z_]", name):
                raise FilterNotUnderstood(
                    "cannot parse filter condition near '&'")
            pos[0] += 1
            return ("addr", name)
        if re.match(r"\d", token):
            pos[0] += 1
            return ("number", token)
        if not re.match(r"[A-Za-z_]", token):
            raise FilterNotUnderstood(
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
                    raise FilterNotUnderstood(
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
                    args[0] and args[0][0] == "&" and \
                    len(args[0]) == 2 and args[1] == [id_param]:
                return ("member", args[0][1])
            return take_opaque(tokens[start:pos[0]])
        node = [token]
        while peek() == "->":
            pos[0] += 1
            field = peek()
            if field is None or not re.match(r"[A-Za-z_]", field):
                raise FilterNotUnderstood(
                    "cannot parse filter condition near '->'")
            node.append(field)
            pos[0] += 1
        if len(node) == 1:
            return ("ident", token)
        return ("field", tuple(node))

    node = parse_or()
    if pos[0] != len(tokens):
        raise FilterNotUnderstood("cannot parse filter condition tail")
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


def _resolve_shadowed_const(name, locals_set, local_values, rev,
                            fn_name, version, what):
    """Canonical name for a compared constant, honoring shadowing.

    An unshadowed name binds as spelled. A name bound as a filter
    local resolves to the canonical name carrying the local's
    provable value; a shadow without a provable value, or one
    whose value matches no (unique) canonical name, is outside
    the grammar.
    """
    if name not in locals_set:
        return name
    if name not in local_values:
        raise FilterNotUnderstood(
            "kfunc filter %s@%s compares against shadowed %s %s "
            "without a provable value; shadowed comparisons are "
            "outside the grammar"
            % (fn_name, version, what, name))
    if local_values[name] not in rev:
        raise FilterNotUnderstood(
            "kfunc filter %s@%s compares against shadowed %s %s "
            "holding value %d, which matches no %s; shadowed "
            "comparisons are outside the grammar"
            % (fn_name, version, what, name, local_values[name],
               what))
    return rev[local_values[name]]


def _bind_condition(node, prog_param, aliases, protected_members,
                    opaque, tokens, fn_name, version, locals_set,
                    local_values, rev_type, rev_attach, param_names,
                    file_values):
    """Bind raw atoms to typed condition leaves.

    Field comparisons against ``prog`` become typed comparison
    leaves; membership aliases resolve to set tests; anything else
    becomes an opaque leaf carrying its original text. Local
    declarations shadow constant names: a compared name bound as
    a filter local resolves to the canonical name carrying its
    provable value, and an unresolvable shadow is outside the
    grammar, as is a bare use of a bound local without a
    provable value (never a spelling-guessed constant). Boolean
    spellings resolve through the file value table when bound
    there and unshadowed; parameters degrade to opaque
    (rejected when load-bearing), while any other unbound
    spelling classifies by legacy spelling.
    """
    kind = node[0]
    if kind in ("const", "member", "opaque", "stops_null"):
        return node
    if kind == "not":
        return ("not", _bind_condition(
            node[1], prog_param, aliases, protected_members,
            opaque, tokens, fn_name, version, locals_set,
            local_values, rev_type, rev_attach, param_names,
            file_values))
    if kind in ("and", "or"):
        return (kind, [_bind_condition(
            sub, prog_param, aliases, protected_members,
            opaque, tokens, fn_name, version, locals_set,
            local_values, rev_type, rev_attach, param_names,
            file_values)
            for sub in node[1]])
    if kind == "ident":
        name = node[1]
        if name in aliases:
            return ("member", aliases[name])
        if name in protected_members:
            return ("member", protected_members[name])
        if name in opaque:
            return ("opaque", name)
        if name in local_values:
            return ("const", local_values[name] != 0)
        if name in locals_set and name not in param_names:
            raise FilterNotUnderstood(
                "kfunc filter %s@%s tests local %s without a "
                "provable value; unresolvable locals are outside "
                "the grammar"
                % (fn_name, version, name))
        if name in ("true", "TRUE", "false", "FALSE"):
            if name in param_names:
                return ("opaque", _opaque_for(opaque, tokens, name))
            if name not in locals_set and name in file_values:
                return ("const", file_values[name] != 0)
            if name in ("true", "TRUE"):
                return ("const", True)
            return ("const", False)
        return ("opaque", _opaque_for(opaque, tokens, name))
    if kind == "number":
        # Bare integer literals in condition position are boolean
        # constants: 0 is false, any other value is true. Only the
        # zero/nonzero distinction matters, so any base or suffix
        # reduces to a digit scan.
        core = re.sub(r"[uUlL]+$", "", node[1])
        digits = None
        hexed = re.match(r"^0[xX]([0-9a-fA-F]+)$", core)
        if hexed:
            digits = hexed.group(1)
        elif re.match(r"^\d+$", core):
            digits = core
        if digits is None:
            return ("opaque", _opaque_for(opaque, tokens, node[1]))
        return ("const", any(char != "0" for char in digits))
    if kind == "addr":
        return ("opaque", _opaque_for(
            opaque, tokens, "&" + node[1]))
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
        if value is not None and left[0] == "field" and \
                left[1][0] == prog_param:
            rest = left[1][1:]
            if rest == ("type",) and value.startswith("BPF_PROG_TYPE_"):
                return ("type_cmp", op, _resolve_shadowed_const(
                    value, locals_set, local_values, rev_type,
                    fn_name, version, "program type"))
            if rest == ("expected_attach_type",) and \
                    value.startswith("BPF_"):
                return ("attach_cmp", op, _resolve_shadowed_const(
                    value, locals_set, local_values, rev_attach,
                    fn_name, version, "attach type"))
            if rest == ("aux", "st_ops") and value.startswith("&"):
                if value[1:] in locals_set:
                    raise FilterNotUnderstood(
                        "kfunc filter %s@%s compares st_ops against "
                        "the address of filter local %s; address "
                        "comparisons against locals are outside the "
                        "grammar"
                        % (fn_name, version, value[1:]))
                return ("stops_cmp", op, value[1:])
        # Mirrored comparison (constant on the left): ``==`` and
        # ``!=`` are symmetric, so the operand order carries no
        # meaning for the two shapes grammar rule C2 mirrors.
        if left[0] == "ident" and right[0] == "field" and \
                right[1][0] == prog_param:
            rest = right[1][1:]
            if rest == ("type",) and \
                    left[1].startswith("BPF_PROG_TYPE_"):
                return ("type_cmp", op, _resolve_shadowed_const(
                    left[1], locals_set, local_values, rev_type,
                    fn_name, version, "program type"))
            if rest == ("expected_attach_type",) and \
                    left[1].startswith("BPF_"):
                return ("attach_cmp", op, _resolve_shadowed_const(
                    left[1], locals_set, local_values, rev_attach,
                    fn_name, version, "attach type"))
        return ("opaque", _opaque_for(
            opaque, tokens, " ".join(tokens[start:end])))
    raise FilterNotUnderstood(
        "cannot parse filter %s condition" % fn_name)


def _protect_condition_atoms(text, id_param, expansion=None,
                             bound=()):
    """Replace opaque-prone groups with placeholders.

    Membership calls over the filter's id parameter become
    ``__member_<set>`` idents; membership calls over any other value
    are left for the bit-op pass so they degrade to opaque atoms.
    Pure integer-literal groups fold to constants under C semantics
    whatever operators they hold; paren groups holding a lone bit
    operator (attach-context bit tests over ``&``, ``|`` or ``^``,
    never address-of, ``&&`` or ``||``) become ``__bitop_<n>``
    idents, except that a group mixing bit tests with top-level
    ``&&``/``||`` keeps its logical shape: only the segments
    holding a lone bit operator become placeholders, so constant
    segments still fold. Zero-absorption purity audits the
    macro-expanded operands through ``expansion``, never raw
    macro identifiers.
    Returns (rewritten, members, opaque) with the back-maps.
    """
    members = {}
    opaque = {}

    def protect_member(match):
        if match.group(2) != id_param:
            return match.group(0)
        name = "__member_%s" % match.group(1)
        members[name] = match.group(1)
        return name

    rewritten = re.sub(
        r"btf_id_set8?_contains\s*\(\s*&(\w+)\s*,\s*(\w+)\s*\)",
        protect_member, text)
    counter = [0]

    def has_lone_bitop(group):
        return re.search(
            r"(?<![&|])&(?![&=|])|(?<![|&])\|(?![|=])|"
            r"(?<!\^)\^(?![=])", group) is not None

    def handle_group(start, end, group):
        nonlocal rewritten
        spans = _split_mixed_group(group)
        if spans is not None:
            rewritten = _protect_group_segments(
                rewritten, start, group, spans, counter, opaque,
                expansion, bound)
            return
        folded = _fold_const_text(
            group[1:-1], opaque, expansion, bound)
        if folded is not None:
            rewritten = (rewritten[:start] + folded + " "
                         + rewritten[end:])
            return
        counter[0] += 1
        name = "__bitop_%d" % counter[0]
        opaque[name] = re.sub(r"\s+", " ", group).strip()
        rewritten = (rewritten[:start] + " " + name + " "
                     + rewritten[end:])

    while True:
        folded_any = False
        # Fold the outermost pure-literal group first, so nested
        # arithmetic and comparisons evaluate inside-out with real
        # values: ``((1 + 1) == 2)`` folds whole to ``1`` while
        # ``((2) & 2)`` folds whole to ``2``. Folding only removes
        # parens (folded spellings hold none), so each splice
        # strictly shrinks the group count and the loop terminates.
        for start, end in _paren_groups_outermost_first(rewritten):
            folded = _fold_const_text(
                rewritten[start + 1:end - 1], opaque, expansion,
                bound)
            if folded is not None:
                rewritten = (rewritten[:start] + folded + " "
                             + rewritten[end:])
                folded_any = True
                break
        if folded_any:
            continue
        progressed = False
        for candidate in re.finditer(r"\([^()]*\)", rewritten):
            group = candidate.group(0)
            # Pure but unprovable groups (and negative-valued ones
            # the folder declines) fall through to the bit-op path
            # below when they hold one, so a wide literal mask stays
            # existential.
            if has_lone_bitop(group):
                handle_group(candidate.start(), candidate.end(),
                             group)
                progressed = True
                break
        if progressed:
            continue
        found = _nested_group_holding_bitop(rewritten)
        if found is None:
            break
        handle_group(*found)
    # A bare pure-literal condition (no enclosing parens of its own)
    # folds whole, so negative intermediates that decline group
    # folding still evaluate inside-out with real values.
    folded_all = _fold_const_text(
        rewritten, opaque, expansion, bound)
    if folded_all is not None:
        rewritten = folded_all
    return rewritten, members, opaque


def _paren_groups_outermost_first(text):
    """Matched paren pairs of ``text``, outermost first.

    Returns [(start, end)] with end exclusive, ordered by start
    ascending and end descending, so each group's contents are
    whole before any nested group folds. Unbalanced parens yield
    no pair and fail closed in the condition parser downstream.
    """
    stack = []
    pairs = []
    for index, char in enumerate(text):
        if char == "(":
            stack.append(index)
        elif char == ")":
            if stack:
                pairs.append((stack.pop(), index + 1))
    pairs.sort(key=lambda pair: (pair[0], -pair[1]))
    return pairs


def _nested_group_holding_bitop(rewritten):
    """Innermost paren group holding a lone bit operator, or None.

    Fallback for the protection loop: when no innermost group
    holds a direct lone bit operator, the innermost group holding
    one at any depth still folds or abstracts as a whole, so an
    outer bit-test over nested groups never reaches the tokenizer
    raw. Groups close in stack order, so the first bit-op close is
    the innermost such group.
    """
    stack = []
    for index, char in enumerate(rewritten):
        if char == "(":
            stack.append(index)
        elif char == ")":
            if not stack:
                continue
            start = stack.pop()
            group = rewritten[start:index + 1]
            if re.search(
                    r"(?<![&|])&(?![&=|])|(?<![|&])\|(?![|=])|"
                    r"(?<!\^)\^(?![=])", group) is not None:
                return (start, index + 1, group)
    return None


def _split_mixed_group(group):
    """Split a bit-op group on top-level ``&&``/``||``.

    A group mixing bit tests with logical operators -- ``(0 &&
    flags & FLAG)`` -- must not collapse into one opaque atom: the
    constant segments fold and only the surviving bit-test segments
    become placeholders. Returns the segment span list, or None
    when the group holds no top-level logical operator (or holds a
    quote, in which case whole-group protection stays).
    """
    if '"' in group or "'" in group:
        return None
    body = group[1:-1]
    spans = []
    depth = 0
    start = 0
    index = 0
    while index < len(body):
        char = body[index]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif depth == 0 and body.startswith("&&", index):
            spans.append((start, index))
            index += 2
            start = index
            continue
        elif depth == 0 and body.startswith("||", index):
            spans.append((start, index))
            index += 2
            start = index
            continue
        index += 1
    if not spans:
        return None
    spans.append((start, len(body)))
    return spans


def _protect_group_segments(rewritten, start, group, spans, counter,
                            opaque, expansion=None, bound=()):
    """Protect the bit-test segments of one mixed group in place."""
    body = group[1:-1]
    for span_start, span_end in reversed(spans):
        segment = body[span_start:span_end]
        if re.search(
                r"(?<![&|])&(?![&=|])|(?<![|&])\|(?![|=])|"
                r"(?<!\^)\^(?![=])", segment) is None:
            continue
        folded = _fold_const_text(segment, opaque, expansion, bound)
        offset = start + 1
        if folded is not None:
            rewritten = (rewritten[:offset + span_start] + folded + " "
                         + rewritten[offset + span_end:])
            continue
        counter[0] += 1
        name = "__bitop_%d" % counter[0]
        opaque[name] = re.sub(r"\s+", " ", segment).strip()
        rewritten = (rewritten[:offset + span_start] + " " + name + " "
                     + rewritten[offset + span_end:])
    return rewritten


_C_CONST_TOKEN_RE = re.compile(r"""
    (?P<num>0[xX][0-9a-fA-F]+[uUlL]*|0[bB][01]+[uUlL]*|\d+[uUlL]*)
  | (?P<op><<|>>|<=|>=|==|!=|&&|\|\||[+\-*/%<>&^|~!])
  | (?P<paren>[()])
  | (?P<space>\s+)
  | (?P<bad>.)
""", re.VERBOSE)

_ZERO_OPERAND_RE = re.compile(
    r"^[+-]?\s*(?:0+[uUlL]*|0[xX]0+[uUlL]*|0[bB]0+[uUlL]*)$")


def _fold_const_text(text, opaque=None, expansion=None, bound=()):
    """Fold a group or segment with C integer semantics.

    Returns the folded literal spelling or None. A pure
    integer-literal expression evaluates under C semantics -- C
    operator precedence, C suffix widths, unsigned wraparound at
    the correct width -- and folds to its actual numeric value
    with its width and signedness (``1 + 1`` folds to ``2``, not
    to Boolean ``1``), so enclosing comparisons and bit tests see
    real values; anything unprovable (signed overflow, bad
    shifts, division hazards, out-of-range literals) stays
    unfolded. A negative result has no spelling the condition
    grammar parses (unary minus is unsupported there) and is
    declined, so the raw group fails closed downstream instead of
    folding to a guessed Boolean. A complete ``&`` expression
    absorbing a literal zero folds to "0" however symbolic the
    other operands are, provided every one is proven pure;
    operands hiding a side effect or an unproven shape decline
    the fold and fail closed downstream instead. Purity audits
    the macro-expanded operands, never raw macro identifiers.
    Nested placeholders expand first (past the cap the fold
    declines), so an abstraction never hides an operand the
    fold would otherwise inspect. Comma, conditional and
    statement shapes never fold.
    """
    core = text.strip()
    if opaque:
        expanded = _expand_bit_text(core, opaque)
        if expanded is None:
            return None
        core = expanded.strip()
    if not core or re.search(r"[,?;:]", core):
        return None
    tokens = _c_const_lex(core)
    if tokens is None:
        if _is_zero_absorbing_and(core, expansion, bound):
            return "0"
        return None
    try:
        result = _c_const_eval(tokens)
    except (RecursionError, MemoryError, OverflowError):
        return None
    if result is None:
        return None
    value, width, signed = result
    if value < 0:
        return None
    if signed:
        if width == 32:
            return "%d" % value
        if width == 64:
            return "%dL" % value
        return None
    if width == 32:
        return "%dU" % value
    if width == 64:
        return "%dUL" % value
    return None


def _c_const_lex(text):
    """Split a pure-literal C expression into tokens, or None.

    Returns None when the text holds anything but integer literals
    (with ``u``/``l`` suffixes), C integer operators and parens --
    identifiers, floats, string quotes and stray punctuation all
    mark the text symbolic.
    """
    tokens = []
    for match in _C_CONST_TOKEN_RE.finditer(text):
        kind = match.lastgroup
        if kind == "space":
            continue
        if kind == "bad":
            return None
        tokens.append((kind, match.group()))
    if not tokens:
        return None
    return tokens


def _c_literal_type(word):
    """(value, width, signed) for one C integer literal, or None.

    Widths follow LP64 (``int`` is 32 bits, ``long`` and ``long
    long`` are 64 bits); a value fitting nowhere yields None.
    """
    match = re.match(
        r"^(0[xX][0-9a-fA-F]+|0[bB][01]+|\d+)([uUlL]*)$", word)
    if not match:
        return None
    digits, suffix = match.group(1), match.group(2).lower()
    if re.fullmatch(r"0[0-7]+", digits):
        value = int(digits, 8)
    else:
        try:
            value = int(digits, 0)
        except ValueError:
            return None
    if suffix not in ("", "u", "l", "ul", "lu", "ll", "ull", "llu"):
        return None
    lower = digits.lower()
    decimal = not lower.startswith(("0x", "0b")) and \
        not (lower.startswith("0") and len(lower) > 1)
    ceil32 = 2 ** 31 - 1
    maxu32 = 2 ** 32 - 1
    ceil64 = 2 ** 63 - 1
    maxu64 = 2 ** 64 - 1
    unsigned = "u" in suffix
    longs = suffix.count("l")
    if longs == 0 and not unsigned:
        if decimal:
            if value <= ceil32:
                return (value, 32, True)
            if value <= ceil64:
                return (value, 64, True)
            return None
        for width, signed, limit in ((32, True, ceil32),
                                     (32, False, maxu32),
                                     (64, True, ceil64),
                                     (64, False, maxu64)):
            if value <= limit:
                return (value, width, signed)
        return None
    if unsigned:
        if longs == 0 and value <= maxu32:
            return (value, 32, False)
        if value <= maxu64:
            return (value, 64, False)
        return None
    if value <= ceil64:
        return (value, 64, True)
    if not decimal and value <= maxu64:
        return (value, 64, False)
    return None


def _c_const_eval(tokens):
    """Evaluate C integer tokens; (value, width, signed) or None.

    Operators parse with C precedence (``==`` binds tighter than
    ``&``) and evaluate with the usual arithmetic conversions;
    unsigned arithmetic wraps at its width while signed overflow,
    division by zero, negative or over-wide shifts and any
    malformed shape yield None (opaque, never a wrong fold).
    """
    pos = 0

    def peek():
        return tokens[pos] if pos < len(tokens) else (None, None)

    def usual(left, right):
        if (left[1] == 64 and not left[2]) or \
                (right[1] == 64 and not right[2]):
            return (64, False)
        if left[1] == 64 or right[1] == 64:
            # A 64-bit signed type represents every 32-bit unsigned
            # value, so it wins over unsigned int.
            return (64, True)
        if not left[2] or not right[2]:
            return (32, False)
        return (32, True)

    def unsigned_rep(value, width):
        return value & ((1 << width) - 1)

    def signed_value(rep, width):
        if rep >= (1 << (width - 1)):
            return rep - (1 << width)
        return rep

    def convert(node, width, signed):
        rep = unsigned_rep(node[0], width)
        if signed:
            return (signed_value(rep, width), width, True)
        return (rep, width, False)

    def arith(left, right, op):
        width, signed = usual(left, right)
        first = convert(left, width, signed)[0]
        second = convert(right, width, signed)[0]
        if not signed:
            mask = (1 << width) - 1
            if op == "+":
                return ((first + second) & mask, width, False)
            if op == "-":
                return ((first - second) & mask, width, False)
            return ((first * second) & mask, width, False)
        if op == "+":
            result = first + second
        elif op == "-":
            result = first - second
        else:
            result = first * second
        if result < -(1 << (width - 1)) or \
                result >= (1 << (width - 1)):
            return None
        return (result, width, True)

    def divmod(left, right, op):
        width, signed = usual(left, right)
        first = convert(left, width, signed)[0]
        second = convert(right, width, signed)[0]
        if second == 0:
            return None
        if not signed:
            if op == "/":
                return (first // second, width, False)
            return (first % second, width, False)
        if first == -(1 << (width - 1)) and second == -1:
            return None
        quot = abs(first) // abs(second)
        if (first < 0) != (second < 0):
            quot = -quot
        if op == "/":
            return (quot, width, True)
        return (first - quot * second, width, True)

    def shift(left, right, op):
        value, width, signed = left
        count = right[0]
        if count < 0 or count >= width or value < 0:
            return None
        if op == "<<":
            result = value << count
            if signed:
                if result >= (1 << (width - 1)):
                    return None
                return (result, width, True)
            return (unsigned_rep(result, width), width, False)
        return (value >> count, width, signed)

    def bitwise(left, right, op):
        width, signed = usual(left, right)
        first = unsigned_rep(convert(left, width, signed)[0], width)
        second = unsigned_rep(convert(right, width, signed)[0], width)
        if op == "&":
            rep = first & second
        elif op == "^":
            rep = first ^ second
        else:
            rep = first | second
        if signed:
            return (signed_value(rep, width), width, True)
        return (rep, width, False)

    def compare(left, right, op):
        width, signed = usual(left, right)
        first = convert(left, width, signed)[0]
        second = convert(right, width, signed)[0]
        if op == "==":
            matched = first == second
        elif op == "!=":
            matched = first != second
        elif op == "<":
            matched = first < second
        elif op == "<=":
            matched = first <= second
        elif op == ">":
            matched = first > second
        else:
            matched = first >= second
        return (1 if matched else 0, 32, True)

    def parse_lor():
        nonlocal pos
        node = parse_land()
        if node is None:
            return None
        while True:
            kind, word = peek()
            if kind == "op" and word == "||":
                pos += 1
                other = parse_land()
                if other is None:
                    return None
                node = (1 if node[0] or other[0] else 0, 32, True)
            else:
                return node

    def parse_land():
        nonlocal pos
        node = parse_bor()
        if node is None:
            return None
        while True:
            kind, word = peek()
            if kind == "op" and word == "&&":
                pos += 1
                other = parse_bor()
                if other is None:
                    return None
                node = (1 if node[0] and other[0] else 0, 32, True)
            else:
                return node

    def parse_bor():
        nonlocal pos
        node = parse_bxor()
        if node is None:
            return None
        while True:
            kind, word = peek()
            if kind == "op" and word == "|":
                pos += 1
                other = parse_bxor()
                if other is None:
                    return None
                node = bitwise(node, other, "|")
                if node is None:
                    return None
            else:
                return node

    def parse_bxor():
        nonlocal pos
        node = parse_band()
        if node is None:
            return None
        while True:
            kind, word = peek()
            if kind == "op" and word == "^":
                pos += 1
                other = parse_band()
                if other is None:
                    return None
                node = bitwise(node, other, "^")
                if node is None:
                    return None
            else:
                return node

    def parse_band():
        nonlocal pos
        node = parse_eq()
        if node is None:
            return None
        while True:
            kind, word = peek()
            if kind == "op" and word == "&":
                pos += 1
                other = parse_eq()
                if other is None:
                    return None
                node = bitwise(node, other, "&")
                if node is None:
                    return None
            else:
                return node

    def parse_eq():
        nonlocal pos
        node = parse_rel()
        if node is None:
            return None
        while True:
            kind, word = peek()
            if kind == "op" and word in ("==", "!="):
                pos += 1
                other = parse_rel()
                if other is None:
                    return None
                node = compare(node, other, word)
            else:
                return node

    def parse_rel():
        nonlocal pos
        node = parse_shift()
        if node is None:
            return None
        while True:
            kind, word = peek()
            if kind == "op" and word in ("<", "<=", ">", ">="):
                pos += 1
                other = parse_shift()
                if other is None:
                    return None
                node = compare(node, other, word)
            else:
                return node

    def parse_shift():
        nonlocal pos
        node = parse_add()
        if node is None:
            return None
        while True:
            kind, word = peek()
            if kind == "op" and word in ("<<", ">>"):
                pos += 1
                other = parse_add()
                if other is None:
                    return None
                node = shift(node, other, word)
                if node is None:
                    return None
            else:
                return node

    def parse_add():
        nonlocal pos
        node = parse_mul()
        if node is None:
            return None
        while True:
            kind, word = peek()
            if kind == "op" and word in ("+", "-"):
                pos += 1
                other = parse_mul()
                if other is None:
                    return None
                node = arith(node, other, word)
                if node is None:
                    return None
            else:
                return node

    def parse_mul():
        nonlocal pos
        node = parse_unary()
        if node is None:
            return None
        while True:
            kind, word = peek()
            if kind == "op" and word in ("*", "/", "%"):
                pos += 1
                other = parse_unary()
                if other is None:
                    return None
                if word == "*":
                    node = arith(node, other, word)
                else:
                    node = divmod(node, other, word)
                if node is None:
                    return None
            else:
                return node

    def parse_unary():
        nonlocal pos
        kind, word = peek()
        if kind == "op" and word in ("+", "-", "~", "!"):
            pos += 1
            node = parse_unary()
            if node is None:
                return None
            value, width, signed = node
            if word == "+":
                return node
            if word == "!":
                return (0 if value else 1, 32, True)
            if word == "~":
                rep = unsigned_rep(value, width) ^ ((1 << width) - 1)
                if signed:
                    return (signed_value(rep, width), width, True)
                return (rep, width, False)
            if signed:
                if value == -(1 << (width - 1)):
                    return None
                return (-value, width, True)
            return (unsigned_rep(-value, width), width, False)
        return parse_primary()

    def parse_primary():
        nonlocal pos
        kind, word = peek()
        if kind == "num":
            pos += 1
            return _c_literal_type(word)
        if kind == "paren" and word == "(":
            pos += 1
            node = parse_lor()
            if node is None:
                return None
            kind, word = peek()
            if kind != "paren" or word != ")":
                return None
            pos += 1
            return node
        return None

    node = parse_lor()
    if node is None or pos != len(tokens):
        return None
    return node


def _c_canonical_literal(value, width, signed):
    """Exact C literal spelling for one evaluated integer, or None.

    The spelling re-lexes to the identical (value, width, signed)
    triple under LP64, so substituting it for the evaluated
    subexpression preserves C semantics exactly (suffix widths and
    unsigned wraparound included). Negative values render as a
    parenthesized subtraction the C evaluator parses; INT_MIN and
    LONG_MIN use the two-literal form since their magnitude fits no
    signed literal of the same width.
    """
    if signed:
        if value >= 0:
            if width == 32:
                return "%d" % value
            if width == 64:
                return "%dL" % value
            return None
        magnitude = -value
        if width == 32:
            if magnitude <= 2 ** 31 - 1:
                return "(0 - %d)" % magnitude
            if magnitude == 2 ** 31:
                return "(-2147483647 - 1)"
            return None
        if width == 64:
            if magnitude <= 2 ** 63 - 1:
                return "(0L - %dL)" % magnitude
            if magnitude == 2 ** 63:
                return "(-9223372036854775807L - 1L)"
            return None
        return None
    if value < 0:
        return None
    if width == 32:
        return "%dU" % value
    if width == 64:
        return "%dUL" % value
    return None


def _zero_fold_core_impure(text, bound=()):
    """Whether a zero-absorption candidate hides effects or shapes.

    True when the text holds anything but proven-pure integer
    expression parts (identifiers, integer literals, C operators
    and parens): an assignment at any depth, an
    increment/decrement, a call (direct or through parentheses,
    which a macro expansion may reveal), a dereference or
    address-take, a dot/subscript/brace shape, a string or
    character literal quote, a digit-led token that is not a
    plain integer literal (a float such as ``1e2`` or ``1.5``,
    which the bit-test path rejects when kept), or any other
    character outside the pure alphabet. A ``)(`` group is a
    call unless its first group is a genuinely unbound cast
    spelling (a typedef shadowed by a name in ``bound`` is a
    callee, never a cast). Folding such a core to "0"
    would discard the operand's side effects on later reads --
    or silently bless a shape the bit-test path rejects when
    kept -- so the fold must decline and let the shape fail
    closed downstream.
    """
    if re.search(r"[^\s\w()+\-*/%<>&^|~!=]", text):
        return True
    if re.search(r"(?<![=!<>])=(?!=)", text):
        return True
    if "++" in text or "--" in text:
        return True
    if re.search(r"\b[A-Za-z_]\w*\s*\(", text):
        return True
    for match in re.finditer(r"\)\s*\(", text):
        depth = 0
        open_pos = None
        for index in range(match.start(), -1, -1):
            char = text[index]
            if char == ")":
                depth += 1
            elif char == "(":
                depth -= 1
                if depth == 0:
                    open_pos = index
                    break
        if open_pos is None:
            return True
        content = text[open_pos + 1:match.start()]
        if _is_cast_group(content) and \
                not _cast_group_shadowed(content, bound):
            continue
        return True
    if re.search(r"(?:^|[(\[,;?=:<>!&|^+\-~%/*])\s*\*", text):
        return True
    if re.search(
            r"(?:^|[(\[,;?=:<>!&|^+\-~%/*])\s*(?<!&)&(?!&|=)",
            text) is not None:
        return True
    for match in re.finditer(r"\b\d[\w.]*", text):
        if re.fullmatch(
                r"(?:0[xX][0-9a-fA-F]+|0[bB][01]+|\d+)[uUlL]*",
                match.group(0)) is None:
            return True
    return False


def _is_zero_absorbing_and(core, expansion=None, bound=()):
    """Whether a symbolic expression is an &-chain absorbing zero.

    True only when the COMPLETE expression is a lone-``&`` chain
    (no top-level ``|``, ``^``, ``&&``, ``||``, conditional, comma
    or assignment, at any bracket depth) holding a literal zero
    operand with every other operand proven pure; a ``0 & ...``
    prefix before a ``|``/``^`` boundary (``0 & flags | F`` is F
    in C) never folds, and neither does a core hiding a side
    effect or an unproven operand shape at any depth.
    Tighter-binding operators (comparisons, shifts, arithmetic,
    unary) inside pure operands keep the annihilation valid, so
    they never block it. The purity check runs on the raw core
    before string stripping: stripping first would blank
    character literals into spaces and let zero absorption
    erase a shape the bit-test path rejects when kept. Purity
    is never decided on a raw macro identifier: atomic macros
    expand first and the expanded tokens audit too, so an
    effect, call or unproven literal hidden behind an alias
    (``0U & LIT`` with ``LIT`` a character literal, a float or
    an assignment) declines the fold and fails closed
    downstream instead of vanishing. The check also stays on
    the raw core, since expansion can only reveal tokens, never
    remove a raw impurity the expanded spelling might respell.
    A parenthesized callee revealed either way counts as a
    call; ``bound`` carries the filter's locally-bound names so
    a shadowed typedef spelling never poses as a cast.
    """
    if _zero_fold_core_impure(core, bound):
        return False
    probe = _expand_all_macros(core, expansion)
    if _zero_fold_core_impure(probe, bound):
        return False
    text = _strip_c_strings(probe)
    if _zero_fold_core_impure(text, bound):
        return False
    depth = 0
    saw_and = False
    end = len(text)
    index = 0
    while index < end:
        char = text[index]
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
            if depth < 0:
                return False
        elif depth == 0:
            pair = text[index:index + 2]
            if pair in ("&&", "||"):
                return False
            if char == "&":
                if pair == "&=":
                    return False
                saw_and = True
            elif char in "|^?,:;":
                return False
            elif char == "=":
                prev = text[index - 1] if index else ""
                nxt = text[index + 1] if index + 1 < end else ""
                if prev not in "=!<>" and nxt != "=":
                    return False
        index += 1
    if depth != 0 or not saw_and:
        return False
    parts = []
    depth = 0
    current = []
    for char in text:
        if char in "([{":
            depth += 1
            current.append(char)
        elif char in ")]}":
            depth -= 1
            current.append(char)
        elif char == "&" and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    parts.append("".join(current))
    for part in parts:
        operand = part.strip()
        while len(operand) >= 2 and operand.startswith("(") and \
                operand.endswith(")"):
            inner_depth = 0
            balanced = True
            for item in operand[1:-1]:
                if item == "(":
                    inner_depth += 1
                elif item == ")":
                    inner_depth -= 1
                    if inner_depth < 0:
                        balanced = False
                        break
            if not balanced or inner_depth != 0:
                break
            operand = operand[1:-1].strip()
        if _ZERO_OPERAND_RE.match(operand):
            return True
    return False


_LONE_BITOP_RE = re.compile(
    r"(?<![&|])&(?![&=|])|(?<![|&])\|(?![|=])|"
    r"(?<!\^)\^(?![=])")


def _call_in_bit_context(text, start, end):
    """Whether a call at [start, end) sits under a bit operator.

    Walks every enclosing paren group (plus the top level with
    all groups blanked): a lone ``&``/``|``/``^`` at the call's
    own nesting level -- nested groups blanked first, so a
    sibling ``(a & b)`` never taints a ``&&`` operand -- puts the
    call's value (not just its truth) to work.
    """
    depths = []
    depth = 0
    for char in text:
        depths.append(depth)
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1

    def blanked(body):
        level = 0
        out = []
        for char in body:
            if char == "(":
                level += 1
                out.append(" ")
            elif char == ")":
                level -= 1
                out.append(" ")
            else:
                out.append(" " if level else char)
        return "".join(out)

    base = depths[start] if start < len(depths) else 0
    for level in range(base - 1, -1, -1):
        opened = None
        for index in range(start - 1, -1, -1):
            if text[index] == "(" and depths[index] == level:
                opened = index
                break
            if depths[index] < level:
                break
        if opened is None:
            continue
        nested = 0
        closed = None
        for index in range(opened, len(text)):
            if text[index] == "(":
                nested += 1
            elif text[index] == ")":
                nested -= 1
                if nested == 0:
                    closed = index
                    break
        if closed is None or closed < end:
            continue
        if _LONE_BITOP_RE.search(
                blanked(text[opened + 1:closed])) is not None:
            return True
    return _LONE_BITOP_RE.search(blanked(text)) is not None


def _parse_condition(text, prog_param, id_param, aliases, pred_exprs,
                   fn_name, version, locals_set, local_values,
                   rev_type, rev_attach, param_names, expansion,
                   file_values):
    """Parse and bind one filter condition for simulation.

    Unsafe (non-atomic) macros splice textually first, matching C
    preprocessing exactly; predicate calls over ``prog`` are then
    inlined one level from ``pred_exprs`` (converted literals,
    narrowing-masked unsigned bodies, or bare boolean bodies),
    unless the inlined expression mentions a name the filter
    binds locally (foreign scope must never resolve through
    filter locals; such calls stay opaque); a bare boolean body
    inlined under a bit operator rejects, since truth and value
    differ there. Membership aliases and membership calls over
    the filter's id parameter resolve to set tests. Compared
    constants honor local shadowing. Returns (node, opaque) with
    opaque mapping placeholders to original text.
    """
    guarded = set(locals_set) - {prog_param}
    expanded = _splice_unsafe_macros(text, expansion)
    for pred, (expr, mask, check_bit, _) in sorted(pred_exprs.items()):
        if set(re.findall(r"[A-Za-z_]\w*", expr)) & guarded:
            continue
        pattern = r"\b%s\s*\(\s*%s\s*\)" % (
            re.escape(pred), re.escape(prog_param))
        if check_bit:
            for call in re.finditer(pattern, expanded):
                if _call_in_bit_context(
                        expanded, call.start(), call.end()):
                    raise FilterNotUnderstood(
                        "kfunc filter %s@%s inlines boolean "
                        "helper %s under a bit operator; truth "
                        "and value differ there and the shape is "
                        "outside the grammar"
                        % (fn_name, version, pred))
        spliced = _splice_unsafe_macros(expr, expansion)
        if mask is None:
            replacement = "(%s)" % spliced
        else:
            replacement = "((%s) & %d)" % (spliced, mask)
        expanded = re.sub(pattern, replacement, expanded)
    expanded, protected_members, protected_opaque = \
        _protect_condition_atoms(
            expanded, id_param, expansion, locals_set)
    node, opaque, tokens = _cond_parse(
        _cond_tokenize(expanded), id_param)
    opaque.update(protected_opaque)
    return _bind_condition(
        node, prog_param, aliases, protected_members,
        opaque, tokens, fn_name, version, locals_set,
        local_values, rev_type, rev_attach, param_names,
        file_values), opaque


# Single-word C type spellings recognized as cast groups by the
# mutation scan (plus ``struct``/``union``/``enum`` tag forms and
# ``*`` declarators). A parenthesized group holding only these is a
# cast and strips to nothing; a group holding one other identifier
# strips to that identifier.
_CAST_WORDS = frozenset((
    "void", "bool", "_Bool", "char", "short", "int", "long", "float",
    "double", "signed", "unsigned", "const", "volatile", "restrict",
    "_Atomic", "u8", "u16", "u32", "u64", "s8", "s16", "s32", "s64",
    "size_t", "ssize_t",
))

# Cast spellings a filter local may shadow. Keywords (``void``,
# ``_Bool``, ``char``, ``short``, ``int``, ``long``, ``float``,
# ``double``, ``signed``, ``unsigned``, ``const``, ``volatile``,
# ``restrict``, ``_Atomic``) can never be identifiers, but typedef
# names are ordinary identifiers in C, so a local ``u64`` shadows
# the typedef and a ``(u64)(x)`` group headed by it is a call,
# never a cast. ``bool`` is a typedef (to ``_Bool``) in the
# kernel headers, so it shadows the same way.
_SHADOWABLE_TYPEDEFS = frozenset((
    "bool",
    "u8", "u16", "u32", "u64", "s8", "s16", "s32", "s64",
    "size_t", "ssize_t",
))


def _cast_group_shadowed(content, bound):
    """Whether a cast-spelled group is shadowed by a local binding."""
    words = set(re.findall(r"[A-Za-z_]\w*", content))
    return bool(words & set(bound) & _SHADOWABLE_TYPEDEFS)

_BARE_MEMBERSHIP_INIT_RE = re.compile(
    r"btf_id_set8?_contains\s*"
    r"\(\s*&\w+\s*,\s*\w+\s*\)")

_MEMBERSHIP_CALL_RE = re.compile(r"\bbtf_id_set8?_contains\b")


def _is_cast_group(content):
    """Whether a paren group's content is a C cast target type."""
    words = content.replace("*", " ").split()
    if not words:
        return False
    if words[0] in ("struct", "union", "enum"):
        return len(words) == 2 and words[1].isidentifier()
    return all(word in _CAST_WORDS for word in words)


def _strip_redundant_parens(scan, locals=()):
    """Collapse redundant parens and casts in a mutation scan.

    ``(name)`` (any nesting) collapses to ``name`` and ``(type)``
    casts collapse to nothing, to a fixpoint, so a mutation written
    through redundant parentheses or casts -- ``(mine) = false``,
    ``((mine)) &= x``, ``&(mine)`` -- is still recognized as a
    mutation of the same target. A cast can never hide the target
    itself: a cast prefix precedes the name the mutation regexes
    anchor at, so only the redundant parentheses need collapsing.
    Resolution is scope-aware: a parenthesized name bound as a local
    (a membership alias or a filter parameter, passed in ``locals``)
    is never a cast, even when it spells a typedef such as ``u64``
    or ``size_t``; the local binding shadows the type name in C, so
    only genuinely unbound type spellings strip as casts.
    """
    bound = set(locals)

    def collapse(match):
        content = match.group(1).strip()
        if re.match(r"^\w+$", content) and \
                (content in bound or not _is_cast_group(content)):
            return " %s " % content
        if _is_cast_group(content) and content not in bound:
            return " "
        return match.group(0)

    while True:
        updated = re.sub(r"\(([^()]*)\)", collapse, scan)
        if updated == scan:
            return scan
        scan = updated


def _strip_c_attributes(text):
    """Remove ``__attribute__((...)))`` spans, honoring nesting."""
    out = []
    pos = 0
    while pos < len(text):
        match = re.match(r"__attribute__\s*\(", text[pos:])
        if not match:
            out.append(text[pos])
            pos += 1
            continue
        depth = 0
        end = None
        for index in range(pos + match.end() - 1, len(text)):
            char = text[index]
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    end = index + 1
                    break
        if end is None:
            out.append(text[pos])
            pos += 1
            continue
        out.append(" ")
        pos = end
    return "".join(out)


def _bool_decl_spans(scan):
    """Yield (start, kwend, end) spans of boolean declarations.

    Each span runs from the ``bool``/``_Bool`` keyword (both
    spellings declare identically in C) to its depth-zero ``;``.
    A keyword whose depth goes negative first (``sizeof``, a
    parameter list) is not a declaration and yields nothing.
    """
    for keyword in re.finditer(r"\b(?:bool|_Bool)\b", scan):
        depth = 0
        end = None
        for index in range(keyword.end(), len(scan)):
            char = scan[index]
            if char in "([{":
                depth += 1
            elif char in ")]}":
                depth -= 1
                if depth < 0:
                    break
            elif char == ";" and depth == 0:
                end = index
                break
        if end is not None:
            yield keyword.start(), keyword.end(), end


def _iter_bool_declarators(inner):
    """Yield (name, init_or_None, start) for each boolean declarator.

    Declaration statements are found by ``bool``/``_Bool`` keyword
    and extend to the depth-zero ``;``; the declarator list then
    splits at depth-zero commas so each initializer anchors to its
    own declarator (a following ``, other = ...`` never leaks into
    the preceding initializer). Attributes between the declarator
    and its initializer are removed before parsing, and redundant
    parentheses around the declarator name collapse. A declarator
    that is not a plain identifier with an optional initializer
    (pointers, arrays, malformed shapes) yields (None, chunk,
    start) so the caller can fail closed when it hides a
    membership call.
    """
    scan = _strip_c_attributes(_strip_c_strings(inner))
    for start, kwend, end in _bool_decl_spans(scan):
        chunks = []
        depth = 0
        current = []
        for char in scan[kwend:end]:
            if char in "([{":
                depth += 1
                current.append(char)
            elif char in ")]}":
                depth -= 1
                current.append(char)
            elif char == "," and depth == 0:
                chunks.append("".join(current))
                current = []
            else:
                current.append(char)
        chunks.append("".join(current))
        for chunk in chunks:
            piece = chunk.strip()
            rest = piece
            opens = 0
            while rest.startswith("("):
                opens += 1
                rest = rest[1:].strip()
            match = re.match(r"^([A-Za-z_]\w*)(.*)$", rest, re.S)
            if not match:
                yield None, piece, start
                continue
            name = match.group(1)
            rest = match.group(2).strip()
            closes = 0
            while rest.startswith(")"):
                closes += 1
                rest = rest[1:].strip()
            if opens != closes:
                yield None, piece, start
                continue
            if not rest:
                yield name, None, start
                continue
            if not rest.startswith("=") or rest.startswith("=="):
                yield None, piece, start
                continue
            yield name, rest[1:].strip(), start


def _reject_compound_alias_initializers(inner, fn_name, version):
    """Reject boolean declarators over non-bare membership calls.

    An alias declaration's initializer must be exactly the bare
    membership call (grammar rule S1): any leading or trailing
    operator or expression beyond the call -- ``&& false``,
    ``|| true``, ``== true``, a wrapping negation or parentheses --
    is outside the grammar, in any declarator of a comma-separated
    list and past any ``__attribute__`` qualifiers. Accepting the
    call prefix alone would model a different value as an ordinary
    membership alias, so these raise FilterNotUnderstood instead of
    silently degrading to opaque atoms, as does any unsupported
    declarator shape hiding a membership call.
    """
    for name, init, _ in _iter_bool_declarators(inner):
        if init is None:
            continue
        if name is None:
            if _MEMBERSHIP_CALL_RE.search(init):
                raise FilterNotUnderstood(
                    "kfunc filter %s@%s declares a bool with an "
                    "unsupported declarator over a membership call; "
                    "only plain identifiers are understood"
                    % (fn_name, version))
            continue
        if _MEMBERSHIP_CALL_RE.search(init) and \
                not _BARE_MEMBERSHIP_INIT_RE.fullmatch(init):
            raise FilterNotUnderstood(
                "kfunc filter %s@%s declares a boolean with a "
                "compound membership initializer; only a bare "
                "membership call is understood"
                % (fn_name, version))


def _filter_id_param(params, prog_param):
    """Return the kfunc-id parameter name of a filter, or None.

    The id parameter is the first ``u32``-typed parameter that is
    not the program parameter. Membership tests and aliases are
    only understood over exactly this argument (grammar rules S1
    and C3); any other tested value degrades to an opaque atom.
    """
    for name in re.findall(r"\bu32\s+(\w+)", params):
        if name != prog_param:
            return name
    return None


def _pp_condition_value(rest):
    """True/False for a provable ``#if``/``#elif`` condition, else None.

    Only self-evidently constant conditions evaluate (integer
    literals, C operators and parentheses under LP64 semantics);
    anything mentioning an identifier -- including ``defined`` --
    is unprovable here (external ``-D`` flags and unparsed headers
    may define it) and yields None.
    """
    core = strip_comments(rest).strip()
    if not core or re.search(r"[A-Za-z_]", core):
        return None
    tokens = _c_const_lex(core)
    if tokens is None:
        return None
    try:
        result = _c_const_eval(tokens)
    except (RecursionError, MemoryError, OverflowError):
        return None
    if result is None:
        return None
    return result[0] != 0


def _pp_line_states(text):
    """Inclusion state of every physical line of ``text``.

    Returns a list parallel to ``text.splitlines()`` with each
    line's conditional-inclusion state: "active" (provably
    included), "inactive" (provably excluded) or "unknown" (the
    governing condition is not provably constant). Directives are
    recognized on backslash-joined logical lines with string
    literals blanked, so a ``#`` inside a string never counts;
    line numbers still align with ``parse_defines`` records.
    Unbalanced trailing directives are tolerated.
    """
    lines = _strip_c_strings(text).splitlines()
    states = ["active"] * len(lines)
    stack = []
    state = "active"
    index = 0
    while index < len(lines):
        start = index
        logical = lines[index]
        while logical.rstrip().endswith("\\") and \
                index + 1 < len(lines):
            index += 1
            logical = logical.rstrip()[:-1] + " " + lines[index]
        for lineno in range(start, index + 1):
            states[lineno] = state
        match = re.match(r"[ \t]*#[ \t]*(\w+)(.*)$", logical, re.S)
        if match:
            keyword, rest = match.group(1), match.group(2)
            if keyword in ("if", "ifdef", "ifndef"):
                if state != "active":
                    stack.append(["skipped", state])
                elif keyword == "if":
                    value = _pp_condition_value(rest)
                    if value is True:
                        stack.append([True, "active"])
                    elif value is False:
                        stack.append([False, "active"])
                        state = "inactive"
                    else:
                        stack.append(["unknown", "active"])
                        state = "unknown"
                else:
                    stack.append(["unknown", "active"])
                    state = "unknown"
            elif keyword == "elif":
                if stack:
                    taken, base = stack[-1]
                    if taken == "skipped":
                        state = base
                    elif taken is True:
                        state = "inactive"
                    elif taken is False:
                        value = _pp_condition_value(rest)
                        if value is True:
                            stack[-1][0] = True
                            state = "active"
                        elif value is False:
                            state = "inactive"
                        else:
                            stack[-1][0] = "unknown"
                            state = "unknown"
                    elif _pp_condition_value(rest) is False:
                        state = "inactive"
                    else:
                        state = "unknown"
            elif keyword == "else":
                if stack:
                    taken, base = stack[-1]
                    if taken == "skipped":
                        state = base
                    elif taken is True:
                        state = "inactive"
                    elif taken is False:
                        stack[-1][0] = True
                        state = "active"
                    else:
                        state = "unknown"
            elif keyword == "endif":
                if stack:
                    _, base = stack.pop()
                    state = base
        index += 1
    return states


def _pp_state_at(text, offset):
    """Inclusion state of ``text`` at ``offset`` ("active" default)."""
    states = _pp_line_states(text)
    lineno = text.count("\n", 0, offset) + 1
    if 1 <= lineno <= len(states):
        return states[lineno - 1]
    return "active"


def _blank_inactive_pp_regions(text):
    """Blank physically-excluded lines, preserving line numbers."""
    states = _pp_line_states(text)
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if index < len(states) and states[index] == "inactive":
            lines[index] = ""
    joined = "\n".join(lines)
    if text.endswith("\n"):
        joined += "\n"
    return joined


def _pp_undef_stream(text):
    """[(lineno, name)] ``#undef`` directives of ``text`` in order."""
    found = []
    for lineno, line in enumerate(text.splitlines(), 1):
        match = re.match(r"\s*#\s*undef\s+([A-Za-z_]\w*)", line)
        if match:
            found.append((lineno, match.group(1)))
    return found


def _file_undefs(text):
    """{name: last lineno} for active-region ``#undef`` directives."""
    states = _pp_line_states(text)
    undefs = {}
    for lineno, name in _pp_undef_stream(text):
        if lineno - 1 < len(states) and \
                states[lineno - 1] != "active":
            continue
        undefs[name] = lineno
    return undefs


def _live_file_defines(text):
    """{name: body} object-like macros live after the last #undef.

    Only defines in provably-included regions count: inactive
    branches are dead as in C, and redefinition resolves
    last-active-wins like gcc; unknown-region directives are
    ignored here and surface through ``_pp_unproven_names``
    instead. Function-like macros never expand here, and any
    definition before the name's last active ``#undef`` is dead.
    """
    states = _pp_line_states(text)
    undefs = _file_undefs(text)
    live = {}
    for name, value_text, func_like, lineno in parse_defines(text):
        if func_like or not value_text:
            continue
        if lineno - 1 < len(states) and \
                states[lineno - 1] != "active":
            continue
        if lineno < undefs.get(name, 0):
            continue
        live[name] = value_text
    return live


def _pp_unproven_names(text):
    """Names with a conditionally-unproven define/undef directive.

    A name touched by a ``#define`` (object- or function-like) or
    ``#undef`` in a region whose inclusion the evaluator cannot
    prove is unproven -- unless a later active directive shadows
    every such touch, in which case the unknown state is
    unobservable. Inactive touches are skipped like C skips them.
    """
    states = _pp_line_states(text)

    def state_at(lineno):
        if 1 <= lineno <= len(states):
            return states[lineno - 1]
        return "active"

    touches = [(lineno, name, state_at(lineno))
               for name, _, _, lineno in parse_defines(text)]
    touches += [(lineno, name, state_at(lineno))
                for lineno, name in _pp_undef_stream(text)]
    flagged = set()
    for _, name, state in sorted(touches):
        if state == "active":
            flagged.discard(name)
        elif state == "unknown":
            flagged.add(name)
    return flagged


def _pp_file_reftexts(texts):
    """{name: idents} referenced by each file constant definition.

    Unions, over every text, the identifiers in active object-like
    macro bodies, enumerator value expressions (provably-excluded
    regions blanked) and const- plus mutable-object initializers.
    The consulted closure walks this map.
    """
    reftexts = {}
    for relpath in sorted(texts):
        text = _strip_c_strings(texts[relpath])
        for name, body in _live_file_defines(text).items():
            reftexts.setdefault(name, set()).update(
                re.findall(r"[A-Za-z_]\w*", body))
        for _, members, _ in parse_enums(
                _blank_inactive_pp_regions(text)):
            for member, value_text in members:
                if value_text:
                    reftexts.setdefault(member, set()).update(
                        re.findall(r"[A-Za-z_]\w*", value_text))
        for name, init, _ in _parse_const_objects(text):
            reftexts.setdefault(name, set()).update(
                re.findall(r"[A-Za-z_]\w*", init))
        for name, init, _ in _parse_mutable_file_objects(text):
            reftexts.setdefault(name, set()).update(
                re.findall(r"[A-Za-z_]\w*", init))
    return reftexts


def _called_helper_idents(pred_exprs, stmts, prog_param, expansion):
    """Identifiers of helper bodies one filter actually calls.

    A helper called from a condition (ternary conditions
    included, after unsafe-macro splicing) evaluates its body
    in its own (file) scope, so its pre-folding identifiers --
    helper dependencies, expanded through every macro alias
    (multi-macro chains included, cycle leftovers kept
    verbatim) to the true file-scope names C read at the
    helper's definition point -- count as consulted even when
    the caller shadows their names. (The inliner still refuses
    to splice a shadowed body through filter locals, but the
    dependency outlives the splice.) The dependency set always
    comes from the original body: a folded literal hides the
    names C expanded at the helper's definition point, and a
    redefinition or mutation of one between definition and use
    must reject. Uncalled helpers consult nothing.
    """
    conds = []
    for kind, cond, extra in stmts:
        if cond is not None:
            conds.append(_splice_unsafe_macros(cond, expansion))
        if kind == "if" and isinstance(extra, tuple) and \
                extra[0] in ("ternary", "ternary_const"):
            conds.append(
                _splice_unsafe_macros(extra[1], expansion))
    idents = set()
    for pred, (_, _, _, orig) in pred_exprs.items():
        pattern = r"\b%s\s*\(\s*%s\s*\)" % (
            re.escape(pred), re.escape(prog_param))
        if any(re.search(pattern, cond) for cond in conds):
            idents.update(orig)
    if expansion is not None:
        expanded = expansion[0]
        queue = sorted(idents)
        while queue:
            name = queue.pop()
            body = expanded.get(name)
            if body is None:
                continue
            for dep in re.findall(r"[A-Za-z_]\w*", body):
                if dep not in idents:
                    idents.add(dep)
                    queue.append(dep)
    return idents


def _pp_consulted_names(params, body, stmts, order, reftexts,
                        helper_idents=()):
    """Names load-bearing for one filter's verdict.

    Covers identifiers in conditions (including ternary arms and
    nested ternary conditions), return statements, local
    initializers (including alias and enumerator expressions),
    inlined helper bodies (``helper_idents``) and parameters --
    every evaluated position -- closed transitively over
    file-constant definitions. Skipped straight-line statements
    consult nothing: their values never reach the verdict.
    """
    idents = set(re.findall(
        r"[A-Za-z_]\w*", _strip_c_strings(params)))
    clean = _strip_c_strings(body)
    for kind, cond, extra in stmts:
        if cond is not None:
            idents.update(re.findall(r"[A-Za-z_]\w*", cond))
        if kind == "if" and isinstance(extra, tuple) and \
                extra[0] in ("ternary", "ternary_const"):
            idents.update(re.findall(r"[A-Za-z_]\w*", extra[1]))
    for arm in re.findall(r"\breturn\b(.*?);", clean, flags=re.S):
        idents.update(re.findall(r"[A-Za-z_]\w*", arm))
    for _, _, init, _, _ in order:
        if isinstance(init, str):
            idents.update(re.findall(r"[A-Za-z_]\w*", init))
        elif isinstance(init, tuple) and len(init) == 2:
            if init[0] == "auto":
                if init[1] is not None:
                    idents.add(init[1])
            elif init[0] == "enuminit" and init[1]:
                idents.update(
                    re.findall(r"[A-Za-z_]\w*", init[1]))
    consulted = set(idents) | set(helper_idents)
    queue = list(consulted)
    while queue:
        name = queue.pop()
        for dep in reftexts.get(name, ()):
            if dep not in consulted:
                consulted.add(dep)
                queue.append(dep)
    return consulted


def _merge_file_defines(texts):
    """{name: body} object-like macros merged across files.

    A name with the same normalized body everywhere keeps it; a
    name with two different bodies is ambiguous and dropped
    rather than guessed, mirroring the value merge.
    """
    merged = {}
    poisoned = set()
    for relpath in sorted(texts):
        for name, body in _live_file_defines(texts[relpath]).items():
            norm = " ".join(body.split())
            if name in poisoned:
                continue
            if name in merged:
                if " ".join(merged[name].split()) != norm:
                    del merged[name]
                    poisoned.add(name)
                continue
            merged[name] = body
    return merged


def _expand_one_macro(name, defines, stack):
    """Fully expanded body of macro ``name`` (cycle-safe).

    Expansion is verbatim C preprocessing: no parentheses are
    added, so ``1 + 1`` in a ``* 2`` context still multiplies
    first. A macro referencing itself (directly or through a
    cycle) leaves the cyclic name unexpanded and fails closed
    downstream as an unknown identifier.
    """
    if name in stack:
        return name
    stack = stack + (name,)

    def sub(match):
        inner = match.group(0)
        if inner in defines and inner not in stack:
            return _expand_one_macro(inner, defines, stack)
        return inner

    try:
        return re.sub(r"[A-Za-z_]\w*", sub, defines[name])
    except RecursionError:
        return defines[name]


def _macro_expansion_is_atomic(expanded):
    """Whether a fully expanded macro body substitutes by value.

    A single literal or identifier (after one optional unary
    operator) and a fully parenthesized body read identically
    under textual and value substitution, so the evaluated value
    may substitute; anything else must splice textually.
    """
    core = expanded.strip()
    if not core:
        return True
    stripped = re.sub(r"^[\+\-~!]\s*", "", core, count=1)
    if re.fullmatch(
            r"(0[xX][0-9a-fA-F]+|0[bB][01]+|\d+)[uUlL]*",
            stripped) is not None:
        return True
    if re.fullmatch(r"[A-Za-z_]\w*", stripped) is not None:
        return True
    if len(core) >= 2 and core.startswith("(") and \
            core.endswith(")"):
        depth = 0
        for index, char in enumerate(core):
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0 and index != len(core) - 1:
                    return False
        return depth == 0
    return False


def _prepare_macro_expansion(defines):
    """(expanded, unsafe) for one object-like macro map.

    ``expanded`` maps every name to its fully expanded body;
    ``unsafe`` holds the names whose expansion is not atomic and
    must therefore splice textually at every use.
    """
    expanded = {}
    for name in defines:
        try:
            expanded[name] = _expand_one_macro(name, defines, ())
        except RecursionError:
            expanded[name] = defines[name]
    unsafe = {name for name, body in expanded.items()
              if not _macro_expansion_is_atomic(body)}
    return expanded, unsafe


def _splice_unsafe_macros(text, expansion):
    """Splice unsafe macros textually into ``text`` (single pass).

    Only ``unsafe`` names splice; atomic macros stay for value
    substitution. The pass scans the original text once, so
    expansions (already full, cycle leftovers included) are never
    rescanned and the splice always terminates.
    """
    if expansion is None:
        return text
    expanded, unsafe = expansion
    if not unsafe:
        return text

    def sub(match):
        name = match.group(0)
        if name in unsafe:
            return expanded[name]
        return name

    return re.sub(r"[A-Za-z_]\w*", sub, text)


def _expand_all_macros(text, expansion):
    """Expand every object-like macro in ``text`` (single pass).

    Unlike the unsafe-only splice, atomic macros expand too:
    purity inspection must see the exact tokens C compiles, so
    an assignment, comma expression or call hidden behind a
    parenthesized alias still invalidates. The pass scans the
    original text once, so expansions (already full, cycle
    leftovers included) are never rescanned and the expansion
    always terminates.
    """
    if expansion is None:
        return text
    expanded, _ = expansion
    if not expanded:
        return text

    def sub(match):
        name = match.group(0)
        if name in expanded:
            return expanded[name]
        return name

    return re.sub(r"[A-Za-z_]\w*", sub, text)


def _eval_text_constexpr(value_text, known, expansion=None):
    """Evaluate a file-local constant expression with C semantics.

    Unsafe (non-atomic) macros splice textually first, matching C
    preprocessing exactly; then ``known`` maps already-resolved
    names to exact literal spellings (suffixed where the resolved
    type demands it), which substitute parenthesized, and the C
    integer evaluator folds the result (unsigned wraparound
    included). Returns the (value, width, signed) triple, or None
    for an unknown name or unprovable shape.
    """
    spliced = _splice_unsafe_macros(value_text, expansion)

    def substitute(match):
        name = match.group(0)
        if name in known:
            return "(%s)" % known[name]
        return name

    expanded = re.sub(r"[A-Za-z_]\w*", substitute, spliced)
    tokens = _c_const_lex(expanded.strip())
    if tokens is None:
        return None
    try:
        return _c_const_eval(tokens)
    except (RecursionError, MemoryError, OverflowError):
        return None


def _enum_value_type(value):
    """(value, width, signed) for an enumerator holding ``value``.

    Follows gcc's value ladder (int, unsigned int, long,
    unsigned long): an enumerator types by its value, never by
    its initializer's spelling, so ``1U`` still types as int.
    """
    if value <= 2 ** 31 - 1:
        return (value, 32, True)
    if value <= 2 ** 32 - 1:
        return (value, 32, False)
    if value <= 2 ** 63 - 1:
        return (value, 64, True)
    return (value, 64, False)


def _const_decl_type(blob):
    """Declared-type descriptor for a const object, or None.

    Returns ``"enum"`` for enum types (typed by value like gcc),
    ``("bool",)`` for boolean types (nonzero converts to 1),
    ``("narrow", width, signed)`` for char/short families
    (initializers wrap modulo the width before promotion; plain
    ``char`` is signed on x86-64 gcc), or ``("int", width,
    signed)`` for int-or-wider types under LP64. Unknown
    (typedef-named) and non-integer (struct/union) types yield
    None and never resolve as constants.
    """
    words = blob.split()
    if not words or any(
            word in ("struct", "union") for word in words):
        return None
    if "enum" in words:
        return "enum"
    known = {"void", "_Bool", "bool", "char", "short", "int", "long",
             "signed", "unsigned", "const", "volatile", "restrict",
             "_Atomic", "u8", "u16", "u32", "u64", "s8", "s16",
             "s32", "s64", "size_t", "ssize_t", "int8_t", "int16_t",
             "int32_t", "int64_t", "uint8_t", "uint16_t", "uint32_t",
             "uint64_t", "__u8", "__u16", "__u32", "__u64", "__s8",
             "__s16", "__s32", "__s64"}
    if any(word not in known for word in words):
        return None
    if "bool" in words or "_Bool" in words:
        return ("bool",)
    if "short" in words or "u16" in words or "s16" in words or \
            "int16_t" in words or "uint16_t" in words or \
            "__u16" in words or "__s16" in words:
        return ("narrow", 16, "unsigned" not in words and
                "u16" not in words and "uint16_t" not in words
                and "__u16" not in words)
    if "char" in words or "u8" in words or "s8" in words or \
            "int8_t" in words or "uint8_t" in words or \
            "__u8" in words or "__s8" in words:
        return ("narrow", 8, "unsigned" not in words and
                "u8" not in words and "uint8_t" not in words
                and "__u8" not in words)
    if words.count("long") >= 2:
        return ("int", 64, "unsigned" not in words)
    if "long" in words or "u64" in words or "s64" in words or \
            "size_t" in words or "ssize_t" in words or \
            "int64_t" in words or "uint64_t" in words or \
            "__u64" in words or "__s64" in words:
        if "size_t" in words:
            return ("int", 64, False)
        if "ssize_t" in words:
            return ("int", 64, True)
        return ("int", 64, "unsigned" not in words and
                "u64" not in words and "uint64_t" not in words
                and "__u64" not in words)
    if "unsigned" in words or "u32" in words or "uint32_t" in words \
            or "__u32" in words:
        return ("int", 32, False)
    return ("int", 32, True)


def _parse_const_objects(text):
    """Return [(name, init_text, declared)] const objects in ``text``.

    Only ``const``-qualified integer objects with a scalar
    initializer qualify: pointers, arrays, braced initializers,
    function declarations and mutable globals never do.
    ``declared`` is the ``_const_decl_type`` descriptor
    (``"enum"``, ``("bool",)``, ``("narrow", ...)`` or
    ``("int", ...)``), or None for unknowable types.
    Multi-declarator lists contribute each initialized declarator
    whose statement head is a const declaration. Provably-excluded
    conditional regions blank first (an inactive object was never
    compiled), then preprocessor logical lines, so a declaration
    spelled inside a macro body never resolves as an object.
    """
    text = _blank_inactive_pp_regions(text)
    text = re.sub(r"^[ \t]*#(?:\\\n|[^\n])*",
                  lambda match: "\n" * match.group(0).count("\n"),
                  text, flags=re.M)
    found = []
    for match in re.finditer(
            r"(?:^|[;{}\n])\s*((?:static\s+|extern\s+|const\s+|"
            r"volatile\s+|register\s+|auto\s+)*)"
            r"([\w\s]+?)\s+(\w+)\s*=\s*([^;,{}]+?)\s*;",
            text):
        quals, blob, name, init = match.groups()
        if "const" not in quals and "const" not in blob.split():
            continue
        found.append((name, init.strip(),
                      _const_decl_type(blob)))
    for match in re.finditer(
            r",\s*(\w+)\s*=\s*([^;,{}()]+?)\s*(?=[;,])", text):
        name, init = match.group(1), match.group(2).strip()
        stmt_start = max(
            text.rfind(";", 0, match.start()),
            text.rfind("{", 0, match.start()),
            text.rfind("}", 0, match.start())) + 1
        head = text[stmt_start:match.start()]
        # The head must open as a const declaration (quals, type
        # blob, first declarator with an initializer); calls, comma
        # expressions and assignments never contribute a constant.
        opened = re.match(
            r"\s*((?:static\s+|extern\s+|const\s+|volatile\s+|"
            r"register\s+|auto\s+)*)([\w\s]+?)\s+(\w+)\s*=",
            head)
        if opened is None:
            continue
        quals, blob = opened.group(1), opened.group(2)
        if "const" not in quals and "const" not in blob.split():
            continue
        found.append((name, init, _const_decl_type(blob)))
    return found


def _parse_mutable_file_objects(text):
    """Return [(name, init_text, declared)] mutable file objects.

    Only true file-scope (depth-zero, outside every function and
    aggregate body) scalar integer/boolean objects with an
    initializer qualify; ``const``-qualified objects belong to
    the const path, and pointers, arrays, braced initializers,
    function declarations, tentative definitions and anything
    declared inside a body never qualify. ``declared`` is the
    ``_const_decl_type`` descriptor, or None for unknowable
    types. Provably-excluded conditional regions and
    preprocessor logical lines blank first, so neither dead text
    nor a declaration spelled inside a macro body resolves.
    """
    scoped = _file_scope_text(text)
    found = []
    quals = (r"(?:(?:static|extern|const|volatile|register|"
             r"auto)[ \t]+)*")
    blob = r"([A-Za-z_]\w*(?:[ \t]+[A-Za-z_]\w*){0,7})"
    gap = r"(?:(?![;{}])\s)*"
    for match in re.finditer(
            r"(?:^|[;{})])" + gap + "(" + quals + r")" + blob +
            r"[ \t]+(\w+)[ \t]*=[ \t]*([^;,\n{}]{1,256}?)"
            r"[ \t]*(?=;)", scoped):
        qual_text, blob_text, name, init = match.groups()
        if "const" in qual_text.split() or \
                "const" in blob_text.split():
            continue
        found.append((name, init.strip(),
                      _const_decl_type(blob_text)))
    for match in re.finditer(
            r",[ \t]*(\w+)[ \t]*=[ \t]*([^;,\n{}()]{1,256}?)"
            r"[ \t]*(?=[;,])", scoped):
        name, init = match.group(1), match.group(2).strip()
        stmt_start = max(
            scoped.rfind(";", 0, match.start()),
            scoped.rfind("{", 0, match.start()),
            scoped.rfind("}", 0, match.start())) + 1
        head = scoped[stmt_start:match.start()]
        opened = re.match(
            gap + "(" + quals + r")" + blob +
            r"[ \t]+(\w+)[ \t]*=", head)
        if opened is None:
            continue
        qual_text, blob_text = opened.group(1), opened.group(2)
        if "const" in qual_text.split() or \
                "const" in blob_text.split():
            continue
        found.append((name, init, _const_decl_type(blob_text)))
    return found


def _pp_contested_names(text, pipeline, declared, renders,
                        expansion):
    """Names whose active file macro fights another binding.

    An active object-like file macro over a pipeline-pinned or
    file-declared (enum/const-object) name is benign only when it
    evaluates to that same value; a different or unevaluatable
    body -- including a self-referential one, which is excluded
    from its own namespace -- contests the name, as do two active
    defines with different values (use order between them is
    unproven) and any active ``#undef`` of a bound name. Returns
    the contested set; the caller rejects when the filter
    consults one.
    """
    states = _pp_line_states(text)

    def is_active(lineno):
        return lineno - 1 >= len(states) or \
            states[lineno - 1] == "active"

    actives = {}
    for name, body, func_like, lineno in parse_defines(text):
        if func_like or not is_active(lineno):
            continue
        actives.setdefault(name, []).append(body or "")
    contested = set()
    for name in _file_undefs(text):
        if name in pipeline or name in declared:
            contested.add(name)
    for name, bodies in actives.items():
        if name in pipeline:
            target = pipeline[name]
        elif name in declared:
            target = declared[name]
        else:
            target = None
        known = {key: val for key, val in renders.items()
                 if key != name}
        seen = set()
        for body in bodies:
            result = _eval_text_constexpr(body, known, expansion)
            seen.add(None if result is None else result[0])
        if len(seen) > 1:
            contested.add(name)
        elif target is not None and seen != {target}:
            contested.add(name)
    return contested


def _filter_const_maps(texts, const_values):
    """Constant values and types visible to one filter.

    Returns (values, typed, contested, mutable): ``values`` maps
    names to integer values for return classification, while
    ``typed`` maps file-local names to exact (value, width,
    signed) triples for type-preserving substitution
    (pipeline-pinned values carry no type and stay out of
    ``typed``); ``contested`` holds names whose active file macro
    fights a pipeline or declared binding (or another active
    define, or an active ``#undef``); ``mutable`` holds merged
    names originating from mutable file-scope objects, whose
    initializer values the caller must invalidate on body writes
    and calls. Pipeline-pinned UAPI values (authoritative per
    version) win; file-local enums, object-like macros and
    integer objects (const-qualified anywhere, plus mutable
    scalars at true file scope) from the filter's own texts fill
    the gaps, with enum auto-numbering poisoned past any
    unresolvable member. Enumerators type by value (gcc's
    ladder), never by initializer spelling; object initializers
    convert to the declared type first (boolean conversion,
    narrow modulo wraparound, while signed out-of-range stays
    unproven). Lowercase ``true``/``false`` seed the render
    namespace as 1/0 unless bound. Only macros live after the
    last active ``#undef`` resolve, provably-excluded regions
    contribute nothing, and non-atomic macro bodies splice
    textually, so evaluation matches C preprocessing exactly.
    Each file evaluates in its own namespace (separate
    translation units may reuse a name); a file-local name
    resolving to two different values across files is ambiguous
    and dropped rather than guessed. Only true integers qualify.
    """
    values = {}
    if const_values:
        for name, value in const_values.items():
            if isinstance(value, int) and not isinstance(value, bool):
                values[name] = value
    seed_render = {name: "%d" % value
                   for name, value in values.items()}
    file_locals = []
    contested = set()
    for relpath in sorted(texts):
        text = _strip_c_strings(texts[relpath])
        local = {}
        lrender = {}
        ltyped = {}
        lknown = dict(values)
        lrender_known = dict(seed_render)
        live_defs = {name: body
                     for name, body in _live_file_defines(text).items()
                     if name not in values}
        expansion = _prepare_macro_expansion(live_defs)
        for keyword, spelling in (("true", "1"), ("false", "0")):
            if keyword not in live_defs and \
                    keyword not in lrender_known:
                lrender_known[keyword] = spelling

        def record(name, value, width, signed):
            render = _c_canonical_literal(value, width, signed)
            if render is None:
                render = "%d" % value
            local[name] = value
            lknown[name] = value
            lrender[name] = render
            lrender_known[name] = render
            ltyped[name] = (value, width, signed)

        for _, members, _ in parse_enums(
                _blank_inactive_pp_regions(text)):
            next_value = 0
            for name, value_text in members:
                if name in values:
                    next_value = values[name] + 1
                    continue
                if name in local:
                    next_value = local[name] + 1
                    continue
                if value_text is None:
                    if next_value is None:
                        continue
                    record(name, *_enum_value_type(next_value))
                    next_value += 1
                    continue
                result = _eval_text_constexpr(
                    value_text, lrender_known, expansion)
                if result is None:
                    next_value = None
                    continue
                record(name, *_enum_value_type(result[0]))
                next_value = result[0] + 1
        pending_defs = [(name, live_defs[name])
                        for name in live_defs]
        pending_objs = [(name, init_text, declared)
                        for name, init_text, declared in
                        _parse_const_objects(text)
                        if name not in values]
        pending_mut = [(name, init_text, declared)
                       for name, init_text, declared in
                       _parse_mutable_file_objects(text)
                       if name not in values]
        pending_objs += pending_mut
        mutable_here = set(name for name, _, _ in pending_mut)
        for _ in range(3):
            for name, value_text in pending_defs:
                if name in local:
                    continue
                result = _eval_text_constexpr(
                    value_text, lrender_known, expansion)
                if result is not None:
                    record(name, *result)
            for name, init_text, declared in pending_objs:
                if name in local or declared is None:
                    continue
                result = _eval_text_constexpr(
                    init_text, lrender_known, expansion)
                if result is None:
                    continue
                init_value = result[0]
                if declared == "enum":
                    record(name, *_enum_value_type(init_value))
                    continue
                if declared[0] == "bool":
                    record(name, 1 if init_value != 0 else 0,
                           32, True)
                    continue
                if declared[0] == "narrow":
                    _, nwidth, nsigned = declared
                    rep = init_value & ((1 << nwidth) - 1)
                    if nsigned and rep >= (1 << (nwidth - 1)):
                        rep -= (1 << nwidth)
                    record(name, rep, 32, True)
                    continue
                _, width, signed = declared
                if signed:
                    if init_value < -(1 << (width - 1)) or \
                            init_value >= (1 << (width - 1)):
                        continue
                    record(name, init_value, width, True)
                    continue
                record(name, init_value & ((1 << width) - 1),
                       width, False)
        lmutable = set(
            name for name in mutable_here if name in local)
        steady = {name: value for name, value in local.items()
                  if name not in lmutable}
        contested.update(_pp_contested_names(
            text, values, steady, lrender_known, expansion))
        file_locals.append((local, lrender, ltyped, lmutable))
    merged = {}
    merged_typed = {}
    poisoned = set()
    for local, _, ltyped, _ in file_locals:
        for name, value in local.items():
            if name in poisoned:
                continue
            if name in merged:
                if merged[name] != value:
                    del merged[name]
                    del merged_typed[name]
                    poisoned.add(name)
                continue
            merged[name] = value
            merged_typed[name] = ltyped[name]
    mutable = set()
    for _, _, _, lmutable in file_locals:
        mutable |= set(name for name in lmutable if name in merged)
    values.update(merged)
    return values, merged_typed, contested, mutable


def _filter_return_bits(texts, fn_name, version):
    """Return width of one filter's integer return type.

    Parses the definition's return-type prefix (``static int``,
    ``long``, ...), skipping conditionally-excluded definitions;
    anything but a plain integer type is outside the grammar.
    Widths follow LP64.
    """
    def bad_type():
        raise FilterNotUnderstood(
            "kfunc filter %s@%s has a non-integer return type; only "
            "integer filters are understood" % (fn_name, version))

    for relpath in sorted(texts):
        text = texts[relpath]
        for match in re.finditer(r"\b%s\s*\(" % re.escape(fn_name),
                                 text):
            if _pp_state_at(text, match.start()) == "inactive":
                continue
            pos = match.end() - 1
            depth = 0
            end = None
            for index in range(pos, len(text)):
                char = text[index]
                if char == "(":
                    depth += 1
                elif char == ")":
                    depth -= 1
                    if depth == 0:
                        end = index
                        break
            if end is None:
                continue
            brace = text.find("{", end)
            if brace == -1 or brace - end > 600:
                continue
            if text.find(";", end, brace) != -1:
                continue
            cut = max(text.rfind(";", 0, match.start()),
                      text.rfind("{", 0, match.start()),
                      text.rfind("}", 0, match.start()),
                      text.rfind(")", 0, match.start()))
            prefix = " ".join(
                line for line in text[cut + 1:match.start()].splitlines()
                if not line.strip().startswith("#"))
            words = [word for word in prefix.split()
                     if word not in ("static", "const", "volatile",
                                     "inline", "extern", "register")]
            kinds = set(words)
            if not words or any("*" in word for word in words):
                bad_type()
            if kinds in ({"bool"}, {"_Bool"}):
                return 1
            if kinds & {"long", "u64", "s64", "size_t", "ssize_t",
                        "int64_t", "uint64_t", "__u64", "__s64"}:
                return 64
            if kinds & {"short", "u16", "s16", "int16_t", "uint16_t",
                        "__u16", "__s16"}:
                return 16
            if kinds & {"char", "u8", "s8", "int8_t", "uint8_t",
                        "__u8", "__s8"}:
                return 8
            if kinds <= {"int", "signed", "unsigned", "u32", "s32",
                         "int32_t", "uint32_t", "__u32", "__s32"}:
                return 32
            bad_type()
    bad_type()


_DECL_TYPE_WORDS = (
    r"u8|u16|u32|u64|s8|s16|s32|s64|int|long|short|"
    r"char|signed|unsigned|size_t|ssize_t|bool|_Bool|void|"
    r"int8_t|int16_t|int32_t|int64_t|"
    r"uint8_t|uint16_t|uint32_t|uint64_t|"
    r"__u8|__u16|__u32|__u64|__s8|__s16|__s32|__s64|"
    r"const|static|volatile|register|auto|extern|__auto_type|"
    r"struct\s+\w+|union\s+\w+|enum\s+\w+"
)

# Keywords that can follow a closing brace without declaring
# anything (``} if (...)``, ``} while (...)``); the struct-suffix
# pattern never binds them.
_C_KEYWORDS = frozenset((
    "if", "else", "for", "while", "do", "switch", "case", "default",
    "return", "goto", "sizeof", "typedef", "struct", "union",
    "enum", "const", "static",
))


def _split_depth0(text, sep):
    """Split ``text`` on ``sep`` at zero bracket depth."""
    parts = []
    depth = 0
    current = []
    for char in text:
        if char in "([{":
            depth += 1
            current.append(char)
        elif char in ")]}":
            depth -= 1
            current.append(char)
        elif char == sep and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    parts.append("".join(current))
    return parts


def _blank_nested_blocks(text):
    """Blank ``{ ... }`` regions nested inside ``text``.

    Depth-zero text (top-level filter statements) is kept; every
    nested brace region becomes spaces, so depth-zero declaration
    scans never see block-scoped names. Unbalanced closers are
    tolerated (blanked) rather than miscounting the depth.
    """
    out = []
    depth = 0
    for char in text:
        if char == "{":
            depth += 1
            out.append(" ")
        elif char == "}":
            if depth > 0:
                depth -= 1
            out.append(" ")
        elif depth >= 1:
            out.append("\n" if char == "\n" else " ")
        else:
            out.append(char)
    return "".join(out)


def _iter_local_enums(scan):
    """Yield (members, is_top, pos) for each enum in ``scan``.

    ``members`` holds (name, value_text_or_None) in source order;
    ``is_top`` tells whether the definition sits at brace depth
    zero; ``pos`` is the definition's offset for source ordering.
    ``scan`` must have string literals blanked already.
    """
    for match in re.finditer(r"\benum\b\s*(\w+)?\s*\{", scan):
        depth = 0
        end = None
        for index in range(match.end() - 1, len(scan)):
            char = scan[index]
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    end = index
                    break
        if end is None:
            continue
        body = scan[match.end():end]
        pre = scan[:match.start()]
        members = []
        for piece in _split_depth0(body, ","):
            piece = piece.strip()
            if not piece:
                continue
            found = re.match(r"([A-Za-z_]\w*)\s*(?:=\s*(.*))?$",
                             piece, re.S)
            if found:
                init = (found.group(2) or "").strip() or None
                members.append((found.group(1), init))
        yield members, pre.count("{") - pre.count("}") == 0, \
            match.start()


def _plain_hit_bool_covered(scan, match):
    """Whether a plain-declarator hit duplicates bool discovery.

    ``bool``-led plain declarators (``bool x``, ``bool (x)``) are
    already reported by the ``bool``-declarator iterator, so the
    plain pattern skips them; pointer, array, function and other
    declarator operators the iterator rejects (a None yield) stay
    with the plain pattern.
    """
    prefix = match.group(0)[:match.start(1) - match.start()]
    if re.search(r"\b(?:bool|_Bool)\b[\s(*]*$", prefix) is None:
        return False
    if "*" in match.group(0):
        return False
    tail = scan[match.end(1):].lstrip()
    while tail.startswith(")"):
        tail = tail[1:].lstrip()
    return tail[:1] not in ("(", "[")


def _comma_head_is_bool(head):
    """Whether a comma-declarator head opens a ``bool`` declaration."""
    return re.match(
        r"\s*(?:static\s+|extern\s+|const\s+|volatile\s+|"
        r"register\s+|auto\s+)*(?:bool|_Bool)\b", head) is not None


def _typedef_segment_names(segment, pos):
    """Alias names defined by one ``typedef`` segment, with ``pos``.

    Handles plain, pointer, array, function and function-pointer
    declarators plus comma-separated lists; an unparseable segment
    over-approximates with every identifier it holds, since
    over-discovery fails closed downstream.
    """
    names = []
    while True:
        inner = re.sub(r"\{[^{}]*\}", " ", segment)
        if inner == segment:
            break
        segment = inner
    if "{" in segment or "}" in segment:
        for extra in re.findall(r"[A-Za-z_]\w*", segment):
            names.append((extra, ("pos", pos)))
        return names
    for chunk in _split_depth0(segment, ","):
        chunk = chunk.strip()
        pointed = re.search(r"\(\s*\*+\s*(\w+)\s*\)", chunk)
        if pointed:
            names.append((pointed.group(1), ("typedef", pos)))
            continue
        core = chunk
        while True:
            stripped = re.sub(r"\([^()]*\)\s*$", "", core).strip()
            stripped = re.sub(r"\[[^\[\]]*\]\s*$", "",
                              stripped).strip()
            if stripped == core:
                break
            core = stripped
        trailing = re.search(r"(\w+)\s*$", core)
        if trailing:
            names.append((trailing.group(1), ("typedef", pos)))
    return names


def _typedef_defined_names(raw):
    """Every alias name a ``typedef`` declaration defines in ``raw``.

    Covers file-scope and body-local aliases alike; the caller
    decides the visibility scope by choosing the scanned text.
    """
    scan = _strip_c_attributes(_strip_c_strings(raw))
    names = set()
    for found in re.finditer(r"\btypedef\b", scan):
        depth = 0
        end = None
        for index in range(found.end(), len(scan)):
            char = scan[index]
            if char in "([{":
                depth += 1
            elif char in ")]}":
                depth -= 1
            elif char == ";" and depth == 0:
                end = index
                break
        if end is None:
            continue
        for name, _ in _typedef_segment_names(
                scan[found.end():end], found.start()):
            names.add(name)
    return names


def _declared_name_hits(raw, extra_types=()):
    """(name, key) hits for every declared name in ``raw``.

    Each hit carries a dedup key so one declarator reported by two
    patterns (a function pointer matching the plain and the
    function-pointer patterns at one position) counts once, while
    two declarators for one name count twice. ``bool``-led plain
    and comma declarators already covered by the boolean
    iterator are skipped here. ``extra_types`` carries typedef
    alias names, which head declarations exactly like the builtin
    type words; declarators they head bind but never resolve to a
    provable value.
    """
    scan = _strip_c_attributes(_strip_c_strings(raw))
    type_words = _DECL_TYPE_WORDS
    if extra_types:
        type_words += "|" + "|".join(
            re.escape(name) for name in sorted(extra_types))
    hits = []
    for index, (name, _, _) in enumerate(
            _iter_bool_declarators(scan)):
        if name is not None:
            hits.append((name, ("bool", index)))
    for match in re.finditer(
            r"\b(?:(?:%s)\b\s*)+(?:\(\s*|\*\s*)*(\w+)"
            % type_words, scan):
        if _plain_hit_bool_covered(scan, match):
            continue
        hits.append((match.group(1), ("pos", match.start(1))))
    for match in re.finditer(
            r"\b(?:%s)\b[\w\s,*]*\(\s*\*+\s*(\w+)\s*\)"
            % type_words, scan):
        hits.append((match.group(1), ("pos", match.start(1))))
    for match in re.finditer(
            r",\s*(?:\(\s*|\*\s*)*(\w+)(?:\s*\))*\s*"
            r"(?=[=;,\[])", scan):
        stmt_start = max(
            scan.rfind(";", 0, match.start()),
            scan.rfind("{", 0, match.start()),
            scan.rfind("}", 0, match.start())) + 1
        head = scan[stmt_start:match.start()]
        if _comma_head_is_bool(head) and \
                "*" not in match.group(0):
            tail = scan[match.end(1):].lstrip()
            while tail.startswith(")"):
                tail = tail[1:].lstrip()
            if tail[:1] not in ("(", "["):
                continue
        hits.append((match.group(1), ("pos", match.start(1))))
    for match in re.finditer(
            r",\s*\(\s*\*+\s*(\w+)\s*\)", scan):
        stmt_start = max(
            scan.rfind(";", 0, match.start()),
            scan.rfind("{", 0, match.start()),
            scan.rfind("}", 0, match.start())) + 1
        head = scan[stmt_start:match.start()]
        head_types = _ALIAS_TYPES
        if extra_types:
            head_types += "|" + "|".join(
                re.escape(name) for name in sorted(extra_types))
        if re.match(
                r"\s*(?:%s)?(?:%s)\b[\w\s,*=]*$"
                % (_ALIAS_QUALIFIERS, head_types), head):
            hits.append((match.group(1), ("pos", match.start(1))))
    for match in re.finditer(
            r"\b(?:__)?typeof\s*\([^;{}]*\)\s*(?:\(\s*|\*\s*)*"
            r"(\w+)", scan):
        hits.append((match.group(1), ("pos", match.start(1))))
    for found in re.finditer(
            r"\btypedef\b", scan):
        depth = 0
        end = None
        for index in range(found.end(), len(scan)):
            char = scan[index]
            if char in "([{":
                depth += 1
            elif char in ")]}":
                depth -= 1
            elif char == ";" and depth == 0:
                end = index
                break
        if end is None:
            continue
        hits.extend(_typedef_segment_names(
            scan[found.end():end], found.start()))
    for members, _, pos in _iter_local_enums(scan):
        for name, _ in members:
            hits.append((name, ("enum", pos)))
    for match in re.finditer(
            r"\}\s*(?:\(\s*)*(?:\*\s*)*(\w+)(?:\s*\)\s*)*\s*"
            r"(?=[=;,\[()])", scan):
        if match.group(1) not in _C_KEYWORDS:
            hits.append((match.group(1), ("pos", match.start(1))))
    return hits


def _discover_declared_names(raw, extra_types=()):
    """Every name a body scan declares, in any declarator form.

    Covers plain, pointer, array, parenthesized and
    function-pointer declarators (C has no functional casts, so
    ``TYPE (name)`` always declares -- even when the name spells
    a cast such as ``u64``), later comma declarators, typedef
    names, local enum members and ``} name`` struct-suffix
    declarators. ``extra_types`` (typedef aliases) head
    declarations like the builtin type words. Casts never match
    (a ``)`` follows the type word). Over-discovery fails closed
    downstream (a use is rejected or degraded); under-discovery
    would misbind, so every form is recognized.
    """
    return {name for name, _ in _declared_name_hits(raw, extra_types)}


def _multi_declared_names(raw, extra_types=()):
    """Names with two or more distinct declarators in ``raw``.

    Bit-test constraints key operands by identity, which is only
    sound for single-binding names; a name declared twice (nested
    shadowing, duplicate declarators) degrades any bit test
    mentioning it to notes-only downstream.
    """
    seen = {}
    multi = set()
    for name, key in _declared_name_hits(raw, extra_types):
        if name in multi:
            continue
        if name in seen:
            if seen[name] != key:
                del seen[name]
                multi.add(name)
            continue
        seen[name] = key
    return multi


def _nested_declared_names(raw, extra_types=()):
    """Names declared inside the nested blocks of ``raw``."""
    scan = _strip_c_attributes(_strip_c_strings(raw))
    names = set()
    depth = 0
    start = None
    for index, char in enumerate(scan):
        if char == "{":
            if depth == 0:
                start = index
            depth += 1
        elif char == "}":
            if depth > 0:
                depth -= 1
            if depth == 0 and start is not None:
                names |= _discover_declared_names(
                    scan[start + 1:index], extra_types)
                start = None
    return names


def _filter_local_names(inner, aliases, params, prog_param,
                        extra_types=()):
    """Names bound as filter locals, shadowing any constant.

    Covers aliases, parameters and every declaration form in the
    whole body (plain, pointer, array, parenthesized and
    function-pointer declarators, comma declarators, typedefs,
    local enums, struct-suffix declarators, boolean declarators,
    and declarators headed by a typedef alias); a return arm
    spelling one of these is dynamic and never a constant.
    """
    bound = set(aliases) | set(_filter_param_names(params, prog_param))
    for name, _, _ in _iter_bool_declarators(inner):
        if name is not None:
            bound.add(name)
    return bound | _discover_declared_names(inner, extra_types)


def _decl_narrow(words, boolean):
    """(width, signed) for a narrow declaration, or None.

    ``words`` are the declaration specifiers. Narrow integer
    types (``char``/``short`` families, explicitly signed or
    not) convert their initializer before any promotion; plain
    ``char`` is signed on the x86-64 System V ABI gcc target.
    Boolean declarations convert instead and never count here.
    """
    if boolean:
        return None
    wide = {"long", "u64", "s64", "size_t", "ssize_t", "int64_t",
            "uint64_t", "__u64", "__s64"}
    if any(word in wide for word in words):
        return None
    if "short" in words or any(word in words for word in
                               ("u16", "s16", "int16_t",
                                "uint16_t", "__u16", "__s16")):
        return (16, "unsigned" not in words and
                "u16" not in words and "uint16_t" not in words
                and "__u16" not in words)
    if "char" in words or any(word in words for word in
                              ("u8", "s8", "int8_t", "uint8_t",
                               "__u8", "__s8")):
        return (8, "unsigned" not in words and
                "u8" not in words and "uint8_t" not in words
                and "__u8" not in words)
    return None


def _decl_int_wide(words, boolean):
    """(width, signed) for a 32/64-bit integer declaration, or None.

    ``words`` are the declaration specifiers. Only known LP64
    integer spellings qualify (plain ``int``/``unsigned``, ``long``,
    ``u32``/``s32``/``u64``/``s64`` and fixed-width/alias forms);
    boolean, narrow, enum/struct/union, ``__auto_type`` and
    typedef-named (unknown) declarations never count here.
    """
    if boolean or "__auto_type" in words:
        return None
    if "short" in words or "char" in words or \
            any(word in words for word in
                ("u16", "s16", "int16_t", "uint16_t", "__u16",
                 "__s16", "u8", "s8", "int8_t", "uint8_t", "__u8",
                 "__s8")):
        return None
    if any(word in ("struct", "union", "enum") for word in words):
        return None
    known = {"void", "char", "short", "int", "long", "signed",
             "unsigned", "const", "volatile", "restrict", "_Atomic",
             "static", "extern", "register", "auto", "u32", "s32",
             "u64", "s64", "size_t", "ssize_t", "int32_t",
             "uint32_t", "int64_t", "uint64_t", "__u32", "__s32",
             "__u64", "__s64"}
    if any(word not in known for word in words):
        return None
    if words.count("long") >= 2:
        return (64, "unsigned" not in words)
    if "long" in words or any(word in words for word in
                              ("u64", "s64", "size_t", "ssize_t",
                               "int64_t", "uint64_t", "__u64",
                               "__s64")):
        if "size_t" in words:
            return (64, False)
        if "ssize_t" in words:
            return (64, True)
        return (64, "unsigned" not in words and
                "u64" not in words and "uint64_t" not in words
                and "__u64" not in words)
    if any(word in words for word in
           ("int", "signed", "unsigned", "u32", "s32", "int32_t",
            "uint32_t", "__u32", "__s32")):
        return (32, "unsigned" not in words and
                "u32" not in words and "uint32_t" not in words
                and "__u32" not in words)
    return None


def _decl_conv(words, boolean):
    """Initializer-conversion descriptor for one declarator.

    Returns ``("narrow", width, signed)`` for char/short families,
    ``("int", width, signed)`` for known 32/64-bit integer types,
    or None when the initializer needs no declared-type conversion
    (booleans convert separately; enum, unknown and non-integer
    declarations stay unconverted).
    """
    narrow = _decl_narrow(words, boolean)
    if narrow is not None:
        return ("narrow", narrow[0], narrow[1])
    wide = _decl_int_wide(words, boolean)
    if wide is not None:
        return ("int", wide[0], wide[1])
    return None


def _is_member_use(text, start):
    """Whether the identifier at ``start`` is a member access."""
    return (start >= 2 and text[start - 2:start] == "->") or \
        (start >= 1 and text[start - 1] == ".")


def _local_write_positions(scan, name, has_init, init_pos):
    """Source positions where ``name`` is written past its init.

    Plain assignments (the declaration's own ``=`` excluded by
    position), compound assignments, increments/decrements and
    address-takes, each outside member access and tolerant of
    redundant parentheses around the target (``(name) = 1``).
    Positions index the same stripped body the declaration order
    does, so writes compare directly against initializer and
    copy points. A ``&`` before the name is a write only when it
    cannot be a binary operator.
    """
    positions = []
    target = r"(?:\(\s*)*\b(%s)\b((?:\s*\))*)" % re.escape(name)
    for match in re.finditer(target + r"\s*=(?!=)", scan):
        if _is_member_use(scan, match.start(1)):
            continue
        if has_init and match.start(1) == init_pos:
            continue
        positions.append(match.start(1))
    for match in re.finditer(
            target + r"\s*(\+\+|--|\+=|-=|\*=|/=|%=|&=|\|=|"
            r"\^=|<<=|>>=)", scan):
        if not _is_member_use(scan, match.start(1)):
            positions.append(match.start(1))
    for match in re.finditer(
            r"(\+\+|--)\s*(?:\(\s*)*\b%s\b" % re.escape(name),
            scan):
        start = match.end() - len(name)
        if not _is_member_use(scan, start):
            positions.append(start)
    for match in re.finditer(
            r"(?<![&])&(?![&=])\s*(?:\(\s*)*%s\b"
            % re.escape(name), scan):
        back = scan[:match.start()].rstrip()
        if back and back[-1] not in "= (,;{[!~+-*/%<>&|^?:}":
            continue
        start = match.end() - len(name)
        if not _is_member_use(scan, start):
            positions.append(start)
    return sorted(positions)


def _local_has_later_write(scan, name, has_init):
    """Whether ``name`` is written past its own initializer.

    Counts plain assignments (the declaration contributes exactly
    one when it initializes), compound assignments,
    increments/decrements and address-takes, each outside member
    access. A ``&`` before the name is a write only when it
    cannot be a binary operator (a bitwise ``flags & mask`` read
    never poisons); member writes never touch the local.
    Redundant parentheses collapse first (the round-5
    paren-tolerant scan), so ``(name) = 1`` counts as a write and
    never leaves a stale initializer behind.
    """
    scan = _strip_redundant_parens(scan, (name,))
    plain = 0
    for match in re.finditer(r"\b%s\s*=(?!=)" % re.escape(name),
                             scan):
        if not _is_member_use(scan, match.start()):
            plain += 1
    if plain > (1 if has_init else 0):
        return True
    for match in re.finditer(
            r"\b%s\s*(\+\+|--|\+=|-=|\*=|/=|%%=|&=|\|=|\^=|"
            r"<<=|>>=)|(\+\+|--)\s*%s\b"
            % (re.escape(name), re.escape(name)), scan):
        if not _is_member_use(scan, match.start()):
            return True
    for match in re.finditer(
            r"(?<![&])&(?![&=])\s*%s\b" % re.escape(name), scan):
        back = scan[:match.start()].rstrip()
        if not back or back[-1] in "= (,;{[!~+-*/%<>&|^?:}":
            return True
    return False


def _filter_local_values(inner, aliases, params, prog_param, values,
                         typed, extra_types=(), expansion=None):
    """Provably-constant depth-zero filter locals.

    Returns (resolved, scan, order): resolved maps names to ints,
    scan is the stripped body the order offsets index into, and
    order holds (pos, name, init_or_None, boolean, conv) in
    source order for flow checks. Top-level declarations with
    constant initializers (scalar variables and local enum
    members) evaluate in a single forward source-order pass
    against the file constants plus earlier locals, since C
    disallows forward references; initializers convert to the
    declared type first (boolean conversion for any
    bool-qualified declarator whatever the qualifier order,
    modulo wraparound for narrow and unsigned 32/64-bit types
    while signed out-of-range initializers stay unproven,
    value-typed ladder renders for enumerators). Nested-block
    declarations never
    contribute values -- a name declared in any nested block is
    poisoned to unknown, since uses inside that block see a
    different binding -- a self-referential initializer never
    sees its own name, a second depth-zero declarator for one
    name poisons it (a redefinition, rejected in C), and any
    later write discards the initializer. Writes propagate
    flow-sensitively through the binding table: a binding
    written between its own initializer and a later copy never
    substitutes into that copy, while copies made before the
    write keep the proven value. A bare file-bound identifier
    resolves by table value, unless a parameter shadows it (the
    scope chain runs params > locals > file, so a shadowed
    file value never substitutes and the initializer stays
    unproven); an otherwise-unbound Boolean spelling classifies
    by legacy spelling, except parameters, which stay unproven.
    Pointer and array declarators, typedef-headed declarators,
    aliases and parameters never resolve.
    """
    scan = _strip_c_attributes(_strip_c_strings(inner))
    nested = _nested_declared_names(inner, extra_types)
    blanked = _blank_nested_blocks(scan)
    order = []
    stmts = []
    depth = 0
    current = []
    start = 0
    for index, char in enumerate(blanked):
        if char in "([{":
            depth += 1
            current.append(char)
        elif char in ")]}":
            depth -= 1
            current.append(char)
        elif char == ";" and depth == 0:
            stmts.append(("".join(current), start))
            current = []
            start = index + 1
        else:
            current.append(char)
    for chunk, offset in stmts:
        stmt = chunk.strip()
        if not stmt or re.match(
                r"(if|for|while|switch|return|do|else|goto|case|"
                r"default|typedef)\b", stmt):
            continue
        base = offset + (len(chunk) - len(chunk.lstrip()))
        plain = []
        for match in re.finditer(
                r"\b(?:(?:%s)\b\s*)+(?:\(\s*|\*\s*)*(\w+)"
                % _DECL_TYPE_WORDS, stmt):
            pointed = "*" in match.group(0)
            prefix = match.group(0)[:match.start(1) - match.start()]
            words = re.findall(r"[A-Za-z_]\w*", prefix)
            boolean = any(word in ("bool", "_Bool")
                          for word in words)
            plain.append((match.start(1), match.group(1),
                          match.end(1), pointed, boolean,
                          _decl_conv(words, boolean)))
        first_spec = None
        if plain:
            first = min(plain, key=lambda decl: decl[0])
            first_spec = (first[4], first[5])
        decls = list(plain)
        for match in re.finditer(
                r"\b(?:%s)\b[\w\s,*]*\(\s*\*+\s*(\w+)\s*\)"
                % _DECL_TYPE_WORDS, stmt):
            decls.append((match.start(1), match.group(1),
                          match.end(1), True, False, None))
        for match in re.finditer(
                r",\s*(?:\(\s*|\*\s*)*(\w+)(?:\s*\))*\s*"
                r"(?=[=;,]|$)", stmt):
            head = stmt[:match.start()]
            if re.match(
                    r"\s*(?:%s)?(?:%s)\b[\w\s,*=]*$"
                    % (_ALIAS_QUALIFIERS, _ALIAS_TYPES), head):
                if first_spec is not None:
                    boolean, conv = first_spec
                else:
                    boolean = re.match(
                        r"\s*(?:static\s+|extern\s+|const\s+|"
                        r"volatile\s+|register\s+|auto\s+)*"
                        r"(?:bool|_Bool)\b", head) is not None
                    conv = None
                decls.append((match.start(1), match.group(1),
                              match.end(1),
                              "*" in match.group(0), boolean,
                              conv))
        decls.sort(key=lambda decl: (decl[0], decl[1]))
        for pos, name, endpos, pointed, boolean, conv in decls:
            if pointed:
                order.append((base + pos, name, None, False, None))
                continue
            rest = stmt[endpos:].strip()
            while rest.startswith(")"):
                rest = rest[1:].strip()
            if rest.startswith("[") or rest.startswith("("):
                order.append((base + pos, name, None, False, None))
            elif rest.startswith("=") and \
                    not rest.startswith("=="):
                init = _split_depth0(rest[1:], ",")[0].strip()
                order.append((base + pos, name, init or None,
                              boolean, conv))
            else:
                order.append((base + pos, name, None, boolean,
                              conv))
    for members, is_top, pos in _iter_local_enums(scan):
        if not is_top:
            continue
        prev = None
        for name, init in members:
            if init is None:
                order.append((pos, name, ("auto", prev), False,
                              None))
            else:
                order.append((pos, name, ("enuminit", init), False,
                              None))
            prev = name
    deduped = []
    seen_keys = set()
    for entry in order:
        key = (entry[1], entry[0])
        if key in seen_keys:
            continue
        seen_keys.add(key)
        deduped.append(entry)
    order = deduped
    counts = {}
    for entry in order:
        counts[entry[1]] = counts.get(entry[1], 0) + 1
    renders = {}
    for name, value in values.items():
        if name in typed:
            renders[name] = _c_canonical_literal(*typed[name]) or \
                "%d" % value
        else:
            renders[name] = "%d" % value
    resolved = {}
    poisoned = set(aliases)
    poisoned.update(name for name, total in counts.items()
                    if total > 1)
    seen_init = set()
    from_init = set()
    param_names = set(_filter_param_names(params, prog_param))
    init_pos = {}
    enum_names = set()
    for pos, entry_name, entry_init, _, _ in order:
        if isinstance(entry_init, tuple):
            enum_names.add(entry_name)
        if entry_init is not None and entry_name not in init_pos:
            init_pos[entry_name] = pos
    write_pos = {}
    for entry_name in counts:
        if entry_name in enum_names:
            # Enumerators are unassignable constants: their
            # declaration ``=`` is never a write.
            write_pos[entry_name] = []
            continue
        write_pos[entry_name] = _local_write_positions(
            scan, entry_name, entry_name in init_pos,
            init_pos.get(entry_name, 0))

    def stale_at(dep, point):
        """Whether ``dep``'s binding is stale at ``point``.

        A write after the dependency's own initializer but ahead
        of the copy reads a different value in C, so the
        initializer-time binding must not substitute there.
        """
        if dep not in init_pos:
            return False
        return any(init_pos[dep] < write < point
                   for write in write_pos.get(dep, ()))

    def known_at(point, skip):
        table = {}
        for key, text in renders.items():
            if key == skip or stale_at(key, point):
                continue
            if key in param_names and key not in resolved:
                # Scope chain params > locals > file: a
                # parameter shadows the file binding in C and
                # never resolves itself, so the file value must
                # not substitute. A resolved depth-zero local of
                # the same name still provides its own value.
                continue
            table[key] = text
        return table

    numbered = sorted(enumerate(order),
                      key=lambda pair: (pair[1][0], pair[0]))
    for _, (point, name, init, boolean, conv) in numbered:
        if name in resolved or name in poisoned or \
                name in nested or init is None:
            continue
        if name in seen_init:
            poisoned.add(name)
            resolved.pop(name, None)
            continue
        seen_init.add(name)
        if isinstance(init, tuple):
            if init[0] == "auto":
                prev = init[1]
                if prev is None:
                    resolved[name] = 0
                    renders[name] = "0"
                elif prev in resolved:
                    value = resolved[prev] + 1
                    resolved[name] = value
                    renders[name] = _ladder_render(value)
                continue
            known = known_at(point, name)
            result = _eval_text_constexpr(
                init[1], known, expansion)
            if result is None:
                continue
            from_init.add(name)
            resolved[name] = result[0]
            renders[name] = _ladder_render(result[0])
            continue
        if re.fullmatch(r"[A-Za-z_]\w*", init) is not None and \
                (init in renders or init in counts or
                 init in nested):
            # A bare identifier bound anywhere resolves through the
            # binding table only: a proven binding substitutes below
            # via ``known`` while a bound-but-unproven spelling
            # stays unproven -- never a spelling-guessed constant.
            # A binding written between its own initializer and
            # this copy is stale here and never substitutes.
            if init == name or init not in renders or \
                    stale_at(init, point):
                continue
        elif init in ("true", "TRUE") and \
                init not in param_names:
            resolved[name] = 1
            renders[name] = "1"
            from_init.add(name)
            continue
        elif init in ("false", "FALSE") and \
                init not in param_names:
            resolved[name] = 0
            renders[name] = "0"
            from_init.add(name)
            continue
        known = known_at(point, name)
        result = _eval_text_constexpr(init, known, expansion)
        if result is None:
            continue
        from_init.add(name)
        if boolean:
            resolved[name] = 1 if result[0] != 0 else 0
            renders[name] = "1" if result[0] != 0 else "0"
            continue
        if conv is not None:
            tag, cwidth, csigned = conv
            if tag == "narrow":
                rep = result[0] & ((1 << cwidth) - 1)
                if csigned and rep >= (1 << (cwidth - 1)):
                    rep -= (1 << cwidth)
                resolved[name] = rep
                renders[name] = _c_canonical_literal(rep, 32, True) or \
                    "%d" % rep
                continue
            if csigned:
                if result[0] < -(1 << (cwidth - 1)) or \
                        result[0] >= (1 << (cwidth - 1)):
                    continue
                resolved[name] = result[0]
                renders[name] = _c_canonical_literal(
                    result[0], cwidth, True) or "%d" % result[0]
                continue
            rep = result[0] & ((1 << cwidth) - 1)
            resolved[name] = rep
            renders[name] = _c_canonical_literal(
                rep, cwidth, False) or "%d" % rep
            continue
        resolved[name] = result[0]
        renders[name] = _c_canonical_literal(*result) or \
            "%d" % result[0]
    for name in list(resolved):
        if _local_has_later_write(scan, name, name in from_init):
            del resolved[name]
    by_name = {}
    for _, entry_name, _, boolean, conv in order:
        by_name.setdefault(entry_name, []).append(
            (boolean, conv))
    value_typed = set(
        name for name, decls in by_name.items()
        if all(boolean or conv is not None
               for boolean, conv in decls))
    return resolved, scan, order, value_typed


def _ladder_render(value):
    """Literal spelling for an auto-numbered enum value.

    Follows gcc's enum type ladder (int, unsigned int, long,
    unsigned long) by value; negative values (counting up from a
    negative explicit member) render as the 32-bit signed form.
    """
    if value < 0:
        return _c_canonical_literal(value, 32, True) or \
            "%d" % value
    if value <= 2 ** 31 - 1:
        return "%d" % value
    if value <= 2 ** 32 - 1:
        return "%dU" % value
    if value <= 2 ** 63 - 1:
        return "%dL" % value
    return "%dUL" % value

_ALIAS_TYPES = (
    r"bool|_Bool|char|short|int|long|signed|unsigned|"
    r"u8|u16|u32|u64|s8|s16|s32|s64|size_t|__auto_type|"
    r"struct\s+\w+|union\s+\w+|enum\s+\w+|"
    r"(?:__)?typeof\s*\([^;{}]*\)"
)

_ALIAS_QUALIFIERS = r"(?:const|static|register|volatile|auto|extern|_Atomic)\s+"


def _strip_c_strings(text):
    """Blank out C string and character literals, keeping newlines."""
    out = []
    pos = 0
    end = len(text)
    while pos < end:
        char = text[pos]
        if char in ("\"", "'"):
            start = pos
            pos += 1
            while pos < end and text[pos] != char:
                if text[pos] == "\\":
                    pos += 1
                pos += 1
            pos += 1
            chunk = text[start:pos]
            out.append("".join(
                "\n" if item == "\n" else " " for item in chunk))
        else:
            out.append(char)
            pos += 1
    return "".join(out)


def _strip_line_splices(text):
    """Remove C line splices (backslash-newline) from scan text.

    Translation phase 2 deletes each backslash immediately
    followed by a newline before any tokenizing, so a call or
    assignment spelled across a splice (``f[0] \\`` + newline +
    ``()``) is one token stream in C. Scans below run on
    spliced text so the same spelling invalidates there too.
    """
    return re.sub(r"\\(?:\r\n|\r|\n)", "", text)


def _blank_alias_decls(scan, aliases, id_param):
    """Blank registered alias initializers inside ``bool`` statements.

    Only the ``<NAME> = btf_id_set8?_contains(&<SET>, <id>)`` prefix
    of a declarator inside a ``bool`` declaration statement blanks,
    so the declaration itself never trips the reassignment check
    while a genuine later ``<NAME> = ...`` statement still does.
    """
    if not aliases or id_param is None:
        return scan
    chars = list(scan)
    for start, _, end in _bool_decl_spans(scan):
        stmt = scan[start:end]
        for name in sorted(aliases):
            for match in re.finditer(
                    r"(?:\(\s*)*\b%s\b(?:\s*\))*\s*=\s*"
                    r"btf_id_set8?_contains\s*\(\s*&\w+\s*,"
                    r"\s*%s\b" % (re.escape(name), re.escape(id_param)),
                    stmt):
                for index in range(start + match.start(),
                                   start + match.end()):
                    chars[index] = " "
    return "".join(chars)


def _check_filter_assignments(inner, aliases, params, prog_param,
                              fn_name, version, extra_types=()):
    """Reject alias and parameter mutations outside the grammar.

    Membership aliases are immutable single-assignment bindings, so
    any later assignment, compound assignment, increment,
    decrement, address-take or redeclaration (shadowing) of an
    alias, and any assignment to or redeclaration (shadowing) of a
    filter parameter, raises FilterNotUnderstood. Shadowing covers
    every declarator form (plain, pointer, array, parenthesized
    and function-pointer declarators, comma declarators, typedefs,
    local enums, struct-suffix declarators, and declarators headed
    by a typedef alias). The scan covers the whole body text
    (including nested blocks) with string literals blanked out, so
    a mutation hidden in a skipped straight-line statement or a
    nested scope cannot silently change a membership verdict.
    """
    id_param = _filter_id_param(params, prog_param)
    param_names = _filter_param_names(params, prog_param)
    blanked = _blank_alias_decls(
        _strip_c_attributes(_strip_c_strings(inner)), aliases, id_param)
    scan = _strip_redundant_parens(
        blanked, set(aliases) | set(param_names))
    declared = _discover_declared_names(blanked, extra_types)
    for name in sorted(aliases):
        if name in param_names:
            raise FilterNotUnderstood(
                "kfunc filter %s@%s declares membership alias %s "
                "over a parameter; shadowing is outside the grammar"
                % (fn_name, version, name))
        if name in declared:
            raise FilterNotUnderstood(
                "kfunc filter %s@%s redeclares membership alias %s; "
                "shadowing is outside the grammar"
                % (fn_name, version, name))
    for name in param_names:
        if name in declared:
            raise FilterNotUnderstood(
                "kfunc filter %s@%s redeclares parameter %s; "
                "shadowing is outside the grammar"
                % (fn_name, version, name))
    for name in sorted(aliases):
        if re.search(r"\b%s\s*=(?!=)" % re.escape(name), scan):
            raise FilterNotUnderstood(
                "kfunc filter %s@%s reassigns membership alias %s; "
                "aliases are immutable"
                % (fn_name, version, name))
        if re.search(
                r"\b%s\s*(\+\+|--|\+=|-=|\*=|/=|%%=|&=|\|=|\^=|"
                r"<<=|>>=)|(\+\+|--)\s*%s\b"
                % (re.escape(name), re.escape(name)), scan):
            raise FilterNotUnderstood(
                "kfunc filter %s@%s mutates membership alias %s; "
                "aliases are immutable"
                % (fn_name, version, name))
        if re.search(r"(?<![&])&(?![&=])\s*%s\b" % re.escape(name),
                     scan):
            raise FilterNotUnderstood(
                "kfunc filter %s@%s takes the address of membership "
                "alias %s; potential mutation is outside the grammar"
                % (fn_name, version, name))
    for name in _filter_param_names(params, prog_param):
        if re.search(r"\b%s\s*=(?!=)" % re.escape(name), scan):
            raise FilterNotUnderstood(
                "kfunc filter %s@%s reassigns parameter %s; "
                "parameter mutation is outside the grammar"
                % (fn_name, version, name))
        if re.search(
                r"\b%s\s*(\+\+|--|\+=|-=|\*=|/=|%%=|&=|\|=|\^=|"
                r"<<=|>>=)|(\+\+|--)\s*%s\b"
                % (re.escape(name), re.escape(name)), scan):
            raise FilterNotUnderstood(
                "kfunc filter %s@%s mutates parameter %s; "
                "parameter mutation is outside the grammar"
                % (fn_name, version, name))


def _file_scope_text(text):
    """Depth-zero text of one file (bodies and directives blanked).

    Provably-excluded conditional regions blank first (an
    inactive binding was never compiled), then function and
    aggregate bodies (only file-scope bindings matter here), as
    do preprocessor logical lines, so a declaration spelled
    inside a macro body never counts as a file binding.
    """
    stripped = re.sub(
        r"^[ \t]*#(?:\\\n|[^\n])*",
        lambda match: "\n" * match.group(0).count("\n"),
        _strip_c_strings(_blank_inactive_pp_regions(text)),
        flags=re.M)
    out = []
    depth = 0
    for char in stripped:
        if char == "{":
            depth += 1
            out.append(" ")
        elif char == "}":
            if depth > 0:
                depth -= 1
            out.append(" ")
        elif depth == 0:
            out.append(char)
        else:
            out.append("\n" if char == "\n" else " ")
    return "".join(out)


def _filter_errno_blocked(texts):
    """Names that defeat the errno-table fallback for return arms.

    Covers ``#undef``-killed names, file-scope declared names
    (mutable objects, prototypes, aliases) and const objects
    whose declared type is unknowable (typedef-named): none of
    them may silently read the tabled kernel errno value.
    """
    blocked = set()
    for relpath in sorted(texts):
        text = texts[relpath]
        blocked.update(_file_undefs(text))
        scoped = _file_scope_text(text)
        blocked.update(_discover_declared_names(
            scoped, _typedef_defined_names(scoped)))
        for name, _, declared in _parse_const_objects(text):
            if declared is None:
                blocked.add(name)
    return blocked


def _name_used_before(scan, name, point):
    """Whether ``name`` is used in ``scan`` ahead of ``point``.

    Member accesses never count as uses of the local.
    """
    for match in re.finditer(r"\b%s\b" % re.escape(name),
                             scan[:point]):
        if not _is_member_use(scan, match.start()):
            return True
    return False


def _reject_flow_violations(scan, order, alias_offsets, aliases,
                            stmts, fn_name, version):
    """Reject uses ahead of their declaration point.

    A provable local or membership alias used before its
    declaration sees the outer meaning in C, never the later
    binding, so the shape is outside the proven set. (Later
    writes already discard the initializer inside
    ``_filter_local_values``; return arms consult whole-body
    bindings and need no position check.)
    """
    conds = []
    for kind, cond, extra in stmts:
        if cond is not None:
            conds.append(cond)
        if kind == "if" and isinstance(extra, tuple) and \
                extra[0] in ("ternary", "ternary_const"):
            conds.append(extra[1])
    if not conds:
        return
    first_decl = {}
    for pos, name, _, _, _ in order:
        if name not in first_decl:
            first_decl[name] = pos
    for name, point in sorted(first_decl.items()):
        if any(re.search(r"\b%s\b" % re.escape(name), cond)
               for cond in conds) and \
                _name_used_before(scan, name, point):
            raise FilterNotUnderstood(
                "kfunc filter %s@%s uses %s before its "
                "declaration; uses ahead of the binding are "
                "outside the grammar"
                % (fn_name, version, name))
    for name, point in sorted(alias_offsets.items()):
        if name in aliases and \
                any(re.search(r"\b%s\b" % re.escape(name), cond)
                    for cond in conds) and \
                _name_used_before(scan, name, point):
            raise FilterNotUnderstood(
                "kfunc filter %s@%s uses membership alias %s "
                "before its declaration; uses ahead of the "
                "binding are outside the grammar"
                % (fn_name, version, name))


def _split_filter_body(body, params, prog_param, fn_name, version,
                       values, typed, ret_bits, extra_types,
                       expansion, errno_blocked, mutable=()):
    """Split a filter body into simulation statements.

    Returns (aliases, stmts, blocked, local_values, multi, widths,
    order, value_typed, straight) where aliases maps local idents
    to kfunc set names and stmts holds ("if", cond, kind) with kind
    allow/deny, ("allow"/"deny", None, None), ("ternary", cond,
    allow_first) or ("ternary_const", cond, allows) for terminal
    returns; blocked holds every
    locally-bound name, local_values the provably-constant
    depth-zero ones, multi the names with two or more
    declarators, widths the (width, signed) pair of every
    single-declared scalar integer local (booleans as unsigned
    width 1) plus the u32 id parameter, order the declaration
    records for flow checks, value_typed the names whose
    every declaration is a proven value type, and straight the
    skipped straight-line statement texts for the invalidation
    scans. Bare compound blocks are
    parsed recursively, so a nested denying block denies instead
    of being silently skipped. Alias and parameter mutations are
    rejected up front, as are uses ahead of their declaration
    point. Return arms classify only immutable constants:
    mutable file bindings never decide an arm (locals and
    parameters never do either). Anything outside the grammar
    raises FilterNotUnderstood.
    """
    inner = body.strip()
    if inner.startswith("{") and inner.endswith("}"):
        inner = inner[1:-1]
    aliases = {}
    alias_offsets = {}
    id_param = _filter_id_param(params, prog_param)
    _reject_compound_alias_initializers(inner, fn_name, version)
    for name, init, start in _iter_bool_declarators(inner):
        if name is None or init is None:
            continue
        found = re.fullmatch(
            r"btf_id_set8?_contains\s*\(\s*&(\w+)\s*,\s*(\w+)\s*\)",
            init)
        if not found:
            continue
        if found.group(2) != id_param:
            # A membership result over any other value is not an
            # alias; its uses degrade to opaque atoms.
            continue
        if name in aliases:
            raise FilterNotUnderstood(
                "kfunc filter %s@%s redeclares membership alias "
                "%s; shadowing is outside the grammar"
                % (fn_name, version, name))
        aliases[name] = found.group(1)
        alias_offsets[name] = start
    _check_filter_assignments(
        inner, aliases, params, prog_param, fn_name, version,
        extra_types)
    blocked = _filter_local_names(
        inner, aliases, params, prog_param, extra_types)
    local_values, scan, order, value_typed = \
        _filter_local_values(
            inner, aliases, params, prog_param, values, typed,
            extra_types, expansion)
    multi = _multi_declared_names(inner, extra_types)
    widths = {}
    for _, name, _, boolean, conv in order:
        if name in multi or name in widths:
            continue
        if boolean:
            widths[name] = (1, False)
        elif conv is not None:
            widths[name] = (conv[1], conv[2])
    if id_param is not None and id_param not in widths and \
            id_param not in multi:
        widths[id_param] = (32, False)
    stmts = []
    steady_values = {name: value for name, value in values.items()
                     if name not in mutable}
    straight = []
    _split_filter_stmts(inner, fn_name, version, stmts,
                        steady_values, ret_bits, blocked,
                        errno_blocked, straight)
    _reject_flow_violations(
        scan, order, alias_offsets, aliases, stmts, fn_name,
        version)
    return aliases, stmts, blocked, local_values, multi, widths, \
        order, value_typed, straight


def _split_filter_stmts(inner, fn_name, version, stmts, values,
                        ret_bits, blocked, errno_blocked, straight):
    """Append one statement list's simulation statements to ``stmts``.

    Straight-line declarations, assignments and calls carry no verdict
    and are skipped (their texts append to ``straight`` for the
    skipped-code invalidation scans); ``if``/``return`` shapes become
    simulation statements and bare ``{ ... }`` blocks recurse so
    nested returns keep their control-flow meaning. Anything else
    fails closed.
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
                raise FilterNotUnderstood(
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
                    raise FilterNotUnderstood(
                        "cannot parse filter %s@%s: complex branch"
                        % (fn_name, version))
                pre = block[1:block.find("return")]
                if pre.strip():
                    raise FilterNotUnderstood(
                        "kfunc filter %s@%s has a guarded branch "
                        "with statements before its return; "
                        "guarded branches hold exactly one return "
                        "and the shape is outside the grammar"
                        % (fn_name, version))
                then = block[block.find("return"):block.rfind("}")].strip()
                pos = brace + len(block)
            else:
                semi = inner.find(";", cond_end + 1)
                if semi == -1:
                    raise FilterNotUnderstood(
                        "cannot parse filter %s@%s: truncated branch"
                        % (fn_name, version))
                then = inner[cond_end + 1:semi].strip()
                pos = semi + 1
            if re.match(r"\s*else\b", inner[pos:]):
                raise FilterNotUnderstood(
                    "cannot parse filter %s@%s: else branch"
                    % (fn_name, version))
            kind = _classify_return(
                then, fn_name, version, values, ret_bits, blocked,
                errno_blocked)
            if kind is None:
                # A guarded non-return statement (for example a
                # nested ``if``) is outside the grammar: skipping it
                # would silently discard a branch verdict.
                raise FilterNotUnderstood(
                    "kfunc filter %s@%s has a non-return branch %r; "
                    "only direct returns are understood"
                    % (fn_name, version, then[:60]))
            stmts.append(("if", cond, kind))
            continue
        if re.match(r"return\b", inner[pos:]):
            semi = inner.find(";", pos)
            if semi == -1:
                raise FilterNotUnderstood(
                    "cannot parse filter %s@%s: truncated return"
                    % (fn_name, version))
            kind = _classify_return(
                inner[pos:semi].strip(), fn_name, version, values,
                ret_bits, blocked, errno_blocked)
            if kind is None:
                raise FilterNotUnderstood(
                    "cannot parse filter %s@%s: empty return"
                    % (fn_name, version))
            stmts.append((kind[0], kind[1], kind[2]))
            pos = semi + 1
            continue
        if re.match(r"(for|while|switch|goto|do|else)\b", inner[pos:]):
            raise FilterNotUnderstood(
                "cannot parse filter %s@%s: unsupported statement"
                % (fn_name, version))
        if inner[pos] == "{":
            block = c_brace_body(inner, pos)
            _split_filter_stmts(
                block[1:-1], fn_name, version, stmts, values,
                ret_bits, blocked, errno_blocked, straight)
            pos += len(block)
            continue
        semi = inner.find(";", pos)
        if semi == -1:
            raise FilterNotUnderstood(
                "cannot parse filter %s@%s: trailing text"
                % (fn_name, version))
        if re.search(r"\breturn\b", inner[pos:semi]):
            raise FilterNotUnderstood(
                "cannot parse filter %s@%s: hidden return"
                % (fn_name, version))
        straight.append(inner[pos:semi + 1])
        pos = semi + 1


# Standard kernel errno values, verified against the pinned stable
# tree (v7.2.9 include/uapi/asm-generic/errno-base.h sha256
# 2c148e92b8318deeb767fabd60822113e575ee664ff09a1873aed8f7a495793c
# and errno.h sha256
# 66a5ad60566fdd62e41701bcfc42bfeca5e5696ad1d47d78981575e0c51622be;
# aliases EWOULDBLOCK/EDEADLOCK/EFSBADCRC/EFSCORRUPTED resolved).
# A negated errno macro classifies by this tabled value, never by
# name spelling; anything absent here is unsupported and rejected.
_ERRNO_VALUES = {
    "EPERM": 1, "ENOENT": 2, "ESRCH": 3, "EINTR": 4, "EIO": 5,
    "ENXIO": 6, "E2BIG": 7, "ENOEXEC": 8, "EBADF": 9, "ECHILD": 10,
    "EAGAIN": 11, "ENOMEM": 12, "EACCES": 13, "EFAULT": 14,
    "ENOTBLK": 15, "EBUSY": 16, "EEXIST": 17, "EXDEV": 18,
    "ENODEV": 19, "ENOTDIR": 20, "EISDIR": 21, "EINVAL": 22,
    "ENFILE": 23, "EMFILE": 24, "ENOTTY": 25, "ETXTBSY": 26,
    "EFBIG": 27, "ENOSPC": 28, "ESPIPE": 29, "EROFS": 30,
    "EMLINK": 31, "EPIPE": 32, "EDOM": 33, "ERANGE": 34,
    "EDEADLK": 35, "ENAMETOOLONG": 36, "ENOLCK": 37, "ENOSYS": 38,
    "ENOTEMPTY": 39, "ELOOP": 40, "ENOMSG": 42, "EIDRM": 43,
    "ECHRNG": 44, "EL2NSYNC": 45, "EL3HLT": 46, "EL3RST": 47,
    "ELNRNG": 48, "EUNATCH": 49, "ENOCSI": 50, "EL2HLT": 51,
    "EBADE": 52, "EBADR": 53, "EXFULL": 54, "ENOANO": 55,
    "EBADRQC": 56, "EBADSLT": 57, "EBFONT": 59, "ENOSTR": 60,
    "ENODATA": 61, "ETIME": 62, "ENOSR": 63, "ENONET": 64,
    "ENOPKG": 65, "EREMOTE": 66, "ENOLINK": 67, "EADV": 68,
    "ESRMNT": 69, "ECOMM": 70, "EPROTO": 71, "EMULTIHOP": 72,
    "EDOTDOT": 73, "EBADMSG": 74, "EOVERFLOW": 75, "ENOTUNIQ": 76,
    "EBADFD": 77, "EREMCHG": 78, "ELIBACC": 79, "ELIBBAD": 80,
    "ELIBSCN": 81, "ELIBMAX": 82, "ELIBEXEC": 83, "EILSEQ": 84,
    "ERESTART": 85, "ESTRPIPE": 86, "EUSERS": 87, "ENOTSOCK": 88,
    "EDESTADDRREQ": 89, "EMSGSIZE": 90, "EPROTOTYPE": 91,
    "ENOPROTOOPT": 92, "EPROTONOSUPPORT": 93,
    "ESOCKTNOSUPPORT": 94, "EOPNOTSUPP": 95, "EPFNOSUPPORT": 96,
    "EAFNOSUPPORT": 97, "EADDRINUSE": 98, "EADDRNOTAVAIL": 99,
    "ENETDOWN": 100, "ENETUNREACH": 101, "ENETRESET": 102,
    "ECONNABORTED": 103, "ECONNRESET": 104, "ENOBUFS": 105,
    "EISCONN": 106, "ENOTCONN": 107, "ESHUTDOWN": 108,
    "ETOOMANYREFS": 109, "ETIMEDOUT": 110, "ECONNREFUSED": 111,
    "EHOSTDOWN": 112, "EHOSTUNREACH": 113, "EALREADY": 114,
    "EINPROGRESS": 115, "ESTALE": 116, "EUCLEAN": 117,
    "ENOTNAM": 118, "ENAVAIL": 119, "EISNAM": 120, "EREMOTEIO": 121,
    "EDQUOT": 122, "ENOMEDIUM": 123, "EMEDIUMTYPE": 124,
    "ECANCELED": 125, "ENOKEY": 126, "EKEYEXPIRED": 127,
    "EKEYREVOKED": 128, "EKEYREJECTED": 129, "EOWNERDEAD": 130,
    "ENOTRECOVERABLE": 131, "ERFKILL": 132, "EHWPOISON": 133,
    "EFTYPE": 134, "EWOULDBLOCK": 11, "EDEADLOCK": 35,
    "EFSBADCRC": 74, "EFSCORRUPTED": 117,
}


def _convert_const_return(value, ret_bits):
    """Convert a constant return value to the filter's return type.

    Only zero-ness decides allow/deny, and out-of-range integers
    convert by wraparound modulo 2**width on the reviewed ABI, so
    4294967296ULL returns 0 from an ``int`` filter.
    """
    if ret_bits <= 1:
        return 0 if value == 0 else 1
    return value & ((1 << ret_bits) - 1)


def _const_return_value(arm, values, ret_bits, blocked,
                        errno_blocked):
    """Classify a return arm by its converted value.

    Returns True when the arm converts to zero under the filter's
    return type (allows), False when it converts to nonzero
    (denies), and None when the arm is not a classified constant.
    Identifiers resolve against pinned and immutable file-local
    constant values (mutable bindings are stripped before
    classification), never by textual shape -- except that a
    negated
    kernel errno macro classifies by its tabled value (the pinned
    SCX filter relies on this for its -EACCES arms), unless the
    name is errno-blocked (``#undef``-killed or carrying a
    file-scope binding the table must not silently override). A
    name bound as a filter local shadows every constant and never
    classifies, whatever its spelling: local bindings are
    consulted before Boolean spellings, constant values and the
    errno table alike. Boolean spellings resolve through the
    file value table when bound there; only lowercase
    ``true``/``false`` classify by keyword, while an unbound
    uppercase spelling never classifies.
    """
    text = arm.strip()
    while len(text) >= 2 and text.startswith("(") and \
            text.endswith(")"):
        depth = 0
        balanced = True
        for char in text[1:-1]:
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth < 0:
                    balanced = False
                    break
        if not balanced or depth != 0:
            break
        text = text[1:-1].strip()
        if not text:
            return None
    core = text
    if core.startswith("-") or core.startswith("+"):
        core = core[1:].strip()
    if re.match(r"^[A-Za-z_]\w*$", core) and core in blocked:
        return None
    if text in ("false", "FALSE"):
        if text in values:
            return _convert_const_return(
                values[text], ret_bits) == 0
        return True if text == "false" else None
    if text in ("true", "TRUE"):
        if text in values:
            return _convert_const_return(
                values[text], ret_bits) == 0
        return False if text == "true" else None
    negated = False
    if text.startswith("-") or text.startswith("+"):
        negated = text.startswith("-")
        text = text[1:].strip()
    match = re.match(
        r"^(0[xX][0-9a-fA-F]+|0[bB][01]+|\d+)[uUlL]*$", text)
    if match:
        core = re.sub(r"[uUlL]+$", "", match.group(1))
        if re.fullmatch(r"0[0-7]+", core):
            value = int(core, 8)
        else:
            try:
                value = int(core, 0)
            except ValueError:
                return None
        if negated:
            value = -value
        return _convert_const_return(value, ret_bits) == 0
    if re.match(r"^[A-Za-z_]\w*$", text):
        if text in values:
            value = values[text]
            if negated:
                value = -value
            return _convert_const_return(value, ret_bits) == 0
        if negated and text in _ERRNO_VALUES and \
                text not in errno_blocked:
            value = -_ERRNO_VALUES[text]
            return _convert_const_return(value, ret_bits) == 0
        return None
    return None


def _classify_return(text, fn_name, version, values, ret_bits, blocked,
                     errno_blocked):
    """Classify a return statement for simulation.

    Returns ("allow"/"deny", None, None), ("ternary", cond, allow_first),
    ("ternary_const", cond, allows) for identical-arm ternaries (whose
    constant verdict still audits the condition downstream) or None
    when the text is not a return at all.
    """
    match = re.match(r"\s*return\b(.*)$", text, re.S)
    if not match:
        return None
    expr = match.group(1).strip()
    if expr.endswith(";"):
        expr = expr[:-1].strip()
    if "?" not in expr:
        allows = _const_return_value(
            expr, values, ret_bits, blocked, errno_blocked)
        if allows is None:
            raise FilterNotUnderstood(
                "cannot parse filter %s@%s return %r"
                % (fn_name, version, expr[:40]))
        if allows:
            return ("allow", None, None)
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
            raise FilterNotUnderstood(
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
            raise FilterNotUnderstood(
                "cannot parse filter %s@%s return %r"
                % (fn_name, version, expr[:40]))
        first = arms[:colon].strip()
        second = arms[colon + 1:].strip()
        first_allows = _const_return_value(
            first, values, ret_bits, blocked, errno_blocked)
        second_allows = _const_return_value(
            second, values, ret_bits, blocked, errno_blocked)
        if first_allows is None or second_allows is None:
            bad = first if first_allows is None else second
            raise FilterNotUnderstood(
                "kfunc filter %s@%s returns a ternary with a "
                "non-constant arm %r; only constant arms are "
                "understood"
                % (fn_name, version, bad[:40]))
        if first_allows and second_allows:
            return ("ternary_const", cond, True)
        if not first_allows and not second_allows:
            return ("ternary_const", cond, False)
        return ("ternary", cond, first_allows)
    raise FilterNotUnderstood(
        "cannot parse filter %s@%s return %r"
        % (fn_name, version, expr[:40]))


def _audit_dropped_condition(sub, opaque, fn_name, version,
                             typed_map, pipe_map, multi, widths,
                             cast_locals, expansion=None):
    """Validate a short-circuited branch that folding discards.

    A constant absorbing its ``&&``/``||`` siblings drops them
    exactly as C short-circuits them, which is only sound for
    pure, proven shapes: dropped bit tests run the same
    validation they would run when kept (so an erased
    assignment, call or unproven operand rejects), dropped calls
    reject (their purity is unproven), and any other dropped
    opaque operand -- a foreign read or numeric comparison C
    would skip -- rejects exactly as it would when kept (an
    unrecognized condition grants or denies nothing silently).
    Proven leaves (membership, type and attach/struct_ops
    comparisons, st_ops-null tests) are plain reads C skips
    without effect and drop silently. Nested placeholders audit
    recursively.
    """
    seen = set()
    stack = [sub]
    while stack:
        node = stack.pop()
        kind = node[0]
        if kind in ("and", "or"):
            stack.extend(node[1])
        elif kind == "not":
            stack.append(node[1])
        elif kind == "opaque" and node[1] not in seen:
            seen.add(node[1])
            name = node[1]
            text = opaque.get(name, "")
            if name.startswith("__bitop_"):
                _bit_test_facts(
                    name, text, True, opaque, typed_map, pipe_map,
                    multi, widths, fn_name, version, cast_locals,
                    expansion)
            elif re.search(r"\b[A-Za-z_]\w*\s*\(", text):
                raise FilterNotUnderstood(
                    "kfunc filter %s@%s short-circuits past a call "
                    "in %r; short-circuited calls are outside the "
                    "grammar"
                    % (fn_name, version, text[:60]))
            else:
                raise FilterNotUnderstood(
                    "kfunc filter %s@%s short-circuits past an "
                    "unrecognized condition %r; short-circuited "
                    "unrecognized conditions are outside the "
                    "grammar"
                    % (fn_name, version, text[:60]))
            for nested in re.findall(
                    r"__bitop_\d+\b|__opaque_\d+\b", text):
                if nested in opaque and nested not in seen:
                    stack.append(("opaque", nested))


def _fold_condition(node, prog_type, member, membersets, _audit=None):
    """Fold type/membership leaves for one caller and member.

    Returns the simplified node: ("const", bool), possibly with
    attach/stops/opaque leaves remaining. Short-circuited
    branches audit through ``_audit`` (when given) before they
    are discarded, so a dropped side effect or unproven operand
    rejects instead of vanishing.
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
        sub = _fold_condition(
            node[1], prog_type, member, membersets, _audit)
        if sub[0] == "const":
            return ("const", not sub[1])
        if sub[0] == "not":
            return sub[1]
        return ("not", sub)
    if kind == "and":
        subs = []
        for index, sub in enumerate(node[1]):
            folded = _fold_condition(
                sub, prog_type, member, membersets, _audit)
            if folded == ("const", False):
                if _audit is not None:
                    for dropped in node[1][:index] + \
                            node[1][index + 1:]:
                        _audit(dropped)
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
        for index, sub in enumerate(node[1]):
            folded = _fold_condition(
                sub, prog_type, member, membersets, _audit)
            if folded == ("const", True):
                if _audit is not None:
                    for dropped in node[1][:index] + \
                            node[1][index + 1:]:
                        _audit(dropped)
                return ("const", True)
            if folded != ("const", False):
                subs.append(folded)
        if not subs:
            return ("const", False)
        if len(subs) == 1:
            return subs[0]
        return ("or", subs)
    raise FilterNotUnderstood("cannot evaluate filter condition")


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


# A context conjunction is a 6-tuple of frozensets:
# (attach_req, stops_req, attach_excl, stops_excl, obits, notes).
# Empty requirement sets mean unconstrained; exclusion sets hold
# values the context must not take. The obits set holds (key, holds)
# bit-test constraints from opaque allow requirements: ("flag",
# OPERAND, CONST) keys track one operand's flag polarity while
# ("text", text) keys track one bit-test spelling's polarity, so
# one operand's flag required and excluded at once contradicts
# while independent operands stay satisfiable. Notes always mirror
# the sets: every requirement and exclusion leaf carries its own
# rendering, so notes unions stay exact across conjunction and
# factoring.
_CONJ_UNCONSTRAINED = (frozenset(), frozenset(), frozenset(),
                       frozenset(), frozenset(), frozenset())


def _conj_merge(base, extra):
    """Conjoin two context conjunctions.

    Returns the merged conjunction, or None when the conjunction is
    contradictory and can never fire: an empty value intersection,
    exclusions covering every required value, one bit-test key
    required and excluded at once, or one operand's held mask
    contained in its excluded mask. A requirement set that merely
    overlaps the exclusions stays satisfiable (it means the
    remaining values) and is kept with both notes.
    """
    base_areq, base_sreq, base_aexc, base_sexc, base_obits, \
        base_notes = base
    extra_areq, extra_sreq, extra_aexc, extra_sexc, extra_obits, \
        extra_notes = extra
    if base_areq and extra_areq:
        areq = base_areq & extra_areq
        if not areq:
            return None
    else:
        areq = base_areq or extra_areq
    if base_sreq and extra_sreq:
        sreq = base_sreq & extra_sreq
        if not sreq:
            return None
    else:
        sreq = base_sreq or extra_sreq
    aexc = base_aexc | extra_aexc
    sexc = base_sexc | extra_sexc
    if areq and not (areq - aexc):
        return None
    if sreq and not (sreq - sexc):
        return None
    obits = base_obits | extra_obits
    polarity = {}
    for key, holds in obits:
        if key in polarity and polarity[key] != holds:
            return None
        polarity[key] = holds
    held_masks = {}
    excl_masks = {}
    for key, holds in obits:
        if not (isinstance(key, tuple) and len(key) == 3 and
                key[0] == "flag"):
            continue
        _, other, const = key
        if not (isinstance(const, tuple) and len(const) == 2 and
                const[0] == "K"):
            continue
        slot = held_masks if holds else excl_masks
        slot.setdefault(other, []).append(const[1])
    for other, held in held_masks.items():
        for mask in excl_masks.get(other, ()):
            for have in held:
                if have != 0 and have & mask == have:
                    return None
    return (frozenset(areq), frozenset(sreq), frozenset(aexc),
            frozenset(sexc), frozenset(obits),
            frozenset(base_notes | extra_notes))


def _dnf_cross(sublists):
    """Cross conjunction lists, dropping contradictory combinations."""
    acc = [_CONJ_UNCONSTRAINED]
    for sub in sublists:
        merged = []
        for base in acc:
            for extra in sub:
                out = _conj_merge(base, extra)
                if out is not None:
                    merged.append(out)
        acc = merged
        if not acc:
            break
    return acc


def _try_factor_or_alts(flat):
    """Merge exactly-factorable disjunctions into one conjunction.

    When every alternative agrees in all dimensions but one positive
    value set, the disjunction is exactly that set ("attach is A or
    B" is "attach is one of A, B") and merges with a "one of" note;
    anything else -- cross-dimension alternatives, exclusions
    differing across branches -- stays split. Returns the factored
    single-conjunction list, or the input unchanged.
    """
    if not flat:
        return flat
    first = flat[0]
    if all(alt[1] == first[1] and alt[2] == first[2]
           and alt[3] == first[3] and alt[4] == first[4]
           for alt in flat) and \
            all(alt[0] for alt in flat):
        union = set()
        for alt in flat:
            union |= set(alt[0])
        notes = set()
        for alt in flat:
            notes |= set(alt[5])
        notes = _union_notes(
            notes, union, "requires expected_attach_type ",
            "attach requirements vary by binding context")
        return [(frozenset(union), first[1], first[2], first[3],
                 first[4], frozenset(notes))]
    if all(alt[0] == first[0] and alt[2] == first[2]
           and alt[3] == first[3] and alt[4] == first[4]
           for alt in flat) and \
            all(alt[1] for alt in flat):
        union = set()
        for alt in flat:
            union |= set(alt[1])
        notes = set()
        for alt in flat:
            notes |= set(alt[5])
        notes = _union_notes(
            notes, union, "requires struct_ops attachment to ",
            "struct_ops requirements vary by binding context")
        return [(first[0], frozenset(union), first[2], first[3],
                 first[4], frozenset(notes))]
    return flat


_SYM_TOKEN_KIND = re.compile(
    r"(?P<num>0[xX][0-9a-fA-F]+[uUlL]*|0[bB][01]+[uUlL]*|"
    r"\d+[uUlL]*)|(?P<ident>[A-Za-z_]\w*)|"
    r"(?P<mem>->)|"
    r"(?P<op><<|>>|<=|>=|==|!=|&&|\|\||[+\-*/%<>&^|~!])|"
    r"(?P<paren>[()])")


def _sym_tokenize(text):
    """Tokenize a bit-test core, or None when it holds other C.

    Returns [(kind, word, start, end)] with kind
    num/ident/mem/op/paren; ``->`` lexes as one member-access
    token (C maximal munch), so only adjacent ``->`` (never
    ``-`` then ``>``) chains. Adjacent ``--``/``++`` spell
    decrement/increment (never double negation) and decline, as
    do calls, strings and every other shape outside integer
    expressions.
    """
    tokens = []
    pos = 0
    while pos < len(text):
        if text[pos].isspace():
            pos += 1
            continue
        match = _SYM_TOKEN_KIND.match(text, pos)
        if match is None or match.end() == pos:
            return None
        tokens.append((match.lastgroup, match.group(match.lastgroup),
                       match.start(), match.end()))
        pos = match.end()
    for first, second in zip(tokens, tokens[1:]):
        if first[0] == "op" and second[0] == "op" and \
                first[3] == second[2] and \
                ((first[1] == "-" and second[1] == "-") or
                 (first[1] == "+" and second[1] == "+")):
            return None
    return tokens


def _sym_key(value):
    """Hashable canonical key for one abstract value.

    Non-negative constants canonicalize across signedness, width
    and spelling (``8``, ``8U`` and a named 8 share one key),
    since bit tests read them identically; negative constants
    keep their full type, whose bit pattern is width-dependent.
    """
    if value[0] == "C":
        if value[1] >= 0:
            return ("K", value[1])
        return ("C", value[1], value[2], value[3])
    if value[0] == "P":
        if value[1] >= 0:
            return ("K", value[1])
        return ("P", value[1])
    return value


def _sym_is_zero(value):
    """Whether an abstract value is exactly zero."""
    return value[0] in ("C", "P") and value[1] == 0


def _sym_fold_const(op, left, right):
    """Re-lexed exact fold of two exactly-typed constants.

    Both operand spellings stay parenthesized, so intermediate
    folds keep their grouping: ``(1 + 1) * 2`` folds to 4, never
    to ``1 + 1 * 2``.
    """
    text = "(%s) %s (%s)" % (left[4], op, right[4])
    tokens = _c_const_lex(text)
    if tokens is None:
        return None
    try:
        result = _c_const_eval(tokens)
    except (RecursionError, MemoryError, OverflowError):
        return None
    if result is None:
        return None
    return ("C", result[0], result[1], result[2], text)


def _sym_small_math(op, first, second):
    """Exact small arithmetic shared by every LP64 integer type.

    Non-negative operands with a result in [0, 2**31) read
    identically under every integer type at least 32 bits wide
    (no overflow, wraparound or division hazard is possible), so
    value-only constants (pipeline and filter-local integers of
    unknown type) fold exactly; anything else stays symbolic.
    Returns the mathematical result, or None.
    """
    if op == "+":
        result = first + second
    elif op == "-":
        result = first - second
    elif op == "*":
        result = first * second
    elif op == "/":
        if second == 0:
            return None
        result = first // second
    elif op == "%":
        if second == 0:
            return None
        result = first % second
    else:
        return None
    if 0 <= result <= 2 ** 31 - 1:
        return result
    return None


def _sym_bit_math(op, left, right):
    """Value-only bitwise fold for type-unknown constants.

    Python integers are infinite-precision two's complement, so a
    result in [0, 2**31) reads identically under every LP64
    integer type at least 32 bits wide (all constant sources
    here); anything else stays symbolic.
    """
    if left[0] not in ("C", "P") or right[0] not in ("C", "P"):
        return None
    if op == "&":
        result = left[1] & right[1]
    elif op == "|":
        result = left[1] | right[1]
    else:
        result = left[1] ^ right[1]
    if 0 <= result <= 2 ** 31 - 1:
        return ("P", result)
    return None


def _sym_const_pair(left, right):
    """Whether both values are constants (any type knowledge)."""
    return left[0] in ("C", "P") and right[0] in ("C", "P")


def _sym_combine_bit(op, tag, left, right):
    """Combine one ``&``/``|``/``^`` node (bitwise: always defined)."""
    if left[0] == "C" and right[0] == "C":
        folded = _sym_fold_const(op, left, right)
        if folded is not None:
            return folded
    elif _sym_const_pair(left, right):
        folded = _sym_bit_math(op, left, right)
        if folded is not None:
            return folded
        if left[1] == right[1]:
            if op == "^":
                return ("P", 0)
            return ("P", left[1])
    if op == "&":
        if _sym_is_zero(left) or _sym_is_zero(right):
            return ("P", 0)
    else:
        if _sym_is_zero(left):
            return right
        if _sym_is_zero(right):
            return left
    if _sym_key(left) == _sym_key(right):
        if op == "^":
            return ("P", 0)
        return left
    kids = []
    for value in (left, right):
        if value[0] == "V" and value[1][0] == tag:
            kids.extend(value[1][1])
        else:
            kids.append(_sym_key(value))
    if tag == "and":
        acc = None
        for kid in kids:
            if kid[0] in ("K", "C", "P"):
                acc = kid[1] if acc is None else acc & kid[1]
        if acc is not None and acc == 0:
            return ("P", 0)
    consts = [kid for kid in kids if kid[0] == "K"]
    if len(consts) >= 2:
        combined = consts[0][1]
        for kid in consts[1:]:
            if op == "&":
                combined &= kid[1]
            elif op == "|":
                combined |= kid[1]
            else:
                combined ^= kid[1]
        rest = [kid for kid in kids if kid[0] != "K"]
        if op == "&" and combined == 0:
            return ("P", 0)
        rest.append(("K", combined))
        kids = rest
    if tag == "and":
        if ("K", 0) in kids:
            return ("P", 0)
        kidset = set(kids)
        for kid in kids:
            if kid[0] == "V" and kid[1][0] == "bitnot" and \
                    kid[1][1] in kidset:
                return ("P", 0)
    if tag == "xor":
        others = [kid for kid in kids if kid != ("K", 0)]
        if others:
            counts = {}
            for kid in others:
                counts[kid] = counts.get(kid, 0) + 1
            if all(count % 2 == 0
                   for count in counts.values()):
                return ("P", 0)
    kids.sort()
    return ("V", (tag, tuple(kids)))


def _sym_combine_addsub(op, left, right):
    """Combine one ``+``/``-`` node (ordered: wraparound is UB)."""
    if left[0] == "C" and right[0] == "C":
        folded = _sym_fold_const(op, left, right)
        if folded is not None:
            return folded
    elif _sym_const_pair(left, right) and left[1] >= 0 and \
            right[1] >= 0:
        folded = _sym_small_math(op, left[1], right[1])
        if folded is not None:
            return ("P", folded)
    if op == "+":
        if _sym_is_zero(left):
            return right
        if _sym_is_zero(right):
            return left
        return ("V", ("add", (_sym_key(left), _sym_key(right))))
    if _sym_is_zero(right):
        return left
    if _sym_key(left) == _sym_key(right):
        return ("P", 0)
    if _sym_const_pair(left, right) and left[1] == right[1]:
        return ("P", 0)
    return ("V", ("sub", (_sym_key(left), _sym_key(right))))


def _sym_combine_muldivmod(op, left, right):
    """Combine one ``*``/``/``/``%`` node (ordered, mostly opaque)."""
    if left[0] == "C" and right[0] == "C":
        folded = _sym_fold_const(op, left, right)
        if folded is not None:
            return folded
    elif _sym_const_pair(left, right) and left[1] >= 0 and \
            right[1] >= 0:
        folded = _sym_small_math(op, left[1], right[1])
        if folded is not None:
            return ("P", folded)
    if op == "*":
        if _sym_is_zero(left) or _sym_is_zero(right):
            return ("P", 0)
        if left[0] in ("C", "P") and left[1] == 1:
            return right
        if right[0] in ("C", "P") and right[1] == 1:
            return left
        return ("V", ("mul", (_sym_key(left), _sym_key(right))))
    if op == "/":
        return ("V", ("div", (_sym_key(left), _sym_key(right))))
    return ("V", ("mod", (_sym_key(left), _sym_key(right))))


def _sym_combine_shift(op, left, right):
    """Combine one shift node (only shift-by-zero reduces)."""
    if left[0] == "C" and right[0] == "C":
        folded = _sym_fold_const(op, left, right)
        if folded is not None:
            return folded
    if right[0] in ("C", "P") and right[1] == 0:
        return left
    tag = "shl" if op == "<<" else "shr"
    return ("V", (tag, (_sym_key(left), _sym_key(right))))


def _sym_combine_eq(op, left, right):
    """Combine one ``==``/``!=`` node (results are always int)."""
    if left[0] == "C" and right[0] == "C":
        folded = _sym_fold_const(op, left, right)
        if folded is not None:
            return folded
    if _sym_key(left) == _sym_key(right):
        return ("C", 1 if op == "==" else 0, 32, True,
                "1" if op == "==" else "0")
    if _sym_const_pair(left, right) and \
            (left[1] >= 0) == (right[1] >= 0):
        matched = left[1] == right[1]
        if op == "!=":
            matched = not matched
        return ("C", 1 if matched else 0, 32, True,
                "1" if matched else "0")
    tag = "eq" if op == "==" else "ne"
    return ("V", (tag, tuple(sorted((_sym_key(left),
                                    _sym_key(right))))))


def _sym_combine_rel(op, left, right):
    """Combine one ordered comparison node."""
    if left[0] == "C" and right[0] == "C":
        folded = _sym_fold_const(op, left, right)
        if folded is not None:
            return folded
    if _sym_key(left) == _sym_key(right):
        truth = 0 if op in ("<", ">") else 1
        return ("C", truth, 32, True, "%d" % truth)
    if _sym_const_pair(left, right) and \
            (left[1] >= 0) == (right[1] >= 0):
        if op == "<":
            truth = left[1] < right[1]
        elif op == "<=":
            truth = left[1] <= right[1]
        elif op == ">":
            truth = left[1] > right[1]
        else:
            truth = left[1] >= right[1]
        return ("C", 1 if truth else 0, 32, True,
                "1" if truth else "0")
    tag = {"<": "lt", "<=": "le", ">": "gt", ">=": "ge"}[op]
    return ("V", (tag, (_sym_key(left), _sym_key(right))))


def _sym_combine_logic(op, left, right):
    """Combine one ``&&``/``||`` node (0/1-valued, order-free)."""
    def truth(value):
        if value[0] in ("C", "P"):
            return value[1] != 0
        return None

    known = (truth(left), truth(right))
    if op == "&&":
        if known[0] is False or known[1] is False:
            return ("C", 0, 32, True, "0")
        if known[0] is True and known[1] is True:
            return ("C", 1, 32, True, "1")
        tag = "andand"
        const_key = ("K", 1)
    else:
        if known[0] is True or known[1] is True:
            return ("C", 1, 32, True, "1")
        if known[0] is False and known[1] is False:
            return ("C", 0, 32, True, "0")
        tag = "oror"
        const_key = ("K", 0)
    kids = []
    for value, holds in ((left, known[0]), (right, known[1])):
        if holds is not None:
            kids.append(const_key)
        elif value[0] == "V" and value[1][0] == tag:
            kids.extend(value[1][1])
        else:
            kids.append(_sym_key(value))
    if len(set(kids)) == 1:
        kids.append(const_key)
    kids.sort()
    return ("V", (tag, tuple(kids)))


def _sym_combine_unary(op, operand):
    """Combine one unary node."""
    if op == "+":
        return operand
    if operand[0] == "C":
        text = "%s(%s)" % (op, operand[4])
        tokens = _c_const_lex(text)
        result = None
        if tokens is not None:
            try:
                result = _c_const_eval(tokens)
            except (RecursionError, MemoryError, OverflowError):
                result = None
        if result is not None:
            return ("C", result[0], result[1], result[2], text)
    if operand[0] == "P":
        if op == "-":
            return ("P", -operand[1])
        if op == "~":
            return ("P", -operand[1] - 1)
        if op == "!":
            truth = 0 if operand[1] else 1
            return ("C", truth, 32, True, "%d" % truth)
    if op == "!":
        return ("V", ("not", _sym_key(operand)))
    if op == "-":
        return ("V", ("neg", _sym_key(operand)))
    return ("V", ("bitnot", _sym_key(operand)))


def _cast_target_width(words):
    """(width, signed) for cast-target words, or None if unproven.

    Covers bool (0/1-valued) and the known LP64 integer spellings
    (plain ``char`` is signed on x86-64 gcc, matching declaration
    handling); typedef names, enum tags, aggregates and anything
    else are outside the proven set.
    """
    if any(word in ("struct", "union", "enum") for word in words):
        return None
    if "bool" in words or "_Bool" in words:
        if any(word not in ("bool", "_Bool", "const", "volatile",
                            "restrict", "_Atomic") for word in words):
            return None
        return (1, False)
    narrow = _decl_narrow(words, False)
    if narrow is not None:
        return narrow
    return _decl_int_wide(words, False)


def _eval_bit_expr(core, typed_map, pipe_map, fn_name, version,
                   cast_locals=()):
    """Abstract value of one bit-test core.

    Exactly-typed file constants substitute with their widths, so
    pure folds keep C semantics; pipeline and filter-local
    integers (unknown type, LP64 int-or-wider) become value-only
    nodes whose identities never depend on width or signedness;
    member-access chains become unproven-width field nodes;
    anything else stays symbolic with a canonical form (redundant
    parens vanish, commutative operators sort). Casts to proven
    integer types become width-carrying ``cast`` nodes (a name
    bound as a filter local shadows the type spelling in C, so a
    parenthesized local is grouping, never a cast); casts to
    pointer, unknown or non-integer types reject, as does a
    trailing open paren (a parenthesized call or invalid C, the
    textual call scan cannot see). Any other unparseable core
    rejects too: only plain lvalues and constants of known
    width are bit-testable, and an unparsed shape must never
    yield a restriction.
    """
    tokens = _sym_tokenize(core)
    if tokens is None:
        raise FilterNotUnderstood(
            "kfunc filter %s@%s tests an unproven bit operand "
            "in (%s); only plain lvalues and constants of known "
            "width are bit-testable, and the shape is outside "
            "the grammar"
            % (fn_name, version, " ".join(core.split())[:60]))
    stream = []
    for kind, word, _, _ in tokens:
        if kind == "ident" and word in typed_map:
            render = _c_canonical_literal(*typed_map[word])
            lexed = _c_const_lex(render) if render else None
            if lexed is None:
                stream.append(("ident", word))
            else:
                stream.extend(lexed)
        else:
            stream.append((kind, word))
    pos = 0
    bound = set(cast_locals)

    def reject_cast(text):
        raise FilterNotUnderstood(
            "kfunc filter %s@%s casts %s in a bit test; casts "
            "outside the proven integer types are outside the "
            "grammar" % (fn_name, version, text[:40]))

    def peek():
        if pos < len(stream):
            return stream[pos]
        return (None, None)

    def advance():
        nonlocal pos
        pos += 1

    def match_close(start):
        depth = 0
        for index in range(start, len(stream)):
            kind, word = stream[index]
            if kind == "paren" and word == "(":
                depth += 1
            elif kind == "paren" and word == ")":
                depth -= 1
                if depth == 0:
                    return index
        return None

    def cast_at():
        """(width, signed, close) for a cast group, else None.

        A paren group holding only type words (``*``-free) that is
        directly followed by an operand start is a C cast; a group
        holding a single locally-bound name is grouping even when
        it spells a type. Anything else (including a group with
        unbalanced contents) is not a cast group.
        """
        kind, word = peek()
        if kind != "paren" or word != "(":
            return None
        close = match_close(pos)
        if close is None:
            return None
        content = stream[pos + 1:close]
        if not content:
            return None
        if any(word == "*" for _, word in content):
            following = close + 1 < len(stream) and \
                stream[close + 1][0] in ("num", "ident")
            if following:
                reject_cast(
                    "(%s)" % " ".join(
                        word for _, word in content))
            return None
        if any(kind != "ident" for kind, _ in content):
            return None
        words = [word for _, word in content]
        if len(words) == 1 and words[0] in bound:
            return None
        if close + 1 >= len(stream):
            return None
        next_kind, next_word = stream[close + 1]
        starts_operand = (
            next_kind in ("num", "ident") or
            (next_kind == "paren" and next_word == "(") or
            (next_kind == "op" and
             next_word in ("!", "~", "+", "-")))
        if not starts_operand:
            return None
        if len(words) == 1 and words[0] not in _CAST_WORDS and \
                words[0] not in bound:
            reject_cast("(%s)" % words[0])
        width = _cast_target_width(words)
        if width is None:
            if all(word in _CAST_WORDS or word in bound
                   for word in words):
                reject_cast("(%s)" % " ".join(words))
            return None
        return (width[0], width[1], close)

    def parse_primary():
        nonlocal pos
        kind, word = peek()
        if kind == "num":
            advance()
            parsed = _c_literal_type(word)
            if parsed is None:
                return ("V", ("lit", word))
            return ("C", parsed[0], parsed[1], parsed[2], word)
        if kind == "ident":
            advance()
            if peek()[0] == "mem":
                path = [word]
                while peek()[0] == "mem":
                    advance()
                    leaf_kind, leaf_word = peek()
                    if leaf_kind != "ident":
                        return None
                    advance()
                    path.append(leaf_word)
                return ("V", ("field", tuple(path)))
            if word in pipe_map and \
                    -(2 ** 63) <= pipe_map[word] < 2 ** 64:
                return ("P", pipe_map[word])
            return ("V", ("var", word))
        if kind == "paren" and word == "(":
            cast = cast_at()
            if cast is not None:
                width, signed, close = cast
                pos = close + 1
                operand = parse_unary()
                if operand is None:
                    return None
                return ("V", ("cast", (width, signed,
                                       _sym_key(operand))))
            advance()
            node = parse_lor()
            kind, word = peek()
            if node is None or kind != "paren" or word != ")":
                return None
            advance()
            return node
        return None

    def parse_unary():
        kind, word = peek()
        if kind == "op" and word in ("!", "~", "+", "-"):
            advance()
            operand = parse_unary()
            if operand is None:
                return None
            return _sym_combine_unary(word, operand)
        return parse_primary()

    def parse_level(next_level, ops, combine):
        left = next_level()
        if left is None:
            return None
        while True:
            kind, word = peek()
            if kind != "op" or word not in ops:
                return left
            advance()
            right = next_level()
            if right is None:
                return None
            left = combine(word, left, right)

    def parse_mul():
        return parse_level(
            parse_unary, ("*", "/", "%"), _sym_combine_muldivmod)

    def parse_add():
        return parse_level(
            parse_mul, ("+", "-"), _sym_combine_addsub)

    def parse_shift():
        return parse_level(
            parse_add, ("<<", ">>"), _sym_combine_shift)

    def parse_rel():
        return parse_level(
            parse_shift, ("<", "<=", ">", ">="), _sym_combine_rel)

    def parse_eq():
        return parse_level(
            parse_rel, ("==", "!="), _sym_combine_eq)

    def parse_band():
        return parse_level(
            parse_eq, ("&",),
            lambda op, left, right: _sym_combine_bit(
                op, "and", left, right))

    def parse_bxor():
        return parse_level(
            parse_band, ("^",),
            lambda op, left, right: _sym_combine_bit(
                op, "xor", left, right))

    def parse_bor():
        return parse_level(
            parse_bxor, ("|",),
            lambda op, left, right: _sym_combine_bit(
                op, "or", left, right))

    def parse_land():
        return parse_level(parse_bor, ("&&",), _sym_combine_logic)

    def parse_lor():
        return parse_level(parse_land, ("||",), _sym_combine_logic)

    try:
        value = parse_lor()
    except (RecursionError, MemoryError, OverflowError):
        raise FilterNotUnderstood(
            "kfunc filter %s@%s tests an unproven bit "
            "expression in (%s); only plain lvalues and "
            "constants of known width are bit-testable, and "
            "the shape is outside the grammar"
            % (fn_name, version, " ".join(core.split())[:60]))
    if value is None or pos != len(stream):
        rest = stream[pos:]
        if any(kind == "paren" and word == "(" for kind, word in
               rest):
            raise FilterNotUnderstood(
                "kfunc filter %s@%s calls %s in a bit test; "
                "calls are not bit-testable operands and the "
                "shape is outside the grammar"
                % (fn_name, version,
                   " ".join(core.split())[:40]))
        raise FilterNotUnderstood(
            "kfunc filter %s@%s tests an unproven bit "
            "expression in (%s); only plain lvalues and "
            "constants of known width are bit-testable, and "
            "the shape is outside the grammar"
            % (fn_name, version, " ".join(core.split())[:60]))
    return value


def _dnf_condition(node, opaque, fn_name, version, allow, typed_map,
                   pipe_map, multi, widths, neg=False,
                   cast_locals=(), expansion=None):
    """Expand a folded condition into alternative conjunctions.

    Returns the list of context conjunctions under which the
    (possibly negated) condition holds; the empty list means
    unsatisfiable. Conjunctions conjoin their leaves while
    disjunctions split into distinct alternatives, except that
    deny narrowings merge exactly-factorable same-dimension
    disjunctions (grammar rule E4). In allow requirements, bit
    tests become restriction notes, provably-decided bit tests
    grant nothing instead of minting permission, and every other
    opaque atom raises FilterNotUnderstood; in deny requirements,
    opaque atoms and st_ops-null tests raise FilterNotUnderstood.
    """
    kind = node[0]
    if kind == "not":
        return _dnf_condition(
            node[1], opaque, fn_name, version, allow, typed_map,
            pipe_map, multi, widths, not neg, cast_locals,
            expansion)
    if kind == "const":
        if node[1] != neg:
            return [_CONJ_UNCONSTRAINED]
        return []
    if kind == "attach_cmp":
        _, op, value = node
        if neg:
            op = "!=" if op == "==" else "=="
        if op == "==":
            return [(frozenset({value}), frozenset(), frozenset(),
                     frozenset(), frozenset(),
                     frozenset({"requires expected_attach_type %s"
                                % value}))]
        return [(frozenset(), frozenset(), frozenset({value}),
                 frozenset(), frozenset(),
                 frozenset({"excludes expected_attach_type %s" % value}))]
    if kind == "stops_cmp":
        _, op, value = node
        if neg:
            op = "!=" if op == "==" else "=="
        if op == "==":
            return [(frozenset(), frozenset({value}), frozenset(),
                     frozenset(), frozenset(),
                     frozenset({"requires struct_ops attachment to %s"
                                % value}))]
        return [(frozenset(), frozenset(), frozenset(),
                 frozenset({value}), frozenset(),
                 frozenset({"rejected when attached to %s" % value}))]
    if kind == "opaque":
        if allow and not node[1].startswith("__bitop_"):
            raise FilterNotUnderstood(
                "kfunc filter %s@%s allows on an unrecognized "
                "condition %r; only bit tests over & | ^ keep "
                "existential permission"
                % (fn_name, version, opaque[node[1]][:60]))
        impossible, facts, decided = _bit_test_facts(
            node[1], opaque[node[1]], not neg, opaque, typed_map,
            pipe_map, multi, widths, fn_name, version,
            cast_locals, expansion)
        if impossible:
            return []
        if not allow:
            if decided:
                return [_CONJ_UNCONSTRAINED]
            raise FilterNotUnderstood(
                "kfunc filter %s@%s denies on an unrecognized "
                "condition %r; cannot scope the denial"
                % (fn_name, version, opaque[node[1]][:60]))
        return [(frozenset(), frozenset(), frozenset(), frozenset(),
                 facts,
                 frozenset(_opaque_notes(node, opaque, fn_name, neg)))]
    if kind == "stops_null":
        if not allow:
            raise FilterNotUnderstood(
                "kfunc filter %s@%s denies on an unrecognized "
                "st_ops-null test; cannot scope the denial"
                % (fn_name, version))
        if neg:
            # Load-phase leniency while st_ops is unset grants
            # nothing steady-state (fail closed).
            return []
        return [_CONJ_UNCONSTRAINED]
    if kind == "and":
        subs = [_dnf_condition(sub, opaque, fn_name, version, allow,
                               typed_map, pipe_map, multi, widths, neg,
                               cast_locals, expansion)
                for sub in node[1]]
        if neg:
            flat = [alt for sub in subs for alt in sub]
            if allow:
                return flat
            return _try_factor_or_alts(flat)
        return _dnf_cross(subs)
    if kind == "or":
        subs = [_dnf_condition(sub, opaque, fn_name, version, allow,
                               typed_map, pipe_map, multi, widths, neg,
                               cast_locals, expansion)
                for sub in node[1]]
        if neg:
            return _dnf_cross(subs)
        flat = [alt for sub in subs for alt in sub]
        if allow:
            return flat
        return _try_factor_or_alts(flat)
    raise FilterNotUnderstood(
        "kfunc filter %s@%s has an unsupported requirement"
        % (fn_name, version))


_OPAQUE_CONST_RE = re.compile(
    r"(?<![A-Za-z0-9_])(?:SCX_KF_ALLOW_\w+|QDISC_OPS_KF_\w+|"
    r"[A-Z][A-Z0-9_]*)"
    r"(?=\s*\)|\s|$)")

_OPAQUE_FLAG_RE = re.compile(
    r"(?:SCX_KF_ALLOW_\w+|QDISC_OPS_KF_\w+|[A-Z][A-Z0-9_]*)\Z")


def _opaque_consts(text):
    """Flag constants a bit-test text mentions (EACCES excluded)."""
    return [item for item in sorted(set(_OPAQUE_CONST_RE.findall(text)))
            if item != "EACCES"]


def _expand_bit_text(text, opaque):
    """Expand nested bit/opaque placeholders in ``text``.

    Inner ``__bitop_N``/``__opaque_N`` spellings are
    occurrence-specific, so they expand to their stored texts
    (parenthesized) before canonicalization; ``__member_X`` names
    are stable per set and stay. Returns None past the depth cap.
    """
    current = text
    seen = set()
    for _ in range(10):
        names = set(re.findall(r"__bitop_\d+\b|__opaque_\d+\b",
                               current)) - seen
        if not names:
            return current
        for name in names:
            seen.add(name)
            if name in opaque:
                current = re.sub(
                    r"%s\b" % re.escape(name),
                    lambda _: "(%s)" % opaque[name], current)
    return None


def _derive_bit_facts(value, holds):
    """(impossible, facts, decided) for one analyzed bit test.

    Provable constants decide the branch directly; symbolic tests
    contribute a wholeness fact (the test holds exactly when its
    canonical form is nonzero), ``&``-operand facts (a held
    conjunction keeps every operand nonzero) and flag-pair facts
    (a held ``&``-chain keeps every operand/const sub-test held,
    so subset tests contradict). Known non-negative consts key by
    bare value (signedness, width and spelling canonicalized),
    unknown consts by spelling (EACCES excluded, as before).
    """
    kind = value[0]
    if kind in ("C", "P"):
        return (value[1] == 0) == holds, frozenset(), True
    node = value[1]
    active = holds
    while node[0] == "not":
        node = node[1]
        active = not active
    facts = {(("nonzero", ("V", node)), active)}
    if node[0] != "and":
        return False, frozenset(facts), False
    consts = []
    others = []
    for operand in node[1]:
        if operand[0] in ("C", "P", "K"):
            consts.append(operand)
        elif operand[0] == "V" and operand[1][0] == "var" and \
                _OPAQUE_FLAG_RE.fullmatch(operand[1][1]):
            if operand[1][1] != "EACCES":
                consts.append(("N", operand[1][1]))
        else:
            others.append(operand)
    if active:
        for operand in node[1]:
            sub = operand
            flips = 0
            while sub[0] == "V" and sub[1][0] == "not":
                sub = sub[1][1]
                flips += 1
            if sub[0] in ("C", "P", "K"):
                continue
            facts.add((("nonzero", sub), flips % 2 == 0))
        for other in others:
            for const in consts:
                facts.add((("flag", other, const), True))
    elif len(node[1]) == 2 and len(consts) == 1 and \
            len(others) == 1:
        facts.add((("flag", others[0], consts[0]), False))
    return False, frozenset(facts), False


def _root_and_constituents(value):
    """(mask, operands, flips) for a root ``&``-chain, else Nones.

    Unwraps logical-``not`` layers (counting them in ``flips``);
    any other root shape yields (None, None, 0). The mask is the
    AND of the chain's non-negative constant operands (None when
    the chain holds none) and the operands its symbolic (``V``)
    operands in order.
    """
    if value[0] != "V":
        return None, None, 0
    node = value[1]
    flips = 0
    while node[0] == "not":
        flips += 1
        node = node[1]
        if not (isinstance(node, tuple) and len(node) == 2 and
                node[0] == "V"):
            return None, None, 0
        node = node[1]
    if node[0] != "and":
        return None, None, 0
    mask = None
    operands = []
    for kid in node[1]:
        if kid[0] == "K":
            mask = kid[1] if mask is None else mask & kid[1]
        elif kid[0] in ("C", "P") and kid[1] >= 0:
            mask = kid[1] if mask is None else mask & kid[1]
        elif kid[0] == "V":
            operands.append(kid)
    return mask, operands, flips


def _usual_width(first, second):
    """C usual-arithmetic-conversion width of two promoted types.

    Both inputs are (width, signed) with widths 32 or 64 (narrow
    types promote to int first); the result follows LP64 rank and
    representability rules exactly.
    """
    (width_a, signed_a), (width_b, signed_b) = first, second
    if (width_a, signed_a) == (width_b, signed_b):
        return (width_a, signed_a)
    if signed_a == signed_b:
        return (max(width_a, width_b), signed_a)
    if signed_a and not signed_b:
        if width_b >= width_a:
            return (width_b, False)
        return (width_a, True)
    if width_a >= width_b:
        return (width_a, False)
    return (width_b, True)


def _promote_width(known):
    """Integer-promoted (width, signed) pair, or None."""
    if known is None:
        return None
    width, signed = known
    if width >= 32:
        return (width, signed)
    return (32, True)


def _operand_proven_width(operand, widths):
    """(width, signed) for one root-``&`` operand, or None.

    Bare variables read the width table; casts carry their target
    width; arithmetic and bitwise combinations (``&``/``|``/``^``
    nesting, ``+``/``-``/``*``/``/``/``%``) combine every leaf
    width under C promotion and conversion rules; shifts keep
    their base's promoted width when the amount is a valid
    constant; negation and bit-not keep the promoted width while
    comparisons and logical operators yield int. Member-access
    fields carry no proven width. Value-only
    constants (``P``/``K``) have unproven types and poison their
    combination, as does any other shape.
    """
    if operand[0] == "C":
        return (operand[2], operand[3])
    if operand[0] != "V":
        return None
    node = operand[1]
    tag = node[0]
    if tag == "var":
        return widths.get(node[1])
    if tag == "cast":
        return (node[1][0], node[1][1])
    if tag in ("not", "eq", "ne", "lt", "le", "gt", "ge",
               "andand", "oror"):
        return (32, True)
    if tag in ("neg", "bitnot"):
        return _promote_width(
            _operand_proven_width(node[1], widths))
    if tag in ("shl", "shr"):
        base = _promote_width(
            _operand_proven_width(node[1][0], widths))
        amount = node[1][1]
        if base is None or amount[0] not in ("C", "P", "K"):
            return None
        if amount[1] < 0 or amount[1] >= base[0]:
            return None
        return base
    if tag in ("and", "or", "xor", "add", "sub", "mul", "div",
               "mod"):
        parts = [_operand_proven_width(kid, widths)
                 for kid in node[1]]
        if any(part is None for part in parts):
            return None
        promoted = [_promote_width(part) for part in parts]
        acc = promoted[0]
        for part in promoted[1:]:
            acc = _usual_width(acc, part)
        return acc
    return None


def _reject_unprovable_width(value, widths, fn_name, version):
    """Reject a wide mask over operands of unproven width.

    A mask with bits at or above 32 over operands whose widths
    are all unproven decides nothing the inventory may claim: a
    32-bit operand makes the test provably zero while a 64-bit
    operand leaves it symbolic, so the shape is outside the
    grammar. Masks inside the assumed 32-bit width stay symbolic,
    as do masks with at least one proven-width operand (folded
    below when provably zero, symbolic otherwise).
    """
    mask, operands, _ = _root_and_constituents(value)
    if mask is None or not operands or mask < 2 ** 32:
        return
    if any(_operand_proven_width(operand, widths) is not None
           for operand in operands):
        return
    raise FilterNotUnderstood(
        "kfunc filter %s@%s tests a bit mask %d over operands "
        "of unproven width; wide masks over unknown widths are "
        "outside the grammar"
        % (fn_name, version, mask))


def _fold_known_width_and(value, widths):
    """Fold a width-proven root ``&``-chain to its constant value.

    A chain holding an operand of known unsigned width with no
    mask bits below that width is provably zero in C (the operand
    cannot carry the masked bits, whatever the chain's other
    operands are); the whole value folds to 0, or to 1 under an
    odd number of negations. Signed operands stay symbolic (sign
    extension may set high bits), as does anything else.
    """
    mask, operands, flips = _root_and_constituents(value)
    if mask is None or not operands:
        return value
    for operand in operands:
        known = _operand_proven_width(operand, widths)
        if known is None:
            continue
        width, signed = known
        if not signed and not mask & ((1 << width) - 1):
            return ("P", 1 if flips % 2 else 0)
    return value


def _reject_unbitlike_core(core, fn_name, version):
    """Reject bit-test cores with unproven operand shapes.

    Bit-test placeholders accept only proven bit-testable
    operands (flag lvalues, constants and composed integer
    expressions over them): ``sizeof``, calls, ternaries and
    array subscripts in bit positions decide nothing the
    inventory may claim, so each rejects loudly instead of
    granting an impossible restriction.
    """
    if re.search(r"\bsizeof\b", core):
        raise FilterNotUnderstood(
            "kfunc filter %s@%s tests sizeof in (%s); sizeof "
            "is not a bit-testable operand and the shape is "
            "outside the grammar"
            % (fn_name, version, " ".join(core.split())[:40]))
    if "?" in core:
        raise FilterNotUnderstood(
            "kfunc filter %s@%s tests a ternary in (%s); "
            "ternaries are not bit-testable operands and the "
            "shape is outside the grammar"
            % (fn_name, version, " ".join(core.split())[:40]))
    if "[" in core or "]" in core:
        raise FilterNotUnderstood(
            "kfunc filter %s@%s tests a subscript in (%s); "
            "array subscripts are not bit-testable operands "
            "and the shape is outside the grammar"
            % (fn_name, version, " ".join(core.split())[:40]))
    match = re.search(r"\b([A-Za-z_]\w*)\s*\(", core)
    if match:
        raise FilterNotUnderstood(
            "kfunc filter %s@%s calls %s in a bit test; calls "
            "are not bit-testable operands and the shape is "
            "outside the grammar"
            % (fn_name, version, match.group(1)[:40]))


_COMPOSED_ZERO_ONE_TAGS = frozenset((
    "not", "eq", "ne", "lt", "le", "gt", "ge", "andand", "oror",
))


def _chain_const_amount(key):
    """Integer value of a constant shift-amount key, or None."""
    if isinstance(key, tuple) and key and \
            key[0] in ("K", "C", "P"):
        return key[1]
    return None


_COMPOSED_ARITH_TAGS = frozenset((
    "and", "or", "xor", "add", "sub", "mul", "div", "mod",
))


def _composed_arith_values(operand):
    """(values, has_composed) for one root-``&`` operand, or None.

    Enumerates the exact reachable C values when every leaf is a
    composed 0/1-valued result (which contributes ``{0, 1}``
    whatever it compares) or a non-negative constant below
    ``2**64``, and every intermediate stays in ``[0, 2**64)``.
    Small intermediates (below ``2**31``) are exact at any
    operand width at or above ``int``: no width wraps,
    overflows or turns a shift, division or negation
    undefined. Larger intermediates are exact whenever C
    computes them at 64 bits (a ``u64`` constant or cast
    widens the computation) or computes them at 32 bits
    without wraparound; a complement reads 32-bit (``~x``
    is ``0xFFFFFFFF ^ x``). ``has_composed`` tells whether
    any composed leaf took part. Anything else (a variable,
    member, unknown literal, out-of-range constant, a
    possibly-zero divisor, a negative subtraction, an
    out-of-range signed cast, a complement past 32 bits, an
    unproven shape, or an enumeration past the combination
    cap) yields None and stays symbolic.
    """
    cap = [1024]

    def const_set(node):
        value = node[1]
        if isinstance(value, bool) or not isinstance(value, int):
            return None
        if 0 <= value < 2 ** 64:
            return (frozenset((value,)), False)
        return None

    def combine(kind, kids):
        sets = []
        has_composed = False
        for kid in kids:
            entry = walk(kid)
            if entry is None:
                return None
            sets.append(entry[0])
            has_composed = has_composed or entry[1]
        if kind in ("and", "or", "xor"):
            acc = None
            for one in sets:
                if acc is None:
                    acc = one
                    continue
                cap[0] -= len(acc) * len(one)
                if cap[0] < 0:
                    return None
                if kind == "and":
                    acc = frozenset(
                        left & right for left in acc for right in one)
                elif kind == "or":
                    acc = frozenset(
                        left | right for left in acc for right in one)
                else:
                    acc = frozenset(
                        left ^ right for left in acc for right in one)
            if acc is None:
                return None
            return (acc, has_composed)
        if len(sets) != 2:
            return None
        if kind in ("shl", "shr"):
            base, amount = sets
            cap[0] -= len(base) * len(amount)
            if cap[0] < 0:
                return None
            if kind == "shl":
                out = frozenset(
                    left << right for left in base for right in amount)
            else:
                out = frozenset(
                    left >> right for left in base for right in amount)
        else:
            left, right = sets
            cap[0] -= len(left) * len(right)
            if cap[0] < 0:
                return None
            if kind == "add":
                out = frozenset(
                    first + second for first in left for second in right)
            elif kind == "sub":
                out = frozenset(
                    first - second for first in left for second in right)
            elif kind == "mul":
                out = frozenset(
                    first * second for first in left for second in right)
            elif 0 in right:
                return None
            elif kind == "div":
                out = frozenset(
                    first // second for first in left for second in right)
            else:
                out = frozenset(
                    first % second for first in left for second in right)
        if any(item < 0 or item >= 2 ** 64 for item in out):
            return None
        return (out, has_composed)

    def walk(node):
        if not (isinstance(node, tuple) and node):
            return None
        if node[0] in ("K", "P"):
            return const_set(node)
        if node[0] == "C":
            return const_set(node)
        if node[0] != "V" or len(node) != 2:
            return None
        inner = node[1]
        if not (isinstance(inner, tuple) and inner):
            return None
        tag = inner[0]
        if tag in _COMPOSED_ZERO_ONE_TAGS:
            return (frozenset((0, 1)), True)
        if tag == "cast":
            entry = walk(inner[1][2])
            if entry is None:
                return None
            width, signed = inner[1][0], inner[1][1]
            out = set()
            for item in entry[0]:
                if signed:
                    if item >= 2 ** (width - 1):
                        return None
                    out.add(item)
                else:
                    out.add(item % (2 ** width))
            if any(item < 0 or item >= 2 ** 64 for item in out):
                return None
            return (frozenset(out), entry[1])
        if tag == "bitnot":
            entry = walk(inner[1])
            if entry is None:
                return None
            if any(item >= 2 ** 32 for item in entry[0]):
                return None
            return (frozenset(
                0xFFFFFFFF ^ item for item in entry[0]), entry[1])
        if tag in ("shl", "shr"):
            return combine(tag, inner[1])
        if tag in _COMPOSED_ARITH_TAGS:
            return combine(tag, inner[1])
        return None

    return walk(operand)


def _composed_enumerable_shape(node):
    """Whether every leaf and operator is enumeration-modeled.

    True when every leaf is a composed 0/1-valued result or a
    non-negative integer constant below ``2**64`` and every
    operator is one ``_composed_arith_values`` models (bitwise,
    arithmetic, shifts, complement and casts). A None from the
    enumeration over such a shape means the values escaped
    ``[0, 2**64)`` (C wraparound or a negative intermediate),
    hit a possibly-zero divisor or an out-of-range cast, or
    passed the combination cap -- all unmodeled wraparound
    shapes that must fail closed rather than keep a symbolic
    restriction. Anything with a variable, member or otherwise
    unmodeled leaf keeps today's symbolic treatment.
    """
    if not (isinstance(node, tuple) and node):
        return False
    if node[0] in ("K", "P", "C"):
        value = node[1]
        return isinstance(value, int) and \
            not isinstance(value, bool) and \
            0 <= value < 2 ** 64
    if node[0] != "V" or len(node) != 2:
        return False
    inner = node[1]
    if not (isinstance(inner, tuple) and inner):
        return False
    tag = inner[0]
    if tag in _COMPOSED_ZERO_ONE_TAGS:
        return True
    if tag == "cast":
        if not (isinstance(inner[1], tuple) and len(inner[1]) == 3):
            return False
        return _composed_enumerable_shape(inner[1][2])
    if tag == "bitnot":
        return _composed_enumerable_shape(inner[1])
    if tag in ("shl", "shr"):
        return all(_composed_enumerable_shape(kid)
                   for kid in inner[1])
    if tag in _COMPOSED_ARITH_TAGS:
        return all(_composed_enumerable_shape(kid)
                   for kid in inner[1])
    return False


def _plausible_const_types(value):
    """Plausible (width, signed) C types for a non-negative constant.

    Canonicalized constants spell no usable type, so every LP64
    integer type the value fits -- int-or-wider, 32 or 64 bits --
    stays plausible: small values may be int, unsigned, long or
    unsigned long, while a value at or above ``2**32`` forces 64
    bits and a value at or above ``2**63`` forces unsigned.
    """
    if value < 0 or value >= 2 ** 64:
        return ()
    if value < 2 ** 31:
        return ((32, True), (32, False), (64, True), (64, False))
    if value < 2 ** 32:
        return ((32, False), (64, True), (64, False))
    if value < 2 ** 63:
        return ((64, True), (64, False))
    return ((64, False),)


def _composed_trunc_div(first, second):
    """C truncating quotient of two integers (exact, no floats)."""
    quotient = abs(first) // abs(second)
    if (first < 0) != (second < 0):
        quotient = -quotient
    return quotient


def _composed_width_verdict(operand, mask):
    """Mask-verdict agreement for one operand across C widths.

    Re-evaluates a composed operand under every plausible type
    assignment -- canonicalized constants take each LP64 type
    their value fits, Boolean results are int, casts and negative
    constants keep their exact types -- applying integer
    promotion, usual arithmetic conversions, unsigned wraparound
    and exact signed arithmetic at each operation. Returns
    "all_miss" when every assignment misses every mask bit,
    "all_hit" when every assignment hits one, and "mixed" for
    anything else: assignments that disagree (a wraparound the
    unbounded enumeration misses, or a complement at the wrong
    width), any possible undefined behavior (signed overflow, a
    bad shift, a zero divisor), any cap exhaustion or any
    unmodeled shape. Only "all_hit" keeps a symbolic
    restriction; any other verdict rejects downstream.
    """
    cap = [4096]
    void = [False]

    def fits_signed(value, width):
        return -(2 ** (width - 1)) <= value < 2 ** (width - 1)

    def combine_pair(kind, left, right):
        out = {}
        for (awidth, asigned), avals in left.items():
            for (bwidth, bsigned), bvals in right.items():
                rwidth, rsigned = _usual_width(
                    _promote_width((awidth, asigned)),
                    _promote_width((bwidth, bsigned)))
                cap[0] -= len(avals) * len(bvals)
                if cap[0] < 0:
                    void[0] = True
                    continue
                for first in avals:
                    for second in bvals:
                        if not rsigned:
                            first_c = first % (2 ** rwidth)
                            second_c = second % (2 ** rwidth)
                        else:
                            first_c, second_c = first, second
                        value = None
                        if kind == "and":
                            value = first_c & second_c
                        elif kind == "or":
                            value = first_c | second_c
                        elif kind == "xor":
                            value = first_c ^ second_c
                        elif kind == "add":
                            value = first_c + second_c
                        elif kind == "sub":
                            value = first_c - second_c
                        elif kind == "mul":
                            value = first_c * second_c
                        elif second_c == 0:
                            void[0] = True
                            continue
                        elif kind == "div":
                            if rsigned and \
                                    first_c == -(2 ** (rwidth - 1)) \
                                    and second_c == -1:
                                void[0] = True
                                continue
                            value = _composed_trunc_div(
                                first_c, second_c)
                        else:
                            if rsigned and \
                                    first_c == -(2 ** (rwidth - 1)) \
                                    and second_c == -1:
                                void[0] = True
                                continue
                            value = first_c - _composed_trunc_div(
                                first_c, second_c) * second_c
                        if rsigned:
                            if not fits_signed(value, rwidth):
                                void[0] = True
                                continue
                        else:
                            value %= 2 ** rwidth
                        out.setdefault(
                            (rwidth, rsigned), set()).add(value)
        return out

    def walk(node):
        if not (isinstance(node, tuple) and node):
            void[0] = True
            return None
        if node[0] in ("K", "P"):
            value = node[1]
            if isinstance(value, bool) or \
                    not isinstance(value, int):
                void[0] = True
                return None
            if value < 0 or value >= 2 ** 64:
                void[0] = True
                return None
            return {(width, signed): {value}
                    for width, signed in
                    _plausible_const_types(value)}
        if node[0] == "C":
            if len(node) < 4:
                void[0] = True
                return None
            return {(node[2], node[3]): {node[1]}}
        if node[0] != "V" or len(node) != 2:
            void[0] = True
            return None
        inner = node[1]
        if not (isinstance(inner, tuple) and inner):
            void[0] = True
            return None
        tag = inner[0]
        if tag in _COMPOSED_ZERO_ONE_TAGS:
            return {(32, True): {0, 1}}
        if tag == "cast":
            entry = walk(inner[1][2])
            if entry is None:
                return None
            width, signed = inner[1][0], inner[1][1]
            out = {}
            for _, vals in entry.items():
                for value in vals:
                    if signed:
                        if fits_signed(value, width):
                            out.setdefault(
                                (width, True), set()).add(value)
                        else:
                            void[0] = True
                    else:
                        out.setdefault(
                            (width, False),
                            set()).add(value % (2 ** width))
            return out
        if tag == "bitnot":
            entry = walk(inner[1])
            if entry is None:
                return None
            out = {}
            for (cwidth, csigned), vals in entry.items():
                pwidth, psigned = _promote_width(
                    (cwidth, csigned))
                for value in vals:
                    if psigned:
                        result = ~value
                    else:
                        result = (2 ** pwidth - 1) ^ value
                    out.setdefault(
                        (pwidth, psigned), set()).add(result)
            return out
        if tag in ("shl", "shr"):
            base = walk(inner[1][0])
            amount = walk(inner[1][1])
            if base is None or amount is None:
                return None
            amounts = set()
            for vals in amount.values():
                amounts |= vals
            out = {}
            for (bwidth, bsigned), bvals in base.items():
                pwidth, psigned = _promote_width(
                    (bwidth, bsigned))
                cap[0] -= len(bvals) * len(amounts)
                if cap[0] < 0:
                    void[0] = True
                    continue
                for value in bvals:
                    for count in amounts:
                        if count < 0 or count >= pwidth:
                            void[0] = True
                            continue
                        if tag == "shl":
                            if psigned:
                                if value < 0 or \
                                        (value << count) >= \
                                        2 ** (pwidth - 1):
                                    void[0] = True
                                    continue
                                result = value << count
                            else:
                                result = (value << count) % \
                                    (2 ** pwidth)
                        else:
                            result = value >> count
                        out.setdefault(
                            (pwidth, psigned), set()).add(result)
            return out
        if tag in ("and", "or", "xor"):
            acc = None
            for kid in inner[1]:
                entry = walk(kid)
                if entry is None:
                    return None
                if acc is None:
                    acc = entry
                else:
                    acc = combine_pair(tag, acc, entry)
            if acc is None:
                void[0] = True
                return None
            return acc
        if tag in ("add", "sub", "mul", "div", "mod"):
            kids = inner[1]
            if len(kids) != 2:
                void[0] = True
                return None
            left = walk(kids[0])
            right = walk(kids[1])
            if left is None or right is None:
                return None
            return combine_pair(tag, left, right)
        void[0] = True
        return None

    outcomes = walk(operand)
    if outcomes is None or void[0] or not outcomes:
        return "mixed"
    hits = 0
    total = 0
    for vals in outcomes.values():
        if not vals:
            return "mixed"
        total += 1
        if any(value & mask != 0 for value in vals):
            hits += 1
    if hits == 0:
        return "all_miss"
    if hits == total:
        return "all_hit"
    return "mixed"


def _subtree_has_boolean_leaf(node):
    """Whether an abstract-value subtree holds a composed 0/1 leaf."""
    stack = [node]
    while stack:
        current = stack.pop()
        if not isinstance(current, tuple):
            continue
        if len(current) == 2 and current[0] == "V":
            inner = current[1]
            if isinstance(inner, tuple) and inner and \
                    inner[0] in _COMPOSED_ZERO_ONE_TAGS:
                return True
        stack.extend(current)
    return False


def _composed_neg_wraps_boolean(operand):
    """Whether a ``neg`` node wraps composed 0/1 results.

    Unary negation has no model in arithmetic enumeration: its
    value range (``-(0 or 1)`` is ``0 or -1`` before any cast)
    is exactly what a wraparound-sensitive composition hides
    behind, so the enumeration declines and the caller must fail
    closed rather than retain a symbolic restriction.
    """
    stack = [operand]
    while stack:
        current = stack.pop()
        if not isinstance(current, tuple):
            continue
        if len(current) == 2 and current[0] == "V":
            inner = current[1]
            if isinstance(inner, tuple) and inner and \
                    inner[0] == "neg":
                if _subtree_has_boolean_leaf(inner[1]):
                    return True
        stack.extend(current)
    return False


def _reject_composed_bit_operands(value, core, widths, fn_name,
                                  version):
    """Reject bit tests with provably-impossible composed operands.

    A root ``&``-chain (past root negations, which only carry
    polarity, and past outer casts, which only carry width)
    conjoins every direct operand with the chain
    mask, so one operand whose value range misses every mask
    bit makes the whole test unsatisfiable: a 0/1-valued
    operand (logical-not, comparison or logical result, past
    direct casts, which preserve 0/1) against a mask with bit
    0 clear; an arithmetic, bitwise, shift or complement
    wrapper around a 0/1-valued operand whose enumerated
    values all miss every mask bit; a left shift by ``k``
    against a mask with no bit at or above ``k`` (narrowed
    further to the base's proven unsigned width when known);
    a logical right shift of a proven-unsigned-width base
    against a mask with no bit below ``width - amount``. Each
    rejects instead of granting an impossible permission.
    A wrapper the unbounded enumeration claims satisfiable
    must also agree at every plausible C operation width (no
    missed wraparound, no complement at the wrong width);
    width-sensitive compositions reject instead of granting
    on wrong values. A wrapper the enumeration abandons --
    values escaping ``[0, 2**64)`` through C wraparound -- runs
    the width verdict too instead of skipping it, so an
    impossible wrapped permission never stays symbolic.
    Unary negation around Boolean results has no enumeration
    model and fails closed too. Satisfiable width-exact
    compositions stay symbolic, as do unproven shapes
    (variable or out-of-range amounts, unknown or signed
    bases, unprovable wrapper inputs). A root ``|``/``^``
    audits every ``&``-chain operand past cast and shift
    wrappers (a wrapper around an impossible chain is still
    impossible); any unsupported chain rejects, however
    satisfiable its siblings are, while operands that are no
    chain even past wrappers constrain nothing here.
    """
    node = value
    while node[0] == "V" and node[1][0] in ("not", "cast"):
        if node[1][0] == "not":
            node = node[1][1]
        else:
            node = node[1][1][2]
        if not (isinstance(node, tuple) and len(node) == 2 and
                node[0] == "V"):
            return

    def reject():
        raise FilterNotUnderstood(
            "kfunc filter %s@%s tests a composed bit operand "
            "in (%s); logical, comparison, shift and complement "
            "results are not plain bit-testable operands and "
            "the shape is outside the grammar"
            % (fn_name, version, " ".join(core.split())[:60]))

    def reject_width():
        raise FilterNotUnderstood(
            "kfunc filter %s@%s tests a width-sensitive "
            "composed bit operand in (%s); arithmetic around "
            "Boolean results whose value depends on the C "
            "operation width is outside the grammar"
            % (fn_name, version, " ".join(core.split())[:60]))

    def reject_negation():
        raise FilterNotUnderstood(
            "kfunc filter %s@%s tests a composed bit operand "
            "with unary negation in (%s); negated Boolean "
            "results are not plain bit-testable operands and "
            "the shape is outside the grammar"
            % (fn_name, version, " ".join(core.split())[:60]))

    def direct_operands(current):
        if current[0] == "V" and current[1][0] == "and":
            for kid in current[1][1]:
                if kid[0] == "V":
                    for found in direct_operands(kid):
                        yield found
        else:
            yield current

    def audit_and_chain(chain):
        mask = None
        for kid in chain[1][1]:
            if kid[0] == "K":
                mask = kid[1] if mask is None else mask & kid[1]
            elif kid[0] in ("C", "P") and kid[1] >= 0:
                mask = kid[1] if mask is None else mask & kid[1]
        if mask is None:
            return
        for operand in direct_operands(chain):
            if operand[0] != "V":
                continue
            inner = operand[1]
            while inner[0] == "cast":
                inner = inner[1][2]
                if not (isinstance(inner, tuple) and len(inner) == 2
                        and inner[0] == "V"):
                    inner = None
                    break
                inner = inner[1]
            if inner is None:
                continue
            if inner[0] in _COMPOSED_ZERO_ONE_TAGS:
                if mask & 1 == 0:
                    reject()
                continue
            if _composed_neg_wraps_boolean(operand):
                reject_negation()
            proved = _composed_arith_values(operand)
            if proved is not None:
                reached, has_composed = proved
                if has_composed and reached and \
                        all(item & mask == 0 for item in reached):
                    reject()
                elif has_composed and reached:
                    worlds = _composed_width_verdict(operand, mask)
                    if worlds == "all_miss":
                        reject()
                    elif worlds != "all_hit":
                        reject_width()
            elif _composed_enumerable_shape(operand):
                worlds = _composed_width_verdict(operand, mask)
                if worlds == "all_miss":
                    reject()
                elif worlds != "all_hit":
                    reject_width()
            if inner[0] not in ("shl", "shr"):
                continue
            base, amount = inner[1]
            count = _chain_const_amount(amount)
            if count is None or count < 0 or count >= 64:
                continue
            if inner[0] == "shl":
                if mask >> count == 0:
                    reject()
                    continue
                if base[0] != "V":
                    continue
                known = _operand_proven_width(base, widths)
                if known is None or known[1] or count >= known[0]:
                    continue
                reachable = ((1 << known[0]) - 1) ^ ((1 << count) - 1)
                if mask & reachable == 0:
                    reject()
                continue
            if base[0] != "V":
                continue
            known = _operand_proven_width(base, widths)
            if known is None or known[1] or count >= known[0]:
                continue
            if mask & ((1 << (known[0] - count)) - 1) == 0:
                reject()

    if node[0] != "V":
        return
    if node[1][0] in ("or", "xor"):
        first = None
        for kid in node[1][1]:
            target = kid
            while isinstance(target, tuple) and \
                    len(target) == 2 and target[0] == "V" and \
                    target[1][0] in ("cast", "shl", "shr"):
                inner = target[1][1]
                if target[1][0] == "cast":
                    target = inner[2]
                else:
                    target = inner[0]
            if not isinstance(target, tuple) or \
                    len(target) != 2 or target[0] != "V" or \
                    target[1][0] != "and":
                continue
            try:
                audit_and_chain(target)
            except FilterNotUnderstood as exc:
                if first is None:
                    first = exc
        if first is not None:
            raise first
        return
    if node[1][0] != "and":
        return
    audit_and_chain(node)


def _bit_test_facts(name, text, holds, opaque, typed_map, pipe_map,
                    multi, widths, fn_name, version,
                    cast_locals=(), expansion=None):
    """(impossible, facts, decided) for one opaque bit test.

    Non-bit placeholders constrain nothing. Atomic macros expand
    first (past nested-placeholder expansion), so the evaluated
    core is the exact tokens C compiles: a non-constant alias
    can no longer pose as a plain lvalue while hiding an
    assignment, a call or an unproven literal. Unproven operand
    shapes (``sizeof``, calls, ternaries, subscripts) reject
    before anything else; a wide mask over operands of unproven
    width rejects next (even for multi-declared names, whose
    width is ambiguous); a mask with no bits below a proven
    unsigned operand width folds the test to its constant value;
    composed operands (logical, comparison and shift results
    under a root ``&``) reject after the fold, so provably-zero
    folds still deny exactly. A test mentioning a
    multi-declared name degrades to notes-only: operand identity
    is only sound for single-binding names. Anything else
    canonicalizes (nested placeholders expanded, known constants
    substituted) and derives facts; a provably-decided test
    reports impossible when the required polarity cannot hold.
    """
    if not name.startswith("__bitop_"):
        return False, frozenset(), False
    core = _expand_bit_text(text, opaque)
    if core is None:
        raise FilterNotUnderstood(
            "kfunc filter %s@%s nests a bit test past the "
            "expansion cap in (%s); only plain lvalues and "
            "constants of known width are bit-testable, and "
            "the shape is outside the grammar"
            % (fn_name, version, " ".join(text.split())[:60]))
    core = _expand_all_macros(core, expansion)
    _reject_unbitlike_core(core, fn_name, version)
    value = _eval_bit_expr(
        core, typed_map, pipe_map, fn_name, version,
        cast_locals)
    _reject_unprovable_width(value, widths, fn_name, version)
    value = _fold_known_width_and(value, widths)
    _reject_composed_bit_operands(
        value, core, widths, fn_name, version)
    if set(re.findall(r"[A-Za-z_]\w*", core)) & multi:
        return False, frozenset(), False
    return _derive_bit_facts(value, holds)

def _opaque_notes(node, opaque, fn_name, neg=False):
    """Render restriction notes for an opaque allow-alternative.

    Negation polarity threads through ``not`` nodes: an opaque bit
    test that must hold renders "requires <FLAG> attach context"
    while one that must be clear renders "excludes <FLAG> attach
    context", so a filter allowing only when a flag is clear is
    never documented as requiring that flag.
    """
    texts = set()

    def visit(current, polarity):
        kind = current[0]
        if kind == "opaque":
            texts.add((opaque[current[1]], polarity))
        elif kind in ("and", "or"):
            for sub in current[1]:
                visit(sub, polarity)
        elif kind == "not":
            visit(current[1], not polarity)

    visit(node, neg)
    notes = set()
    for text, polarity in sorted(texts):
        consts = _opaque_consts(text)
        if consts and "&" in text:
            for const in consts:
                if polarity:
                    notes.add("excludes %s attach context (via %s)"
                              % (const, fn_name))
                else:
                    notes.add("requires %s attach context (via %s)"
                              % (const, fn_name))
        elif polarity:
            notes.add("additionally restricted by %s (not %s)"
                      % (fn_name, re.sub(r"\s+", " ", text)[:80]))
        else:
            notes.add("additionally restricted by %s (%s)"
                      % (fn_name, re.sub(r"\s+", " ", text)[:80]))
    return notes


def _helper_return_kind(text, name_start):
    """Declared return kind of a helper, or None if unproven.

    Returns ("bool",), ("uint", width) or ("sint", width) for
    plain boolean and LP64 integer return spellings (storage
    qualifiers stripped); pointers, aggregates, enums, typedef
    names and anything else are outside the proven set.
    """
    cut = max(text.rfind(";", 0, name_start),
              text.rfind("{", 0, name_start),
              text.rfind("}", 0, name_start))
    prefix = " ".join(
        line for line in text[cut + 1:name_start].splitlines()
        if not line.strip().startswith("#"))
    words = [word for word in prefix.replace("*", " * ").split()
             if word not in ("static", "inline", "const",
                             "volatile", "extern", "register")]
    if not words or "*" in words:
        return None
    if set(words) == {"bool"} or set(words) == {"_Bool"}:
        return ("bool",)
    narrow = _decl_narrow(words, False)
    if narrow is not None:
        width, signed = narrow
        return ("sint" if signed else "uint", width)
    wide = _decl_int_wide(words, False)
    if wide is None:
        return None
    width, signed = wide
    return ("sint" if signed else "uint", width)


def _collect_pred_exprs(texts, fn_name, version, renders,
                        expansion):
    """Collect single-return predicate bodies callable from a filter.

    Returns {name: (splice, mask, check_bit, orig_idents)} for
    every inlinable helper: ``splice`` is the return expression
    (a converted literal when the expression is a provable
    constant), ``mask`` the narrowing ``&``-mask for symbolic
    unsigned returns narrower than 64 bits (None otherwise),
    ``check_bit`` whether call sites need a bit-context check
    (symbolic boolean returns only), and ``orig_idents`` the
    identifiers of the pre-folding return expression, so
    dependency collection sees the helper's true inputs even
    when the splice is a folded literal. Only the active
    (post-conditional-inclusion) definition inlines:
    provably-excluded definitions never compiled, and a name
    with any unknown-region definition never inlines (unknown
    inclusion stays opaque at the call site and rejects when
    load-bearing). A helper whose own file proves its macro
    inputs unprovable (``#undef``-killed, or only defined at or
    after the helper, so C never expanded the folded value)
    never inlines either. Inlined constants convert to the
    helper's declared return type first (boolean truth,
    unsigned modulo wraparound; signed out-of-range and
    symbolic signed bodies stay unproven and never inline).
    Only one level of inlining is supported.
    """
    found = {}
    deflocs = {}
    for relpath in sorted(texts):
        clean = texts[relpath]
        for match in re.finditer(
                r"\b(\w+)\s*\(\s*(?:const\s+)?struct\s+bpf_prog\s*\*"
                r"\s*\w+\s*\)\s*\{", clean):
            name = match.group(1)
            if name == fn_name:
                continue
            state = _pp_state_at(clean, match.start())
            if state == "inactive":
                continue
            lineno = clean.count("\n", 0, match.start()) + 1
            deflocs.setdefault(name, []).append((relpath, lineno))
            try:
                body = c_brace_body(clean, match.end() - 1)
            except InventoryError:
                continue
            inner = body.strip()[1:-1].strip()
            ret = re.match(r"\s*return\b(.*);\s*$", inner, re.S)
            if ret and "?" not in ret.group(1) and \
                    ";" not in ret.group(1):
                entry = (ret.group(1).strip(),
                         _helper_return_kind(clean, match.start()))
            else:
                entry = None
            found.setdefault(name, []).append((state, entry))
    exprs = {}
    for name in sorted(found):
        actives = [entry for state, entry in found[name]
                   if state == "active"]
        unknowns = [entry for state, entry in found[name]
                    if state == "unknown"]
        if unknowns:
            continue
        cands = [entry for entry in actives if entry is not None]
        if not cands:
            continue
        first = cands[0]
        if any(entry != first for entry in cands):
            raise InventoryError(
                "kfunc filter helper %s@%s is defined twice"
                % (name, version))
        expr, kind = first
        if kind is None:
            continue
        orig = frozenset(re.findall(r"[A-Za-z_]\w*", expr))
        result = _eval_text_constexpr(expr, renders, expansion)
        if result is not None:
            value = result[0]
            if kind[0] == "bool":
                exprs[name] = ("1" if value != 0 else "0",
                               None, False, orig)
            elif kind[0] == "uint":
                rep = value & ((1 << kind[1]) - 1)
                render = _c_canonical_literal(
                    rep, kind[1], False) or "%d" % rep
                exprs[name] = (render, None, False, orig)
            elif -(1 << (kind[1] - 1)) <= value < \
                    (1 << (kind[1] - 1)):
                render = _c_canonical_literal(
                    value, kind[1], True) or "%d" % value
                exprs[name] = (render, None, False, orig)
            continue
        if kind[0] == "bool":
            exprs[name] = (expr, None, True, orig)
        elif kind[0] == "uint":
            if kind[1] >= 64:
                exprs[name] = (expr, None, False, orig)
            else:
                exprs[name] = (expr, (1 << kind[1]) - 1, False,
                               orig)
    for name in list(exprs):
        if _helper_macro_inputs_unprovable(
                texts, deflocs.get(name, ()), exprs[name][3]):
            del exprs[name]
    return exprs


def _helper_macro_inputs_unprovable(texts, deflocs, orig):
    """Whether a helper's own file disproves its macro inputs.

    C expands a helper body's macros when the definition is
    parsed, so a depended macro the helper's own file proves
    unobservable there -- ``#undef``-killed (an active define
    with nothing live, so the folded value has no source), or
    only defined at or after the helper's own line (so C never
    expanded it) -- makes the inlined value unprovable and the
    helper never inlines; its call sites stay opaque and reject
    when load-bearing. Names with no file-local directive
    activity stay provable here (cross-file inputs consult
    through the dependency closure instead).
    """
    for relpath, lineno in deflocs:
        text = _strip_c_strings(texts[relpath])
        states = _pp_line_states(text)
        live = _live_file_defines(text)
        defines = {}
        for dname, _, func_like, dlino in parse_defines(text):
            if func_like:
                continue
            if dlino - 1 < len(states) and \
                    states[dlino - 1] != "active":
                continue
            defines.setdefault(dname, []).append(dlino)
        for dep in orig:
            if dep not in defines:
                continue
            if dep not in live:
                return True
            if all(dlino >= lineno for dlino in defines[dep]):
                return True
    return False


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


def _compared_member_fields(parsed, prog_param):
    """Field names one filter's conditions consult through members.

    Covers the understood comparison leaves (type, attach type and
    the ``aux``/``st_ops`` path, including null tests) plus every
    ``prog->...`` chain spelled inside an opaque condition text
    (nested placeholders expanded), since a skipped write feeding
    any later condition -- understood or opaque -- is not
    skippable. Returns the set of consulted field names.
    """
    fields = set()

    def walk(node):
        kind = node[0]
        if kind == "type_cmp":
            fields.add("type")
        elif kind == "attach_cmp":
            fields.add("expected_attach_type")
        elif kind in ("stops_cmp", "stops_null"):
            fields.update(("aux", "st_ops"))
        elif kind == "not":
            walk(node[1])
        elif kind in ("and", "or"):
            for sub in node[1]:
                walk(sub)

    chain_re = re.compile(
        r"\b%s\b\s*((?:->|\.)\s*[A-Za-z_]\w*)+"
        % re.escape(prog_param))
    for kind, node, extra, opaque in parsed:
        if node is not None:
            walk(node)
        opaques = [opaque]
        if kind == "if" and isinstance(extra, tuple) and \
                extra and extra[0] in ("ternary", "ternary_const"):
            walk(extra[1][0])
            opaques.append(extra[1][1])
        for table in opaques:
            for name, text in table.items():
                core = _expand_bit_text(text, table)
                if core is None:
                    core = text
                for match in chain_re.finditer(core):
                    fields.update(
                        re.findall(r"[A-Za-z_]\w*", match.group(1)))
    return fields


def _prog_alias_locals(scan, prog_param, value_typed):
    """Local names that may alias program-derived state.

    A bare identifier bound (declared or assigned, subscripted
    element assignments included) from an expression mentioning
    the program parameter -- or another alias, transitively --
    may point into compared member state, so calls through such
    names may mutate it. Names with proven value types (boolean
    or converted integer in every declaration) pass by value
    and never alias; anything else -- pointers, arrays,
    typedef-headed and undeclared names -- may carry a
    reference. Member writes never bind their leaf, comparisons
    never bind, and each right-hand side ends at the next
    depth-zero ``,``/``;`` so a later declarator's initializer
    never taints an earlier one.
    """
    bindings = []
    for match in re.finditer(
            r"\b([A-Za-z_]\w*)((?:\s*\[[^\];]*\])*)\s*"
            r"(?<![=!<>+\-*/%&|^])=(?!=)", scan):
        head = scan[:match.start(1)].rstrip()
        if head.endswith("->") or head.endswith("."):
            continue
        depth = 0
        end = len(scan)
        for index in range(match.end(), len(scan)):
            char = scan[index]
            if char in "([{":
                depth += 1
            elif char in ")]}":
                if depth:
                    depth -= 1
            elif depth == 0 and char in ",;":
                end = index
                break
        bindings.append((match.group(1), scan[match.end():end]))
    aliases = set()
    changed = True
    while changed:
        changed = False
        for name, rhs in bindings:
            if name in aliases or name in value_typed:
                continue
            if re.search(r"\b%s\b" % re.escape(prog_param), rhs):
                aliases.add(name)
                changed = True
                continue
            for alias in sorted(aliases):
                if re.search(r"\b%s\b" % re.escape(alias), rhs):
                    aliases.add(name)
                    changed = True
                    break
    return aliases


def _pred_body_proven_pure(expr, expansion=None):
    """Whether an inlined helper body is proven free of mutations.

    A pure body -- no assignment (outside ``==``, ``!=``,
    ``<=``, ``>=``), increment/decrement, comma expression or
    call -- evaluates without changing file bindings or member
    state, so a statement call to it invalidates nothing.
    ``sizeof`` is no call (its operand is unevaluated, and any
    effect inside still trips the other checks). The check runs
    on the macro-expanded body: C compiles the expanded
    tokens, so an effect hidden behind an alias still
    invalidates. Call recognition sees through parentheses and
    indirection: a call through a parenthesized callee
    (``(f)(q)``) or a subscript (``table[i](q)``) is still a
    call -- only a cast group ahead of the second group (``(u32)
    (x)``) is grouping, never a call. Anything else may mutate
    and never earns the predicate exemption.
    """
    text = _strip_c_strings(_expand_all_macros(expr, expansion))
    if re.search(r"(?<![=!<>])=(?!=)", text):
        return False
    if "++" in text or "--" in text:
        return False
    if "," in text:
        return False
    if re.search(r"\b(?!sizeof\b)[A-Za-z_]\w*\s*\(", text):
        return False
    if re.search(r"\]\s*\(", text):
        return False
    for match in re.finditer(r"\)\s*\(", text):
        depth = 0
        open_pos = None
        for index in range(match.start(), -1, -1):
            char = text[index]
            if char == ")":
                depth += 1
            elif char == "(":
                depth -= 1
                if depth == 0:
                    open_pos = index
                    break
        if open_pos is None:
            return False
        if _is_cast_group(text[open_pos + 1:match.start()]):
            continue
        return False
    return True


def _reject_invalidated_file_bindings(body, consulted, mutable,
                                      blocked, pred_exprs, fn_name,
                                      version, helper_scope=(), order=(),
                                      param_names=(), straight=(),
                                      expansion=None):
    """Reject consulted mutable file bindings the body disturbs.

    A mutable file-scope object consults by its initializer
    value, which a body write (plain, compound,
    increment/decrement or address-take, past redundant
    parentheses, outside member access) or any straight-line
    call (proven-pure single-return predicates excepted --
    anything else, including a mutating or comma-bearing
    predicate, may change it -- and parenthesized callees and
    subscripted callees included) may change; a consulted
    binding with either in the body is outside the grammar.
    The write scan runs on the macro-expanded body, so an
    assignment hidden behind a macro-only statement never
    keeps a stale initializer. The call scan runs on the
    macro-expanded straight-line statements, so a call hidden
    behind a macro-only statement never escapes it. Both scans
    run past line splices (a backslash-newline joins tokens in
    C before any recognition, so a spliced call or write
    counts). Purity is proven on the macro-expanded predicate
    body, so a mutation hidden behind an alias never earns
    the exemption. Calls inside conditions evaluate
    downstream (inlined or opaque) and never reach this scan.
    A ``)(`` group is a call unless it declares a function
    pointer or casts through a genuinely unbound type spelling
    (a typedef shadowed by a locally-bound name is a callee,
    never a cast), so a harmless cast statement never
    invalidates. Helper-scope dependencies consult
    the file binding even when the caller shadows their names,
    so shadowing never suppresses them; their body writes
    count only where the name still resolves to file scope
    (ahead of the caller's first declaration, or nowhere for
    parameters), while calls count everywhere. Other locally
    shadowed names never consult the file binding and are
    ignored.
    """
    helper_targets = set(helper_scope) & set(mutable)
    targets = sorted(
        ((set(consulted) & set(mutable)) - set(blocked)) |
        helper_targets)
    if not targets:
        return
    scan = _strip_c_attributes(_strip_c_strings(body))
    first = {}
    for pos, name, _, _, _ in order:
        if name not in first:
            first[name] = pos
    params = set(param_names)
    inner = scan.strip()
    if inner.startswith("{") and inner.endswith("}"):
        inner = inner[1:-1]
    for name in targets:
        scoped = scan
        if name in helper_targets and name in blocked:
            if name in params:
                scoped = ""
            elif name in first:
                scoped = inner[:first[name]]
            # else: shadowed only inside a nested block (or a
            # non-value binding): the file binding stays
            # reachable elsewhere, so every spelling counts.
        expanded_scoped = _strip_line_splices(_strip_c_attributes(
            _strip_c_strings(
                _expand_all_macros(scoped, expansion))))
        if _local_write_positions(expanded_scoped, name, False, 0):
            raise FilterNotUnderstood(
                "kfunc filter %s@%s writes consulted mutable "
                "file binding %s; the initializer value no "
                "longer decides and the shape is outside the "
                "grammar" % (fn_name, version, name))
    calls = _strip_line_splices(_strip_c_attributes(
        _strip_c_strings(
            _expand_all_macros("\n".join(straight), expansion))))

    def reject_paren_call():
        raise FilterNotUnderstood(
            "kfunc filter %s@%s calls through parentheses while "
            "consulting mutable file binding %s; the call may "
            "mutate it and the shape is outside the grammar"
            % (fn_name, version, targets[0]))

    for match in re.finditer(r"\)\s*\(", calls):
        depth = 0
        open_pos = None
        for index in range(match.start(), -1, -1):
            char = calls[index]
            if char == ")":
                depth += 1
            elif char == "(":
                depth -= 1
                if depth == 0:
                    open_pos = index
                    break
        if open_pos is None:
            reject_paren_call()
        callee_text = calls[open_pos + 1:match.start()]
        arg_open = match.end() - 1
        arg_depth = 0
        arg_end = None
        for index in range(arg_open, len(calls)):
            char = calls[index]
            if char == "(":
                arg_depth += 1
            elif char == ")":
                arg_depth -= 1
                if arg_depth == 0:
                    arg_end = index
                    break
        if arg_end is None:
            reject_paren_call()
        args = calls[match.end():arg_end]
        if _paren_call_is_declaration(callee_text, args):
            continue
        if _is_cast_group(callee_text) and \
                not _cast_group_shadowed(callee_text, blocked):
            continue
        reject_paren_call()
    if re.search(r"\]\s*\(", calls):
        raise FilterNotUnderstood(
            "kfunc filter %s@%s calls through a subscript while "
            "consulting mutable file binding %s; the call may "
            "mutate it and the shape is outside the grammar"
            % (fn_name, version, targets[0]))
    for match in re.finditer(r"\b([A-Za-z_]\w*)\s*\(", calls):
        callee = match.group(1)
        if callee in ("if", "return", "sizeof"):
            continue
        if callee in pred_exprs and \
                _pred_body_proven_pure(
                    pred_exprs[callee][0], expansion):
            continue
        raise FilterNotUnderstood(
            "kfunc filter %s@%s calls %s while consulting "
            "mutable file binding %s; the call may mutate it "
            "and the shape is outside the grammar"
            % (fn_name, version, callee[:40], targets[0]))


def _paren_call_callee(text):
    """Canonical callee of a call-through-parens group, or None.

    Strips redundant parentheses and pointer dereferences around
    the callee expression (``(f)``, ``(*f)``, ``(**f)`` all name
    ``f``); anything else (an operator, a call result, a member
    path) is unrecognized and yields None.
    """
    current = text.strip()
    while True:
        while current.startswith("*"):
            current = current[1:].strip()
        if len(current) >= 2 and current.startswith("(") and \
                current.endswith(")"):
            depth = 0
            balanced = True
            for char in current[1:-1]:
                if char == "(":
                    depth += 1
                elif char == ")":
                    depth -= 1
                    if depth < 0:
                        balanced = False
                        break
            if not balanced or depth != 0:
                return None
            current = current[1:-1].strip()
            continue
        break
    if re.fullmatch(r"[A-Za-z_]\w*", current):
        return current
    return None


_PARAM_DECL_WORDS = frozenset(
    _CAST_WORDS | {"struct", "union", "enum"})


def _paren_call_is_declaration(callee_text, args):
    """Whether a ``)(`` shape declares a function pointer.

    A declaration ``R (*fp)(P)`` and a dereferenced call
    ``(*fp)(A)`` share their prefix and differ only in the
    second group: parameter declarations name types while call
    arguments name values. A group whose callee holds ``*``
    and whose every comma-separated part names a type word
    (or is empty or ``...``) is a declaration; anything else
    is a call. Empty argument lists never invalidate either
    way and always count as calls.
    """
    if "*" not in callee_text or not args.strip():
        return False
    for part in _split_depth0(args, ","):
        words = set(re.findall(r"[A-Za-z_]\w*", part))
        if words <= {"void"} or "..." in part:
            continue
        if words & _PARAM_DECL_WORDS:
            continue
        return False
    return True


def _reject_compared_member_writes(body, parsed, prog_param, pred_exprs,
                                   fn_name, version,
                                   value_typed=(), straight=(),
                                   expansion=None, shadowed=()):
    """Reject skipped writes that feed a later member comparison.

    Straight-line member writes (plain, compound and
    increment/decrement assignments through any pointer, past
    redundant parentheses), address-takes of a compared member
    path, and straight-line calls mentioning the program
    parameter or any local that may alias program-derived state
    (declared or assigned from ``prog``, transitively, except
    names with proven value types, which pass by value) -- which
    may mutate compared members through it -- are outside the
    grammar whenever the filter compares that member later
    (grammar rule S5). Only proven-pure single-return predicates
    earn an exemption, with purity proven on the macro-expanded
    body; a mutating or comma-bearing predicate (however
    aliased) may change compared state and invalidates like
    any other call.
    Calls inside conditions evaluate downstream (inlined or
    opaque) and never reach this scan. The scan runs on the
    macro-expanded straight-line statements, so a call hidden
    behind a macro-only statement invalidates like a direct
    one. Call recognition sees through parentheses,
    dereferences and indirection: ``(f)(q)``, ``(*f)(q)`` and
    ``table[i](q)`` invalidate like ``f(q)`` (an unrecognized
    callee shape invalidates whenever its arguments mention
    the program or an alias), while a function-pointer
    declaration (type words in the second group) and a cast
    (a genuinely unbound type group ahead of the second
    group) declare nothing to invalidate. Cast recognition is
    scope-aware: a typedef spelling shadowed by a name in
    ``shadowed`` is a callee, never a cast. Writes match by
    leaf field name
    across any base pointer, since a foreign pointer may alias
    the program object, and an intermediate path (``prog->aux``)
    counts when a longer compared path runs through it. With no
    compared member the scan passes: uncompared writes cannot
    change the verdict.
    """
    compared = _compared_member_fields(parsed, prog_param)
    if not compared:
        return
    base = strip_comments(_strip_c_strings(body))
    base = re.sub(r"^[ \t]*#(?:\\\n|[^\n])*",
                  lambda match: "\n" * match.group(0).count("\n"),
                  base, flags=re.M)
    base = _strip_c_attributes(base)

    def collapse_chains(text):
        while True:
            updated = re.sub(
                r"\(\s*([A-Za-z_]\w*(?:\s*(?:->|\.)\s*[A-Za-z_]\w*)+)"
                r"\s*\)", r" \1 ", text)
            if updated == text:
                return text
            text = updated

    scan = collapse_chains(_strip_redundant_parens(base, ()))
    # Call shapes keep their parens: the redundant-paren strip
    # would eat single-argument calls (``f(prog)``), hiding the
    # callee from the mutation scan below. Calls scan only the
    # skipped straight-line statements: calls inside conditions
    # evaluate downstream instead of invalidating here.
    straight_base = strip_comments(_strip_c_strings(
        _expand_all_macros("\n".join(straight), expansion)))
    straight_base = re.sub(
        r"^[ \t]*#(?:\\\n|[^\n])*",
        lambda match: "\n" * match.group(0).count("\n"),
        straight_base, flags=re.M)
    straight_base = _strip_c_attributes(straight_base)
    cscan = collapse_chains(straight_base)

    def reject(what):
        raise FilterNotUnderstood(
            "kfunc filter %s@%s writes compared member state %s "
            "outside a condition; skipped writes that feed a later "
            "comparison are outside the grammar"
            % (fn_name, version, what))

    chain_re = re.compile(
        r"[A-Za-z_]\w*((?:\s*(?:->|\.)\s*[A-Za-z_]\w*)+)")
    assign_re = re.compile(
        r"\s*(=(?!=)|\+=|-=|\*=|/=|%=|&=|\|=|\^=|<<=|>>=|"
        r"\+\+|--)")
    for match in chain_re.finditer(scan):
        leaf = re.findall(r"[A-Za-z_]\w*", match.group(0))[-1]
        if leaf not in compared:
            continue
        if assign_re.match(scan, match.end()):
            reject(match.group(0).strip()[:40])
        if re.search(r"(\+\+|--)\s*$",
                     scan[:match.start()]):
            reject(match.group(0).strip()[:40])
    for match in re.finditer(r"(?<![&])&(?![&=])", scan):
        back = scan[:match.start()].rstrip()
        if back and back[-1] not in "= (,;{[!~+-*/%<>&|^?:}":
            continue
        chained = chain_re.match(scan, match.end())
        if chained is None:
            continue
        leaf = re.findall(r"[A-Za-z_]\w*", chained.group(0))[-1]
        if leaf in compared:
            reject("&" + chained.group(0).strip()[:40])
    aliases = _prog_alias_locals(
        collapse_chains(_strip_redundant_parens(straight_base, ())),
        prog_param, value_typed)
    alias_re = None
    if aliases:
        alias_re = re.compile(
            r"\b(?:%s)\b" % "|".join(
                re.escape(name) for name in sorted(aliases)))
    calls = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
    prog_re = re.compile(r"\b%s\b" % re.escape(prog_param))

    def args_mention_prog(args):
        if prog_re.search(args):
            return True
        return alias_re is not None and alias_re.search(args)

    def balanced_end(text, open_pos):
        depth = 0
        for index in range(open_pos, len(text)):
            char = text[index]
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    return index
        return None

    for match in calls.finditer(cscan):
        callee = match.group(1)
        if callee in ("if", "return", "sizeof"):
            continue
        if callee in pred_exprs and \
                _pred_body_proven_pure(
                    pred_exprs[callee][0], expansion):
            continue
        end = balanced_end(cscan, match.end() - 1)
        if end is None:
            reject("in call %s" % callee[:40])
        if args_mention_prog(cscan[match.end():end]):
            reject("in call %s" % callee[:40])
    for match in re.finditer(r"\)\s*\(", cscan):
        depth = 0
        open_pos = None
        for index in range(match.start(), -1, -1):
            char = cscan[index]
            if char == ")":
                depth += 1
            elif char == "(":
                depth -= 1
                if depth == 0:
                    open_pos = index
                    break
        if open_pos is None:
            reject("in call %s" % cscan[:40])
        callee_text = cscan[open_pos + 1:match.start()]
        arg_open = match.end() - 1
        end = balanced_end(cscan, arg_open)
        if end is None:
            reject("in call %s" % callee_text.strip()[:40])
        args = cscan[match.end():end]
        if _paren_call_is_declaration(callee_text, args):
            continue
        if _is_cast_group(callee_text) and \
                not _cast_group_shadowed(callee_text, shadowed):
            continue
        callee = _paren_call_callee(callee_text)
        if callee is not None and (
                callee in ("if", "return", "sizeof") or
                (callee in pred_exprs and _pred_body_proven_pure(
                    pred_exprs[callee][0], expansion))):
            continue
        if args_mention_prog(args):
            reject("in call %s"
                   % (callee if callee is not None
                      else callee_text.strip()[:40])[:40])
    for match in re.finditer(r"\]\s*\(", cscan):
        arg_open = match.end() - 1
        end = balanced_end(cscan, arg_open)
        if end is None:
            reject("in call [...]%s" % cscan[:40])
        if args_mention_prog(cscan[match.end():end]):
            names = re.findall(r"[A-Za-z_]\w*",
                               cscan[:match.start()])
            base = names[-1] if names else "table"
            reject("in call %s[...]" % base[:40])


def _reverse_const_map(values, prefix, excluded):
    """{value: unique name} for one constant class.

    Only names with ``prefix`` (minus any ``excluded`` prefix)
    qualify; a value carried by two names is ambiguous and maps to
    nothing, so shadow resolution never guesses between aliases.
    """
    rev = {}
    ambiguous = set()
    for name in sorted(values):
        if not name.startswith(prefix):
            continue
        if any(name.startswith(what) for what in excluded):
            continue
        value = values[name]
        if value in ambiguous:
            continue
        if value in rev:
            del rev[value]
            ambiguous.add(value)
            continue
        rev[value] = name
    return rev


def simulate_kfunc_filter(fn_name, texts, version, members, membersets,
                          hook_types, const_values=None):
    """Simulate one ``.filter`` callback over callers and members.

    ``texts`` maps relpaths to comment-stripped version sources,
    ``members`` lists the governed set members, ``membersets`` maps
    every ID-block name to its member set and ``hook_types`` lists
    the candidate caller program types. ``const_values`` optionally
    carries the pipeline-pinned integer constants for ``version``;
    each is the mathematical value of an LP64 int-or-wider object
    (all UAPI enum/macro sources qualify), since value-only
    reasoning assumes at least 32-bit width. File-local constants
    carry their exact widths instead.
    Returns {member: verdict}
    where each verdict holds the allowed program types ("types", a
    subset of ``hook_types``), the unioned attach/stops value sets
    and restriction notes ("attach"/"stops"/"notes"), the per-caller
    alternative lists ("by_caller": {caller: [conjunctions]}) and
    the caller-grouped scoped alternatives ("alternatives":
    [{callers, attach, stops, notes}]). Program-type atoms decide
    directly; attach and struct_ops atoms narrow the context without
    deciding, since the pinned load path default-allows unexpected
    attach pairings and struct_ops values are not statically known.
    Any construct outside FILTER_BODY_GRAMMAR raises
    FilterNotUnderstood and the filter yields no permission.
    """
    found = None
    found_state = None
    saw_inactive = False
    for relpath in sorted(texts):
        for offset, params, body in _c_definition_hits(
                texts[relpath], fn_name):
            state = _pp_state_at(texts[relpath], offset)
            if state == "inactive":
                saw_inactive = True
                continue
            if found is not None:
                if found_state == "unknown" or state == "unknown":
                    raise FilterNotUnderstood(
                        "kfunc filter %s@%s has a conditionally-"
                        "included duplicate definition; the compiled "
                        "definition is unproven and outside the grammar"
                        % (fn_name, version))
                raise InventoryError(
                    "kfunc filter %s@%s is defined twice"
                    % (fn_name, version))
            found = (params, body)
            found_state = state
            break
    if found is None:
        if saw_inactive:
            raise FilterNotUnderstood(
                "kfunc filter %s@%s is conditionally excluded from "
                "the pinned sources; an excluded filter yields no "
                "permission"
                % (fn_name, version))
        raise InventoryError(
            "kfunc filter %s@%s is not defined in the pinned sources"
            % (fn_name, version))
    if found_state == "unknown":
        raise FilterNotUnderstood(
            "kfunc filter %s@%s sits in a conditionally-included "
            "region the evaluator cannot prove; unproven "
            "preprocessor state is outside the grammar"
            % (fn_name, version))
    params, body = found
    if re.search(r"^[ \t]*#", _strip_c_strings(body), flags=re.M):
        raise FilterNotUnderstood(
            "kfunc filter %s@%s contains a preprocessor directive "
            "inside its body; preprocessor use inside a body is "
            "outside the grammar"
            % (fn_name, version))
    prog_param = _filter_prog_param(params, fn_name, version)
    id_param = _filter_id_param(params, prog_param)
    ret_bits = _filter_return_bits(texts, fn_name, version)
    values, typed, contested, mutable = _filter_const_maps(
        texts, const_values)
    extra_types = _typedef_defined_names(body)
    for relpath in sorted(texts):
        extra_types |= _typedef_defined_names(texts[relpath])
    pipeline_names = set(const_values or ())
    expansion = _prepare_macro_expansion(
        {name: body for name, body in
         _merge_file_defines(texts).items()
         if name not in pipeline_names})
    errno_blocked = _filter_errno_blocked(texts)
    aliases, stmts, blocked, local_values, multi, widths, order, \
        value_typed, straight = _split_filter_body(
            body, params, prog_param, fn_name, version, values,
            typed, ret_bits, extra_types, expansion,
            errno_blocked, mutable)
    file_renders = {}
    for name, value in values.items():
        if name in typed:
            file_renders[name] = \
                _c_canonical_literal(*typed[name]) or "%d" % value
        else:
            file_renders[name] = "%d" % value
    file_renders.setdefault("true", "1")
    file_renders.setdefault("false", "0")
    pred_exprs = _collect_pred_exprs(
        texts, fn_name, version, file_renders, expansion)
    helper_idents = _called_helper_idents(
        pred_exprs, stmts, prog_param, expansion)
    consulted = _pp_consulted_names(
        params, body, stmts, order, _pp_file_reftexts(texts),
        helper_idents)
    unproven = set()
    for relpath in sorted(texts):
        unproven |= _pp_unproven_names(texts[relpath])
    bad = sorted((unproven | contested) & consulted)
    if bad:
        raise FilterNotUnderstood(
            "kfunc filter %s@%s consults %s with unproven "
            "preprocessor state (conditional inclusion or "
            "redefinition); unproven state is outside the grammar"
            % (fn_name, version, ", ".join(bad[:5])))
    rev_type = _reverse_const_map(values, "BPF_PROG_TYPE_", ())
    rev_attach = _reverse_const_map(values, "BPF_", ("BPF_PROG_TYPE_",))
    typed_map = {name: triple for name, triple in typed.items()
                 if name not in blocked}
    pipe_map = {name: value for name, value in values.items()
                if name not in typed and name not in blocked}
    pipe_map.update(local_values)
    param_names = frozenset(_filter_param_names(params, prog_param))
    _reject_invalidated_file_bindings(
        body, consulted, mutable, blocked, pred_exprs, fn_name,
        version, helper_idents, order, param_names, straight,
        expansion)
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
            cond, prog_param, id_param, aliases, pred_exprs, fn_name,
            version, blocked, local_values, rev_type, rev_attach,
            param_names, expansion, values)
        if kind == "if" and extra[0] in ("ternary", "ternary_const"):
            inner_node, inner_opaque = _parse_condition(
                extra[1], prog_param, id_param, aliases, pred_exprs,
                fn_name, version, blocked, local_values, rev_type,
                rev_attach, param_names, expansion, values)
            extra = (extra[0], (inner_node, inner_opaque), extra[2])
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
    _reject_compared_member_writes(
        body, parsed, prog_param, pred_exprs, fn_name, version,
        value_typed, straight, expansion, blocked)
    results = {}
    for member in members:
        by_caller = {}
        for prog_type in hook_types:
            alts = _simulate_filter_caller(
                parsed, prog_type, member, membersets,
                fn_name, version, typed_map, pipe_map, multi,
                widths, blocked, expansion)
            by_caller[prog_type] = _normalize_alts(alts)
        allowed = set(
            prog_type for prog_type, alts in by_caller.items() if alts)
        attach_union = set()
        stops_union = set()
        notes_union = set()
        for alts in by_caller.values():
            for areq, sreq, _, _, _, notes in alts:
                attach_union |= set(areq)
                stops_union |= set(sreq)
                notes_union |= set(notes)
        results[member] = {
            "types": allowed,
            "attach": attach_union,
            "stops": stops_union,
            "notes": sorted(notes_union),
            "by_caller": {
                prog_type: [
                    (set(areq), set(sreq), set(aexc), set(sexc),
                     set(obits), set(notes))
                    for areq, sreq, aexc, sexc, obits, notes in alts]
                for prog_type, alts in by_caller.items()
            },
            "alternatives": _group_alternatives(by_caller),
        }
    return results


def _normalize_alts(alts):
    """Normalize alternative conjunctions and prune dominated ones.

    Exact duplicates collapse, and an unconditional alternative
    dominates its caller's conditional ones since it grants
    everything they do.
    """
    seen = []
    for alt in alts:
        if alt not in seen:
            seen.append(alt)
    if _CONJ_UNCONSTRAINED in seen:
        return [_CONJ_UNCONSTRAINED]
    return seen


def _group_alternatives(by_caller):
    """Group {caller: [alternatives]} into scoped alternatives.

    Callers sharing identical requirements merge into one
    alternative; branch alternatives with different requirements
    stay distinct. Exclusion constraints render as their notes.
    Returns [{callers, attach, stops, notes}] with sorted lists in
    deterministic order.
    """
    groups = {}
    for caller in sorted(by_caller):
        for alt in by_caller[caller]:
            areq, sreq, aexc, sexc, _, notes = alt
            rendered = set(notes)
            for value in aexc:
                rendered.add(
                    "excludes expected_attach_type %s" % value)
            for value in sexc:
                rendered.add(
                    "rejected when attached to %s" % value)
            key = (frozenset(areq), frozenset(sreq),
                   frozenset(rendered))
            groups.setdefault(key, set()).add(caller)
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

    Returns the cartesian product with conjoined requirements;
    contradictory combinations drop out, and an empty result means
    the hook denies this caller.
    """
    acc = [_CONJ_UNCONSTRAINED]
    for alts in per_filt:
        merged = []
        for base in acc:
            for extra in alts:
                out = _conj_merge(base, extra)
                if out is not None:
                    merged.append(out)
        acc = merged
        if not acc:
            break
    return acc


def _simulate_filter_caller(stmts, prog_type, member, membersets,
                            fn_name, version, typed_map, pipe_map,
                            multi, widths, cast_locals=(),
                            expansion=None):
    """Simulate one filter over a single (caller, member) pair.

    Returns the list of allow-alternatives, each a context
    conjunction giving the requirements under which this caller may
    call this member. The empty list means denied. The fall-through
    path is itself a disjunction of conjunctions: each deny
    narrowing distributes over it, and each allow branch grants the
    paths crossed with the branch alternatives. A final allow keeps
    every earlier grant; contradictory combinations drop out, so a
    requirement that can never fire yields no permission.
    """
    paths = [_CONJ_UNCONSTRAINED]
    granted = []

    def audit_for(branch_opaque):
        def audit(dropped):
            _audit_dropped_condition(
                dropped, branch_opaque, fn_name, version,
                typed_map, pipe_map, multi, widths, cast_locals,
                expansion)
        return audit

    def grant(branch):
        for base in paths:
            for extra in branch:
                merged = _conj_merge(base, extra)
                if merged is not None:
                    granted.append(merged)

    def allow_half(node, opaque):
        """Grant the paths crossed with this allow branch.

        Returns True when the fall-through path is dead (the branch
        condition holds unconditionally), in which case later
        statements are unreachable. The fall-through path keeps no
        narrowing from an allow branch: paths where the branch
        condition holds were granted here already.
        """
        folded = _fold_condition(
            node, prog_type, member, membersets,
            audit_for(opaque))
        if folded == ("const", True):
            granted.extend(paths)
            return True
        if folded == ("const", False):
            return False
        if folded == ("not", ("stops_null",)):
            # Load-phase leniency while st_ops is unset: the verifier
            # re-runs the filter once attachment is known, so the
            # transient allow is not a steady-state caller permission
            # and narrowing must still apply below (fail closed).
            return False
        grant(_dnf_condition(
            folded, opaque, fn_name, version, allow=True,
            typed_map=typed_map, pipe_map=pipe_map, multi=multi,
            widths=widths, cast_locals=cast_locals,
            expansion=expansion))
        return False

    def deny_half(node, opaque):
        """Narrow the fall-through paths with this deny requirement.

        Returns True when the fall-through path is dead (the deny
        condition holds unconditionally, or the narrowed paths are
        all contradictory), in which case later statements are
        unreachable.
        """
        folded = _fold_condition(
            node, prog_type, member, membersets,
            audit_for(opaque))
        if folded == ("const", True):
            return True
        if folded == ("const", False):
            return False
        required = _dnf_condition(
            _negate_condition(folded), opaque, fn_name, version,
            allow=False, typed_map=typed_map, pipe_map=pipe_map,
            multi=multi, widths=widths, cast_locals=cast_locals,
            expansion=expansion)
        narrowed = []
        for base in paths:
            for extra in required:
                merged = _conj_merge(base, extra)
                if merged is not None:
                    narrowed.append(merged)
        paths[:] = narrowed
        return not narrowed

    def run_ternary(inner_node, inner_opaque, allow_first):
        """Decide a ``return (C) ? 0 : -E`` statement.

        Returns the granted alternatives: the allow arm grants the
        paths crossed with its alternatives while the deny arm dies,
        so only previously granted alternatives survive a taken deny
        arm.
        """
        folded = _fold_condition(
            inner_node, prog_type, member, membersets,
            audit_for(inner_opaque))
        if folded == ("const", True):
            if allow_first:
                return list(granted + paths)
            return list(granted)
        if folded == ("const", False):
            if allow_first:
                return list(granted)
            return list(granted + paths)
        if allow_first:
            arm = _dnf_condition(
                folded, inner_opaque, fn_name, version, allow=True,
                typed_map=typed_map, pipe_map=pipe_map, multi=multi,
                widths=widths, cast_locals=cast_locals,
                expansion=expansion)
        else:
            arm = _dnf_condition(
                _negate_condition(folded), inner_opaque, fn_name,
                version, allow=True, typed_map=typed_map,
                pipe_map=pipe_map, multi=multi, widths=widths,
                cast_locals=cast_locals, expansion=expansion)
        grant(arm)
        return list(granted)

    def run_const_ternary(inner_node, inner_opaque, allows):
        """Decide a ``return (C) ? K : K`` statement (identical arms).

        The verdict is constant, but C still evaluates the
        condition: audit it whole as dropped -- short-circuit
        leaves included -- so an erased foreign read, comparison
        or side effect rejects instead of vanishing, then grant
        like the matching terminal arm.
        """
        audit_for(inner_opaque)(inner_node)
        if allows:
            granted.extend(paths)
        return list(granted)

    for kind, node, extra, opaque in stmts:
        if kind == "allow":
            granted.extend(paths)
            return list(granted)
        if kind == "deny":
            return list(granted)
        if kind == "ternary":
            return run_ternary(node, opaque, extra)
        if kind == "ternary_const":
            return run_const_ternary(node, opaque, extra)
        # kind == "if": the branch kind decides the halves.
        branch, branch_extra, allow_first = extra
        if branch == "allow":
            if allow_half(node, opaque):
                return list(granted)
        elif branch == "deny":
            if deny_half(node, opaque):
                return list(granted)
        elif branch == "ternary_const":
            folded_outer = _fold_condition(
                node, prog_type, member, membersets,
                audit_for(opaque))
            if folded_outer == ("const", False):
                audit_for(branch_extra[1])(branch_extra[0])
                continue
            audit_for(branch_extra[1])(branch_extra[0])
            if allow_first:
                if allow_half(node, opaque):
                    return list(granted)
            elif deny_half(node, opaque):
                return list(granted)
        else:  # ternary branch under the if condition
            folded_outer = _fold_condition(
                node, prog_type, member, membersets,
                audit_for(opaque))
            inner_node, inner_opaque = branch_extra
            if folded_outer == ("const", False):
                audit_for(inner_opaque)(inner_node)
                continue
            if folded_outer != ("const", True):
                raise FilterNotUnderstood(
                    "kfunc filter %s@%s nests a ternary under a "
                    "partial condition; cannot scope it"
                    % (fn_name, version))
            return run_ternary(inner_node, inner_opaque, allow_first)
    if not granted:
        raise FilterNotUnderstood(
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


def kfunc_callable_types(tables, version, prog_types, const_values=None):
    """Return {kfunc: per-version verdicts} for one version.

    Each verdict holds refs/flags/types/attach/stops/notes plus the
    caller-grouped scoped alternatives ("alternatives"), the
    evaluated registration filters ("filters") and the unrecognized
    governing filters ("needs_owner"). Evaluation follows the pinned
    kernel matching order: each hook owns the union of its
    registered sets and the deduped list of its registration
    filters (btf_populate_kfunc_set), and a caller may call a member
    when the member sits in the COMMON set or its typed hook's set
    and every filter on that hook allows (btf_kfunc_is_allowed).
    Grants via either hook suffice; denials by any hook filter deny
    that hook, including for members of unfiltered sets. A filter
    outside FILTER_BODY_GRAMMAR denies by default: every member
    registered on its hooks is callable:false for this version and
    flagged for owner review, even when another hook would grant.
    Extension programs inherit their target and are covered by the
    prog:EXT record, not listed here.
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
    unrecognized = {}
    for filt in sorted(all_filts):
        try:
            sims[filt] = simulate_kfunc_filter(
                filt, tables["kernel_texts"], version,
                sorted(all_bound), membersets, concrete,
                const_values=const_values)
        except FilterNotUnderstood as exc:
            unrecognized[filt] = str(exc)
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
                       "alternatives": {}, "needs_owner": {}})
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
        slot["needs_owner"].setdefault(version, [])
        if name not in all_bound:
            # A referenced but never registered set: present in the
            # source, bound to no program type. Still inventoried,
            # with no callable contexts.
            slot["filtered"][version] = False
            continue
        member_hooks = sorted(
            hook for hook, members in hook_members.items()
            if name in members)
        unrec = sorted(
            filt for hook in member_hooks
            for filt in hook_filters.get(hook, ())
            if filt in unrecognized)
        if unrec:
            # Default-deny: an unrecognized governing filter yields
            # no permission for this version, however other hooks
            # would decide. The record carries the reason and fails
            # completeness until an owner extends the grammar.
            slot["needs_owner"][version] = [
                "filter %s (%s): %s" % (filt, version,
                                        unrecognized[filt])
                for filt in unrec]
            slot["filtered"][version] = False
            for filt in unrec:
                if filt in filter_files:
                    slot["filters"][version].add(
                        (filt, filter_files[filt]))
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
                    combined.append(_CONJ_UNCONSTRAINED)
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
            for areq, sreq, _, _, _, notes in alts:
                slot["attach"][version] |= set(areq)
                slot["stops"][version] |= set(sreq)
                slot["notes"][version] |= set(notes)
        uncond_sets = (set(), set(), set(), set(), set(), set())
        for hook in member_hooks:
            for filt in sorted(hook_filters.get(hook, ())):
                verdict = sims[filt][name]
                if all(alts == [uncond_sets]
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
        for key in slot["needs_owner"]:
            slot["needs_owner"][key] = sorted(slot["needs_owner"][key])
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
        version_values = {}
        for atom_name, atom in atoms.items():
            value = atom.values.get(version)
            if isinstance(value, int) and not isinstance(value, bool):
                version_values[atom_name] = value
        for name, slot in kfunc_callable_types(
                tables, version, uapi_prog_types[version],
                version_values).items():
            dest = kfunc_index.setdefault(
                name, {"refs": [], "flags": {}, "types": {},
                       "attach": {}, "stops": {}, "notes": {},
                       "filtered": {}, "filters": {}, "fmodret": [],
                       "alternatives": {}, "needs_owner": {}})
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
            dest["needs_owner"][version] = slot["needs_owner"][version]
        for block in tables["fmodret_blocks"]:
            info = tables["kfunc_sets"][block]
            for name, _ in info["members"]:
                if block in bound:
                    dest = kfunc_index.setdefault(
                        name, {"refs": [], "flags": {}, "types": {},
                               "attach": {}, "stops": {}, "notes": {},
                               "filtered": {}, "filters": {},
                               "fmodret": [], "alternatives": {},
                               "needs_owner": {}})
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
        flagged = sorted(reason
                         for version in present
                         for reason in slot["needs_owner"][version])
        if flagged and not callable:
            predicate = (
                "kernel kfunc %s (first pinned in %s) is registered "
                "but a governing filter uses constructs outside the "
                "understood grammar; callable:false by default-deny"
                % (name, oldest)
            )
            next_action = ("Assign an owner to extend the filter "
                           "grammar and tests under X-KFUNCS.")
        elif callable:
            predicate = (
                "kernel kfunc %s (first pinned in %s) is registered "
                "for %d program types"
                % (name, oldest, type_count)
            )
            next_action = ("Implement the typed kfunc binding "
                           "under X-KFUNCS.")
            if flagged:
                next_action += (" Assign an owner to extend the "
                                "filter grammar and tests for the "
                                "remaining versions.")
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
        if flagged:
            record["needs_owner_review"] = flagged
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
            elif slot["needs_owner"][version]:
                for reason in slot["needs_owner"][version]:
                    predicates.append("NEEDS-OWNER: %s" % reason)
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
        if entry.get("needs_owner_review"):
            errors.append(
                "%s: needs owner review: %s"
                % (rec_id, "; ".join(entry["needs_owner_review"]))
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
