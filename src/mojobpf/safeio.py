"""Capped regular-file reads and streamed hashing for untrusted inputs.

The core lives in :mod:`mojobpf.execution` (stdlib only: that module is
mirrored standalone into native bundles and must stay free of
``mojobpf`` imports) and is re-exported here as the stable home the
other readers import.
"""

from .execution import (
    DIST_LIMIT,
    IR_LIMIT,
    JSON_LIMIT,
    LOCK_LIMIT,
    MANIFEST_LIMIT,
    MOJO_LIMIT,
    OBJECT_LIMIT,
    FileTooLargeError,
    NonRegularFileError,
    hash_file_capped,
    read_capped,
)

__all__ = [
    "DIST_LIMIT",
    "IR_LIMIT",
    "JSON_LIMIT",
    "LOCK_LIMIT",
    "MANIFEST_LIMIT",
    "MOJO_LIMIT",
    "OBJECT_LIMIT",
    "FileTooLargeError",
    "NonRegularFileError",
    "hash_file_capped",
    "read_capped",
]
