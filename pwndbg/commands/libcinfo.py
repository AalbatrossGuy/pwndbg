from __future__ import annotations

import pwndbg.color.memory
import pwndbg.commands
import pwndbg.libc
import pwndbg.libc.facade
from pwndbg.commands import CommandCategory
from pwndbg.libc.dispatch import LibcType

RELATED_COMMANDS: dict[LibcType, tuple[str, ...]] = {
    LibcType.GLIBC: (
        "heap, arena, bins, tcache, vis-heap-chunks, try-free  (ptmalloc heap)",
        "canary, onegadget, exithandlers, errno",
        "got, plt, linkmap, tls, auxv  (libc-agnostic)",
    ),
    LibcType.MUSL: (
        "mallocng (ng)  (musl >= 1.2.1 heap)",
        "errno",
        "got, plt, linkmap, tls, auxv  (libc-agnostic)",
        "not supported: glibc heap commands, canary, onegadget, exithandlers",
    ),
    LibcType.BIONIC: (
        "jemalloc  (Android builds that ship jemalloc)",
        "got, plt, linkmap, tls, auxv  (libc-agnostic)",
        "not supported: heap, canary, onegadget, exithandlers, errno",
    ),
    LibcType.UNKNOWN: (
        "got, plt, linkmap, tls, auxv  (libc-agnostic)",
        "libc not detected: it may not be loaded yet (break at main), or use `set glibc X.Y`",
    ),
}


@pwndbg.commands.Command(
    "Show various information about the currently used libc",
    category=CommandCategory.LINUX,
    notes="""
Pwndbg detects the libc type (glibc, musl, bionic or unknown) and its version from
symbols or embedded strings in the mapped libc. Support differs per libc:

glibc

- Detected via the `__GI_exit` symbol or the "GNU C Library" banner; version from
  `__libc_version` or the banner. Override with `set glibc X.Y` when detection fails.
- Heap structures are known from glibc < 2.22 up to >= 2.44; CI tests cover 2.35 - 2.43.
- Heap: heap, arena(s), bins, fastbins, smallbins, largebins, unsortedbin, tcache(bins),
  mp, top-chunk, malloc-chunk, vis-heap-chunks (vis), find-fake-fast, try-free, track-heap.
- Also: canary (x86-64, i386, aarch64), onegadget (needs the one_gadget tool), exithandlers, errno.

musl

- Detected via the `__freadahead` export, the `/tmp/tmpnam_XXXX` string (>= 1.1.2) or the
  mallocng size class table in static binaries (>= 1.2.1). The version is only known when
  internal symbols are present (>= 1.1.21); otherwise it is reported as unknown.
- CI tests cover 1.1.24 and 1.2.1 - 1.2.6.
- Heap: mallocng (ng) for musl >= 1.2.1; the glibc heap commands refuse to run.
- Also: errno. Not supported: canary, onegadget, exithandlers.

bionic (Android)

- Detected via the `android_reset_stack_guards` symbol (Android 12+, API level 31+); the
  reported version is the API level, probed from the libc symbols.
- Only libcinfo understands bionic. No heap, canary, onegadget, exithandlers or errno
  support; jemalloc works on Android builds that ship jemalloc.

Libc-agnostic commands work for every libc type: got, plt, gotplt, linkmap, tls, auxv,
elfsections, track-got, jemalloc.
""",
)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWhenUserspace
def libcinfo() -> None:
    libc_type = pwndbg.libc.which()
    version = pwndbg.libc.facade.version()
    version_str = ".".join(map(str, version))
    urls_heading = "URLs:"
    if version_str == "-1.-1":
        version_str = "no version information"
        urls_heading = "URLs (unversioned):"

    print(f"libc: {libc_type.value}")
    print(f"libc version: {version_str}")
    print(
        "linked:",
        "dynamically" if pwndbg.dbg.selected_inferior().is_dynamically_linked() else "statically",
    )

    urls = pwndbg.libc.urls()
    print(urls_heading)
    print("    project homepage:      ", urls.homepage)
    print("    read the source:       ", urls.versioned_readable_source)
    print("    download the archive:  ", urls.versioned_compressed_source)
    print("    git clone              ", urls.git)
    print("Mappings:")
    print("    libc is at:            ", pwndbg.color.memory.get(pwndbg.libc.addr()))
    print("          ", pwndbg.libc.filepath())
    print("    ld is at:              ", pwndbg.color.memory.get(pwndbg.libc.loader_addr()))
    print("          ", pwndbg.libc.loader_filepath())
    print("Symbolication:")
    print("    has exported symbols: ", "yes" if pwndbg.libc.has_exported_symbols() else "no")
    print("    has internal symbols: ", "yes" if pwndbg.libc.has_internal_symbols() else "no")
    print("    has debug info:       ", "yes" if pwndbg.libc.has_debug_info() else "no")
    print("Related commands:")
    for related_line in RELATED_COMMANDS[libc_type]:
        print("    " + related_line)
