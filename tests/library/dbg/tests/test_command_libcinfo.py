from __future__ import annotations

from ....host import Controller
from . import break_at_sym
from . import get_binary
from . import pwndbg_test

REFERENCE_BINARY = get_binary("reference-binary.native.out")


@pwndbg_test
async def test_command_libcinfo(ctrl: Controller) -> None:
    """
    Tests the libcinfo command
    """
    await ctrl.launch(REFERENCE_BINARY)

    help_text = await ctrl.execute_and_capture("libcinfo -h")
    assert "Notes:" in help_text
    assert "glibc" in help_text and "musl" in help_text and "bionic" in help_text
    assert "mallocng" in help_text
    assert "set glibc X.Y" in help_text

    result = (await ctrl.execute_and_capture("libcinfo")).splitlines()
    assert result[0] == "libc: unknown"
    assert "Related commands:" in result
    assert any("set glibc" in line for line in result)

    # Continue until main, so the libc is actually loaded
    break_at_sym("main")
    await ctrl.cont()

    result = (await ctrl.execute_and_capture("libcinfo")).splitlines()
    assert result[0] == "libc: glibc"
    assert "libc version: 2." in result[1] and result[1] != "libc version: no version information"
    assert result[2] == "linked: dynamically"
    assert "libc.so.6" in result[10]
    assert "ld-linux" in result[12]

    symbolication_index = result.index("Symbolication:")
    related_index = result.index("Related commands:")
    assert related_index == symbolication_index + 4
    assert result[symbolication_index + 1] == "    has exported symbols:  yes"
    assert result[symbolication_index + 2] == "    has internal symbols:  yes"
    assert result[symbolication_index + 3] == "    has debug info:        yes"

    related = result[related_index + 1 :]
    assert len(related) == 3
    assert related[0].startswith("    heap, arena, bins, tcache")
    assert "canary, onegadget, exithandlers, errno" in related[1]
    assert "libc-agnostic" in related[2]
