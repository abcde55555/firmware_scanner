"""Static ELF32 frame experiment; generated code is never loaded or executed."""
import runpy
import shutil
import subprocess
from pathlib import Path

import pytest

from firmware_scanner.extraction.semantic_version import ELFView, SemanticVersionExtractor


def _image(tmp_path, body, prolog="push %ebp; mov %esp,%ebp; and $-4,%esp",
           epilog="mov %ebp,%esp; pop %ebp; ret", extra=""):
    compiler = shutil.which("cc")
    if compiler is None:
        pytest.skip("ELF32 assembler/linker required")
    source = tmp_path / "frame.S"
    output = tmp_path / "frame.so"
    source.write_text(f"""
.text
.globl sqlite3_libversion_number
.type sqlite3_libversion_number,@function
sqlite3_libversion_number:
{prolog}
{body}
{epilog}
.size sqlite3_libversion_number,.-sqlite3_libversion_number
{extra}
.section .note.GNU-stack,"",@progbits
""")
    subprocess.run([compiler, "-m32", "-shared", "-nostdlib", str(source), "-o", str(output)],
                   check=True, capture_output=True)
    image = ELFView(output.read_bytes())
    return image, image.instructions(*image.functions["sqlite3_libversion_number"])


def _evaluate(image, instructions):
    namespace = runpy.run_path(str(Path(__file__).resolve().parents[2]
                                  / "experiments/version_coverage/x86_frame_probe.py"))
    return namespace["x86_frame_return"](image, instructions)


@pytest.mark.parametrize("alignment", [None, 2, 4, 8, 16, 32, 64])
def test_aligned_frame_recovers_constant_without_target_execution(tmp_path, alignment):
    prolog = "push %ebp; mov %esp,%ebp"
    if alignment:
        prolog += f"; and $-{alignment},%esp"
    image, instructions = _image(tmp_path, "mov $3044005,%eax", prolog=prolog)
    assert SemanticVersionExtractor._x86_32_return(image, instructions) is None
    assert _evaluate(image, instructions) == 3044005


@pytest.mark.parametrize("alignment", [None, 4, 64])
def test_frame_pic_string_preserves_original_return_address(tmp_path, alignment):
    prolog = "push %ebp; mov %esp,%ebp"
    if alignment:
        prolog += f"; and $-{alignment},%esp"
    image, instructions = _image(
        tmp_path, "call .Lthunk\n.Lreturn:\nadd $(.Lrelease-.Lreturn),%eax",
        prolog=prolog, extra='''
.Lthunk: mov (%esp),%eax; ret
.section .rodata
.Lrelease: .asciz "3.44.5-vendor"
''')
    assert SemanticVersionExtractor._x86_32_return(image, instructions) is None
    pointer = _evaluate(image, instructions)
    assert pointer is not None
    assert image.c_string(pointer, readonly=True) == "3.44.5-vendor"


def test_verified_pic_thunk_can_use_a_non_return_register(tmp_path):
    image, instructions = _image(
        tmp_path, "call .Lthunk\n.Lreturn:\nadd $(.Lrelease-.Lreturn),%edx; mov %edx,%eax",
        extra='''
.Lthunk: mov (%esp),%edx; ret
.section .rodata
.Lrelease: .asciz "1.10.0"
''')
    pointer = _evaluate(image, instructions)
    assert pointer is not None
    assert image.c_string(pointer, readonly=True) == "1.10.0"


def test_full_width_alignment_encoding_is_bounded(tmp_path):
    image, instructions = _image(
        tmp_path, "mov $3044005,%eax",
        prolog="push %ebp; mov %esp,%ebp; .byte 0x81,0xe4,0xc0,0xff,0xff,0xff")
    assert _evaluate(image, instructions) == 3044005


@pytest.mark.parametrize("body,epilog,extra", [
    ("mov $3044005,%eax; mov $0,%ebp", "mov %ebp,%esp; pop %ebp; ret", ""),
    ("mov $3044005,%eax; mov $0,%esp", "mov %ebp,%esp; pop %ebp; ret", ""),
    ("mov %esp,%edx; mov $3044005,%eax", "mov %ebp,%esp; pop %ebp; ret", ""),
    ("lea 4(%ebp),%edx; mov $3044005,%eax", "mov %ebp,%esp; pop %ebp; ret", ""),
    ("mov $0,%bp; mov $3044005,%eax", "mov %ebp,%esp; pop %ebp; ret", ""),
    ("mov $3044005,%eax", "pop %ebp; ret", ""),
    ("mov $3044005,%eax", "mov %ebp,%esp; ret", ""),
    ("mov $3044005,%eax; ret", "mov %ebp,%esp; pop %ebp; ret", ""),
    ("jmp .Ldone; mov $3044005,%eax; .Ldone:", "mov %ebp,%esp; pop %ebp; ret", ""),
    ("int3; mov $3044005,%eax", "mov %ebp,%esp; pop %ebp; ret", ""),
    ("ud2; mov $3044005,%eax", "mov %ebp,%esp; pop %ebp; ret", ""),
    ("call .Lunknown; mov $3044005,%eax", "mov %ebp,%esp; pop %ebp; ret", ".Lunknown: ret"),
    ("call .Lthunk; mov $3044005,%eax", "mov %ebp,%esp; pop %ebp; ret", ".Lthunk: mov (%esp),%ebp; ret"),
    ("call .Lthunk; mov $3044005,%eax", "mov %ebp,%esp; pop %ebp; ret", ".Lthunk: mov (%esp),%esp; ret"),
    ("call .Lthunk; mov $3044005,%eax", "mov %ebp,%esp; pop %ebp; ret", ".Lthunk: mov %gs:(%esp),%eax; ret"),
    ("sub $1,%eax", "mov %ebp,%esp; pop %ebp; ret", ""),
    ("call .Lpop; .Lpop: pop %eax; mov $3044005,%eax", "mov %ebp,%esp; pop %ebp; ret", ""),
    ("mov $3044005,%eax", "mov %ebp,%esp; pop %ebp; ret $4", ""),
    ("mov $3044005,%eax", "leave; ret", ""),
    ("mov $3044005,%eax", "mov %ebp,%esp; pop %ebp; ret; nop", ""),
], ids=["clobber-ebp", "clobber-esp", "read-esp", "lea-ebp", "partial-bp",
        "missing-mov-restore", "missing-pop", "early-ret", "branch", "trap", "ud2",
        "unknown-call", "thunk-ebp", "thunk-esp", "thunk-segment", "baseline-unknown",
        "call-pop-pic-unsupported", "ret-stack-arguments", "leave-unsupported", "trailing-code"])
def test_unsafe_frame_bodies_fail_closed(tmp_path, body, epilog, extra):
    image, instructions = _image(tmp_path, body, epilog=epilog, extra=extra)
    assert _evaluate(image, instructions) is None


@pytest.mark.parametrize("mask", [-128, -3, 0, -1])
def test_invalid_stack_alignment_is_refused(tmp_path, mask):
    image, instructions = _image(tmp_path, "mov $3044005,%eax",
                                 prolog=f"push %ebp; mov %esp,%ebp; and ${mask},%esp")
    assert _evaluate(image, instructions) is None


def test_unframed_baseline_and_partial_decode_bounds(tmp_path):
    image, instructions = _image(tmp_path, "mov $3044005,%eax", prolog="", epilog="ret")
    assert _evaluate(image, instructions) == SemanticVersionExtractor._x86_32_return(image, instructions) == 3044005
    assert _evaluate(image, instructions[:-1]) is None
    assert _evaluate(image, []) is None


def test_oversized_function_is_refused(tmp_path):
    image, instructions = _image(tmp_path, "nop; " * 128 + "mov $3044005,%eax")
    assert _evaluate(image, instructions) is None
