# Backends and targets — implementation notes (M6 F7–F9)

The x86-64 Linux backend is the only complete path. This file records what
exists for the other targets so the gap is explicit.

## Target matrix

| triple | resolve | object | executable | notes |
|---|---|---|---|---|
| `x86_64-linux` | ✅ | ELF64 `ET_REL` | ELF64 `ET_EXEC` (no `ld`) | default |
| `x86_64-macos` | ✅ (`_main`, `_` prefix) | Mach-O `MH_OBJECT` | ❌ | F8 partial |
| `aarch64-linux` | ✅ target facts | ❌ | ❌ | F7 |
| `xtensa-esp32s3` | ✅ target facts | ❌ | ❌ | F9 |

`yana build --target <triple>` rejects unsupported combinations with a
single clear error instead of silently producing the wrong format.

## F8 — Mach-O object writer

`crates/yana-back-iced/src/macho.rs` emits an `MH_OBJECT` file with:

- `LC_SEGMENT_64` containing `__TEXT,__text`, `__TEXT,__const`,
  `__DATA,__data`, `__DATA,__bss`;
- `LC_SYMTAB` + `LC_DYSYMTAB` (locals → external definitions → undefined);
- `nlist_64` symbols and `relocation_info` entries for `__text`:
  - `Pc32` → `X86_64_RELOC_SIGNED`;
  - `Plt32` → `X86_64_RELOC_BRANCH`;
  - `Abs32`/`Abs64` → `X86_64_RELOC_UNSIGNED`.

Mach-O has no explicit relocation addend, so `write_object` patches the
addend into the section bytes before emitting them. The resolver already
applies `TargetInfo::symbol_prefix()` (leading `_`) and `entry_symbol()`
(`_main`), so the writer uses symbol names verbatim.

Validated with `llvm-readobj`/`llvm-objdump --macho`: sections, symbols
(`_main`, `_ext`) and the branch relocation are recognized. There is no
Mach-O executable writer and no macOS syscall/libSystem shim yet, so
`yana build --target x86_64-macos` without `--object` is an error.

## F7 — AArch64

Only target facts exist: `Arch::Aarch64`, 64-bit `usize`, `sp` 16-aligned
(`stack_entry_offset() == 0`), `elf64`/`macho64`, and
`unsupported-atomic-target` for atomics. The IR is still x86-specific
(register names, `Insn` variants, addressing modes); a real backend needs a
target-specific lowering layer (load/store forms, `adrp`+`add`, `movz`/`movk`)
before encoding.

## F9 — Xtensa LX7 (ESP32-S3)

Only target facts exist: `Arch::Xtensa`, 32-bit `usize`, `elf32`,
`_start`, and the ABI decision from SPEC §15 (`entry a1, <framesize>`,
`return` → `retw`, arguments in `a2`–`a7`). A textual GNU-as emitter from
the Espressif toolchain is the intended first step; it also needs
target-specific lowering.
