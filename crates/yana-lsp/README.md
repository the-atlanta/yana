# yana-lsp — language server + debug adapter for YANA

One binary, two protocols:

| mode | command | transport |
|------|---------|-----------|
| LSP  | `yana-lsp` | stdio (JSON-RPC, `Content-Length` framing) |
| DAP  | `yana-lsp --dap` | stdio (DAP, `Content-Length` framing) |

Build:

```sh
cargo build -p yana-lsp --release
install -Dm755 target/release/yana-lsp ~/.local/bin/yana-lsp
```

## LSP

Everything works from the compiler's own frontend, no LLM involved:

| Category | Features |
|----------|----------|
| Diagnostics | lex / parse / resolve errors on open & change |
| Completion | keywords, registers, types, sections, flags, attributes, symbols from all workspace files |
| Hover | explanations with SPEC.md references (§3–§12): bindings, registers, sections, instructions |
| Hover | **syscalls**: `#[syscall(N)]` → name, C signature, per-register args, return, man page |
| Navigation | go-to-definition, references, document symbols |
| Signatures | `call fn { ... }` signature help |
| Edits | code actions (add `mut`/`alt`, declare missing name, fix type, add label, rename conflicts), rename |
| Extras | inlay hints (bind type, register width, **const value**), code lens (Run / Build / references), folding, selection ranges, semantic tokens |
| Commands | `yana.build`, `yana.run`, `yana.expand`, `yana.debug`, `yana.ir` |

`yana.ir` shows the **source → IR** mapping: every generated instruction next to
the YANA line it came from.

The server scans the workspace (`rootUri`) for closed `.yana` files, so
completion/references/definition work across the whole project.

### Syscall documentation

`#[syscall(N)]` is the bridge from YANA to the kernel (§5.5), and the hover
explains the actual syscall instead of just the attribute:

```yana
#[syscall(1)]
extern fn write(fd @ rdi: u64, buf @ rsi: *u8, len @ rdx: u64) -> rax: i64;
```

Hovering `1` (or the attribute, or `write` at the declaration and at every
`call write`) shows:

- the name and number: `write`, syscall 1;
- the C prototype: `ssize_t write(int fd, const void *buf, size_t count);`;
- a table of arguments by register (`rdi`/`rsi`/`rdx`/`r10`/`r8`/`r9`) with types and meaning;
- the return convention (`rax`, negative = `-errno`);
- the clobbers (`rcx`, `r11`) and the man page (`man 2 write`).

Inlay hints also print the syscall name right after the attribute:

```yana
#[syscall(1)] write
```

The table lives in [`crates/yana-lsp/src/syscalls.rs`](src/syscalls.rs) — ~75
common Linux x86-64 syscalls (`read`, `write`, `open`/`openat`, `mmap`,
`brk`, `futex`, `statx`, `execve`, `exit`/`exit_group`, …). Unknown numbers
still get the generic ABI explanation.

Test it without an editor:

```sh
python3 scripts/lsp-hover-smoke.py
```

## DAP

`yana-lsp --dap` interprets the YANA **IR** directly: every IR instruction keeps
its source span, so breakpoints and stack traces need no DWARF or ELF debug
info.

Supported:

- launch a `.yana` file, entry stop
- line breakpoints (verified against generated code)
- continue / step over / step in / step out / pause
- stack trace with function names and source lines
- scopes: **Registers** (16 GPRs), **Stack** (`[rsp+N]`), **Flags** (cf/zf/sf/of/pf)
- `evaluate` (`rax`, `0x100000`, `[rsp+8]`), `setVariable` (registers & flags)
- `output` events from `write(2)`, `exited` with the exit code

Syscalls emulated: `read` (returns 0), `write`, `exit`/`exit_group`, `brk`/`mmap`
(stubs). Everything else returns `-ENOSYS`. The adapter works on a single
source file (imports are not resolved), which matches the LSP's per-file view.

Test it without an editor:

```sh
cargo build -p yana-lsp
python3 scripts/dap-smoke.py
```

## Helix

`scripts/install-helix.sh` compiles the grammar and links the queries. Then add
to `~/.config/helix/languages.toml`:

```toml
[[language]]
name = "yana"
scope = "source.yana"
file-types = ["yana", "yn"]
comment-token = "//"
grammar = "yana"
language-servers = ["yana-lsp"]

[[grammar]]
name = "yana"
source = { path = "/home/nikki/projects/yana/zed-extension/grammars/yana" }

[language.debugger]
name = "yana-dap"
transport = "stdio"
command = "yana-lsp"
args = ["--dap"]

[[language.debugger.templates]]
name = "launch file"
request = "launch"
completion = [{ name = "file", completion = "filename", default = "examples/hello.yana" }]
args = { program = "{0}" }
```

Check everything:

```sh
helix --health yana
```

Expected: language server ✓, parser ✓, highlight/textobject/indent queries ✓,
and `Configured debug adapter: yana-dap`.

Usage in Helix (default keymap — DAP actions are keybinds, not `:` commands):

| keys | action |
|------|--------|
| `<space>k` | hover (register / keyword / **syscall** docs) |
| `<space>G` | open the sticky **Debug** menu |
| `<space>G l` | launch (pick the `launch file` template, then the file) |
| `<space>G b` | toggle a breakpoint on the current line |
| `<space>G c` | continue |
| `<space>G n` / `i` / `o` | step over / in / out |
| `<space>G v` | variables (Registers / Stack / Flags) |
| `<space>G t` | terminate the session |

`:lsp-workspace-command` lists the YANA commands (`yana.run`, `yana.ir`, …).
`:debug-start <template> <file>` also works, but it bypasses the interactive
prompt, so prefer the menu above.

## Tree-sitter

The grammar lives in `zed-extension/grammars/yana` (shared with the Zed
extension) and the queries in `zed-extension/languages/yana`. Regenerate after
editing `grammar.js`:

```sh
cd zed-extension/grammars/yana
tree-sitter generate          # writes src/parser.c
./scripts/install-helix.sh    # from the repo root: compiles + links
```

Helix reads:

- `~/.config/helix/runtime/grammars/yana.so`
- `~/.config/helix/runtime/queries/yana/{highlights,indents,outline,textobjects}.scm`
