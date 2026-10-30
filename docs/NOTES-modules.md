# Modules (SPEC §10) — implementation notes

Branch: `feat/modules`. Scope: BOTH stages of §10 — one-object-file-per-source
file with `#[global]` exports (stage 1) AND `use path::name;` imports of
`fn`/`extern fn` signatures, `const` values and statics (stage 2). Macro
imports are OUT of scope (another branch does macros).

## Binding decisions

### Syntax and resolution

- `use seg(::seg)*;` is a top-level item (`Item::Use`). Grammar rule
  `UseItem`/`UsePath` in `yana.lalrpop`; `KwUse`/`ColonColon` tokens already
  existed and were already mapped in the extern block.
- The LAST segment names the imported item; preceding segments are a file
  path RELATIVE to the importing file's directory:
  - `use math::divmod;` → `math.yana` (or `.yn`) next to the importer, item
    `divmod`;
  - `use lib::math::divmod;` → `lib/math.yana`.
- A single-segment `use foo;` has no module part → error `use-path`.
- Both `.yana` and `.yn` extensions are accepted (SPEC §15, решение 30.10),
  tried in that order.
- The resolver itself skips `Item::Use` (single-file resolve of a file with
  `use` produces `unknown-call` etc. for the missing names — LSP behaves this
  way until use-completions are wired post-merge).

### Export = `#[global]` only

`pub` is gone (§15). Only `#[global]` items are importable. Importing a
present-but-not-exported name is `unresolved-import` with help
"not exported: add #[global]". To make `#[global] const` expressible,
`ConstItem`/`ConstFnItem` gained an `attrs` field and the grammar now accepts
attributes before `const` items (previously attributes were ignored there).

### No mangling

Symbol name = item name verbatim (§10). The entry symbol `_start` is the only
renamed symbol (existing `#[entry]` behavior, unchanged).

### Imports — what crosses the module boundary

`ImportedDecl` (yana-codegen::target), extracted by the loader from the
dependency's AST + resolved IR:

- `Fn { sig, clobbers }` — full signature. The importer's resolver seeds an
  extern-like symbol: undefined, `STB_GLOBAL`/`SHN_UNDEF` in the object,
  `real_call` set. Clobbers come from the dependency's resolved IR symbol
  (the declared `clobbers:` block — the resolver now stores it — or the
  derivation the §14.3 analysis pass stored), so call-site lowering, results
  and contracts behave exactly as for a local `extern fn`.
- `Const { name, value }` — the evaluated value; usable in const expressions
  and as an immediate at the importer. No runtime symbol.
- `Static { name, size }` — new `SymbolKind::ExternStatic`: an undefined
  symbol reference usable in places/`lea` (Pc32 relocation). `size` feeds
  `name.len`. `StaticInfo.offset` stays 0 so the existing `disp_sym` addend
  path works unchanged.

Resolution plumbing: `ResolveOptions.imports: Vec<ImportedDecl>`; the
resolver seeds them before pass 1 (`seed_imports`). Local declarations that
clash with an imported name give `duplicate-import` (checked in the three
`collect_*` functions; the check list is populated only AFTER seeding so the
imports themselves don't trip it).

### Orchestration (yana-cli/src/loader.rs)

DFS post-order load: parse the file → for each `use`, resolve the module file
(relative to the importer's dir), recurse, extract the declaration → resolve
the importer with `imports`. Dependencies therefore appear BEFORE their
importers in `Loader::mods`, which is also the argument order for `ld`.
Each file is loaded and resolved exactly once (path-keyed, canonicalized).

Diagnostics are structured `Diagnostic`s tagged with their module, rendered
with the existing ariadne renderer against the right source text. Kinds:

- `module-not-found` (file missing), help names the expected path;
- `unresolved-import` (name absent OR not `#[global]`), help
  "not exported: add #[global]";
- `circular-use` (module transitively uses itself — detected via the DFS
  chain; reported at the use site in the deepest importer);
- `duplicate-import` (same name imported twice from different origins;
  importing the same name from the same module twice is idempotent and OK).

### Object files / linking

- `yana build <file>` / `yana run <file>` auto-discover `use` items. With
  uses: every involved module is resolved, assembled (`assemble_text` object
  mode) and written as ONE `.o` (`write_object`), then all `.o` are linked
  with the system `ld` (same shell-out pattern as the nasm backend path).
  Entry = the root module's `#[entry]` symbol (ld's default `_start`).
- Without uses: the single-file `link_exe` static path, byte-for-byte
  unchanged.
- `--object` emits a single `.o` for the given file even when it has `use`
  items (imports stay `SHN_UNDEF` for the user's own link; a test links
  main.o + math.o with plain `ld` and runs the result).
- Temp `.o` files go to `std::env::temp_dir()/yana-build-*` (unique per
  invocation: pid + nanos, because parallel `yana run` calls used to collide
  with a pid-only name — "Text file busy").

### write_object changes (elf.rs)

- `#[syscall(N)]` externs are NO LONGER emitted to the symbol table: they
  lower inline (`mov rax,N; syscall`) and never appear in a relocation, so a
  symtab entry made every multi-module link fail with "undefined symbol".
- `const` symbols are skipped (no runtime presence).
- Locals are emitted BEFORE globals (GNU ld hard-requires `sh_info` = first
  global index; a local after a global is a hard link error).
- Defined statics now carry their real `size` in the symtab.
- Undefined symbols: `extern fn` → `STT_FUNC`, imported static →
  `STT_OBJECT`, both `STB_GLOBAL` + `SHN_UNDEF`.
- `.rela` entries remain 24 bytes: `r_offset` u64, `r_info` u64, `r_addend`
  i64 (the u32-r_offset bug did NOT regress — verified with readelf).

### Call ABI facts

The clobbers chain: for a `fn` with an explicit `clobbers:` block the
resolver now stores it on the Symbol (it previously only honored the syscall
default rcx/r11 — a latent gap this branch fixes). The dependency's analysis
pass (§14.3) does not yet write derived clobbers back to the symbol, so an
imported `fn` without a declared block currently imports with an empty
clobber list. Documented; the fixture declares its block explicitly.

## Out of scope / follow-ups

- Macro imports (§10 mentions them; the macros branch owns this).
- LSP use-completions (yana-lsp untouched on this branch by instruction).
- `use` inside the oracle/nasm/expand commands: they stay per-file.
- Const-eval of an imported `const` whose value itself references a const
  from a third module: works only if that third module is also in the
  dependency graph of the importer (it will be, transitively, whenever the
  const is reachable — the loader resolves dependencies first).

## Test coverage

- parser: `use` item parses (single/nested paths, span, mixing with items);
- loader: unresolved-import (missing name), unresolved-import (non-global,
  help text), module-not-found, circular-use, missing root file;
- e2e: `fixtures/modules/{math,main}.yana` build via ld → execute → exit 45;
  `yana run` same; `--object` emits ET_REL with UND imports; two `--object`
  outputs link with plain `ld` and run;
- baseline: workspace green, oracle MATCH ×2, hello prints, factorial 120.
