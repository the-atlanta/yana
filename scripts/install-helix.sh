#!/usr/bin/env bash
# Install YANA tree-sitter highlighting + queries for Helix.
#
# Grammar source of truth: zed-extension/grammars/yana (also used by Zed).
# Queries:                 zed-extension/languages/yana/*.scm
#
# Helix looks for:
#   $XDG_CONFIG_HOME/helix/runtime/grammars/<name>.so
#   $XDG_CONFIG_HOME/helix/runtime/queries/<name>/*.scm
#
# The language entry itself must live in $XDG_CONFIG_HOME/helix/languages.toml
# (see the snippet printed at the end if it is missing).
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
grammar_dir="$repo/zed-extension/grammars/yana"
queries_src="$repo/zed-extension/languages/yana"
helix_cfg="${XDG_CONFIG_HOME:-$HOME/.config}/helix"
runtime="$helix_cfg/runtime"

if [[ ! -f "$grammar_dir/src/parser.c" ]]; then
    echo "error: $grammar_dir/src/parser.c not found" >&2
    echo "       run: (cd \"$grammar_dir\" && tree-sitter generate)" >&2
    exit 1
fi

mkdir -p "$runtime/grammars" "$runtime/queries/yana"

# 1. Compile the parser. Helix expects <grammar>.so exporting tree_sitter_<name>.
cc -O2 -shared -fPIC \
    -I "$grammar_dir/src" \
    -o "$runtime/grammars/yana.so" \
    "$grammar_dir/src/parser.c"

# 2. Symlink queries so edits in the repo take effect immediately.
for f in "$queries_src"/*.scm; do
    ln -sf "$f" "$runtime/queries/yana/$(basename "$f")"
done

echo "installed:"
echo "  $runtime/grammars/yana.so"
echo "  $runtime/queries/yana/{$(cd "$runtime/queries/yana" && ls -1 | paste -sd, -)}"

if ! grep -q 'name = "yana"' "$helix_cfg/languages.toml" 2>/dev/null; then
    cat <<'EOF'

Add this to ~/.config/helix/languages.toml:

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
EOF
fi

echo
echo "check: helix --health yana"
