# YANA for Zed

Расширение Zed для языка YANA: подсветка (tree-sitter), live-диагностика,
комплишены и hover через нативный LSP (`crates/yana-lsp`).

## Установка (dev-режим)

1. Собери LSP и CLI из корня репо YANA:

   ```sh
   cargo install --path crates/yana-lsp   # либо просто cargo build --release
   ```

2. В Zed: Extensions → **Install Dev Extension** → выбери этот каталог
   (`zed-extension/`). Zed сам скачает wasi-sdk и скомпилирует tree-sitter
   грамматику (`grammars/yana/grammar.js` → `parser.c` уже сгенерирован).

3. Открой `.yana`-файл. Язык подхватится по расширению `yana`/`yn`.

## Как оно устроено

- `grammars/yana/` — tree-sitter-грамматика (сгенерированный `src/parser.c`
  закоммичен, как требует Zed для grammar-сборок). Запросы:
  `highlights.scm` (подсветка + закрытый набор регистров), `indents.scm`,
  `outline.scm`, `textobjects.scm` (vim-текстовые объекты).
- `languages/yana/config.toml` — метаданные языка (комменты `//`, скобки,
  суффиксы).
- `src/lib.rs` — wasm-расширение (zed_extension_api 0.7): ищет нативный
  `yana-lsp` (target/release → target/debug → PATH) и отдаёт его Zed как
  subprocess-сервер. LSP сам по себе нативный: tokio+tower-lsp в wasm-песочницу
  расширений не помещаются.

## Что даёт LSP

- Диагностика на каждое изменение: лексер, парсер, семантика (mut-контракты,
  hardware-порядок `rdx:rax`, div-by-zero, unknown labels/bindings, классы
  `redundant`/`contract` из спеки).
- Комплишены по контексту: после `@` — места (регистры, секции, биндинги
  файла), после `:` — типы, в `#[` — атрибуты, в `branch (` — флаги, после
  `=>` — метки функции, плюс ключевые слова и сниппеты конструкций (§3–§9).
- Hover: регистры (ширина + алиасы rax/eax/ax/al), ключевые слова с выдержками
  из спеки, секции, биндинги.

## Проверка без Zed

```sh
# грамматика парсит примеры без ошибок
cd grammars/yana
tree-sitter generate
tree-sitter parse ../../../examples/hello.yana      # 0 ERROR
tree-sitter parse ../../../examples/factorial.yana  # 0 ERROR

# wasm-расширение собирается
cargo build --target wasm32-wasip1 --release

# LSP живёт (JSON-RPC смоук)
python3 ../../scripts/lsp-smoke.py                  # из корня репо
```
