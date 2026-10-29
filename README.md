# YANA — Yet Another New Assembly

Ассемблер-язык с явной моделью исполнения: конструкция раскрывается в заранее
известный, видимый набор инструкций. Скрытых решений ассемблера нет.

```
bind hello @ .rodata: [u8] = "Hello, YANA!\n";

#[syscall(1)]
extern fn write(fd @ rdi: u64, buf @ rsi: *u8, len @ rdx: u64) -> rax: i64;

#[syscall(60)]
extern fn exit(code @ rdi: u64) -> !;

#[entry]
fn main() -> ! {
    call write { fd: 1, buf: &hello, len: hello.len };
    call exit { code: 0 };
}
```

Спецификация: [SPEC.md](SPEC.md).

## Пайплайн

```
.yana → logos (лексика) → LALRPOP (грамматика) → AST
      → resolve (семантика, const-eval, контракты) → IR
      ├── back-iced: iced-x86 Encoder → свой ELF-writer → exe/.o
      └── back-nasm: текст NASM (комментарии сохраняются) → nasm(1)
```

- `yana oracle file.yana` собирает файл **обоими** бэкендами и сравнивает
  дизассемблер — NASM-эмиттер работает как тестовый оракул (§13 спеки).
- Диагностика в двух классах: `redundant` (глушится) и `contract`
  (ошибка в `--strict`). Рендер — ariadne.

## CLI

```
yana build hello.yana                  # статический exe (iced backend)
yana build hello.yana --backend nasm   # через nasm + ld
yana build hello.yana --object         # relocatable .o
yana run hello.yana                    # собрать и запустить
yana expand hello.yana                 # IR: одна строка = одна инструкция
yana nasm hello.yana                   # эмит NASM-текста
yana oracle hello.yana                 # сверка двух бэкендов
yana build x.yana --strict             # contract-варнинги → ошибки
```

## Крейты

| Крейт | Назначение |
|---|---|
| `yana-ast` | AST, спаны, модель регистров/мест/типов, диагностика |
| `yana-lexer` | logos-лексика; комменты → trivia-канал; препроход `rdx:rax`→PairReg |
| `yana-parser` | LALRPOP-грамматика, драйвер, ошибки со спанами |
| `yana-codegen` | AST→IR, таблица инструкций, const-eval (§8), контракты (§4.2/§4.5/§5.2) |
| `yana-back-iced` | iced-x86 кодер + ELF64-writer (ET_EXEC и ET_REL) |
| `yana-back-nasm` | текстовый эмиттер + `expand` |
| `yana-cli` | драйвер, ariadne-рендер, oracle |
| `yana-lsp` | LSP-сервер (в работе) |

## Статус

MVP-срез x86-64/Linux: `bind/alt`, mov-семейство, push/pop (+ `_`-слоты),
branch (cmp/флаги), fn/extern/`#[syscall]`/`#[entry]`, метки, call с
именованными аргументами, `.rodata/.data/.bss`, `const`/`const fn`,
wide mul/div (`rdx:rax`), касты `as`, `.len`, деструктурирующий bind.

Hello world и факториал работают на обоих бэкендах; oracle = MATCH.
