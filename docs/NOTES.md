# YANA — заметки реализации

## Доказанные контракты (спайки)

1. **ELF/iced** (`docs/spike-elf-iced.rs.txt`): iced-x86 `Encoder` кодирует,
   свой writer собирает ET_REL (symtab + `.rela.text`), `R_X86_64_PC32`
   с addend −4 резолвит rip-relative `lea` на `.rodata`, `ld` линкует,
   sysv hello запускается.
2. **LALRPOP**: extern-enum поверх потока `(usize, Token, usize)` от logos
   работает на nightly.

## Гочи, найденные по дороге

- `/tmp` на ukko — tmpfs 5.9G; сборки LALRPOP-деревьев убивают его (ENOSPC).
  Все cargo-билды — на диске (`~/dev/*`, scratch).
- logos: нет `\b` (Unicode word boundary) и lookahead — DFA не умеет;
  `[^\n]*` требует `allow_greedy = true`; максимум одно поле на вариант
  (синтетические ошибки — struct `BadLit`); `_` vs ident разруливается
  priority.
- LALRPOP LALR(1) не делит `rdx:rax` (пара) и `rax: u64` (аннотация) —
  нужен препроход токенов (слот §0.5): `Ident ":" Ident(reg)` → синтетический
  `PairReg`. Регистры и типы — непересекающиеся классы токенов, коллапс
  безопасен.
- `#[syscall(1)]`: `syscall` — keyword, имя атрибута ждёт Ident → отдельное
  правило AttrKeyword.
- iced-x86: варианты Code называются `Mov_rm64_imm32` (не `Mov_r64_imm32`);
  инструкции без операндов — `Instruction::default()+set_code` или
  `with1(code, Register::None)`; `With2<_, u8>` не реализован — imm8
  передавать как u32 (Code диктует ширину поля); 8-битные r8+ называются
  `R8L..R15L` (не `R8B`).
- rela entry = 24 байта: r_offset **u64**, r_info u64, r_addend i64.
  Ошибка на u32 → readelf показывает 0 entries, линкер молча не резолвит.
- ET_EXEC для ядра: `p_offset ≡ p_vaddr (mod page)` — иначе SIGSEGV при
  запуске (проверено). Файловые оффсеты секций = 0x1000/0x2000/0x3000.
- iced `Encoder::encode(&ins, rip)` — rip нужен для правильного rel32/disp;
  ветки: собирать с `set_near_branch64(target)` до encode.
- NASM оптимизирует `mov rbx, 5` → `mov ebx, 5` (zero-extends, семантически
  идентично) — оракул нормализует ширину 64/32 GPR-имён, но НЕ 8/16.
- iced FastFormatter печатает hex как `1234h`, NASM/objdump — `0x1234`;
  нормализация оракула blanks-ит все числа.
- `default rel` в NASM = rip-relative по умолчанию — совпадает с
  кодировкой iced для символьных disp.
- **iced displ_size в 64-битной адресации = {0, 1, 8}** (8 означает disp32;
  значение 4 валидно ТОЛЬКО для 32-битной адресации и даёт
  «Invalid memory_displ_size() value»). Все старые тесты имели disp=0,
  поэтому баг не проявлялся; пойман на `align`/`_`-слотах (`lea rsp,[rsp-8]`).
- `align N;` (§4.3): паддинг зависит от СТАТИЧЕСКОЙ глубины стека, поэтому
  раскрывается не в resolve, а в анализе (§14.3): `Insn::StackAlign{N}` →
  `Insn::StackPad{pad}` in-place (индексы инструкций не должны съезжать —
  на них смотрят CFG и label_defs). entry_offset: 8 для вызываемых функций,
  0 для `#[entry]` (ядро даёт 16-выровненный rsp на `_start` — проверено
  зондом). pad=0 → ноль байт в обоих бэкендах (iced: build_insn возвращает
  Option; NASM: пустая строка пропускается).

## Архитектура

- Одна инструкция = одна строка (§4.1): `a = b + c;` невыразимо.
- IR символический: метки/символы резолвятся на этапе бэкенда
  (двухпроходно: sizing pass с placeholder-диспами, затем fixup — длины
  rel32/disp32 от значений не зависят).
- Таблица инструкций (`insn::insn_info`) — flags/terminator/call — общая
  для кодировщика и будущих анализов (§14).
- `#[syscall(N)] extern` раскрывается в `mov rax,N; syscall` в точке вызова
  (clobbers rcx/r11 записаны в символ).
- Statics получают символ ДО data-item (NASM-эмиттер печатает `hello:`
  из `DataItem.sym`).
- Диагностика: `redundant` (глушится атрибутом), `contract` (ошибка в
  `--strict`); лекс/парс/семантика — всегда ошибки.
