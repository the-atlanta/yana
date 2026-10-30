/// tree-sitter grammar for YANA (Yet Another New Assembly).
///
/// Mirrors the LALRPOP grammar's shape so highlighting matches the language
/// the compiler accepts. It is intentionally permissive (an editor grammar
/// must not choke on half-typed lines) but highlights the real constructs:
/// attributes, bind/alt, push/pop, branch/call/return, fn/extern, const,
/// data bindings, places (registers, pairs, memory), types, literals.

module.exports = grammar({
  name: 'yana',

  extras: $ => [/\s/, $.comment],

  word: $ => $.ident,

  rules: {
    source: $ => repeat($._item),

    comment: $ => token(seq('//', /.*/)),

    _item: $ => choice(
      $.fn_item,
      $.extern_fn,
      $.const_item,
      $.const_fn,
      $.static_bind,
      // macro_item (§9) is not in the compiler MVP yet — grammar follows suit
    ),

    // ---- attributes ----
    attribute: $ => seq(
      '#[',
      field('name', $.ident),
      optional(seq('(', optional(commaSep($._attr_arg)), ')')),
      ']',
    ),
    _attr_arg: $ => choice(
      $.ident,
      $.int,
      $.string,
      seq($.ident, '=', $._attr_arg),
    ),
    // ---- functions ----
    fn_item: $ => seq(
      repeat($.attribute),
      'fn',
      field('name', $.ident),
      '(', optional(commaSep($.param)), ')',
      optional($.ret_sig),
      optional($.clobbers),
      field('body', $.block),
    ),

    extern_fn: $ => seq(
      repeat($.attribute),
      'extern',
      optional($.abi),
      'fn',
      field('name', $.ident),
      '(', optional(commaSep($.param)), ')',
      optional($.ret_sig),
      optional($.clobbers),
      ';',
    ),

    abi: $ => $.string,

    param: $ => seq(
      optional($.mut),
      field('name', $.ident),
      '@',
      field('place', $._place),
    ),

    clobbers: $ => seq('clobbers', ':', optional(commaSep($.ident)), ','),

    ret_sig: $ => seq(
      '->',
      choice(
        '!',
        $._place,
        seq('(', commaSep2($.ret_part), ')'),
      ),
    ),
    ret_part: $ => seq(optional($.mut), $.ident, '@', $._place),

    // ---- consts ----
    const_item: $ => seq(
      repeat($.attribute),
      'const',
      field('name', $.ident),
      ':',
      field('type', $._type),
      '=',
      field('value', $.const_expr),
      ';',
    ),
    const_fn: $ => seq(
      'const', 'fn',
      field('name', $.ident),
      '(', optional(commaSep($.const_param)), ')',
      optional(seq('->', $._type)),
      '{', 'return', $.const_expr, ';', '}',
    ),
    const_param: $ => seq($.ident, ':', $._type),

    // precedence ladder, loosest first
    const_expr: $ => $._c_or,
    _c_or: $ => prec.left(seq($._c_and, '||', $._c_or)),
    _c_and: $ => prec.left(seq($._c_eq, '&&', $._c_and)),
    _c_eq: $ => prec.left(seq($._c_cmp, $.eqop, $._c_eq)),
    _c_cmp: $ => prec.left(seq($._c_bitor, $.cmpop, $._c_cmp)),
    _c_bitor: $ => prec.left(seq($._c_bitxor, '|', $._c_bitor)),
    _c_bitxor: $ => prec.left(seq($._c_bitand, '^', $._c_bitxor)),
    _c_bitand: $ => prec.left(seq($._c_shift, '&', $._c_bitand)),
    _c_shift: $ => prec.left(seq($._c_add, $.shiftop, $._c_shift)),
    _c_add: $ => prec.left(seq($._c_mul, $.addop, $._c_add)),
    _c_mul: $ => prec.left(seq($._c_un, $.mulop, $._c_mul)),
    _c_un: $ => choice(
      prec(1, seq('-', $._c_un)),
      prec(1, seq('!', $._c_un)),
      $._c_atom,
    ),
    _c_atom: $ => choice(
      $.int,
      $.bool,
      seq($.ident, '(', optional(commaSep($._c_or)), ')'),
      $.ident,
      seq('(', $._c_or, ')'),
      seq('(', commaSep2($._c_or), ')'),
      seq('[', optional(commaSep($._c_or)), ']'),
      seq('[', $._c_or, ';', $._c_or, ']'),
      seq('if', $._c_or, '{', $._c_or, '}', 'else', '{', $._c_or, '}'),
    ),
    eqop: $ => choice('==', '!='),
    cmpop: $ => choice('<', '<=', '>', '>='),
    shiftop: $ => choice('<<', '>>'),
    addop: $ => choice('+', '-'),
    mulop: $ => choice('*', '/', '%'),
    bool: $ => choice('true', 'false'),

    // ---- statics ----
    static_bind: $ => seq(
      repeat($.attribute),
      'bind',
      field('name', $.ident),
      '@',
      field('place', $._place),
      optional(seq('=', field('value', $._value))),
      ';',
    ),

    // ---- statements ----
    block: $ => seq('{', repeat($._stmt), '}'),

    _stmt: $ => choice(
      $.bind_stmt,
      $.alt_stmt,
      $.push_stmt,
      $.pop_stmt,
      $.branch_stmt,
      $.call_stmt,
      $.return_stmt,
      $.syscall_stmt,
      $.label_stmt,
      $.block,
    ),

    bind_stmt: $ => seq(
      'bind',
      optional($.mut),
      choice(
        seq(field('name', $.ident), '@', field('place', $._place)),
        seq('(', commaSep2($.destructure), ')'),
      ),
      optional(seq('=', field('value', $._value))),
      ';',
    ),
    destructure: $ => seq(optional($.mut), $.ident, '@', $._place),

    alt_stmt: $ => seq(
      'alt',
      choice(
        seq('(', commaSep2($.ident), ')', '=', $._place, '/%', $._value),
        seq(field('dst', $._place), $.assign_op, field('src', $._value)),
      ),
      ';',
    ),
    assign_op: $ => choice('=', '+=', '-=', '*=', '^=', '&=', '|=', '<<=', '>>='),

    push_stmt: $ => seq('push', '{', optional(commaSep($._place)), '}', ';'),
    pop_stmt: $ => seq('pop', '{', optional(commaSep($._place)), '}', ';'),

    branch_stmt: $ => seq(
      'branch',
      optional(seq('(', $.branch_cond, ')')),
      '=>',
      $.label_ref,
      ';',
    ),
    branch_cond: $ => choice(
      seq($._value, $.cmpop, $._value),
      seq(optional('!'), $.flag),
    ),
    cmpop: $ => choice('==', '!=', '<', '<=', '>', '>='),
    flag: $ => choice('zero', 'carry', 'negative', 'overflow', 'even'),

    call_stmt: $ => seq(
      optional(seq('bind', choice(seq($.ident), seq('(', commaSep2($.ident), ')')), '=')),
      'call',
      field('name', $.ident),
      optional(seq('{', optional(commaSep($.call_arg)), '}')),
      ';',
    ),
    call_arg: $ => seq(optional(seq($.ident, ':')), $._value, optional(seq('@', $._place))),

    return_stmt: $ => seq('return', optional($._value), ';'),
    syscall_stmt: $ => seq('syscall', ';'),

    label_stmt: $ => seq('label', '(', field('name', $.ident), ')', field('body', $.block)),

    // ---- values & places ----
    _value: $ => choice(
      prec.left(1, seq($._value, '*', $._val_atom)),
      $._val_suffix,
    ),
    _val_suffix: $ => choice(
      $._val_atom,
      prec(2, seq($._val_atom, 'as', $._type)),
      prec(2, seq($._val_atom, '.', $.ident)),
    ),
    _val_atom: $ => choice(
      $._place,
      $.int,
      $.char,
      $.string,
      seq('&', $._place),
      seq('const', '{', $.const_expr, '}'),
    ),

    _place: $ => choice(
      $.reg_pair,
      $.named,
      $.mem,
      // section places can carry a type annotation: `bind h @ .rodata: [u8]`
      seq($.section, optional(seq(':', $._type))),
      $.discard,
    ),

    // `rdx:rax` — no inline type annotation (the compiler splits pair vs
    // `rax: u64` because type keywords are a distinct token class there; the
    // editor grammar keeps pairs bare and resolves call-arg ambiguity by GLR).
    reg_pair: $ => prec(1, seq($.ident, ':', $.ident)),
    discard: $ => '_',
    section: $ => token(seq('.', choice('text', 'rodata', 'data', 'bss'))),
    named: $ => seq($.ident, optional(seq(':', $._type))),

    mem: $ => seq(
      '[',
      commaSep1($._mem_term),
      ']',
      optional(seq(':', $._type)),
    ),
    _mem_term: $ => choice(
      seq(optional(choice('+', '-')), $.ident, optional(seq('*', $.int))),
      seq(optional(choice('+', '-')), $.ident, optional(seq('*', $.int))),
      seq(optional('-'), $.int),
    ),

    // ---- types ----
    _type: $ => choice(
      $.prim_type,
      seq('*', $._type),
      seq('[', $._type, ']'),
      seq('[', $._type, ';', $.int, ']'),
      seq('(', commaSep2($._type), ')'),
    ),
    prim_type: $ => choice(
      'u8', 'u16', 'u32', 'u64', 'u128', 'usize',
      'i8', 'i16', 'i32', 'i64', 'i128', 'isize',
    ),

    // ---- tokens ----
    label_ref: $ => seq("'", $.ident),
    mut: $ => 'mut',

    ident: $ => /[A-Za-z_][A-Za-z0-9_]*/,

    int: $ => token(choice(
      seq('0x', /[0-9a-fA-F][0-9a-fA-F_]*/),
      seq('0b', /[01][01_]*/),
      /[0-9][0-9_]*/,
    )),

    char: $ => /'([^'\\]|\\(n|r|t|0|\\|'|\"|x[0-9a-fA-F]{2}))'/,

    string: $ => seq('"', repeat(choice(/[^"\\]/, /\\./)), '"'),
  },
});

function commaSep(rule) {
  return optional(commaSep1(rule));
}
function commaSep1(rule) {
  return seq(rule, repeat(seq(',', rule)), optional(','));
}
function commaSep2(rule) {
  return seq(rule, repeat1(seq(',', rule)), optional(','));
}
