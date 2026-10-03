"""Wrap user-visible literals so they can be translated.

    python tools/wrap_lang.py            # rewrite the sources in place
    python tools/wrap_lang.py --check    # report what would change, write nothing

Narrow literals containing CJK become L("..."), wide ones become W("...") (the
GUI's labels are wide, so they are translated first and widened after).

This is a lexer rather than a regex on purpose: a naive search and replace walks
into comments, character literals and the escaped quotes inside strings. It is
idempotent - an already wrapped literal is skipped - so it is safe to re-run
after editing the sources by hand.
"""
import glob
import io
import re
import sys

CJK = re.compile('[　-〿一-鿿＀-￯]')

# Static initialisers cannot call a function, so these two macros keep their
# literals and the translation happens in pw_cat_name / pw_lvl_name instead.
SKIP_LINE = re.compile(r'^\s*#define\s+PW_(CAT|LVL)_NAMES\b')

TARGETS = sorted(glob.glob('src/*.c') + glob.glob('src/*.h'))
TARGETS = [f for f in TARGETS if 'pw_lang' not in f]


def line_of(src, pos):
    start = src.rfind('\n', 0, pos) + 1
    end = src.find('\n', pos)
    return src[start:end if end >= 0 else len(src)]


def scan_literal(src, i):
    """`i` points at the opening quote. Returns (end_index, body)."""
    j = i + 1
    n = len(src)
    while j < n:
        if src[j] == '\\':
            j += 2
            continue
        if src[j] == '"':
            return j + 1, src[i + 1:j]
        if src[j] == '\n':          # unterminated: bail out rather than eat code
            return i + 1, src[i + 1:j]
        j += 1
    return n, src[i + 1:n]


def wrap(src):
    out = []
    i = 0
    n = len(src)
    wrapped = 0

    while i < n:
        c = src[i]

        if c == '/' and i + 1 < n and src[i + 1] == '/':
            j = src.find('\n', i)
            j = n if j < 0 else j
            out.append(src[i:j])
            i = j
            continue

        if c == '/' and i + 1 < n and src[i + 1] == '*':
            j = src.find('*/', i + 2)
            j = n if j < 0 else j + 2
            out.append(src[i:j])
            i = j
            continue

        if c == "'":                # character literal, may contain \'
            j = i + 1
            while j < n:
                if src[j] == '\\':
                    j += 2
                    continue
                if src[j] == "'":
                    j += 1
                    break
                j += 1
            out.append(src[i:j])
            i = j
            continue

        is_wide = (c == 'L' and i + 1 < n and src[i + 1] == '"' and
                   (i == 0 or not (src[i - 1].isalnum() or src[i - 1] == '_')))

        if is_wide or c == '"':
            quote = i + 1 if is_wide else i
            end, body = scan_literal(src, quote)
            line = line_of(src, i)
            if CJK.search(body) and not SKIP_LINE.match(line):
                out.append('W("' + body + '")' if is_wide else 'L("' + body + '")')
                wrapped += 1
            else:
                out.append(src[i:end])
            i = end
            continue

        out.append(c)
        i += 1

    return ''.join(out), wrapped


def main():
    check = '--check' in sys.argv
    total = 0
    for path in TARGETS:
        src = io.open(path, encoding='utf-8').read()
        new, n = wrap(src)
        if n and new != src:
            print('%-30s %4d' % (path, n))
            total += n
            if not check:
                io.open(path, 'w', encoding='utf-8', newline='').write(new)
    print('-' * 40)
    print('%s %d literals' % ('would wrap' if check else 'wrapped', total))
    return 0


if __name__ == '__main__':
    sys.exit(main())
