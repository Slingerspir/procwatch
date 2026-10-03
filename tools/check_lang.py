"""Verify that every translation preserves its format specifiers.

A translation that drops a %s or turns %lu into %u is not a cosmetic problem:
the string is a printf format, so the argument list no longer matches the
format and the output is garbage or the process faults. The check is cheap, so
it runs here and again in CI.

    python tools/check_lang.py
"""
import io
import re
import sys

TABLE = 'build/gen/pw_lang_table.h'

# %[flags][width][.precision][length]conversion
SPEC = re.compile(r'%[-+ #0]*[0-9]*(?:\.[0-9]+)?(?:hh|h|ll|l|z|j|t|L)?[diouxXeEfgGaAcspn%]')

PAIR = re.compile(r'\{ "((?:[^"\\]|\\.)*)",\s*\n\s*"((?:[^"\\]|\\.)*)" \}')

# %hs / %ls are Microsoft extensions used with wide printf.
SPEC_WIDE = re.compile(r'%[-+ #0]*[0-9]*(?:hh|h|ll|l|w)?[diouxXeEfgGaAcspn%]')


def specifiers(text, pattern):
    return pattern.findall(text)


def main():
    if '--fix' in sys.argv:
        return fix_edge_spaces('tools/lang_en.tsv')

    try:
        table = io.open(TABLE, encoding='utf-8').read()
    except IOError:
        sys.stderr.write('%s not found; run tools/gen_lang.py first\n' % TABLE)
        return 1

    pairs = PAIR.findall(table)
    if not pairs:
        sys.stderr.write('no pairs found in %s\n' % TABLE)
        return 1

    problems = 0
    for zh, en in pairs:
        bad = False
        for pattern in (SPEC, SPEC_WIDE):
            if specifiers(zh, pattern) != specifiers(en, pattern):
                sys.stderr.write('SPEC MISMATCH\n  zh: %s\n  en: %s\n' % (zh, en))
                bad = True
                break
        if bad:
            problems += 1
            continue

        # Leading and trailing ASCII spaces are separators here, not formatting:
        # the caller concatenates these strings onto others, so dropping one
        # welds two words together ("resolve host" + "port" -> "resolve hostport").
        # Only checked in this direction - a key wrapped in full-width brackets
        # legitimately gains spaces when it becomes "(like this)".
        if zh[:1] == ' ' and en[:1] != ' ':
            problems += 1
            sys.stderr.write('LEADING SPACE LOST\n  zh: [%s]\n  en: [%s]\n' % (zh, en))
        elif zh[-1:] == ' ' and en[-1:] != ' ':
            problems += 1
            sys.stderr.write('TRAILING SPACE LOST\n  zh: [%s]\n  en: [%s]\n' % (zh, en))

    print('%d translations checked, %d problems' % (len(pairs), problems))
    return 1 if problems else 0


def fix_edge_spaces(path):
    """Restore separator spaces the translation dropped, in place."""
    raw = io.open(path, encoding='utf-8').read().split('\n')
    if raw and raw[-1] == '':
        raw.pop()
    fixed = 0
    out = []
    for line in raw:
        if line.startswith('#') or '\t' not in line:
            out.append(line)
            continue
        zh, en = line.split('\t', 1)
        new = en
        if zh[:1] == ' ' and new[:1] != ' ':
            new = ' ' + new
        if zh[-1:] == ' ' and new[-1:] != ' ':
            new = new + ' '
        if new != en:
            fixed += 1
        out.append('%s\t%s' % (zh, new))
    io.open(path, 'w', encoding='utf-8', newline='').write('\n'.join(out) + '\n')
    print('restored edge spaces on %d entries' % fixed)
    return 0


if __name__ == '__main__':
    sys.exit(main())
