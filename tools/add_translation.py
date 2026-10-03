"""Add or update one translation, taking the key from the sources.

Retyping a Chinese literal by hand is how the two columns drift apart - a
single missing space and the lookup silently misses, leaving the string in
Chinese. This finds the exact key in the sources and writes it for you.

    python tools/add_translation.py "界面语言" "    --lang=auto|zh|en interface language ..."

The first argument is a substring that identifies the literal; the second is the
English. An existing entry for the same key is replaced.
"""
import io
import sys
import importlib.util

spec = importlib.util.spec_from_file_location('gen_lang', 'tools/gen_lang.py')
gen = importlib.util.module_from_spec(spec)
sys.modules['gen_lang'] = gen
spec.loader.exec_module(gen)

TSV = 'tools/lang_en.tsv'


def load(path):
    try:
        raw = io.open(path, encoding='utf-8').read().split('\n')
    except IOError:
        raw = []
    if raw and raw[-1] == '':
        raw.pop()
    return raw


def main():
    if len(sys.argv) < 3:
        sys.stderr.write(__doc__)
        return 1
    needle, english = sys.argv[1], sys.argv[2]

    keys = [k for k in gen.extract() if needle in k]
    if len(keys) != 1:
        sys.stderr.write('needle matches %d literals, expected exactly 1:\n' % len(keys))
        for k in keys:
            sys.stderr.write('    %s\n' % k)
        return 1
    key = keys[0]

    lines = load(TSV)
    header = [l for l in lines if l.startswith('#')]
    body = [l for l in lines if l and not l.startswith('#')]

    replaced = 0
    out = []
    for line in body:
        if line.split('\t', 1)[0] == key:
            out.append('%s\t%s' % (key, english))
            replaced += 1
        else:
            out.append(line)
    if not replaced:
        out.append('%s\t%s' % (key, english))

    io.open(TSV, 'w', encoding='utf-8', newline='').write(
        '\n'.join(header + out) + '\n')
    print('%s entry for:\n    %s\n  -> %s' % ('replaced' if replaced else 'added', key, english))
    return 0


if __name__ == '__main__':
    sys.exit(main())
