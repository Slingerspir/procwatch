"""Compile tools/lang_en.tsv into the language table the DLL carries.

Keys are matched by value, not by position. An entry the sources no longer
contain is reported as unused; a source literal with no entry is reported as
untranslated and simply stays Chinese at run time, which is the safe direction
to fail in.

    python tools/gen_lang.py            # write build/gen/pw_lang_table.h
    python tools/gen_lang.py --dump     # list the literals found in the sources
"""
import glob
import io
import re
import sys

# Full-width punctuation, CJK symbols, unified ideographs, halfwidth forms.
CJK = re.compile('[　-〿一-鿿＀-￯]')
LITERAL = re.compile(r'"((?:[^"\\]|\\.)*)"')

SOURCES = sorted(glob.glob('src/*.c') + glob.glob('src/*.h'))
SKIP = ('pw_lang',)
TSV = 'tools/lang_en.tsv'
OUT = 'build/gen/pw_lang_table.h'
WEB_SOURCES = ('web/webui.html', 'web/hub.html')

STYLE = re.compile(r'<style>.*?</style>', re.S)
SCRIPT = re.compile(r'<script>.*?</script>', re.S)
TAG = re.compile(r'<[^>]*>')
# Values of attributes the page shows to the user. These are not text nodes, so
# the DOM walk does not see them until it is told to look.
ATTRIBUTE = re.compile(r'(?:placeholder|title|alt)\s*=\s*"([^"]*)"')

# JavaScript string literals, matched statelessly. A proper lexer would have to
# tell a regex literal from a division, and /[&<>"]/ contains a quote that
# desyncs any stateful scan for the rest of the file. Matching each quoted span
# independently means a wrong guess costs one bogus match instead of hiding
# everything after it; the CJK filter drops the rest.
# A JavaScript string literal never contains a raw newline, so refusing to cross
# one keeps a misread quote (from a regex such as /[&<>"]/) from swallowing the
# rest of the file.
JS_STRING = re.compile(r'"((?:[^"\\\n]|\\.)*)"' + r"|'((?:[^'\\\n]|\\.)*)'")


def extract_web():
    """Chinese strings in the web assets.

    The pages are localised by walking their text nodes once at load, so plain
    markup text is a key just as much as a JavaScript literal is. Attribute
    values are collected too, because the page fills them in separately."""
    found = []
    for path in WEB_SOURCES:
        src = io.open(path, encoding='utf-8').read()

        markup = TAG.split(STYLE.sub(' ', SCRIPT.sub(' ', src)))
        for chunk in markup:
            text = chunk.strip()
            if text and CJK.search(text) and text not in found:
                found.append(text)

        for m in ATTRIBUTE.finditer(src):
            text = m.group(1).strip()
            if text and CJK.search(text) and text not in found:
                found.append(text)

        script = src[src.find('<script>'):]
        for m in JS_STRING.finditer(script):
            body = m.group(1) if m.group(1) is not None else m.group(2)
            if CJK.search(body) and body not in found:
                found.append(body)
    return found


def _scan_literal(src, i):
    """i points at the opening quote. Returns (end, body)."""
    n = len(src)
    j = i + 1
    while j < n:
        if src[j] == '\\':
            j += 2
            continue
        if src[j] == '"':
            return j + 1, src[i + 1:j]
        j += 1
    return n, src[i + 1:n]


def _skip_trivia(src, i):
    """Skip whitespace and comments - the only things C allows between two
    adjacent string literals."""
    n = len(src)
    while i < n:
        if src[i] in ' \t\r\n':
            i += 1
            continue
        if src.startswith('//', i):
            j = src.find('\n', i)
            i = n if j < 0 else j
            continue
        if src.startswith('/*', i):
            j = src.find('*/', i + 2)
            i = n if j < 0 else j + 2
            continue
        break
    return i


def _scan_string(src, i, quote):
    """i points at the opening quote. Returns (end, body)."""
    n = len(src)
    j = i + 1
    while j < n:
        if src[j] == '\\':
            j += 2
            continue
        if src[j] == quote:
            return j + 1, src[i + 1:j]
        j += 1
    return n, src[i + 1:n]


def iter_literal_runs(src, js=False):
    """Yield every string literal, with adjacent ones already concatenated.

    C joins "a" "b" into a single value at compile time, so the run - not each
    piece - is what the lookup sees at run time. Keying on the pieces would
    leave the real string untranslated and put two dead entries in the table.

    `js` switches the lexing to JavaScript, where a single quote starts a string
    rather than a character constant. Reading a script with C rules desyncs the
    scan at the first '...' and silently misses everything after it."""
    i = 0
    n = len(src)
    while i < n:
        if src.startswith('//', i):
            j = src.find('\n', i)
            i = n if j < 0 else j
            continue
        if src.startswith('/*', i):
            j = src.find('*/', i + 2)
            i = n if j < 0 else j + 2
            continue

        if not js and src[i] == "'":            # C character literal
            j = i + 1
            while j < n:
                if src[j] == '\\':
                    j += 2
                    continue
                if src[j] == "'":
                    j += 1
                    break
                j += 1
            i = j
            continue

        wide = (src[i] == 'L' and i + 1 < n and src[i + 1] == '"' and
                (i == 0 or not (src[i - 1].isalnum() or src[i - 1] == '_')))
        if wide or src[i] == '"' or (js and src[i] == "'"):
            pos = i + 1 if wide else i
            quote = '"' if (wide or src[i] == '"') else "'"
            parts = []
            while True:
                end, body = _scan_string(src, pos, quote)
                parts.append(body)
                k = _skip_trivia(src, end)
                nxt = None
                if k + 1 < n and src[k] == 'L' and src[k + 1] == '"':
                    nxt = (k + 1, '"')
                elif k < n and src[k] == '"':
                    nxt = (k, '"')
                elif js and k < n and src[k] == "'":
                    nxt = (k, "'")
                if nxt is None:
                    i = end
                    break
                pos, quote = nxt
            yield ''.join(parts)
            continue

        i += 1


def extract():
    """Every literal containing CJK, de-duplicated, in source order.

    Both narrow and L"..." wide forms are collected: the wrapper converts wide
    ones to W("..."), but a hand-written wide literal should still be found."""
    seen = []
    for path in SOURCES:
        if any(s in path for s in SKIP):
            continue
        src = io.open(path, encoding='utf-8', errors='replace').read()
        for body in iter_literal_runs(src):
            if CJK.search(body) and body not in seen:
                seen.append(body)
    return seen


def load_tsv(path):
    table = {}
    for line in io.open(path, encoding='utf-8'):
        line = line.rstrip('\n').rstrip('\r')
        if not line or line.startswith('#') or '\t' not in line:
            continue
        key, value = line.split('\t', 1)
        table[key] = value
    return table


def prune(path, keys):
    """Drop entries the sources no longer contain, keeping the header."""
    known = set(keys)
    raw = io.open(path, encoding='utf-8').read().split('\n')
    if raw and raw[-1] == '':
        raw.pop()
    kept, dropped = [], 0
    for line in raw:
        if line.startswith('#') or not line:
            kept.append(line)
            continue
        if not line.strip():
            kept.append(line)
            continue
        if '\t' not in line:
            kept.append(line)
            continue
        if line.split('\t', 1)[0] in known:
            kept.append(line)
        else:
            dropped += 1
    io.open(path, 'w', encoding='utf-8', newline='').write('\n'.join(kept) + '\n')
    return dropped


def main():
    keys = extract()
    if '--dump' in sys.argv:
        for i, k in enumerate(keys, 1):
            print('%4d  %s' % (i, k))
        return 0
    if '--web-dump' in sys.argv:
        try:
            table = load_tsv(TSV)
        except IOError:
            table = {}
        missing = [k for k in extract_web() if k not in table]
        for k in missing:
            print(k)
        sys.stderr.write('%d web strings missing a translation\n' % len(missing))
        return 0

    try:
        table = load_tsv(TSV)
    except IOError:
        sys.stderr.write('%s is missing\n' % TSV)
        return 1

    if '--prune' in sys.argv:
        print('pruned %d unused entries from %s'
              % (prune(TSV, keys + extract_web()), TSV))
        table = load_tsv(TSV)

    untranslated = [k for k in keys if k not in table]
    known = set(keys) | set(extract_web())
    unused = [k for k in table if k not in known]

    out = io.StringIO()
    out.write('/* Generated by tools/gen_lang.py from tools/lang_en.tsv.\n')
    out.write(' * Do not edit: edit the TSV and re-run the generator.\n */\n')
    out.write('#ifndef PW_LANG_TABLE_H\n#define PW_LANG_TABLE_H\n\n')
    out.write('static const PW_LANG_PAIR pw_lang_pairs[] = {\n')
    for key in keys:
        en = table.get(key)
        if en is None:
            continue
        out.write('    { "%s",\n      "%s" },\n' % (key, en))
    out.write('};\n\n')
    out.write('#define PW_LANG_PAIR_COUNT '
              '((int)(sizeof(pw_lang_pairs) / sizeof(pw_lang_pairs[0])))\n\n')
    out.write('#endif /* PW_LANG_TABLE_H */\n')

    io.open(OUT, 'w', encoding='utf-8', newline='').write(out.getvalue())

    print('%s: %d translations, %d source literals' % (OUT, len(keys) - len(untranslated), len(keys)))
    if untranslated:
        print('%d literals have no translation and will stay Chinese:' % len(untranslated))
        for k in untranslated[:20]:
            print('    %s' % k)
    if unused:
        print('%d translation entries are unused (left over from removed strings):' % len(unused))
        for k in unused[:20]:
            print('    %s' % k)
    return 0


if __name__ == '__main__':
    sys.exit(main())
