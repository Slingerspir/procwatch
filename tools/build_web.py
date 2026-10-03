"""Inline the translation dictionary into a web asset at build time.

The page is localised at run time by looking strings up in PW_T. Generating that
table here, from the same file the DLL uses, means the in-process window and the
WebUI cannot end up disagreeing about what a string says in English.

    python tools/build_web.py web/webui.html build/gen/webui.html
"""
import importlib.util
import io
import json
import sys

MARKER = '/*PW_I18N_TABLE*/'

# The TSV stores literals exactly as they appear in the C source, so a newline
# is the two characters \ and n. In the C table the compiler turns that back
# into a newline; here it has to be done by hand, because a JavaScript key
# written as "a\nb" holds a real newline and would never match an escaped one.
ESCAPES = {'n': '\n', 't': '\t', 'r': '\r', '0': '\0', '\\': '\\', '"': '"', "'": "'"}


def c_unescape(s):
    out = []
    i = 0
    while i < len(s):
        if s[i] == '\\' and i + 1 < len(s) and s[i + 1] in ESCAPES:
            out.append(ESCAPES[s[i + 1]])
            i += 2
        else:
            out.append(s[i])
            i += 1
    return ''.join(out)


def load_generator():
    spec = importlib.util.spec_from_file_location('gen_lang', 'tools/gen_lang.py')
    gen = importlib.util.module_from_spec(spec)
    sys.modules['gen_lang'] = gen
    spec.loader.exec_module(gen)
    return gen


def main():
    if len(sys.argv) != 3:
        sys.stderr.write(__doc__)
        return 1
    src_path, out_path = sys.argv[1], sys.argv[2]

    gen = load_generator()
    table = gen.load_tsv(gen.TSV)
    table = dict((c_unescape(k), c_unescape(v)) for k, v in table.items())

    # ensure_ascii=False keeps the keys readable; the asset is UTF-8 end to end.
    dictionary = 'const PW_T = ' + json.dumps(table, ensure_ascii=False, sort_keys=True) + ';'

    src = io.open(src_path, encoding='utf-8').read()
    if MARKER not in src:
        sys.stderr.write('%s does not contain %s\n' % (src_path, MARKER))
        return 1

    io.open(out_path, 'w', encoding='utf-8', newline='').write(src.replace(MARKER, dictionary))
    print('  [web] %s <- %s (%d strings)' % (out_path, src_path, len(table)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
