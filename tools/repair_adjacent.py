"""Rejoin wrapped literals that C would have concatenated.

    L("first half")            L("first half"
    L("second half")     ->        "second half")

The run is one value at run time, so it has to be one lookup key and one call.
The original line breaks are kept, so this is a formatting-neutral repair.

    python tools/repair_adjacent.py [--check]
"""
import glob
import io
import re
import sys

# A call whose argument is nothing but string literals, e.g. L("a" "b"). Runs of
# three or more literalse are common (a long format split across lines), so the
# pattern has to accept a call that already holds several.
CALL = r'[LW]\((?:\s*"(?:[^"\\]|\\.)*")+\s*\)'

# L("a") <trivia> L("b")  ->  L("a" <trivia> "b")
GROUP = re.compile(
    r'([LW]\()'                                   # opening call
    r'((?:\s*"(?:[^"\\]|\\.)*")+\s*)'             # one or more literals
    r'\)'                                         # close of first call
    r'(\s*(?://[^\n]*\n\s*)?)'                    # whitespace / one line comment
    r'[LW]\('                                     # open of second call
    r'((?:\s*"(?:[^"\\]|\\.)*")+\s*)'             # one or more literals
    r'\)',                                        # close of second call
    re.S)


def repair(src):
    total = 0
    while True:
        new, n = GROUP.subn(r'\1\2\3\4)', src, count=1)
        if n == 0:
            return src, total
        src = new
        total += n


def main():
    check = '--check' in sys.argv
    grand = 0
    for path in sorted(glob.glob('src/*.c') + glob.glob('src/*.h')):
        src = io.open(path, encoding='utf-8').read()
        new, n = repair(src)
        if n:
            print('%-30s %d rejoined' % (path, n))
            grand += n
            if not check:
                io.open(path, 'w', encoding='utf-8', newline='').write(new)
    print('-' * 40)
    print('%s %d groups' % ('would rejoin' if check else 'rejoined', grand))
    return 0


if __name__ == '__main__':
    sys.exit(main())
