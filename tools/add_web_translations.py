"""One-off: add the web-only strings to tools/lang_en.tsv.

Kept in the tree because it documents where these came from; it is idempotent
(an entry already present is left alone).

    python tools/add_web_translations.py
"""
import io
import sys

PAIRS = [
    ('ProcWatch 行为监控', 'ProcWatch behaviour monitor'),
    ('连接中…', 'connecting...'),
    ('用户', 'User'),
    ('运行', 'Uptime'),
    ('丢弃', 'Dropped'),
    ('暂停采集', 'Pause'),
    ('自动滚动', 'Auto-scroll'),
    ('导出 JSONL', 'Export JSONL'),
    ('导出 CSV', 'Export CSV'),
    ('复制当前视图', 'Copy current view'),
    ('等待事件…', 'waiting for events...'),
    ('关闭', 'Close'),
    ('ProcWatch 控制台', 'ProcWatch console'),
    ('控制台', 'Console'),
    ('已监控进程', 'Monitored processes'),
    ('事件合计', 'Total events'),
    ('可疑合计', 'Total suspect'),
    ('立即刷新', 'Refresh now'),
    ('这里列出所有已注入 ProcWatch 的进程。点击"打开 WebUI"查看该进程的实时行为；'
     '"停用"会还原该进程的所有挂钩。',
     'Every process with ProcWatch injected is listed here. Click "Open WebUI" to '
     'watch one live; "Deactivate" restores all of its hooks.'),
    ('运行时长', 'Uptime'),
    ('操作', 'Actions'),
    ('正在扫描…', 'scanning...'),
    ('关键字过滤：路径 / 域名 / API …', 'filter: path / domain / API ...'),

    # Status line and dashboard controls, set from script rather than markup.
    ('实时推送中', 'live'),
    ('推送中断，重试中…', 'stream dropped, retrying...'),
    ('轮询模式', 'polling'),
    ('连接已断开', 'disconnected'),
    ('继续采集', 'Resume'),
    ('复制当前视图', 'Copy current view'),
    ('无法读取历史', 'could not read history'),
    ('ProcWatch - 元数据读取失败', 'ProcWatch - could not read metadata'),
    ('读取失败: ', 'read failed: '),
    ('已复制 ', 'copied '),
    (' 行', ' rows'),
    ('显示', 'Shown'),
    ('没有符合过滤条件的事件', 'no events match the filter'),
    ('[规则]', '[rule]'),

    # Detail drawer labels, written into the DOM by the script.
    ('线程', 'Thread'),
    ('字节数', 'Bytes'),
    ('返回值', 'Result'),

    # Uptime formatting.
    ('时', 'h'),
    ('分', 'm'),
    ('秒', 's'),
    (' 时 ', ' h '),
    (' 分 ', ' m '),
    (' 秒', ' s'),

    # Hub actions.
    ('打开 WebUI', 'Open WebUI'),
    ('停用', 'Deactivate'),
    ('清除记录', 'Forget'),
    ('停用 PID ', 'Deactivate PID '),
    (' 的监控？\n将还原该进程内所有被改写的导入/导出表，监控停止。',
     '?\nEvery rewritten import table in that process will be restored and '
     'monitoring will stop.'),
    ('没有发现已注入的进程。用 injector.exe 启动或注入一个目标程序。',
     'No process with ProcWatch injected was found. Start one with injector.exe, '
     'or inject into a running process.'),
]

TSV = 'tools/lang_en.tsv'

raw = io.open(TSV, encoding='utf-8').read().split('\n')
if raw and raw[-1] == '':
    raw.pop()

existing = set(l.split('\t', 1)[0] for l in raw if l and not l.startswith('#') and '\t' in l)

added = 0
for key, value in PAIRS:
    if key in existing:
        continue
    raw.append('%s\t%s' % (key, value))
    added += 1

io.open(TSV, 'w', encoding='utf-8', newline='').write('\n'.join(raw) + '\n')
print('added %d entries, %d already present' % (added, len(PAIRS) - added))
sys.exit(0)
