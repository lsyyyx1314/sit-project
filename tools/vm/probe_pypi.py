import json, urllib.request
for pkg in ['ryu', 'os-ken', 'eventlet']:
    try:
        d = json.load(urllib.request.urlopen('https://pypi.org/pypi/%s/json' % pkg, timeout=20))
        i = d['info']
        cls = [c.split('::')[-1].strip() for c in i.get('classifiers', []) if c.startswith('Programming Language :: Python :: 3.')]
        rel = d['releases'].get(i['version']) or []
        print(pkg, '| latest', i['version'], '| requires_python', i.get('requires_python'), '| py', cls, '| date', (rel[0]['upload_time'][:10] if rel else 'n/a'))
    except Exception as e:
        print(pkg, 'ERR', repr(e))
