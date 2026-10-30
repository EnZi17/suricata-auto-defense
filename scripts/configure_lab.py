"""Configure the dedicated single-VM capture interface and alert output."""
from pathlib import Path
import os
import shutil
import sys
import tempfile
import yaml

def lab_settings(data, local):
    """Return the lab configuration while preserving unrelated settings."""
    data.setdefault('vars', {}).setdefault('address-groups', {})['HOME_NET'] = '[10.203.0.0/30]'
    data['af-packet'] = [{'interface': 'suri-host', 'cluster-id': 99,
                          'cluster-type': 'cluster_flow', 'defrag': True}]
    data['default-log-dir'] = '/var/log/suricata/'
    rules = data.setdefault('rule-files', [])
    if str(local) not in rules:
        rules.append(str(local))
    for output in data.setdefault('outputs', []):
        if 'eve-log' in output:
            eve = output['eve-log']
            eve.update(enabled=True, filetype='regular', filename='eve.json', threaded=False)
            types = eve.setdefault('types', [])
            if not any(t == 'alert' or isinstance(t, dict) and 'alert' in t for t in types):
                types.append('alert')
            break
    else:
        data['outputs'].append({'eve-log': {'enabled': True, 'filetype': 'regular',
                                          'filename': 'eve.json', 'types': ['alert']}})
    data['unix-command'] = {'enabled': True, 'filename': '/run/suricata/suricata-command.socket'}
    return data


def main():
    path = Path(sys.argv[1])
    data = yaml.safe_load(path.read_text())
    local = Path('/etc/suricata/rules/local.rules')
    local.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(sys.argv[2], local)
    local.chmod(0o644)
    data = lab_settings(data, local)
    with tempfile.NamedTemporaryFile(mode='w', dir=path.parent, delete=False) as f:
        f.write('%YAML 1.1\n---\n')
        yaml.safe_dump(data, f, sort_keys=False)
        tmp = Path(f.name)
    shutil.copystat(path, tmp)
    os.chown(tmp, path.stat().st_uid, path.stat().st_gid)
    os.replace(tmp, path)


if __name__ == '__main__':
    main()
