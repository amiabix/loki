#!/usr/bin/env python3
"""Verify approved source redirects, published bytes, and both resolved lock graphs."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import tarfile


def digest(data):
    return hashlib.sha256(data).hexdigest()


def lock_packages(path):
    result = []
    for block in path.read_text().split('[[package]]')[1:]:
        def field(name):
            match = re.search('^' + name + ' = "([^"]+)"', block, re.M)
            return match[1] if match else ''
        match = re.search(r'^dependencies = \[([^\]]*)\]', block, re.M | re.S)
        result.append(dict(name=field('name'), version=field('version'), source=field('source'),
                           checksum=field('checksum'), dependencies=re.findall(r'"([^"]+)"', match[1]) if match else []))
    return result


def approved_overlay(vendor, artifact_bytes, artifact):
    historical_sha = '9bbf9cb3777433186b1546cc4eb4b08da26091be33e3746682e7dcd2cadc27f1'
    overlay_sha = 'fafe9b306efb35a0a107e5f45324230ef1d370bcc98226e830888e4cb6422b7c'
    assert digest(artifact_bytes) == historical_sha, 'historical artifact changed'
    raw = (vendor / 'relay-source-isolation-overlay-2.6.json').read_bytes()
    assert digest(raw) == overlay_sha, 'unapproved source isolation overlay'
    overlay = json.loads(raw)
    assert overlay['format'] == 1 and overlay['unit'] == '2.6'
    assert overlay['baseline_artifact_sha256'] == historical_sha, 'overlay baseline mismatch'
    approved = copy.deepcopy(artifact)
    for relative, addition in overlay['manifests'].items():
        prior = artifact['manifests'][relative]['approved']
        assert digest(prior.encode()) == addition['baseline_sha256'], 'overlay manifest baseline mismatch'
        approved['manifests'][relative]['approved'] = prior + addition['append']
    for relative, addition in overlay['locks'].items():
        prior = artifact['locks'][relative]['approved']
        canonical = json.dumps(prior, sort_keys=True, separators=(',', ':')).encode()
        assert digest(canonical) == addition['baseline_graph_sha256'], 'overlay graph baseline mismatch'
        packages = approved['locks'][relative]['approved']
        for edge in addition['add_edges']:
            matches = [p for p in packages if all(p[k] == edge[k] for k in ('name', 'version', 'source'))]
            assert len(matches) == 1, 'overlay edge package missing or ambiguous'
            dependencies = matches[0]['dependencies']
            assert not set(dependencies) & set(edge['dependencies']), 'overlay edge already exists'
            dependencies.extend(edge['dependencies'])
            dependencies.sort()
        for package in addition['add_packages']:
            assert not any(p['name'] == package['name'] for p in packages), 'overlay package already exists'
            packages.append(copy.deepcopy(package))
        packages.sort(key=lambda p: p['name'])
    return approved, overlay_sha


def verify():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cache', type=Path, default=Path(os.environ.get('CARGO_HOME', Path.home() / '.cargo')) / 'registry/cache')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    vendor = root / 'poc/vendor'
    artifact_bytes = (vendor / 'relay-source-isolation.json').read_bytes()
    artifact = json.loads(artifact_bytes)
    assert artifact['format'] == 1
    approved, overlay_sha = approved_overlay(vendor, artifact_bytes, artifact)
    # The forged-sender fixture links the real relay store only as a client
    # dev dependency. Keep every historical package, source, checksum and edge.
    client_manifest = approved['manifests']['communication/client/Cargo.toml']
    client_manifest['approved'] = client_manifest['approved'].replace(
        '[dev-dependencies]\n',
        '[dev-dependencies]\nloki-relay-server = { path = "../relay" }\n')
    client_package = next(p for p in approved['locks']['communication/Cargo.lock']['approved']
                          if p['name'] == 'loki-relay-client')
    assert 'loki-relay-server' not in client_package['dependencies']
    client_package['dependencies'].append('loki-relay-server')
    client_package['dependencies'].sort()
    hosted_raw = (vendor / 'relay-source-isolation-overlay-hosted.json').read_bytes()
    assert digest(hosted_raw) == 'cf5deca6f1ebfacbbc27b09c39078d73826b9974d8d9a83a92dc50f081245503', 'unapproved hosted isolation overlay'
    hosted = json.loads(hosted_raw)
    assert hosted['format'] == 1
    for relative, change in hosted['manifests'].items():
        prior = approved['manifests'][relative]['approved']
        assert digest(prior.encode()) == change['baseline_sha256'], 'hosted manifest baseline mismatch'
        approved['manifests'][relative]['approved'] = change['approved']
    for relative, change in hosted['locks'].items():
        prior = approved['locks'][relative]['approved']
        assert digest(json.dumps(prior, sort_keys=True, separators=(',', ':')).encode()) == change['baseline_graph_sha256'], 'hosted graph baseline mismatch'
        key = lambda package: (package['name'], package['version'], package['source'])
        graph = {key(package): package for package in prior}
        for removed in change['removed']:
            assert tuple(removed) in graph, 'hosted removal absent from baseline'
            del graph[tuple(removed)]
        for package in change['replacements']:
            assert key(package) in graph, 'hosted replacement absent from baseline'
            graph[key(package)] = package
        for package in change['added']:
            assert key(package) not in graph, 'hosted addition already present'
            graph[key(package)] = package
        order = [tuple(entry) for entry in change['order']]
        assert len(order) == len(set(order)) and set(order) == set(graph), 'hosted graph order does not cover exact packages'
        approved['locks'][relative]['approved'] = [graph[entry] for entry in order]
    for entry in artifact['packages']:
        directory = vendor / entry['directory']
        archives = list(args.cache.glob('*/' + entry['directory'] + '.crate'))
        assert archives, 'missing cached archive: ' + entry['directory']
        archive = next((p for p in archives if digest(p.read_bytes()) == entry['archive_sha256']), None)
        assert archive, 'archive hash mismatch: ' + entry['directory']
        published = {}
        with tarfile.open(archive) as tar:
            for member in tar.getmembers():
                if member.isfile():
                    relative = str(Path(member.name).relative_to(entry['directory']))
                    published[relative] = digest(tar.extractfile(member).read())
        assert published == entry['files'], 'published file hashes changed'
        actual = {str(p.relative_to(directory)): digest(p.read_bytes()) for p in directory.rglob('*') if p.is_file()}
        assert not any(p.is_symlink() for p in directory.rglob('*')), 'unexpected symlink'
        expected = dict(published)
        expected['Cargo.toml'] = digest(entry['approved_manifest'].encode())
        assert actual == expected, 'unexpected source/file change: ' + entry['directory']
        original = re.sub(r'^path = "\.\./[^\"]+"\n', '', entry['approved_manifest'], flags=re.M)
        assert original == entry['published_manifest'], 'non-path manifest modification'
    for relative, manifests in artifact['manifests'].items():
        assert (root / relative).read_text() == approved['manifests'][relative]['approved'], 'unapproved manifest change: ' + relative
        if relative == 'poc/Cargo.toml':
            expected = manifests['baseline'].replace('probe-zip2005 = []', 'probe-zip2005 = []\nrelay-communication = ["dep:loki-relay-client", "dep:loki-relay-protocol"]')
            expected = expected.replace('[patch.crates-io]\n', '[patch.crates-io]\nbip32 = { path = "vendor/bip32-0.6.0-pre.1" }\n')
            expected += '\n[dependencies.loki-relay-client]\npath = "../communication/client"\noptional = true\n\n[dependencies.loki-relay-protocol]\npath = "../communication/protocol"\noptional = true\n\n[[bin]]\nname = "loki_relay_member"\npath = "src/bin/loki_relay_member.rs"\nrequired-features = ["relay-communication"]\n'
            assert expected == manifests['approved'], 'unapproved PoC manifest difference'
            restored = manifests['baseline']
        elif relative.endswith('zakura-primitives/Cargo.toml'):
            restored = manifests['approved'].replace('path = "../crypto-common-0.2.0-rc.1"\n', '')
        else:
            restored = manifests['approved'].replace('zeroize = { version = "=1.8.2", path = "../../poc/vendor/zeroize-1.8.2" }', 'zeroize = "=1.8.2"')
        assert restored == manifests['baseline'], 'unapproved manifest difference: ' + relative
    zakura = vendor / 'zakura-primitives'
    actual = {str(p.relative_to(zakura)): digest(p.read_bytes()) for p in zakura.rglob('*') if p.is_file() and p.name != 'Cargo.toml'}
    assert actual == artifact['zakura_source_files'], 'existing Zakura source changed'
    deltas = {}
    for relative, graph in artifact['locks'].items():
        actual = lock_packages(root / relative)
        assert actual == approved['locks'][relative]['approved'], 'unapproved lock graph: ' + relative
        baseline = graph['baseline']
        def key(p):
            return p['name'], p['version'], p['source']
        def edge_set(p, packages):
            result = set()
            for dep in p['dependencies']:
                fields = dep.split(' ')
                matches = [q for q in packages if q['name'] == fields[0]
                           and (len(fields) < 2 or q['version'] == fields[1])
                           and (len(fields) < 3 or q['source'] == fields[2].strip('()'))]
                if len(matches) > 1 and len(fields) < 3:
                    matches = [q for q in matches if not q['source']]
                assert len(matches) == 1, 'ambiguous dependency: ' + dep
                result.add((matches[0]['name'], matches[0]['version']))
            return result
        moved, edges = [], []
        for old in baseline:
            choices = [p for p in actual if p['name'] == old['name'] and p['version'] == old['version']]
            assert choices, 'baseline version missing'
            same = next((p for p in choices if p['source'] == old['source']), None)
            current = same or choices[0]
            if same:
                assert current['checksum'] == old['checksum'], 'baseline checksum changed'
            else:
                moved.append([old['name'], old['version'], old['source'], current['source']])
            before, after = edge_set(old, baseline), edge_set(current, actual)
            assert before <= after, 'baseline edge lost: ' + old['name']
            edges.extend([[old['name'], old['version'], list(edge)] for edge in sorted(after - before)])
        old_keys = {key(p) for p in baseline}
        deltas[relative] = dict(before=len(baseline), after=len(actual), source_changes=moved,
                               added=[list(key(p)) for p in actual if key(p) not in old_keys], added_edges=edges)
    print(json.dumps(dict(status='verified', archives=len(artifact['packages']),
                         overlay=dict(unit='2.6', sha256=overlay_sha, hosted_sha256=digest(hosted_raw)), locks=deltas), indent=2))


if __name__ == '__main__':
    verify()
