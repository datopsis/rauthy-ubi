#!/usr/bin/env python3
"""Report High/Critical findings in the pinned upstream lockfiles that the image gate cannot see.

Non-blocking by design: it never changes the image gate's verdict. It fails closed (exit 1)
when an input is missing or a scan did not cover an ecosystem, never reporting "clean".
"""
import argparse
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import sys

SEVERITIES = ('CRITICAL', 'HIGH')
MINIMUM_LOCK = {'cargo': 500, 'npm': 100}
MINIMUM_SHIPPED = {'rustbinary': 500, 'node-pkg': 100}
ECOSYSTEM = {'cargo': 'cargo', 'rustbinary': 'cargo', 'npm': 'npm', 'node-pkg': 'npm'}
SERVER_ROOT, WASM_ROOT = 'rauthy', 'rauthy-wasm-modules'
SERVER_STEP = 'server build (`cargo auditable build --bin rauthy`, `cargo run --bin fido-mds-prep`)'
WASM_STEP = 'WASM module build (`cargo build -p rauthy-wasm-modules --target wasm32-unknown-unknown`)'


class AuditError(Exception):
    pass


def load(path):
    try:
        return json.loads(Path(path).read_text(encoding='utf-8'))
    except (OSError, ValueError) as error:
        raise AuditError(f'cannot read {path}: {error}') from error


def packages(report, trivy_type):
    results = [r for r in report.get('Results') or [] if r.get('Type') == trivy_type]
    return results, {(p['Name'], p['Version']) for r in results for p in r.get('Packages') or []}


def shipped_inventory(reports):
    shipped = defaultdict(set)
    for arch, report in reports.items():
        for trivy_type, minimum in MINIMUM_SHIPPED.items():
            _, found = packages(report, trivy_type)
            if len(found) < minimum:
                raise AuditError(f'{arch} image report has {len(found)} {trivy_type} packages')
            for item in found:
                shipped[(ECOSYSTEM[trivy_type], *item)].add(arch)
    return shipped


def crate_steps(metadata):
    """Map (crate, version) -> {step description: set(arch)} from cargo metadata graphs."""
    steps = defaultdict(lambda: defaultdict(set))
    for (arch, root, step), meta in metadata.items():
        by_id = {p['id']: p for p in meta['packages']}
        members = set(meta['workspace_members'])
        nodes = {n['id']: n for n in meta['resolve']['nodes']}
        roots = [i for i in members if by_id[i]['name'] == root]
        if len(roots) != 1:
            raise AuditError(f'{arch}: workspace member {root} not found')
        queue, seen = [(roots[0], 'linked', None)], set()
        while queue:
            package_id, mode, via = queue.pop()
            if (package_id, mode) in seen:
                continue
            seen.add((package_id, mode))
            package = by_id[package_id]
            if mode == 'linked' and root == WASM_ROOT:
                text = (f'{step}: linked into the WASM embedded in the shipped server binary, '
                        'which its cargo-auditable inventory does not list')
            elif mode == 'linked':
                text = f'{step}: linked, but absent from the binary inventory (not in the final link)'
            elif mode == 'build':
                text = f'{step}: compile-time only ({via})'
            else:
                text = f'workspace tests only ({via}); not compiled by the image build'
            steps[(package['name'], package['version'])][text].add(arch)
            for dependency in nodes[package_id]['deps']:
                child = by_id[dependency['pkg']]
                for kind in {k['kind'] for k in dependency['dep_kinds']}:
                    if kind == 'dev':
                        if package_id not in members or mode != 'linked':
                            continue
                        queue.append((child['id'], 'dev', f'dev-dependency of {package["name"]}'))
                    elif mode == 'dev':
                        queue.append((child['id'], 'dev', via))
                    elif kind == 'build' or mode == 'build':
                        queue.append((child['id'], 'build',
                                      via if mode == 'build' else f'build-dependency of {package["name"]}'))
                    elif any('proc-macro' in t['kind'] for t in child['targets']):
                        queue.append((child['id'], 'build', f'proc-macro {child["name"]}'))
                    else:
                        queue.append((child['id'], 'linked', None))
    return steps


def npm_steps(package_lock, name, version):
    entries = [e for path, e in package_lock['packages'].items()
               if path.rsplit('node_modules/', 1)[-1] == name and e.get('version') == version]
    if not entries:
        return ['not in the upstream package-lock']
    texts = set()
    for entry in entries:
        role = 'devDependency' if entry.get('dev') else 'dependency'
        platform = ', '.join(f'{k}={",".join(entry[k])}' for k in ('os', 'cpu', 'libc') if entry.get(k))
        texts.add('frontend `npm ci` / `vite build` ' + role
                  + (f'; platform-specific ({platform}), not installed on native linux builds' if platform
                     else '; not installed by the native builds'))
    return sorted(texts)


def audit(lock_report, shipped_reports, metadata, package_lock):
    for trivy_type, minimum in MINIMUM_LOCK.items():
        _, found = packages(lock_report, trivy_type)
        if len(found) < minimum:
            raise AuditError(f'lockfile scan has {len(found)} {trivy_type} packages (< {minimum})')
    shipped = shipped_inventory(shipped_reports)
    crates = crate_steps(metadata)
    findings, covered = {}, set()
    for result in lock_report['Results']:
        ecosystem = ECOSYSTEM.get(result.get('Type'))
        if ecosystem is None:
            continue
        for vulnerability in result.get('Vulnerabilities') or []:
            if vulnerability.get('Severity') not in SEVERITIES:
                continue
            name, version = vulnerability['PkgName'], vulnerability['InstalledVersion']
            key = (vulnerability['VulnerabilityID'], ecosystem, name, version)
            if (ecosystem, name, version) in shipped:
                covered.add(key)
                continue
            if ecosystem == 'cargo':
                attributed = crates.get((name, version))
                steps = sorted(f'{text} [{", ".join(sorted(arches))}]' for text, arches in attributed.items()) \
                    if attributed else ['not compiled for the native linux or wasm32 builds']
            else:
                steps = npm_steps(package_lock, name, version)
            findings[key] = {'id': key[0], 'ecosystem': ecosystem, 'package': name, 'version': version,
                             'severity': vulnerability['Severity'],
                             'fixed_version': vulnerability.get('FixedVersion') or 'none',
                             'title': (vulnerability.get('Title') or '')[:160], 'build_steps': steps}
    ordered = [findings[k] for k in sorted(findings, key=lambda k: (SEVERITIES.index(findings[k]['severity']), k))]
    identity = '\n'.join(f'{f["id"]}|{f["ecosystem"]}|{f["package"]}|{f["version"]}|{f["fixed_version"]}'
                         for f in sorted(ordered, key=lambda f: (f['id'], f['ecosystem'], f['package'], f['version'])))
    return {'fingerprint': hashlib.sha256(identity.encode()).hexdigest(), 'build_time_only': ordered,
            'shipped_high_critical_covered_by_image_gate': len(covered),
            'architectures': sorted(shipped_reports)}


def markdown(summary):
    rows = summary['build_time_only']
    lines = ['## Build-time dependency vulnerabilities (non-blocking)', '',
             'High/Critical findings in the pinned upstream Cargo.lock and package-lock.json that are '
             'not in the shipped image inventory of any native architecture '
             f'({", ".join(summary["architectures"])}). Shipped findings stay with the blocking image gate '
             f'({summary["shipped_high_critical_covered_by_image_gate"]} lockfile High/Critical finding(s) '
             'matched shipped packages).', '',
             f'Build-time only: **{len(rows)}**. Set fingerprint `{summary["fingerprint"]}`.', '']
    if rows:
        lines += ['| Severity | Finding | Package | Version | Fixed version | Build step |',
                  '| --- | --- | --- | --- | --- | --- |']
        for f in rows:
            lines.append(f'| {f["severity"]} | {f["id"]} | {f["ecosystem"]}:{f["package"]} | {f["version"]} | '
                         f'{f["fixed_version"]} | {"<br>".join(s.replace("|", "/") for s in f["build_steps"])} |')
    return '\n'.join(lines) + '\n'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--lock-report', required=True)
    parser.add_argument('--image-report', action='append', required=True, metavar='ARCH=PATH')
    parser.add_argument('--metadata', action='append', required=True, metavar='ARCH=PATH',
                        help='cargo metadata for the native target; ARCH "wasm32" is the WASM target')
    parser.add_argument('--package-lock', required=True)
    parser.add_argument('--summary', required=True)
    parser.add_argument('--markdown', required=True)
    args = parser.parse_args()
    try:
        shipped = {a: load(p) for a, p in (item.split('=', 1) for item in args.image_report)}
        if set(shipped) != {'amd64', 'arm64'}:
            raise AuditError(f'need amd64 and arm64 image reports, got {sorted(shipped)}')
        metadata = {}
        for arch, path in (item.split('=', 1) for item in args.metadata):
            root, step = (WASM_ROOT, WASM_STEP) if arch == 'wasm32' else (SERVER_ROOT, SERVER_STEP)
            metadata[(arch, root, step)] = load(path)
        if {a for a, _, _ in metadata} != {'amd64', 'arm64', 'wasm32'}:
            raise AuditError('need cargo metadata for amd64, arm64 and wasm32')
        summary = audit(load(args.lock_report), shipped, metadata, load(args.package_lock))
    except (AuditError, KeyError) as error:
        print(f'build-time audit failed closed: {type(error).__name__}: {error}', file=sys.stderr)
        return 1
    Path(args.summary).write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')
    Path(args.markdown).write_text(markdown(summary), encoding='utf-8')
    print(markdown(summary))
    return 0


if __name__ == '__main__':
    sys.exit(main())
