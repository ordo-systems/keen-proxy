#!/usr/bin/env python3
"""Compare WireGuard memory runs and report candidate-only AmneziaWG metrics.

Usage:
    python3 test/memory/compare.py --baseline DIR --candidate DIR --output FILE

Reads baseline/wireguard-{1,2,3}.json, candidate/wireguard-{1,2,3}.json, and
the required candidate/amneziawg-1.json. Identity fields must match the
directory role and filename. Any other JSON input fails closed. Non-JSON
files are ignored so a runner can keep logs beside the results.

Exit codes:
    0  every candidate median is within the limit
    1  at least one WireGuard metric regressed
    2  missing, unexpected, or malformed input, or a passing report could not
       be written

The report is replaced atomically for pass, regression, and malformed input.
Malformed results set passed to false, list errors, and omit comparison rows
so a partial set cannot look successful. A regression still writes the report.

Threshold, for each of idle, loaded, drained, and reapplied, and for
rss_bytes, anon_bytes, and peak_rss_bytes:
    candidate_median <= baseline_median + max(baseline_median // 10, 12 MiB)
Equality passes. Integer medians make the floor division the same bound as
baseline + baseline/10.

Each run object accepts schema_version, variant, scenario, run, phases,
evidence, and optional samples. phases has exactly those four names, each
with positive integer rss_bytes, anon_bytes, and peak_rss_bytes, rss >= anon,
and peak >= rss. Bool is not an integer. samples, when present, is a JSON
object or array of raw evidence and is not interpreted.

evidence requires tcp_bytes and udp_bytes objects with positive wg1 and wg2
counts, apply_count >= 3, loaded_connections >= 32 (TCP sessions),
drained_connections == 0 (TCP sessions after drain), and
drained_udp_connections == 2. Those two counts are the proven live UDP
mappings kept after TCP close, not an arbitrary residual. udp_during_load
and udp_drain_verified must be JSON true. The load flag proves UDP happened
during measurement. The drain flag proves fresh UDP exchanges while TCP
client and server counts were zero. Neither flag nor the UDP count is a
regression input. Additional evidence keys are allowed. AmneziaWG uses the
same evidence shape, is validated and copied into the report, and is excluded
from WireGuard medians. Baseline AmneziaWG input is rejected.
"""
from pathlib import Path
import argparse
import json
import os
import sys
import tempfile

PHASES = ('idle', 'loaded', 'drained', 'reapplied')
METRICS = ('rss_bytes', 'anon_bytes', 'peak_rss_bytes')
WG_RUNS = (1, 2, 3)
WG_NAMES = tuple('wireguard-%d.json' % run for run in WG_RUNS)
AWG_NAME = 'amneziawg-1.json'
CANDIDATE_NAMES = WG_NAMES + (AWG_NAME,)
TOP_KEYS = {'schema_version', 'variant', 'scenario', 'run', 'phases', 'evidence', 'samples'}
ABSOLUTE_ALLOWANCE_BYTES = 12 * 1024 * 1024
RELATIVE_DIVISOR = 10
EXIT_PASS = 0
EXIT_REGRESSION = 1
EXIT_MALFORMED = 2


def problem(file, path, message):
    """Build one machine-readable diagnostic."""
    return {'file': str(file), 'path': path, 'message': message}


def describe(value):
    """Render a rejected JSON value without treating bool as an integer."""
    if type(value) is bool:
        return 'true' if value else 'false'
    return repr(value)


def reject_constant(token):
    """Refuse JSON Infinity and NaN, which are not finite measurements."""
    raise ValueError('non-finite number %s' % token)


def object_pairs(pairs):
    """Decode one object and fail closed on duplicate keys."""
    found = {}
    for key, value in pairs:
        if key in found:
            raise ValueError('duplicate key %r' % key)
        found[key] = value
    return found


def check_int(value, file, path, errors, accept, message):
    """Accept only a real integer that satisfies accept; bool is not an int."""
    if type(value) is int and accept(value):
        return True
    errors.append(problem(file, path, '%s, got %s' % (message, describe(value))))
    return False


def check_positive(value, file, path, errors):
    """Require a positive byte or connection count."""
    return check_int(value, file, path, errors, lambda item: item > 0, 'must be a positive integer')


def check_tunnels(value, file, path, errors):
    """Require positive TCP or UDP bytes on both tunnel ids."""
    if not isinstance(value, dict) or set(value) != {'wg1', 'wg2'}:
        errors.append(problem(file, path, 'must be an object with exactly wg1 and wg2'))
        return False
    first = check_positive(value['wg1'], file, path + '.wg1', errors)
    second = check_positive(value['wg2'], file, path + '.wg2', errors)
    return first and second


def check_apply(value, file, path, errors):
    """Require at least three real Apply cycles."""
    return check_int(value, file, path, errors, lambda item: item >= 3, 'must be an integer >= 3')


def check_loaded(value, file, path, errors):
    """Require the TCP session minimum observed during load."""
    return check_int(
        value, file, path, errors, lambda item: item >= 32,
        'must be an integer >= 32 for TCP sessions during load',
    )


def check_drained_tcp(value, file, path, errors):
    """Require the fixture TCP sessions to be zero after drain."""
    return check_int(
        value, file, path, errors, lambda item: item == 0,
        'must be integer 0 for TCP sessions after drain',
    )


def check_drained_udp(value, file, path, errors):
    """Require the two proven live UDP mappings retained after TCP close."""
    return check_int(
        value, file, path, errors, lambda item: item == 2,
        'must be integer 2 for the proven live UDP mappings',
    )


def check_true(value, file, path, errors):
    """Require JSON true. Integer 1 compares equal to True and is not proof."""
    if value is True:
        return True
    errors.append(problem(file, path, 'must be true, got %s' % describe(value)))
    return False


EVIDENCE_CHECKS = (
    ('tcp_bytes', check_tunnels),
    ('udp_bytes', check_tunnels),
    ('apply_count', check_apply),
    ('loaded_connections', check_loaded),
    ('drained_connections', check_drained_tcp),
    ('drained_udp_connections', check_drained_udp),
    ('udp_during_load', check_true),
    ('udp_drain_verified', check_true),
)


def validate_evidence(evidence, file, errors):
    """Validate required evidence and allow fixture-specific extra keys."""
    if not isinstance(evidence, dict):
        errors.append(problem(file, 'evidence', 'must be a JSON object'))
        return False
    missing = [key for key, _check in EVIDENCE_CHECKS if key not in evidence]
    if missing:
        errors.append(problem(file, 'evidence', 'missing ' + ', '.join(missing)))
    ok = not missing
    for key, check in EVIDENCE_CHECKS:
        if key in evidence and not check(evidence[key], file, 'evidence.' + key, errors):
            ok = False
    return ok


def evidence_summary(evidence):
    """Copy the comparable evidence fields, leaving extra keys in the run file."""
    return {
        'tcp_bytes': {'wg1': evidence['tcp_bytes']['wg1'], 'wg2': evidence['tcp_bytes']['wg2']},
        'udp_bytes': {'wg1': evidence['udp_bytes']['wg1'], 'wg2': evidence['udp_bytes']['wg2']},
        'apply_count': evidence['apply_count'],
        'loaded_connections': evidence['loaded_connections'],
        'drained_connections': evidence['drained_connections'],
        'drained_udp_connections': evidence['drained_udp_connections'],
        'udp_during_load': evidence['udp_during_load'],
        'udp_drain_verified': evidence['udp_drain_verified'],
    }


def phase_key_error(phases):
    """Describe missing and unexpected phase names, if any."""
    missing = [name for name in PHASES if name not in phases]
    extra = [name for name in phases if name not in PHASES]
    parts = []
    if missing:
        parts.append('missing ' + ', '.join(missing))
    if extra:
        parts.append('unexpected ' + ', '.join(extra))
    return '; '.join(parts)


def phase_invariants(values, file, path, errors):
    """Enforce rss >= anon and peak >= rss, including equality."""
    ok = True
    if values['rss_bytes'] < values['anon_bytes']:
        errors.append(problem(
            file, path,
            'rss_bytes %s is below anon_bytes %s' % (values['rss_bytes'], values['anon_bytes']),
        ))
        ok = False
    if values['peak_rss_bytes'] < values['rss_bytes']:
        errors.append(problem(
            file, path,
            'peak_rss_bytes %s is below rss_bytes %s' % (values['peak_rss_bytes'], values['rss_bytes']),
        ))
        ok = False
    return ok


def validate_phase(phase, file, path, errors):
    """Parse one phase or record why it cannot be compared."""
    if not isinstance(phase, dict) or set(phase) != set(METRICS):
        errors.append(problem(file, path, 'must contain exactly rss_bytes, anon_bytes, peak_rss_bytes'))
        return None
    values = {}
    ok = True
    for metric in METRICS:
        pointer = path + '.' + metric
        if check_positive(phase[metric], file, pointer, errors):
            values[metric] = phase[metric]
        else:
            ok = False
    if not ok or not phase_invariants(values, file, path, errors):
        return None
    return values


def validate_phases(phases, file, errors):
    """Require the four measured phases and no others."""
    if not isinstance(phases, dict):
        errors.append(problem(file, 'phases', 'must be a JSON object'))
        return None
    key_error = phase_key_error(phases)
    ok = True
    if key_error:
        errors.append(problem(file, 'phases', key_error))
        ok = False
    parsed = {}
    for name in PHASES:
        if name not in phases:
            continue
        phase = validate_phase(phases[name], file, 'phases.' + name, errors)
        if phase is None:
            ok = False
        else:
            parsed[name] = phase
    if not ok:
        return None
    return parsed


def check_top_level(data, file, errors):
    """Reject keys outside the run contract."""
    extra = sorted(set(data) - TOP_KEYS)
    if not extra:
        return True
    errors.append(problem(file, '', 'unexpected keys: ' + ', '.join(extra)))
    return False


def check_identity(data, file, variant, scenario, run, errors):
    """Match schema, variant, scenario, and run to the file location."""
    specs = (
        ('schema_version', 1, 'integer 1'),
        ('variant', variant, "'%s' to match the %s directory" % (variant, variant)),
        ('scenario', scenario, "'%s' to match filename" % scenario),
        ('run', run, 'integer %s to match filename' % run),
    )
    ok = True
    for key, expected, label in specs:
        if key not in data:
            errors.append(problem(file, key, 'missing'))
            ok = False
            continue
        value = data[key]
        if type(value) is type(expected) and value == expected:
            continue
        errors.append(problem(file, key, 'must be %s, got %s' % (label, describe(value))))
        ok = False
    return ok


def check_samples(data, file, errors):
    """Allow omitted samples or structured raw evidence only."""
    if 'samples' not in data:
        return True
    if isinstance(data['samples'], (dict, list)):
        return True
    errors.append(problem(file, 'samples', 'must be a JSON object or array of raw evidence'))
    return False


def read_phases(data, file, errors):
    """Return parsed phases, or None when the object is absent or invalid."""
    if 'phases' not in data:
        errors.append(problem(file, 'phases', 'missing phases'))
        return None
    return validate_phases(data['phases'], file, errors)


def read_evidence(data, file, errors):
    """Return the evidence summary, or None when evidence is absent or invalid."""
    if 'evidence' not in data:
        errors.append(problem(file, 'evidence', 'missing evidence'))
        return None
    if not validate_evidence(data['evidence'], file, errors):
        return None
    return evidence_summary(data['evidence'])


def validate_document(data, file, variant, scenario, run, errors):
    """Return a normalized run, or None after recording every problem."""
    ok = check_top_level(data, file, errors)
    ok = check_identity(data, file, variant, scenario, run, errors) and ok
    phases = read_phases(data, file, errors)
    evidence = read_evidence(data, file, errors)
    if not check_samples(data, file, errors):
        ok = False
    if not ok or phases is None or evidence is None:
        return None
    return {'run': run, 'scenario': scenario, 'phases': phases, 'evidence': evidence}


def load_document(path, errors):
    """Read one UTF-8 JSON object, rejecting duplicates and non-finite numbers."""
    try:
        text = path.read_text(encoding='utf-8')
    except OSError as exc:
        errors.append(problem(path, '', 'cannot read file: %s' % (exc.strerror or exc)))
        return None
    except UnicodeDecodeError:
        errors.append(problem(path, '', 'file is not valid UTF-8'))
        return None
    try:
        data = json.loads(text, object_pairs_hook=object_pairs, parse_constant=reject_constant)
    except ValueError as exc:
        errors.append(problem(path, '', 'invalid JSON: %s' % exc))
        return None
    if isinstance(data, dict):
        return data
    errors.append(problem(path, '', 'document must be a JSON object'))
    return None


def iter_json(directory, role, errors):
    """List JSON entries in one result directory, or None when it cannot be read."""
    try:
        if not directory.exists():
            errors.append(problem(directory, '', '%s directory is missing' % role))
            return None
        if not directory.is_dir():
            errors.append(problem(directory, '', '%s path is not a directory' % role))
            return None
        entries = [path for path in directory.iterdir() if path.suffix == '.json']
    except OSError as exc:
        errors.append(problem(directory, '', 'cannot read directory: %s' % (exc.strerror or exc)))
        return None
    entries.sort(key=lambda path: path.name)
    return entries


def extra_message(path, role):
    """Explain unexpected JSON, including AmneziaWG results in the baseline."""
    if role == 'baseline' and path.name.startswith('amneziawg'):
        return 'baseline cannot include amneziawg results'
    return 'unexpected JSON input'


def select_runs(directory, entries, expected, role, errors):
    """Choose the expected run files and reject every other JSON entry."""
    by_name = dict((path.name, path) for path in entries)
    expected_names = set(expected)
    selected = []
    for name in expected:
        path = by_name.get(name)
        if path is None:
            errors.append(problem(directory / name, '', 'missing required run file'))
            continue
        if not path.is_file():
            errors.append(problem(path, '', 'not a regular file'))
            continue
        selected.append(path)
    for path in entries:
        if path.name in expected_names:
            continue
        errors.append(problem(path, '', extra_message(path, role)))
    return selected


def split_name(name):
    """Return the scenario and run encoded in an expected result filename."""
    scenario, run_text = name[:-len('.json')].split('-')
    return scenario, int(run_text)


def read_variant(directory, role, names, variant, errors):
    """Validate every expected file for one variant. Invalid files are omitted."""
    directory = Path(directory)
    entries = iter_json(directory, role, errors)
    if entries is None:
        return {}
    docs = {}
    for path in select_runs(directory, entries, names, role, errors):
        scenario, run = split_name(path.name)
        data = load_document(path, errors)
        if data is None:
            continue
        doc = validate_document(data, path, variant, scenario, run, errors)
        if doc is not None:
            docs[path.name] = doc
    return docs


def median(values):
    """Return the middle value. Callers pass the three paired runs."""
    return sorted(values)[len(values) // 2]


def metric_row(phase, metric, baseline_values, candidate_values):
    """Apply the fixed gate. Equality passes.

    For an integer candidate median, baseline + baseline/10 is the same bound
    as baseline + baseline//10, so the byte comparison stays exact.
    """
    baseline_median = median(baseline_values)
    candidate_median = median(candidate_values)
    relative = baseline_median // RELATIVE_DIVISOR
    allowance = max(relative, ABSOLUTE_ALLOWANCE_BYTES)
    limit = baseline_median + allowance
    return {
        'phase': phase,
        'metric': metric,
        'baseline_median': baseline_median,
        'candidate_median': candidate_median,
        'delta_bytes': candidate_median - baseline_median,
        'relative_allowance_bytes': relative,
        'absolute_allowance_bytes': ABSOLUTE_ALLOWANCE_BYTES,
        'allowance_bytes': allowance,
        'limit_bytes': limit,
        'passed': candidate_median <= limit,
    }


def build_rows(baseline, candidate):
    """Compare WireGuard medians only. AmneziaWG is not a fourth sample."""
    rows = []
    for phase in PHASES:
        for metric in METRICS:
            rows.append(metric_row(
                phase,
                metric,
                [baseline[name]['phases'][phase][metric] for name in WG_NAMES],
                [candidate[name]['phases'][phase][metric] for name in WG_NAMES],
            ))
    return rows


def threshold_info():
    """Describe the fixed threshold without making it configurable."""
    return {
        'absolute_bytes': ABSOLUTE_ALLOWANCE_BYTES,
        'relative_divisor': RELATIVE_DIVISOR,
        'rule': 'candidate_median <= baseline_median + max(baseline_median // 10, absolute_bytes)',
    }


def awg_section(doc):
    """Copy validated AmneziaWG metrics, or None when that run is unusable."""
    if doc is None:
        return None
    return {
        'file': AWG_NAME,
        'variant': 'candidate',
        'scenario': 'amneziawg',
        'run': doc['run'],
        'phases': doc['phases'],
        'evidence': doc['evidence'],
    }


def wireguard_ready(baseline, candidate):
    """Return whether all six WireGuard runs survived validation."""
    return all(name in baseline and name in candidate for name in WG_NAMES)


def status_for(errors, failures):
    """Map validation and comparison results to the report status."""
    if errors:
        return 'malformed', False
    if failures:
        return 'regression', False
    return 'pass', True


def evaluate(baseline_dir, candidate_dir):
    """Validate both directories and compare WireGuard medians.

    Comparison rows are omitted when any input is invalid. A validated
    AmneziaWG run is still reported so its cost and UDP residual remain visible.
    """
    errors = []
    baseline = read_variant(baseline_dir, 'baseline', WG_NAMES, 'baseline', errors)
    candidate = read_variant(candidate_dir, 'candidate', CANDIDATE_NAMES, 'candidate', errors)
    rows = []
    if not errors and wireguard_ready(baseline, candidate):
        rows = build_rows(baseline, candidate)
    failures = [row for row in rows if not row['passed']]
    status, passed = status_for(errors, failures)
    return {
        'schema_version': 1,
        'status': status,
        'passed': passed,
        'threshold': threshold_info(),
        'comparisons': rows,
        'failures': failures,
        'amneziawg': awg_section(candidate.get(AWG_NAME)),
        'errors': errors,
    }


def write_report(path, report):
    """Atomically replace the report, including regression and malformed results."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + '\n'
    descriptor, name = tempfile.mkstemp(prefix='.' + path.name + '.', dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, 'w', encoding='utf-8') as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except Exception:
        if temporary.exists():
            temporary.unlink()
        raise


def format_error(error):
    """Render one diagnostic for the CLI."""
    if error['path']:
        return '%s: %s: %s' % (error['file'], error['path'], error['message'])
    return '%s: %s' % (error['file'], error['message'])


def format_failure(failure):
    """Render one over-limit metric for the CLI."""
    return (
        '%s %s: candidate median %s exceeds limit %s '
        '(baseline median %s, delta %s)'
    ) % (
        failure['phase'], failure['metric'], failure['candidate_median'],
        failure['limit_bytes'], failure['baseline_median'], failure['delta_bytes'],
    )


def write_diagnostics(report, stream):
    """Print regression or malformed details without claiming success."""
    if report['status'] == 'regression':
        print(
            'memory comparison failed: %d metric(s) above the limit' % len(report['failures']),
            file=stream,
        )
        for failure in report['failures']:
            print(format_failure(failure), file=stream)
        return
    print('memory comparison malformed: %d error(s)' % len(report['errors']), file=stream)
    for error in report['errors']:
        print(format_error(error), file=stream)


def emit(report, output):
    """Print the CLI summary for a report that was stored successfully."""
    if report['status'] == 'pass':
        print('memory comparison passed: %s' % output)
        return
    write_diagnostics(report, sys.stderr)
    print('report: %s' % output, file=sys.stderr)


def exit_code(report):
    """Return 0, 1, or 2 from a finished report."""
    if report['status'] == 'pass':
        return EXIT_PASS
    if report['status'] == 'regression':
        return EXIT_REGRESSION
    return EXIT_MALFORMED


def parse_args(argv):
    """Parse the comparator CLI. Missing arguments exit 2."""
    parser = argparse.ArgumentParser(description='Compare memory regression measurements.')
    parser.add_argument('--baseline', required=True, type=Path)
    parser.add_argument('--candidate', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    return parser.parse_args(argv)


def main(argv=None):
    """Compare the directories and write the report. Never exits 0 unreadably."""
    args = parse_args(argv)
    report = evaluate(args.baseline, args.candidate)
    try:
        write_report(args.output, report)
    except OSError as exc:
        print('cannot write report %s: %s' % (args.output, exc), file=sys.stderr)
        if report['status'] != 'pass':
            write_diagnostics(report, sys.stderr)
        if report['status'] == 'regression':
            return EXIT_REGRESSION
        return EXIT_MALFORMED
    emit(report, args.output)
    return exit_code(report)


if __name__ == '__main__':
    raise SystemExit(main())
