/**
 * Leak scanner: finds stored secret values (and their common encodings) in files,
 * staged git changes and Claude Code transcripts. Findings name the secret, the
 * encoding and the location — never the value itself.
 *
 * Unlike pattern-based scanners this knows the actual values, so a hit is a real
 * leak, not a guess.
 */
import { createReadStream, existsSync, readdirSync, readFileSync, statSync, writeFileSync, chmodSync } from 'fs';
import { homedir } from 'os';
import { join, resolve } from 'path';
import { createInterface } from 'readline';
import { exec } from './platform/exec.js';
import { secretVariants } from './redact.js';
/** Shorter values are skipped: they would match ordinary text. */
export const MIN_SCAN_LENGTH = 8;
const MAX_FILE_BYTES = 20 * 1024 * 1024;
const SKIP_DIRS = new Set(['.git', 'node_modules', '.hg', '.svn']);
export class Scanner {
    needles;
    constructor(values) {
        this.needles = Object.entries(values)
            .flatMap(([secret, value]) => secretVariants(value, MIN_SCAN_LENGTH).map(v => ({ secret, kind: v.kind, text: v.text })))
            .sort((a, b) => b.text.length - a.text.length);
    }
    get empty() { return this.needles.length === 0; }
    /** All hits in `text`; `firstLine` offsets line numbers when scanning chunks. */
    scanText(text, file, firstLine = 1) {
        const findings = [];
        const seen = new Set();
        let lineStarts = null;
        for (const n of this.needles) {
            for (let i = text.indexOf(n.text); i !== -1; i = text.indexOf(n.text, i + n.text.length)) {
                lineStarts ??= computeLineStarts(text);
                const line = firstLine + lineIndex(lineStarts, i);
                const key = `${n.secret}:${line}`;
                if (seen.has(key))
                    continue; // a longer variant on this line was already reported
                seen.add(key);
                findings.push({ secret: n.secret, kind: n.kind, file, line });
            }
        }
        return findings;
    }
}
function computeLineStarts(text) {
    const starts = [0];
    for (let i = text.indexOf('\n'); i !== -1; i = text.indexOf('\n', i + 1))
        starts.push(i + 1);
    return starts;
}
function lineIndex(starts, pos) {
    let lo = 0;
    let hi = starts.length - 1;
    while (lo < hi) {
        const mid = (lo + hi + 1) >> 1;
        if (starts[mid] <= pos)
            lo = mid;
        else
            hi = mid - 1;
    }
    return lo;
}
function looksBinary(buf) {
    return buf.subarray(0, 8000).includes(0);
}
function* walk(path) {
    const st = statSync(path);
    if (st.isFile()) {
        yield path;
        return;
    }
    if (!st.isDirectory())
        return;
    for (const entry of readdirSync(path, { withFileTypes: true })) {
        if (entry.isDirectory() && SKIP_DIRS.has(entry.name))
            continue;
        if (entry.isSymbolicLink())
            continue;
        yield* walk(join(path, entry.name));
    }
}
/** Values to look for. Linked secrets are resolved through their password manager unless localOnly. */
export async function collectValues(store, opts = {}) {
    const values = {};
    const warnings = [];
    for (const s of store.list()) {
        if (s.source && opts.localOnly)
            continue;
        try {
            const v = await store.resolve(s.name);
            if (v.length < MIN_SCAN_LENGTH)
                warnings.push(`${s.name}: shorter than ${MIN_SCAN_LENGTH} characters, not scanned`);
            else
                values[s.name] = v;
        }
        catch (e) {
            warnings.push(`${s.name}: not checked (${e instanceof Error ? e.message : String(e)})`);
        }
    }
    return { values, warnings };
}
export function scanPaths(scanner, paths) {
    const findings = [];
    let scannedFiles = 0;
    for (const p of paths) {
        const root = resolve(p);
        if (!existsSync(root))
            throw new Error(`Path not found: ${root}`);
        for (const file of walk(root)) {
            if (statSync(file).size > MAX_FILE_BYTES)
                continue;
            const buf = readFileSync(file);
            if (looksBinary(buf))
                continue;
            scannedFiles++;
            findings.push(...scanner.scanText(buf.toString('utf-8'), file));
        }
    }
    return { findings, scannedFiles };
}
/** Scans the *staged* content (what would be committed), not the working tree. */
export async function scanStaged(scanner, cwd = process.cwd()) {
    const list = await exec('git', ['diff', '--cached', '--name-only', '-z', '--diff-filter=ACMR'], { cwd });
    if (list.code !== 0)
        throw new Error(`git diff failed: ${list.stderr.trim()}`);
    const files = list.stdout.split('\0').filter(Boolean);
    const findings = [];
    let scannedFiles = 0;
    for (const f of files) {
        const blob = await exec('git', ['show', `:${f}`], { cwd });
        if (blob.code !== 0 || blob.stdout.includes('\0'))
            continue;
        scannedFiles++;
        findings.push(...scanner.scanText(blob.stdout, f));
    }
    return { findings, scannedFiles };
}
export function claudeProjectsDir() {
    return join(process.env.CLAUDE_CONFIG_DIR ?? join(homedir(), '.claude'), 'projects');
}
/** Streams Claude Code session transcripts (*.jsonl) line by line. */
export async function scanTranscripts(scanner, dir = claudeProjectsDir()) {
    if (!existsSync(dir))
        return { findings: [], scannedFiles: 0 };
    const findings = [];
    let scannedFiles = 0;
    for (const file of walk(dir)) {
        if (!file.endsWith('.jsonl'))
            continue;
        scannedFiles++;
        const rl = createInterface({ input: createReadStream(file, { encoding: 'utf-8' }), crlfDelay: Infinity });
        let lineNo = 0;
        for await (const line of rl) {
            lineNo++;
            findings.push(...scanner.scanText(line, file, lineNo));
        }
    }
    return { findings, scannedFiles };
}
export async function runScan(store, opts) {
    const { values, warnings } = await collectValues(store, { localOnly: opts.localOnly });
    const scanner = new Scanner(values);
    const report = { findings: [], scannedFiles: 0, secretsChecked: Object.keys(values).sort(), warnings };
    if (scanner.empty)
        return report;
    const add = (r) => {
        report.findings.push(...r.findings);
        report.scannedFiles += r.scannedFiles;
    };
    if (opts.staged)
        add(await scanStaged(scanner, opts.cwd));
    if (opts.transcripts)
        add(await scanTranscripts(scanner));
    if (opts.paths?.length)
        add(scanPaths(scanner, opts.paths.map(p => resolve(opts.cwd ?? process.cwd(), p))));
    return report;
}
export function formatReport(report) {
    const lines = [];
    for (const w of report.warnings)
        lines.push(`! ${w}`);
    if (report.findings.length === 0) {
        lines.push(`✓ no stored secret found (${report.scannedFiles} files, ${report.secretsChecked.length} secrets checked)`);
        return lines.join('\n');
    }
    for (const f of report.findings)
        lines.push(`✗ ${f.file}:${f.line}  ${f.secret} (${f.kind})`);
    const leaked = [...new Set(report.findings.map(f => f.secret))];
    lines.push(`\n${report.findings.length} finding(s) for: ${leaked.join(', ')}. Remove them; if the value was ever committed, pushed or shared, rotate it.`);
    return lines.join('\n');
}
const HOOK_MARKER = '# tresor:pre-commit';
const HOOK_SCRIPT = `#!/bin/sh
${HOOK_MARKER} – blocks commits that contain a value stored in tresor
command -v tresor >/dev/null 2>&1 || { echo "tresor not on PATH – skipping secret scan" >&2; exit 0; }
exec tresor scan --staged
`;
/** Installs a git pre-commit hook; refuses to overwrite a foreign hook unless forced. */
export async function installPreCommitHook(cwd = process.cwd(), force = false) {
    const r = await exec('git', ['rev-parse', '--git-path', 'hooks'], { cwd });
    if (r.code !== 0)
        throw new Error('Not inside a git repository.');
    const hooksDir = resolve(cwd, r.stdout.trim());
    const hook = join(hooksDir, 'pre-commit');
    if (existsSync(hook) && !readFileSync(hook, 'utf-8').includes(HOOK_MARKER) && !force) {
        throw new Error(`${hook} already exists. Add "tresor scan --staged" to it yourself, or re-run with --force to replace it.`);
    }
    writeFileSync(hook, HOOK_SCRIPT);
    if (process.platform !== 'win32')
        chmodSync(hook, 0o755);
    return hook;
}
