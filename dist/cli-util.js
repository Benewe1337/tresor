/** Small helpers shared by the CLI commands. */
import { createInterface } from 'readline';
export function fail(msg) {
    process.stderr.write(`tresor: ${msg}\n`);
    process.exit(1);
}
export const say = (s) => { process.stdout.write(`${s}\n`); };
/** Removes every `flag value` pair from args and returns the values. */
export function takeFlag(args, flag) {
    const values = [];
    for (let i = args.indexOf(flag); i !== -1; i = args.indexOf(flag)) {
        if (i + 1 >= args.length)
            fail(`${flag} needs a value`);
        values.push(args[i + 1]);
        args.splice(i, 2);
    }
    return values;
}
export function takeSwitch(args, flag) {
    const i = args.indexOf(flag);
    if (i === -1)
        return false;
    args.splice(i, 1);
    return true;
}
/** Comma-separated and repeated flags: --only A,B --only C → [A, B, C]. */
export function takeList(args, flag) {
    const raw = takeFlag(args, flag).flatMap(v => v.split(',')).map(s => s.trim()).filter(Boolean);
    return raw.length ? raw : undefined;
}
export async function readHidden(question) {
    if (!process.stdin.isTTY) {
        const chunks = [];
        for await (const c of process.stdin)
            chunks.push(c);
        return Buffer.concat(chunks).toString('utf-8').trim();
    }
    const rl = createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    // Suppress echo of typed characters.
    rl._writeToOutput = (s) => {
        if (s.includes(question))
            process.stdout.write(s);
    };
    const answer = await new Promise(res => rl.question(question, res));
    rl.close();
    process.stdout.write('\n');
    return answer.trim();
}
/** y/N prompt; false when not interactive. */
export async function askYesNo(question) {
    if (!process.stdin.isTTY)
        return false;
    const rl = createInterface({ input: process.stdin, output: process.stdout });
    const answer = await new Promise(res => rl.question(`${question} [y/N] `, res));
    rl.close();
    return /^y(es)?$/i.test(answer.trim());
}
