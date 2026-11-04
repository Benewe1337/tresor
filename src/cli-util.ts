/** Small helpers shared by the CLI commands. */

import { createInterface } from 'readline';

export function fail(msg: string): never {
  process.stderr.write(`tresor: ${msg}\n`);
  process.exit(1);
}

export const say = (s: string): void => { process.stdout.write(`${s}\n`); };

/** Removes every `flag value` pair from args and returns the values. */
export function takeFlag(args: string[], flag: string): string[] {
  const values: string[] = [];
  for (let i = args.indexOf(flag); i !== -1; i = args.indexOf(flag)) {
    if (i + 1 >= args.length) fail(`${flag} needs a value`);
    values.push(args[i + 1]);
    args.splice(i, 2);
  }
  return values;
}

export function takeSwitch(args: string[], flag: string): boolean {
  const i = args.indexOf(flag);
  if (i === -1) return false;
  args.splice(i, 1);
  return true;
}

/** Comma-separated and repeated flags: --only A,B --only C → [A, B, C]. */
export function takeList(args: string[], flag: string): string[] | undefined {
  const raw = takeFlag(args, flag).flatMap(v => v.split(',')).map(s => s.trim()).filter(Boolean);
  return raw.length ? raw : undefined;
}

export async function readHidden(question: string): Promise<string> {
  if (!process.stdin.isTTY) {
    const chunks: Buffer[] = [];
    for await (const c of process.stdin) chunks.push(c as Buffer);
    return Buffer.concat(chunks).toString('utf-8').trim();
  }
  const rl = createInterface({ input: process.stdin, output: process.stdout, terminal: true });
  // Suppress echo of typed characters.
  (rl as unknown as { _writeToOutput: (s: string) => void })._writeToOutput = (s: string) => {
    if (s.includes(question)) process.stdout.write(s);
  };
  const answer = await new Promise<string>(res => rl.question(question, res));
  rl.close();
  process.stdout.write('\n');
  return answer.trim();
}

/** y/N prompt; false when not interactive. */
export async function askYesNo(question: string): Promise<boolean> {
  if (!process.stdin.isTTY) return false;
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  const answer = await new Promise<string>(res => rl.question(`${question} [y/N] `, res));
  rl.close();
  return /^y(es)?$/i.test(answer.trim());
}
