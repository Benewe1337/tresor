/**
 * Output redaction: replaces every secret value — and its common encodings — with
 * a marker like `[tresor:openai]` before anything is handed back to the model.
 *
 * This is a safety net against *accidental* leaks (a tool echoing its config, a
 * verbose curl, `env`), not a guarantee against deliberate transformation of the
 * value (reversing, slicing). Values shorter than MIN_REDACT_LENGTH are not
 * redacted because they'd shred ordinary output.
 */

export const MIN_REDACT_LENGTH = 4;

export interface Variant {
  /** How the value is encoded, e.g. "raw", "base64" — safe to show, never the value. */
  kind: string;
  text: string;
}

/** The value plus the encodings it commonly shows up in (headers, URLs, JSON, logs). */
export function secretVariants(value: string, minLength = MIN_REDACT_LENGTH): Variant[] {
  const b64 = Buffer.from(value, 'utf-8').toString('base64');
  const candidates: Variant[] = [
    { kind: 'raw', text: value },
    { kind: 'trimmed', text: value.trim() },
    { kind: 'base64', text: b64 },
    { kind: 'base64', text: b64.replace(/=+$/, '') },
    { kind: 'base64url', text: Buffer.from(value, 'utf-8').toString('base64url') },
    { kind: 'url-encoded', text: encodeURIComponent(value) },
    { kind: 'json-escaped', text: JSON.stringify(value).slice(1, -1) },
  ];
  const seen = new Set<string>();
  return candidates.filter(v => v.text.length >= minLength && !seen.has(v.text) && seen.add(v.text));
}

export class Redactor {
  private readonly pairs: Array<[string, string]>;

  constructor(secrets: Record<string, string>) {
    const pairs: Array<[string, string]> = [];
    for (const [name, value] of Object.entries(secrets)) {
      for (const v of secretVariants(value)) pairs.push([v.text, `[tresor:${name}]`]);
    }
    // Longest first so a value that contains another secret is caught whole.
    this.pairs = pairs.sort((a, b) => b[0].length - a[0].length);
  }

  redact(text: string): string {
    let out = text;
    for (const [needle, marker] of this.pairs) out = out.split(needle).join(marker);
    return out;
  }
}

export function truncate(text: string, maxChars: number): string {
  if (text.length <= maxChars) return text;
  const head = Math.floor(maxChars * 0.6);
  const tail = maxChars - head;
  return `${text.slice(0, head)}\n…[${text.length - maxChars} chars truncated]…\n${text.slice(-tail)}`;
}
