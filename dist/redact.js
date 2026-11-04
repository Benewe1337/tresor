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
function variants(value) {
    const b64 = Buffer.from(value, 'utf-8').toString('base64');
    const out = new Set([
        value,
        value.trim(),
        b64,
        b64.replace(/=+$/, ''),
        Buffer.from(value, 'utf-8').toString('base64url'),
        encodeURIComponent(value),
        JSON.stringify(value).slice(1, -1),
    ]);
    return [...out].filter(v => v.length >= MIN_REDACT_LENGTH);
}
export class Redactor {
    pairs;
    constructor(secrets) {
        const pairs = [];
        for (const [name, value] of Object.entries(secrets)) {
            for (const v of variants(value))
                pairs.push([v, `[tresor:${name}]`]);
        }
        // Longest first so a value that contains another secret is caught whole.
        this.pairs = pairs.sort((a, b) => b[0].length - a[0].length);
    }
    redact(text) {
        let out = text;
        for (const [needle, marker] of this.pairs)
            out = out.split(needle).join(marker);
        return out;
    }
}
export function truncate(text, maxChars) {
    if (text.length <= maxChars)
        return text;
    const head = Math.floor(maxChars * 0.6);
    const tail = maxChars - head;
    return `${text.slice(0, head)}\n…[${text.length - maxChars} chars truncated]…\n${text.slice(-tail)}`;
}
