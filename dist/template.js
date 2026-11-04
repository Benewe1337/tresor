/**
 * Placeholder syntax: `{{secret:NAME}}`. Deliberately namespaced so it never
 * collides with Mustache/Handlebars/Helm `{{ ... }}` in config files.
 */
const PLACEHOLDER_RE = /\{\{secret:([A-Za-z0-9_.-]{1,64})\}\}/g;
export function placeholderNames(...texts) {
    const names = new Set();
    for (const t of texts) {
        if (!t)
            continue;
        for (const m of t.matchAll(PLACEHOLDER_RE))
            names.add(m[1]);
    }
    return [...names];
}
export function fill(text, values) {
    return text.replace(PLACEHOLDER_RE, (_m, name) => {
        const v = values[name];
        if (v === undefined)
            throw new Error(`No value resolved for {{secret:${name}}}`);
        return v;
    });
}
