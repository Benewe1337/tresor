import { describe, expect, it } from 'vitest';
import { browserDialog } from '../src/platform/prompt.js';

/** Simulates the user: load the form, then submit it. */
function user(fields: Record<string, string>, tamper?: (url: string) => string) {
  return (url: string) => {
    void (async () => {
      const page = await (await fetch(url)).text();
      expect(page).toContain('<form');
      await fetch(tamper ? tamper(url) : url, { method: 'POST', body: new URLSearchParams(fields) });
    })();
  };
}

describe('browser fallback dialog', () => {
  it('returns the entered secret', async () => {
    const r = await browserDialog('secret', 'Wert für x', user({ action: 'ok', value: '  s3cret-value  ' }));
    expect(r).toEqual({ status: 'ok', value: 's3cret-value' });
  });

  it('reports cancel and confirm', async () => {
    expect((await browserDialog('secret', 'x', user({ action: 'cancel' }))).status).toBe('cancelled');
    expect((await browserDialog('confirm', 'ok?', user({ action: 'ok' }))).status).toBe('ok');
  });

  it('ignores requests without the random token', async () => {
    let base = '';
    const p = browserDialog('confirm', 'x', url => {
      base = url;
      void (async () => {
        const wrong = await fetch(url.replace(/\/[0-9a-f]+$/, '/nope'), { method: 'POST', body: 'action=ok' });
        expect(wrong.status).toBe(404);
        await fetch(url, { method: 'POST', body: 'action=cancel' });
      })();
    });
    expect((await p).status).toBe('cancelled');
    expect(base).toMatch(/^http:\/\/127\.0\.0\.1:\d+\/[0-9a-f]{48}$/);
  });

  it('escapes the prompt text', async () => {
    let html = '';
    await browserDialog('confirm', '<script>alert(1)</script>', url => {
      void (async () => {
        html = await (await fetch(url)).text();
        await fetch(url, { method: 'POST', body: 'action=cancel' });
      })();
    });
    expect(html).not.toContain('<script>alert');
  });
});
