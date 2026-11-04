/** `tresor dynamic <name> <type> …` – define a short-lived credential generator (human-only). */

import { readFileSync } from 'fs';
import { fail, readHidden, say, takeFlag, takeList } from './cli-util.js';
import {
  DYNAMIC_TYPES, githubKeyInternal, isBundle, oauthClientSecretInternal, oauthRefreshInternal,
  type DynamicConfig, type DynamicType,
} from './dynamic.js';
import type { SecretStore } from './store.js';

function parseKeyValues(list: string[] | undefined, what: string): Record<string, string> | undefined {
  if (!list) return undefined;
  return Object.fromEntries(list.map(kv => {
    const eq = kv.indexOf('=');
    if (eq <= 0) fail(`bad ${what} "${kv}", expected key=value`);
    return [kv.slice(0, eq), kv.slice(eq + 1)];
  }));
}

export async function cmdDynamic(store: SecretStore, args: string[]): Promise<void> {
  const description = takeFlag(args, '-d')[0];
  const hosts = takeFlag(args, '--host');
  const [name, type] = args.splice(0, 2) as [string | undefined, string | undefined];
  if (!name || !type || !DYNAMIC_TYPES.includes(type as DynamicType)) {
    fail(`usage: tresor dynamic <name> <${DYNAMIC_TYPES.join('|')}> [options] – see tresor --help`);
  }
  const options: Record<string, unknown> = {};
  const internal = store.providerContext().internal;
  const pending: Array<[string, string]> = []; // internal secrets, stored only after validation

  switch (type as DynamicType) {
    case 'aws-sso':
      options.profile = takeFlag(args, '--profile')[0] ?? fail('--profile is required');
      break;
    case 'gcloud':
      options.impersonate = takeFlag(args, '--impersonate')[0];
      options.account = takeFlag(args, '--account')[0];
      break;
    case 'azure':
      options.resource = takeFlag(args, '--resource')[0];
      options.scope = takeFlag(args, '--scope')[0];
      options.tenant = takeFlag(args, '--tenant')[0];
      break;
    case 'github-app': {
      options.appId = takeFlag(args, '--app-id')[0] ?? fail('--app-id (or client id) is required');
      options.installationId = takeFlag(args, '--installation-id')[0] ?? fail('--installation-id is required');
      options.apiUrl = takeFlag(args, '--api-url')[0];
      options.repositories = takeList(args, '--repos');
      options.permissions = parseKeyValues(takeList(args, '--permissions'), 'permission');
      const keySecret = takeFlag(args, '--private-key-secret')[0];
      const keyFile = takeFlag(args, '--private-key-file')[0];
      if (keySecret) options.privateKeySecret = keySecret;
      else if (keyFile) pending.push([githubKeyInternal(name), readFileSync(keyFile, 'utf-8')]);
      else fail('--private-key-file <app.pem> or --private-key-secret <name> is required');
      break;
    }
    case 'oauth': {
      options.tokenUrl = takeFlag(args, '--token-url')[0] ?? fail('--token-url is required');
      options.clientId = takeFlag(args, '--client-id')[0] ?? fail('--client-id is required');
      options.authMethod = takeFlag(args, '--auth')[0] ?? 'basic';
      options.scope = takeFlag(args, '--scope')[0];
      if (options.authMethod !== 'none') pending.push([oauthClientSecretInternal(name), await readHidden('Client secret: ')]);
      pending.push([oauthRefreshInternal(name), await readHidden('Refresh token: ')]);
      if (pending.some(([, v]) => !v)) fail('empty input, nothing stored');
      break;
    }
    case 'command': {
      const argv = takeFlag(args, '--argv')[0] ?? fail('--argv \'["cmd","arg"]\' is required');
      try { options.argv = JSON.parse(argv); } catch { fail('--argv must be a JSON array of strings'); }
      options.jsonPath = takeFlag(args, '--json-path')[0];
      const outputs = takeFlag(args, '--output');
      options.outputs = parseKeyValues(outputs.length ? outputs : undefined, 'output');
      options.expiresPath = takeFlag(args, '--expires-path')[0];
      options.ttlPath = takeFlag(args, '--ttl-path')[0];
      const ttl = takeFlag(args, '--ttl')[0];
      if (ttl) options.ttlSeconds = Number(ttl);
      options.hint = takeFlag(args, '--hint')[0];
      break;
    }
  }
  if (args.length) fail(`unknown option(s): ${args.join(' ')}`);

  const cleaned = Object.fromEntries(Object.entries(options).filter(([, v]) => v !== undefined && v !== ''));
  const config: DynamicConfig = { type: type as DynamicType, options: cleaned };
  const action = store.defineDynamic(name, config, { description, hosts });
  for (const [k, v] of pending) internal.set(k, v);

  try {
    const values = isBundle(config) ? await store.resolveBundle(name) : { value: await store.resolve(name) };
    const what = isBundle(config) ? `bundle with ${Object.keys(values).join(', ')}` : `token of ${values.value.length} chars`;
    say(`✓ ${name} ${action === 'created' ? 'defined' : 'updated'} (${type}) – test mint ok: ${what}`);
    if (isBundle(config)) say(`  use it with: tresor run -b ${name} -- <cmd>   or "bundles": ["${name}"] in .tresor.json`);
  } catch (e) {
    say(`! ${name} defined (${type}), but the test mint failed: ${e instanceof Error ? e.message : String(e)}`);
  }
}
