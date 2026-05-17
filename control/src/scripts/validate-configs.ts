/**
 * validate-configs : valide tous les fichiers configs/base/<family>.yaml
 * contre leur schéma JSON correspondant configs/schemas/<family>.schema.json.
 *
 * Usage : pnpm validate-configs
 *         tsx src/scripts/validate-configs.ts
 *
 * Loopback only : ne fait aucun appel réseau.
 */
import { readFileSync, readdirSync } from 'node:fs';
import { join, resolve, basename } from 'node:path';
import { parse as parseYaml } from 'yaml';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormatsImport from 'ajv-formats';

// ajv-formats est exporté en CJS avec un default ; selon resolution
// NodeNext on tombe parfois sur le namespace. On gère les deux.
const addFormatsRaw = addFormatsImport as unknown as
  | ((ajv: unknown) => void)
  | { default: (ajv: unknown) => void };
const addFormats: (ajv: unknown) => void =
  typeof addFormatsRaw === 'function' ? addFormatsRaw : addFormatsRaw.default;

function fail(msg: string): never {
  process.stderr.write(`[validate-configs] ${msg}\n`);
  process.exit(1);
}

function main(): void {
  // configs/ vit à la racine du repo, on remonte deux niveaux depuis control/.
  const repoRoot = resolve(process.cwd(), process.cwd().endsWith('control') ? '..' : '.');
  const schemasDir = join(repoRoot, 'configs', 'schemas');
  const baseDir = join(repoRoot, 'configs', 'base');

  let baseFiles: string[];
  try {
    baseFiles = readdirSync(baseDir).filter((f) => f.endsWith('.yaml') || f.endsWith('.yml'));
  } catch {
    process.stdout.write('[validate-configs] no configs/base/ directory, skipping\n');
    return;
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const ajv = new (Ajv2020 as unknown as { new (opts: object): any })({
    allErrors: true,
    strict: false,
  });
  addFormats(ajv);

  let failures = 0;

  for (const file of baseFiles) {
    const family = basename(file, file.endsWith('.yaml') ? '.yaml' : '.yml');
    const schemaPath = join(schemasDir, `${family}.schema.json`);
    const yamlPath = join(baseDir, file);

    let schema: unknown;
    try {
      schema = JSON.parse(readFileSync(schemaPath, 'utf8'));
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      process.stderr.write(`[validate-configs] FAIL ${file}: missing schema (${msg})\n`);
      failures++;
      continue;
    }

    const data = parseYaml(readFileSync(yamlPath, 'utf8'));
    const validate = ajv.compile(schema);
    if (!validate(data)) {
      failures++;
      process.stderr.write(`[validate-configs] FAIL ${file}\n`);
      for (const e of validate.errors ?? []) {
        process.stderr.write(`  - ${e.instancePath} ${e.message}\n`);
      }
      continue;
    }
    process.stdout.write(`[validate-configs] OK ${file}\n`);
  }

  if (failures > 0) {
    fail(`${failures} file(s) failed validation`);
  }
}

main();
