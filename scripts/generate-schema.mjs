#!/usr/bin/env node
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { zodToJsonSchema } from "zod-to-json-schema";

import { SandboxConfigSchema } from "../src/config/schema.ts";

const outputPath = resolve("schema", "sandbox.schema.json");
const schema = zodToJsonSchema(SandboxConfigSchema, {
	name: "SandboxConfig",
	$refStrategy: "none",
});

await mkdir(dirname(outputPath), { recursive: true });
await writeFile(outputPath, `${JSON.stringify(schema, null, "\t")}\n`);
console.log(`Wrote ${outputPath}`);
