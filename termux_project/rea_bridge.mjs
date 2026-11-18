#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

const [, , mode, targetPath] = process.argv;

function resolveReaBin() {
  const localBin = path.resolve(process.cwd(), 'node_modules', '.bin', 'rea');
  if (fs.existsSync(localBin)) {
    return { cmd: localBin, prefixArgs: [] };
  }
  const whichRea = spawnSync('which', ['rea'], { encoding: 'utf8' });
  if (whichRea.status === 0 && whichRea.stdout.trim()) {
    return { cmd: whichRea.stdout.trim(), prefixArgs: [] };
  }
  const localReaAgents = path.resolve(process.cwd(), 'node_modules', '.bin', 'rea-agents');
  if (fs.existsSync(localReaAgents)) {
    return { cmd: localReaAgents, prefixArgs: [] };
  }
  return null;
}

function runCommand(cmd, args, timeoutMs = 45000) {
  const res = spawnSync(cmd, args, {
    encoding: 'utf8',
    timeout: timeoutMs,
    maxBuffer: 16 * 1024 * 1024,
  });
  return {
    status: res.status ?? -1,
    stdout: (res.stdout || '').trim(),
    stderr: (res.stderr || '').trim(),
    error: res.error ? res.error.message : null,
  };
}

if (mode === 'doctor') {
  const bin = resolveReaBin();
  if (!bin) {
    console.log(JSON.stringify({
      available: false,
      reason: 'أداة rea-agents غير مثبتة محلياً أو عالمياً عبر npm.',
      providers: null,
    }));
    process.exit(0);
  }
  const doctor = runCommand(bin.cmd, [...bin.prefixArgs, 'doctor'], 15000);
  const providers = runCommand(bin.cmd, [...bin.prefixArgs, 'providers', '--json'], 15000);
  let parsedProviders = null;
  try {
    parsedProviders = providers.stdout ? JSON.parse(providers.stdout) : null;
  } catch {
    parsedProviders = { raw: providers.stdout };
  }
  console.log(JSON.stringify({
    available: doctor.status === 0 || providers.status === 0,
    doctorOutput: doctor.stdout || doctor.stderr,
    providers: parsedProviders,
  }));
  process.exit(0);
}

if (mode === 'analyze-js' || mode === 'analyze') {
  if (!targetPath || !fs.existsSync(targetPath)) {
    console.log(JSON.stringify({
      ok: false,
      skipped: true,
      reason: 'المسار المستهدف غير موجود.',
    }));
    process.exit(0);
  }
  const bin = resolveReaBin();
  if (!bin) {
    console.log(JSON.stringify({
      ok: false,
      skipped: true,
      reason: 'rea-agents غير متوفر؛ تم تخطي تحليل REA الخارجي والاعتماد على المحلل الثابت الداخلي.',
    }));
    process.exit(0);
  }

  const subcommand = mode === 'analyze-js' ? 'analyze-javascript-application' : 'analyze';
  const result = runCommand(bin.cmd, [...bin.prefixArgs, subcommand, path.resolve(targetPath), '--json'], 60000);

  let parsed = null;
  if (result.stdout) {
    try {
      parsed = JSON.parse(result.stdout);
    } catch {
      parsed = null;
    }
  }

  console.log(JSON.stringify({
    ok: result.status === 0 && parsed !== null,
    skipped: false,
    exitCode: result.status,
    command: `${bin.cmd} ${subcommand} ${path.resolve(targetPath)} --json`,
    data: parsed,
    rawStdout: parsed ? undefined : result.stdout.slice(0, 4000),
    stderr: result.stderr.slice(0, 2000),
    error: result.error,
  }));
  process.exit(0);
}

console.log(JSON.stringify({ ok: false, error: 'Unsupported mode. Use doctor | analyze | analyze-js' }));
process.exit(1);
