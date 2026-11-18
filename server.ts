import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const { ZipArchive } = require('archiver') as { ZipArchive: new (options?: any) => any };
import busboy from 'busboy';
import crypto from 'node:crypto';
import express from 'express';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createServer as createViteServer } from 'vite';
import {
  generateSampleXapkFile,
  getToolsStatus,
  runLiveAnalysisPipeline,
  type AnalysisLogEntry,
} from './src/server/analyzer.ts';

interface JobRecord {
  id: string;
  status: 'running' | 'completed' | 'failed';
  progress: number;
  logs: AnalysisLogEntry[];
  result: any;
  output_zip: string | null;
  error: string | null;
}

const JOBS = new Map<string, JobRecord>();
const JOBS_ROOT = path.join(os.tmpdir(), 'rea_web_jobs');
fs.mkdirSync(JOBS_ROOT, { recursive: true });

function appendJobLog(jobId: string, message: string, progress: number) {
  const job = JOBS.get(jobId);
  if (!job) return;
  const ts = new Date().toTimeString().slice(0, 8);
  job.progress = progress;
  job.logs.push({ ts, message, progress });
}

function startWorker(jobId: string, inputPaths: string[], workDir: string, outZip: string) {
  (async () => {
    try {
      const result = await runLiveAnalysisPipeline(
        inputPaths,
        outZip,
        path.join(workDir, 'bundle'),
        (msg, pct) => appendJobLog(jobId, msg, pct),
      );
      const job = JOBS.get(jobId);
      if (job) {
        job.status = 'completed';
        job.progress = 100;
        job.result = result;
        job.output_zip = outZip;
      }
    } catch (err: any) {
      appendJobLog(jobId, `خطأ أثناء التحليل: ${err?.message || String(err)}`, 100);
      const job = JOBS.get(jobId);
      if (job) {
        job.status = 'failed';
        job.error = err?.message || String(err);
      }
    } finally {
      for (const cleanup of [path.join(workDir, 'uploads'), path.join(workDir, 'bundle')]) {
        if (fs.existsSync(cleanup)) {
          fs.rmSync(cleanup, { recursive: true, force: true });
        }
      }
    }
  })();
}

async function startServer() {
  const app = express();
  app.use(express.json());

  app.get('/api/tools/status', (_req, res) => {
    res.json({
      tools: getToolsStatus(),
      platform: process.platform,
      arch: process.arch,
      nodeVersion: process.version,
    });
  });

  const UPLOAD_SESSIONS = new Map<string, { workDir: string; uploadDir: string; files: Set<string> }>();

  app.post('/api/uploads/init', (_req, res) => {
    const uploadId = crypto.randomBytes(6).toString('hex');
    const workDir = path.join(JOBS_ROOT, uploadId);
    const uploadDir = path.join(workDir, 'uploads');
    fs.mkdirSync(uploadDir, { recursive: true });
    UPLOAD_SESSIONS.set(uploadId, { workDir, uploadDir, files: new Set() });
    res.json({ upload_id: uploadId });
  });

  app.post('/api/uploads/:uploadId/chunk', (req, res) => {
    const { uploadId } = req.params;
    const session = UPLOAD_SESSIONS.get(uploadId);
    if (!session) {
      return res.status(404).json({ error: 'جلسة الرفع غير موجودة أو انتهت.' });
    }
    const rawName = String(req.query.filename || 'upload.bin');
    const safeName = path.basename(rawName);
    const chunkIndex = Number(req.query.chunkIndex || 0);
    if (!safeName || safeName === '.' || safeName === '..') {
      return res.status(400).json({ error: 'اسم ملف غير صالح.' });
    }

    const destPath = path.join(session.uploadDir, safeName);
    const flags = chunkIndex === 0 ? 'w' : 'a';
    const out = fs.createWriteStream(destPath, { flags });

    let received = 0;
    req.on('data', (buf: Buffer) => {
      received += buf.length;
    });
    req.pipe(out);

    out.on('finish', () => {
      session.files.add(destPath);
      res.json({ ok: true, filename: safeName, chunkIndex, bytesReceived: received });
    });
    out.on('error', (err: any) => {
      if (!res.headersSent) res.status(500).json({ error: err?.message || 'فشل كتابة جزء الملف على القرص.' });
    });
    req.on('error', (err: any) => {
      out.destroy();
      if (!res.headersSent) res.status(500).json({ error: err?.message || 'انقطع تدفق الرفع.' });
    });
  });

  app.post('/api/uploads/:uploadId/commit', (req, res) => {
    const { uploadId } = req.params;
    const session = UPLOAD_SESSIONS.get(uploadId);
    if (!session) {
      return res.status(404).json({ error: 'جلسة الرفع غير موجودة.' });
    }
    UPLOAD_SESSIONS.delete(uploadId);

    const savedPaths = Array.from(session.files).filter((p) => fs.existsSync(p));
    if (savedPaths.length === 0) {
      return res.status(400).json({ error: 'لم يتم استلام أي ملفات في هذه الجلسة.' });
    }

    const outZip = path.join(session.workDir, `rea_analysis_${uploadId}.zip`);
    const fileLogs: AnalysisLogEntry[] = savedPaths.map((p) => ({
      ts: new Date().toTimeString().slice(0, 8),
      message: `تم استلام الملف كاملاً على القرص: ${path.basename(p)} (${fs.statSync(p).size.toLocaleString('en-US')} بايت)`,
      progress: 4,
    }));

    JOBS.set(uploadId, {
      id: uploadId,
      status: 'running',
      progress: 4,
      logs: fileLogs,
      result: null,
      output_zip: null,
      error: null,
    });

    startWorker(uploadId, savedPaths, session.workDir, outZip);
    res.json({ job_id: uploadId });
  });

  app.post('/api/analyze', (req, res) => {
    const jobId = crypto.randomBytes(6).toString('hex');
    const workDir = path.join(JOBS_ROOT, jobId);
    const uploadDir = path.join(workDir, 'uploads');
    fs.mkdirSync(uploadDir, { recursive: true });
    const outZip = path.join(workDir, `rea_analysis_${jobId}.zip`);

    JOBS.set(jobId, {
      id: jobId,
      status: 'running',
      progress: 1,
      logs: [
        {
          ts: new Date().toTimeString().slice(0, 8),
          message: 'استقبال الملفات عبر التدفق المباشر للقرص...',
          progress: 1,
        },
      ],
      result: null,
      output_zip: null,
      error: null,
    });

    const savedPaths: string[] = [];
    const writePromises: Promise<void>[] = [];

    const bb = busboy({
      headers: req.headers,
      limits: { fileSize: 1024 * 1024 * 1024 }, // Up to 1GB streaming to disk
    });

    bb.on('file', (_fieldname, fileStream, info) => {
      const safeName = path.basename(info.filename || `upload_${Date.now()}.bin`);
      const destPath = path.join(uploadDir, safeName);
      const out = fs.createWriteStream(destPath);
      savedPaths.push(destPath);

      const p = new Promise<void>((resolve, reject) => {
        fileStream.pipe(out);
        out.on('finish', () => {
          const size = fs.existsSync(destPath) ? fs.statSync(destPath).size : 0;
          appendJobLog(jobId, `تم حفظ الملف على القرص: ${safeName} (${size.toLocaleString('en-US')} بايت)`, 4);
          resolve();
        });
        out.on('error', reject);
        fileStream.on('error', reject);
      });
      writePromises.push(p);
    });

    bb.on('finish', async () => {
      try {
        await Promise.all(writePromises);
        if (savedPaths.length === 0) {
          const job = JOBS.get(jobId);
          if (job) {
            job.status = 'failed';
            job.error = 'لم يتم استلام أي ملفات صالحة.';
          }
          return res.status(400).json({ error: 'يرجى اختيار ملف واحد على الأقل.' });
        }
        startWorker(jobId, savedPaths, workDir, outZip);
        res.json({ job_id: jobId });
      } catch (err: any) {
        res.status(500).json({ error: err?.message || 'فشل حفظ الملفات المرفوعة.' });
      }
    });

    bb.on('error', (err: any) => {
      res.status(500).json({ error: err?.message || 'خطأ في استقبال الرفع المتدفق.' });
    });

    req.pipe(bb);
  });

  app.post('/api/analyze-sample-xapk', (_req, res) => {
    const jobId = crypto.randomBytes(6).toString('hex');
    const workDir = path.join(JOBS_ROOT, jobId);
    const uploadDir = path.join(workDir, 'uploads');
    fs.mkdirSync(uploadDir, { recursive: true });
    const samplePath = path.join(uploadDir, 'acme_shop_test.xapk');
    const outZip = path.join(workDir, `rea_analysis_${jobId}.zip`);

    try {
      generateSampleXapkFile(samplePath);
    } catch (err: any) {
      return res.status(500).json({ error: `تعذر إنشاء ملف XAPK التجريبي: ${err.message}` });
    }

    JOBS.set(jobId, {
      id: jobId,
      status: 'running',
      progress: 2,
      logs: [
        {
          ts: new Date().toTimeString().slice(0, 8),
          message: 'تم توليد حزمة acme_shop_test.xapk (base.apk + config.arm64_v8a.apk + config.en.apk + manifest.json)',
          progress: 2,
        },
      ],
      result: null,
      output_zip: null,
      error: null,
    });

    startWorker(jobId, [samplePath], workDir, outZip);
    res.json({ job_id: jobId });
  });

  app.get('/api/jobs/:id/events', (req, res) => {
    const jobId = req.params.id;
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');

    let lastIdx = 0;
    const timer = setInterval(() => {
      const job = JOBS.get(jobId);
      if (!job) {
        res.write(`data: ${JSON.stringify({ error: 'المهمة غير موجودة' })}\n\n`);
        clearInterval(timer);
        res.end();
        return;
      }
      const newLogs = job.logs.slice(lastIdx);
      lastIdx += newLogs.length;
      for (const entry of newLogs) {
        res.write(
          `data: ${JSON.stringify({ type: 'log', entry, status: job.status, progress: job.progress })}\n\n`,
        );
      }
      if (job.status === 'completed' || job.status === 'failed') {
        res.write(`data: ${JSON.stringify({ type: 'done', status: job.status, progress: job.progress })}\n\n`);
        clearInterval(timer);
        res.end();
      }
    }, 300);

    req.on('close', () => clearInterval(timer));
  });

  app.get('/api/jobs/:id', (req, res) => {
    const job = JOBS.get(req.params.id);
    if (!job) return res.status(404).json({ error: 'المهمة غير موجودة.' });
    res.json(job);
  });

  app.get('/api/jobs/:id/download', (req, res) => {
    const job = JOBS.get(req.params.id);
    if (!job || !job.output_zip || !fs.existsSync(job.output_zip)) {
      return res.status(404).json({ error: 'ملف النتائج غير جاهز.' });
    }
    res.download(job.output_zip, `rea_output_${job.id}.zip`);
  });

  app.get('/api/termux-bundle.zip', (_req, res) => {
    const bundleDir = path.resolve(process.cwd(), 'termux_project');
    if (!fs.existsSync(bundleDir)) {
      return res.status(404).json({ error: 'مجلد حزمة Termux غير موجود.' });
    }
    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', 'attachment; filename="rea-termux-analyzer.zip"');

    const archive = new ZipArchive({ zlib: { level: 9 } });
    archive.on('error', (err: any) => {
      if (!res.headersSent) res.status(500).send(err.message);
    });
    archive.pipe(res);

    const addDir = (dir: string, prefix: string) => {
      for (const item of fs.readdirSync(dir, { withFileTypes: true })) {
        if (item.name === 'node_modules' || item.name === '__pycache__' || item.name.startsWith('.')) continue;
        const full = path.join(dir, item.name);
        const rel = prefix ? `${prefix}/${item.name}` : item.name;
        if (item.isDirectory()) {
          addDir(full, rel);
        } else {
          const isExec = item.name.endsWith('.sh') || item.name.endsWith('.py');
          archive.file(full, { name: `rea-termux-analyzer/${rel}`, mode: isExec ? 0o755 : 0o644 });
        }
      }
    };
    addDir(bundleDir, '');
    archive.finalize();
  });

  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distDir));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distDir, 'index.html'));
    });
  }

  const port = Number(process.env.PORT || 3000);
  app.listen(port, '0.0.0.0', () => {
    console.log(`REA Static Analysis Lab listening on http://0.0.0.0:${port}`);
  });
}

startServer();
