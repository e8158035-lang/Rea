import { useRef, useState } from 'react';
import { Upload, FileArchive, ShieldCheck, Play, Trash2 } from 'lucide-react';
import { AnalysisReportView } from './components/AnalysisReportView';
import { TermuxGuideView } from './components/TermuxGuideView';
import type { AnalysisResultPayload, LogEntry } from './types';

type NavSection = 'workspace' | 'report' | 'termux';

export default function App() {
  const [section, setSection] = useState<NavSection>('workspace');
  const [selectedFiles, setSelectedFiles] = useState<File[]>([]);
  const [isDragging, setIsDragging] = useState(false);

  const [jobId, setJobId] = useState<string | null>(null);
  const [jobStatus, setJobStatus] = useState<'idle' | 'uploading' | 'running' | 'completed' | 'failed'>('idle');
  const [progress, setProgress] = useState(0);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [result, setResult] = useState<AnalysisResultPayload | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const addFiles = (incoming: FileList | null) => {
    if (!incoming) return;
    const next = [...selectedFiles];
    for (const f of Array.from(incoming)) {
      if (!next.some((ex) => ex.name === f.name && ex.size === f.size)) {
        next.push(f);
      }
    }
    setSelectedFiles(next);
  };

  const formatBytes = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  };

  const subscribeJob = (id: string) => {
    setJobId(id);
    setJobStatus('running');
    const ev = new EventSource(`/api/jobs/${id}/events`);
    ev.onmessage = async (msg) => {
      const payload = JSON.parse(msg.data);
      if (payload.type === 'log') {
        setProgress(payload.progress);
        setLogs((prev) => [...prev, payload.entry]);
      } else if (payload.type === 'done') {
        ev.close();
        setJobStatus(payload.status === 'completed' ? 'completed' : 'failed');
        const jr = await fetch(`/api/jobs/${id}`);
        const job = await jr.json();
        if (job.result) {
          setResult(job.result);
          setSection('report');
        } else if (job.error) {
          setErrorMsg(job.error);
        }
      }
    };
    ev.onerror = () => {
      ev.close();
      setJobStatus('failed');
      setErrorMsg('انقطع الاتصال بتدفق الأحداث أثناء المعالجة.');
    };
  };

  const startUploadAndAnalyze = async () => {
    if (selectedFiles.length === 0) return;
    setErrorMsg(null);
    setResult(null);
    setLogs([]);
    setProgress(0);
    setJobStatus('uploading');

    const CHUNK_SIZE = 5 * 1024 * 1024; // 5 MB chunks (safe for reverse proxies & low-RAM mobile browsers)
    const totalBytes = selectedFiles.reduce((acc, f) => acc + f.size, 0) || 1;
    let uploadedBytes = 0;

    const parseJsonSafe = async (res: Response) => {
      const text = await res.text();
      try {
        return JSON.parse(text);
      } catch {
        throw new Error(`استجابة غير صالحة من الخادم (HTTP ${res.status}): ${text.slice(0, 140)}`);
      }
    };

    try {
      const initRes = await fetch('/api/uploads/init', { method: 'POST' });
      const initData = await parseJsonSafe(initRes);
      if (!initRes.ok || !initData.upload_id) {
        throw new Error(initData.error || `فشل تهيئة جلسة الرفع (HTTP ${initRes.status})`);
      }
      const uploadId: string = initData.upload_id;

      for (const file of selectedFiles) {
        const totalChunks = Math.max(1, Math.ceil(file.size / CHUNK_SIZE));
        setLogs((prev) => [
          ...prev,
          {
            ts: new Date().toTimeString().slice(0, 8),
            message: `بدء رفع ${file.name} (${totalChunks} مقطع)...`,
            progress: Math.round((uploadedBytes / totalBytes) * 100),
          },
        ]);

        for (let chunkIndex = 0; chunkIndex < totalChunks; chunkIndex++) {
          const start = chunkIndex * CHUNK_SIZE;
          const end = Math.min(file.size, start + CHUNK_SIZE);
          const slice = file.slice(start, end);

          const qs = new URLSearchParams({
            filename: file.name,
            chunkIndex: String(chunkIndex),
            totalChunks: String(totalChunks),
          });
          const chunkRes = await fetch(`/api/uploads/${uploadId}/chunk?${qs.toString()}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/octet-stream' },
            body: slice,
          });
          const chunkData = await parseJsonSafe(chunkRes);
          if (!chunkRes.ok || !chunkData.ok) {
            throw new Error(chunkData.error || `فشل رفع الجزء ${chunkIndex + 1} من ${file.name}`);
          }

          uploadedBytes += end - start;
          const pct = Math.min(99, Math.round((uploadedBytes / totalBytes) * 100));
          setProgress(pct);
        }
      }

      const commitRes = await fetch(`/api/uploads/${uploadId}/commit`, { method: 'POST' });
      const commitData = await parseJsonSafe(commitRes);
      if (!commitRes.ok || !commitData.job_id) {
        throw new Error(commitData.error || 'فشل بدء التحليل بعد اكتمال الرفع.');
      }

      setLogs((prev) => [
        ...prev,
        {
          ts: new Date().toTimeString().slice(0, 8),
          message: `اكتمل رفع ${selectedFiles.length} ملف بنجاح؛ بدء خط المعالجة...`,
          progress: 5,
        },
      ]);
      subscribeJob(commitData.job_id);
    } catch (err: any) {
      setJobStatus('failed');
      setErrorMsg(err?.message || 'حدث خطأ أثناء رفع الملفات.');
    }
  };

  const runSampleXapkTest = async () => {
    setErrorMsg(null);
    setResult(null);
    setLogs([]);
    setProgress(2);
    setJobStatus('running');
    try {
      const res = await fetch('/api/analyze-sample-xapk', { method: 'POST' });
      const data = await res.json();
      if (res.ok && data.job_id) {
        subscribeJob(data.job_id);
      } else {
        setJobStatus('failed');
        setErrorMsg(data.error || 'تعذر تشغيل الاختبار التجريبي.');
      }
    } catch {
      setJobStatus('failed');
      setErrorMsg('تعذر الاتصال بالخادم لتشغيل الاختبار التجريبي.');
    }
  };

  return (
    <div className="min-h-screen bg-[#0b111e] text-slate-100 flex flex-col overflow-x-hidden">
      {/* 3-Zone Top Bar Contract */}
      <header className="border-b border-[#283548] bg-[#111827]">
        <div className="max-w-[1280px] mx-auto px-3 sm:px-6 py-3 flex items-center justify-between gap-3 sm:gap-8">
          {/* Zone 1: Single-line Brand wordmark */}
          <button
            type="button"
            onClick={() => setSection('workspace')}
            className="text-sm sm:text-base font-bold tracking-tight text-slate-100 whitespace-nowrap shrink-0 cursor-pointer truncate max-w-[165px] sm:max-w-none"
          >
            مختبر التحليل الثابت REA
          </button>

          {/* Zone 2: Clean text navigation links */}
          <nav className="hidden md:flex items-center gap-6 text-sm font-medium text-slate-400">
            <button
              type="button"
              onClick={() => setSection('workspace')}
              className={`hover:text-slate-100 transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                section === 'workspace' ? 'text-slate-100 underline underline-offset-8 decoration-[#38bdf8]' : ''
              }`}
            >
              مساحة التحليل
            </button>
            <button
              type="button"
              onClick={() => setSection('report')}
              className={`hover:text-slate-100 transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                section === 'report' ? 'text-slate-100 underline underline-offset-8 decoration-[#38bdf8]' : ''
              }`}
            >
              تقرير الأدلة
            </button>
            <button
              type="button"
              onClick={() => setSection('termux')}
              className={`hover:text-slate-100 transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                section === 'termux' ? 'text-slate-100 underline underline-offset-8 decoration-[#38bdf8]' : ''
              }`}
            >
              فحص البيئة ودليل Termux
            </button>
          </nav>

          {/* Zone 3: Single primary action */}
          <div className="shrink-0">
            <a
              href="/api/termux-bundle.zip"
              className="inline-flex items-center px-3 sm:px-4 py-2 text-xs font-semibold text-white bg-[#0284c7] hover:bg-[#0369a1] rounded-md transition-colors whitespace-nowrap shrink-0"
            >
              تنزيل حزمة Termux (ZIP)
            </a>
          </div>
        </div>
      </header>

      <main className="max-w-[1280px] w-full mx-auto px-3 sm:px-6 py-4 sm:py-6 space-y-5 flex-1 min-w-0">
        {/* Legal Notice */}
        <div className="bg-[#111827] border border-[#283548] rounded-lg px-3.5 py-3 flex items-start gap-2.5 text-xs text-amber-200">
          <ShieldCheck className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
          <p className="leading-relaxed min-w-0">
            <strong>تنبيه قانوني:</strong> هذه الأداة مخصصة حصرياً لتحليل التطبيقات والملفات التي يملكها المستخدم أو لديه إذن صريح بتحليلها. يتم حفظ النسخ الأصلية بايت ببايت دون تعديل، ويتم التحقق من سلامتها ببصمة SHA-256.
          </p>
        </div>

        {/* Mobile Nav Fallback */}
        <div className="flex md:hidden items-center gap-2 overflow-x-auto pb-1">
          <button
            type="button"
            onClick={() => setSection('workspace')}
            className={`px-3 py-1.5 text-xs rounded whitespace-nowrap shrink-0 ${
              section === 'workspace' ? 'bg-[#0284c7] text-white' : 'bg-[#111827] text-slate-300 border border-[#283548]'
            }`}
          >
            مساحة التحليل
          </button>
          <button
            type="button"
            onClick={() => setSection('report')}
            className={`px-3 py-1.5 text-xs rounded whitespace-nowrap shrink-0 ${
              section === 'report' ? 'bg-[#0284c7] text-white' : 'bg-[#111827] text-slate-300 border border-[#283548]'
            }`}
          >
            تقرير الأدلة
          </button>
          <button
            type="button"
            onClick={() => setSection('termux')}
            className={`px-3 py-1.5 text-xs rounded whitespace-nowrap shrink-0 ${
              section === 'termux' ? 'bg-[#0284c7] text-white' : 'bg-[#111827] text-slate-300 border border-[#283548]'
            }`}
          >
            دليل Termux
          </button>
        </div>

        {section === 'workspace' && (
          <div className="space-y-6 min-w-0">
            <section className="bg-[#111827] border border-[#283548] rounded-lg p-4 sm:p-6 space-y-5 min-w-0">
              <div className="flex flex-wrap items-start justify-between gap-4">
                <div className="max-w-2xl">
                  <h1 className="text-xl font-bold text-slate-100" style={{ textWrap: 'balance' }}>
                    تحليل الحزم والملفات التنفيذية بدليل موثّق وإعادة بناء صادقة
                  </h1>
                  <p className="text-sm text-slate-400 mt-1.5">
                    يدعم رفع ملف واحد أو عدة ملفات حتى 500MB+ عبر التدفق المباشر للقرص: APK · XAPK · APKS · APKM · ZIP · EXE.
                  </p>
                </div>
                <button
                  type="button"
                  onClick={runSampleXapkTest}
                  disabled={jobStatus === 'uploading' || jobStatus === 'running'}
                  className="inline-flex items-center gap-2 px-4 py-2 text-xs font-semibold text-slate-100 bg-[#1e293b] hover:bg-[#334155] border border-[#283548] rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-50"
                >
                  <Play className="w-3.5 h-3.5 text-sky-400" />
                  <span>تشغيل اختبار XAPK التجريبي</span>
                </button>
              </div>

              {/* Dropzone */}
              <div
                onDragOver={(e) => {
                  e.preventDefault();
                  setIsDragging(true);
                }}
                onDragLeave={() => setIsDragging(false)}
                onDrop={(e) => {
                  e.preventDefault();
                  setIsDragging(false);
                  addFiles(e.dataTransfer.files);
                }}
                className={`border border-dashed rounded-lg p-8 text-center transition-colors ${
                  isDragging ? 'border-[#38bdf8] bg-[#1e293b]/70' : 'border-[#334155] bg-[#0b111e]'
                }`}
              >
                <input
                  ref={fileInputRef}
                  type="file"
                  multiple
                  className="hidden"
                  onChange={(e) => addFiles(e.target.files)}
                />
                <Upload className="w-7 h-7 text-sky-400 mx-auto mb-3" />
                <p className="text-sm text-slate-200 font-medium">
                  اسحب الملفات إلى هنا أو اخترها من جهازك
                </p>
                <p className="text-xs text-slate-400 mt-1">
                  يتم تحديد نوع الملف من التوقيع الثنائي الفعلي (Magic Bytes) وليس من الامتداد، مع حماية Zip Slip وتنظيف الملفات المؤقتة.
                </p>
                <button
                  type="button"
                  onClick={() => fileInputRef.current?.click()}
                  className="mt-4 px-4 py-2 text-xs font-semibold text-white bg-[#0284c7] hover:bg-[#0369a1] rounded-md transition-colors cursor-pointer"
                >
                  اختيار الملفات
                </button>
              </div>

              {/* Selected Files Queue */}
              {selectedFiles.length > 0 && (
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold text-slate-300">
                      الملفات المحددة ({selectedFiles.length})
                    </span>
                    <button
                      type="button"
                      onClick={() => setSelectedFiles([])}
                      className="inline-flex items-center gap-1 text-xs text-slate-400 hover:text-red-400 cursor-pointer"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                      <span>مسح القائمة</span>
                    </button>
                  </div>
                  <div className="divide-y divide-[#283548] border border-[#283548] rounded-md bg-[#0b111e]">
                    {selectedFiles.map((f, idx) => (
                      <div key={`${f.name}-${idx}`} className="flex items-center justify-between px-3 py-2 text-xs">
                        <div className="flex items-center gap-2 min-w-0">
                          <FileArchive className="w-4 h-4 text-slate-400 shrink-0" />
                          <span className="font-mono text-slate-200 truncate">{f.name}</span>
                        </div>
                        <span className="font-mono tabular-nums text-slate-400 shrink-0">
                          {formatBytes(f.size)}
                        </span>
                      </div>
                    ))}
                  </div>
                  <div className="flex justify-end">
                    <button
                      type="button"
                      onClick={startUploadAndAnalyze}
                      disabled={jobStatus === 'uploading' || jobStatus === 'running'}
                      className="px-5 py-2 text-sm font-semibold text-white bg-[#0284c7] hover:bg-[#0369a1] rounded-md transition-colors cursor-pointer disabled:opacity-50"
                    >
                      {jobStatus === 'uploading'
                        ? 'جاري الرفع للقرص...'
                        : jobStatus === 'running'
                          ? 'جاري التحليل...'
                          : 'بدء التحليل وحفظ الأصل'}
                    </button>
                  </div>
                </div>
              )}

              {/* Live Progress & Step Log */}
              {(jobStatus !== 'idle' || logs.length > 0) && (
                <div className="border-t border-[#283548] pt-5 space-y-3">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-slate-300 font-medium">
                      {jobStatus === 'uploading' && 'الرفع المتدفق إلى التخزين المؤقت...'}
                      {jobStatus === 'running' && 'تنفيذ خط التحليل الثابت...'}
                      {jobStatus === 'completed' && 'اكتمل التحليل بنجاح'}
                      {jobStatus === 'failed' && 'توقف التحليل بسبب خطأ'}
                    </span>
                    <span className="font-mono tabular-nums text-sky-400">{progress}%</span>
                  </div>
                  <div className="w-full h-2 bg-[#0b111e] border border-[#283548] rounded overflow-hidden">
                    <div
                      className="h-full bg-[#0284c7] transition-all duration-200"
                      style={{ width: `${progress}%` }}
                    />
                  </div>
                  {errorMsg && (
                    <div className="text-xs text-red-400 border border-red-900/60 bg-red-950/30 rounded p-3">
                      {errorMsg}
                    </div>
                  )}
                  <div
                    className="bg-[#060a12] border border-[#283548] rounded-md p-3 max-h-52 overflow-y-auto font-mono text-xs text-slate-300 space-y-1"
                    dir="ltr"
                  >
                    {logs.map((entry, idx) => (
                      <div key={idx}>
                        <span className="text-slate-500">[{entry.ts}]</span>{' '}
                        <span className="text-sky-400">({entry.progress}%)</span>{' '}
                        <span>{entry.message}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </section>
          </div>
        )}

        {section === 'report' && (
          <div>
            {result && jobId ? (
              <AnalysisReportView jobId={jobId} result={result} />
            ) : (
              <div className="bg-[#111827] border border-[#283548] rounded-lg p-10 text-center space-y-3">
                <h2 className="text-base font-semibold text-slate-200">لا يوجد تقرير معروض حالياً</h2>
                <p className="text-xs text-slate-400">
                  ارفع ملف APK أو XAPK أو ZIP أو EXE من مساحة التحليل، أو شغّل اختبار XAPK التجريبي لعرض تقرير الأدلة الكامل.
                </p>
                <div className="pt-2 flex items-center justify-center gap-3">
                  <button
                    type="button"
                    onClick={() => setSection('workspace')}
                    className="px-4 py-2 text-xs font-semibold text-white bg-[#0284c7] hover:bg-[#0369a1] rounded-md cursor-pointer"
                  >
                    العودة لمساحة التحليل
                  </button>
                  <button
                    type="button"
                    onClick={runSampleXapkTest}
                    className="px-4 py-2 text-xs font-semibold text-slate-200 bg-[#1e293b] hover:bg-[#334155] border border-[#283548] rounded-md cursor-pointer"
                  >
                    تشغيل اختبار XAPK التجريبي
                  </button>
                </div>
              </div>
            )}
          </div>
        )}

        {section === 'termux' && <TermuxGuideView />}
      </main>
    </div>
  );
}
