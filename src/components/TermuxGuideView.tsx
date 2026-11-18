import { useEffect, useState } from 'react';
import { Check, Copy, Download, RefreshCw } from 'lucide-react';

const TERMUX_COMMANDS = [
  'termux-setup-storage',
  'pkg update -y && pkg upgrade -y',
  'pkg install -y python python-pip nodejs-lts openjdk-17 p7zip unzip curl',
  'npm install -g rea-agents',
  'mkdir -p ~/rea-lab && cd ~/rea-lab',
  'unzip -o ~/storage/downloads/rea-termux-analyzer.zip -d .',
  'cd ~/rea-lab/rea-termux-analyzer',
  'pip install -r requirements.txt',
  'npm install',
  'bash setup_check.sh',
  'python tests/self_test_xapk.py',
  'python app.py',
  'termux-open-url http://127.0.0.1:5000',
];

export function TermuxGuideView() {
  const [toolsData, setToolsData] = useState<Record<string, boolean> | null>(null);
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);

  const loadTools = async () => {
    setLoading(true);
    try {
      const r = await fetch('/api/tools/status');
      const d = await r.json();
      setToolsData(d.tools || null);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadTools();
  }, []);

  const copyCommands = async () => {
    await navigator.clipboard.writeText(TERMUX_COMMANDS.join('\n'));
    setCopied(true);
    setTimeout(() => setCopied(false), 1800);
  };

  return (
    <div className="space-y-6">
      <section className="bg-[#111827] border border-[#283548] rounded-lg p-6 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <h2 className="text-lg font-semibold text-slate-100">حزمة التشغيل المحلي على Termux</h2>
            <p className="text-sm text-slate-400 mt-1">
              تتضمن الحزمة خادم FastAPI على العنوان <span className="font-mono">127.0.0.1:5000</span>، ومحلل Python الصافي بدون تجميع معقد، وجسر Node.js لـ <span className="font-mono">morluto/rea</span>، وسكربت الفحص، والاختبار الذاتي لـ XAPK.
            </p>
          </div>
          <a
            href="/api/termux-bundle.zip"
            className="inline-flex items-center gap-2 px-4 py-2 text-sm font-semibold text-white bg-[#0284c7] hover:bg-[#0369a1] rounded-md transition-colors whitespace-nowrap shrink-0"
          >
            <Download className="w-4 h-4" />
            <span>تنزيل المشروع الكامل (ZIP)</span>
          </a>
        </div>

        <div className="border border-[#283548] rounded-md p-4 bg-[#0b111e] space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-slate-200">أوامر التثبيت والتشغيل في Termux (أمر في كل سطر)</h3>
            <button
              type="button"
              onClick={copyCommands}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-200 bg-[#1e293b] hover:bg-[#334155] border border-[#283548] rounded transition-colors cursor-pointer"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copied ? 'تم النسخ' : 'نسخ الأوامر'}</span>
            </button>
          </div>
          <pre
            className="bg-[#060a12] border border-[#283548] rounded p-4 text-xs font-mono text-sky-200 overflow-x-auto leading-6"
            dir="ltr"
          >
            {TERMUX_COMMANDS.join('\n')}
          </pre>
        </div>
      </section>

      <section className="bg-[#111827] border border-[#283548] rounded-lg p-6 space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-base font-semibold text-slate-100">فحص أدوات التحليل في الخادم الحالي</h3>
            <p className="text-xs text-slate-400 mt-1">
              عند غياب أي أداة خارجية (مثل jadx أو apktool أو blutter)، يتعطل الجزء الخاص بها فقط مع تحذير واضح في completeness_report ويكمل النظام بقية التحليل.
            </p>
          </div>
          <button
            type="button"
            onClick={loadTools}
            disabled={loading}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-200 bg-[#1e293b] hover:bg-[#334155] border border-[#283548] rounded transition-colors cursor-pointer"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>إعادة الفحص</span>
          </button>
        </div>

        {toolsData && (
          <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-3">
            {Object.entries(toolsData).map(([tool, ok]) => (
              <div
                key={tool}
                className="flex items-center justify-between px-3 py-2.5 bg-[#0b111e] border border-[#283548] rounded-md"
              >
                <span className="font-mono text-xs text-slate-200">{tool}</span>
                <span className={`text-xs font-medium ${ok ? 'text-emerald-400' : 'text-amber-400'}`}>
                  {ok ? 'متوفر' : 'غير مثبت'}
                </span>
              </div>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}
