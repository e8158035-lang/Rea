import { useMemo, useState } from 'react';
import { Download, Search, CheckCircle2, AlertTriangle, XCircle } from 'lucide-react';
import type { AnalysisResultPayload } from '../types';

interface Props {
  jobId: string;
  result: AnalysisResultPayload;
}

type ReportTab =
  | 'overview'
  | 'splits'
  | 'assets'
  | 'app_code'
  | 'libraries'
  | 'strings_perms'
  | 'exe'
  | 'rebuild';

export function AnalysisReportView({ jobId, result }: Props) {
  const [activeTab, setActiveTab] = useState<ReportTab>('overview');
  const [query, setQuery] = useState('');

  const rep = result.rea_report;
  const comp = rep.completeness_report;
  const counts = comp.summary_counts_app_only;

  const filteredFunctions = useMemo(() => {
    const q = query.trim().toLowerCase();
    const list = result.functions_map.app_functions;
    if (!q) return list.slice(0, 200);
    return list
      .filter(
        (f) =>
          f.class_name.toLowerCase().includes(q) ||
          f.method_name.toLowerCase().includes(q) ||
          f.evidence.toLowerCase().includes(q),
      )
      .slice(0, 200);
  }, [query, result.functions_map.app_functions]);

  const filteredStrings = useMemo(() => {
    const q = query.trim().toLowerCase();
    const list = result.strings_index;
    if (!q) return list.slice(0, 200);
    return list
      .filter((s) => s.value.toLowerCase().includes(q) || s.evidence.toLowerCase().includes(q))
      .slice(0, 200);
  }, [query, result.strings_index]);

  const filteredAssets = useMemo(() => {
    const q = query.trim().toLowerCase();
    const list = rep.assets_index || [];
    if (!q) return list.slice(0, 250);
    return list
      .filter((a) => a.path.toLowerCase().includes(q) || a.kind.toLowerCase().includes(q))
      .slice(0, 250);
  }, [query, rep.assets_index]);

  const tabs: Array<{ id: ReportTab; label: string }> = [
    { id: 'overview', label: 'الاكتمال والسلامة' },
    { id: 'splits', label: 'الحزم المقسّمة و.so' },
    { id: 'assets', label: `الأصول والموارد (${(rep.assets_index || []).length})` },
    { id: 'app_code', label: 'الشاشات والدوال (التطبيق فقط)' },
    { id: 'libraries', label: 'مكتبات الطرف الثالث' },
    { id: 'strings_perms', label: 'النصوص والصلاحيات' },
    ...(rep.exe_reports.length > 0 ? [{ id: 'exe' as ReportTab, label: 'تحليل EXE' }] : []),
    { id: 'rebuild', label: 'إعادة البناء الصادق' },
  ];

  return (
    <section className="bg-[#111827] border border-[#283548] rounded-lg p-4 sm:p-6 space-y-5 min-w-0">
      <div className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b border-[#283548]">
        <div className="min-w-0">
          <h2 className="text-lg font-semibold text-slate-100">تقرير الأدلة والتحليل الثابت</h2>
          <p className="text-xs text-slate-400 mt-1 break-words">
            <span>حزمة المخرجات: </span>
            <span className="font-mono" dir="ltr">original/ · extracted/ · analyzed/ · rebuilt_project/</span>
          </p>
        </div>
        <a
          href={`/api/jobs/${jobId}/download`}
          className="inline-flex items-center gap-2 px-4 py-2 text-sm font-semibold text-white bg-[#0284c7] hover:bg-[#0369a1] rounded-md transition-colors whitespace-nowrap shrink-0"
        >
          <Download className="w-4 h-4" />
          <span>تنزيل حزمة النتائج (ZIP)</span>
        </a>
      </div>

      {/* App-only vs Isolated Libraries Summary Strip */}
      <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-6 gap-3">
        <div className="bg-[#1e293b]/60 border border-[#283548] rounded-md p-3">
          <div className="text-xs text-slate-400">دوال التطبيق فقط</div>
          <div className="text-xl font-semibold font-mono tabular-nums text-slate-100 mt-1">
            {counts.app_functions}
          </div>
        </div>
        <div className="bg-[#1e293b]/60 border border-[#283548] rounded-md p-3">
          <div className="text-xs text-slate-400">شاشات التطبيق</div>
          <div className="text-xl font-semibold font-mono tabular-nums text-slate-100 mt-1">
            {counts.app_screens}
          </div>
        </div>
        <div className="bg-[#1e293b]/60 border border-[#283548] rounded-md p-3">
          <div className="text-xs text-slate-400">مكتبات معزولة</div>
          <div className="text-xl font-semibold font-mono tabular-nums text-slate-300 mt-1">
            {counts.third_party_library_packages}
          </div>
        </div>
        <div className="bg-[#1e293b]/60 border border-[#283548] rounded-md p-3">
          <div className="text-xs text-slate-400">الحزم المقسّمة</div>
          <div className="text-xl font-semibold font-mono tabular-nums text-slate-100 mt-1">
            {counts.splits_processed}
          </div>
        </div>
        <div className="bg-[#1e293b]/60 border border-[#283548] rounded-md p-3">
          <div className="text-xs text-slate-400">ملفات .so الأصلية</div>
          <div className="text-xl font-semibold font-mono tabular-nums text-slate-100 mt-1">
            {counts.native_so_libraries}
          </div>
        </div>
        <div className="bg-[#1e293b]/60 border border-[#283548] rounded-md p-3">
          <div className="text-xs text-slate-400">تطابق الأصل SHA-256</div>
          <div className="mt-1 flex items-center gap-1.5 text-sm font-semibold">
            {comp.integrity_verified ? (
              <>
                <CheckCircle2 className="w-4 h-4 text-emerald-500 shrink-0" />
                <span className="text-emerald-400">مطابق بايت ببايت</span>
              </>
            ) : (
              <>
                <XCircle className="w-4 h-4 text-red-500 shrink-0" />
                <span className="text-red-400">عدم تطابق</span>
              </>
            )}
          </div>
        </div>
      </div>

      {/* Segmented Tabs */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-1 p-1 bg-[#0b111e] border border-[#283548] rounded-md">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              type="button"
              onClick={() => setActiveTab(tab.id)}
              className={`px-3 py-1.5 text-xs font-medium rounded transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                activeTab === tab.id
                  ? 'bg-[#0284c7] text-white'
                  : 'text-slate-400 hover:text-slate-100'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {(activeTab === 'app_code' || activeTab === 'strings_perms' || activeTab === 'assets') && (
          <div className="relative w-full sm:w-64">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute right-3 top-1/2 -translate-y-1/2 pointer-events-none" />
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="بحث في النتائج..."
              className="w-full bg-[#0b111e] border border-[#283548] rounded-md pr-8 pl-3 py-1.5 text-xs text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-[#38bdf8]"
            />
          </div>
        )}
      </div>

      {/* Tab Content */}
      {activeTab === 'overview' && (
        <div className="space-y-6">
          {/* Integrity Verification Table (Desktop) + Stacked Cards (Mobile) */}
          <div className="min-w-0">
            <h3 className="text-sm font-semibold text-slate-200 mb-3">سجل حفظ الملفات الأصلية والتحقق التلقائي</h3>
            <div className="sm:hidden space-y-2.5">
              {comp.integrity_checks.map((chk) => {
                const inp = rep.inputs.find((i) => i.filename === chk.filename);
                return (
                  <div key={chk.filename} className="border border-[#283548] rounded-md p-3 bg-[#0b111e] space-y-2 text-xs">
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-mono font-semibold text-slate-100 break-all">{chk.filename}</span>
                      {chk.matched ? (
                        <span className="text-emerald-400 font-medium shrink-0">مطابق 100%</span>
                      ) : (
                        <span className="text-red-400 font-medium shrink-0">غير مطابق</span>
                      )}
                    </div>
                    <div className="text-slate-300 font-mono break-all" dir="ltr">
                      {inp ? `${inp.detected_type.primary_type} / ${inp.detected_type.sub_type}` : '-'}
                    </div>
                    <div className="text-slate-400 font-mono tabular-nums">
                      الحجم: {chk.actual_size.toLocaleString('en-US')} بايت
                    </div>
                    <div className="text-slate-400 font-mono break-all text-[11px]" dir="ltr">
                      SHA-256: {chk.actual_sha256}
                    </div>
                  </div>
                );
              })}
            </div>

            <div className="hidden sm:block overflow-x-auto border border-[#283548] rounded-md">
              <table className="w-full text-xs text-right">
                <thead className="bg-[#0b111e] text-slate-400 border-b border-[#283548]">
                  <tr>
                    <th className="py-2.5 px-3 font-medium">الملف</th>
                    <th className="py-2.5 px-3 font-medium">النوع الفعلي (Magic Bytes)</th>
                    <th className="py-2.5 px-3 font-medium">الحجم (بايت)</th>
                    <th className="py-2.5 px-3 font-medium">بصمة SHA-256</th>
                    <th className="py-2.5 px-3 font-medium">حالة المطابقة</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#283548]">
                  {comp.integrity_checks.map((chk) => {
                    const inp = rep.inputs.find((i) => i.filename === chk.filename);
                    return (
                      <tr key={chk.filename} className="hover:bg-[#1e293b]/40">
                        <td className="py-2.5 px-3 font-mono text-slate-200">{chk.filename}</td>
                        <td className="py-2.5 px-3 font-mono text-slate-300">
                          {inp ? `${inp.detected_type.primary_type} / ${inp.detected_type.sub_type}` : '-'}
                        </td>
                        <td className="py-2.5 px-3 font-mono tabular-nums text-slate-300">
                          {chk.actual_size.toLocaleString('en-US')}
                        </td>
                        <td className="py-2.5 px-3 font-mono text-slate-400 max-w-[240px] truncate" dir="ltr">
                          {chk.actual_sha256}
                        </td>
                        <td className="py-2.5 px-3">
                          {chk.matched ? (
                            <span className="text-emerald-400 font-medium">مطابق 100%</span>
                          ) : (
                            <span className="text-red-400 font-medium">غير مطابق</span>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>

          {/* Frameworks & Explicit Limitations */}
          <div className="min-w-0">
            <h3 className="text-sm font-semibold text-slate-200 mb-3">أطر العمل المكتشفة والقيود الصريحة</h3>
            {rep.frameworks.length === 0 ? (
              <p className="text-xs text-slate-400 border border-[#283548] rounded-md p-4 bg-[#0b111e]">
                لم يتم رصد إطار عمل هجين (Flutter / React Native / Unity / Xamarin).
              </p>
            ) : (
              <div className="divide-y divide-[#283548] border border-[#283548] rounded-md bg-[#0b111e]">
                {rep.frameworks.map((fw) => (
                  <div key={fw.name} className="p-4 space-y-1.5 min-w-0">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <span className="text-sm font-semibold text-slate-100">{fw.name}</span>
                      <span className="text-xs text-slate-400 font-mono break-all" dir="ltr">
                        {fw.evidence.join(' · ')}
                      </span>
                    </div>
                    {fw.status_note && (
                      <p className="text-xs text-amber-300 flex items-start gap-2">
                        <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-0.5" />
                        <span className="min-w-0">{fw.status_note}</span>
                      </p>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Warnings */}
          {comp.warnings.length > 0 && (
            <div>
              <h3 className="text-sm font-semibold text-amber-400 mb-2">تحذيرات الأمان والفك</h3>
              <ul className="text-xs text-amber-200 space-y-1 border border-[#283548] rounded-md p-3 bg-[#0b111e]">
                {comp.warnings.map((w, idx) => (
                  <li key={idx}>· {w}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {activeTab === 'splits' && (
        <div className="space-y-6">
          {rep.bundle_manifest_json && (
            <div>
              <h3 className="text-sm font-semibold text-slate-200 mb-2">بيانات manifest.json للحزمة</h3>
              <pre
                className="bg-[#0b111e] border border-[#283548] rounded-md p-3 text-xs font-mono text-slate-300 overflow-x-auto"
                dir="ltr"
              >
                {JSON.stringify(rep.bundle_manifest_json, null, 2)}
              </pre>
            </div>
          )}

          <div>
            <h3 className="text-sm font-semibold text-slate-200 mb-2">
              ملفات APK المعالجة والمدمجة ({rep.splits_processed.length})
            </h3>
            <div className="overflow-x-auto border border-[#283548] rounded-md">
              <table className="w-full text-xs text-right">
                <thead className="bg-[#0b111e] text-slate-400 border-b border-[#283548]">
                  <tr>
                    <th className="py-2.5 px-3 font-medium">اسم الملف</th>
                    <th className="py-2.5 px-3 font-medium">الدور</th>
                    <th className="py-2.5 px-3 font-medium">عدد الملفات</th>
                    <th className="py-2.5 px-3 font-medium">مكتبات lib/</th>
                    <th className="py-2.5 px-3 font-medium">موارد res/</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#283548]">
                  {rep.splits_processed.map((s) => (
                    <tr key={s.apk_name} className="hover:bg-[#1e293b]/40">
                      <td className="py-2 px-3 font-mono text-slate-200">{s.apk_name}</td>
                      <td className="py-2 px-3 font-mono text-slate-300">{s.role}</td>
                      <td className="py-2 px-3 font-mono tabular-nums text-slate-300">{s.file_count}</td>
                      <td className="py-2 px-3 text-slate-300">{s.has_native_libs ? 'نعم' : 'لا'}</td>
                      <td className="py-2 px-3 text-slate-300">{s.has_resources ? 'نعم' : 'لا'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          <div>
            <h3 className="text-sm font-semibold text-slate-200 mb-2">
              المكتبات الأصلية المستخرجة (.so) ({rep.native_libraries_so.length})
            </h3>
            {rep.native_libraries_so.length === 0 ? (
              <p className="text-xs text-slate-400">لا توجد مكتبات أصلية (.so) في هذه الحزمة.</p>
            ) : (
              <div className="overflow-x-auto border border-[#283548] rounded-md">
                <table className="w-full text-xs text-right">
                  <thead className="bg-[#0b111e] text-slate-400 border-b border-[#283548]">
                    <tr>
                      <th className="py-2.5 px-3 font-medium">المسار المدمج</th>
                      <th className="py-2.5 px-3 font-medium">المعمارية (ABI)</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#283548]">
                    {rep.native_libraries_so.map((lib) => (
                      <tr key={lib.path} className="hover:bg-[#1e293b]/40">
                        <td className="py-2 px-3 font-mono text-slate-200" dir="ltr">
                          {lib.path}
                        </td>
                        <td className="py-2 px-3 font-mono text-slate-300">{lib.abi}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}

      {activeTab === 'assets' && (
        <div className="space-y-4 min-w-0">
          <h3 className="text-sm font-semibold text-slate-200">
            محتوى الأصول والموارد والترجمات المفهرسة ({(rep.assets_index || []).length})
          </h3>
          {filteredAssets.length === 0 ? (
            <p className="text-xs text-slate-400">لا توجد ملفات assets أو resources مطابقة.</p>
          ) : (
            <div className="overflow-x-auto border border-[#283548] rounded-md max-h-96 overflow-y-auto">
              <table className="w-full text-xs text-right">
                <thead className="bg-[#0b111e] text-slate-400 border-b border-[#283548] sticky top-0">
                  <tr>
                    <th className="py-2.5 px-3 font-medium">مسار الأصل</th>
                    <th className="py-2.5 px-3 font-medium">النوع</th>
                    <th className="py-2.5 px-3 font-medium">الحجم (بايت)</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#283548]">
                  {filteredAssets.map((a) => (
                    <tr key={a.path} className="hover:bg-[#1e293b]/40">
                      <td className="py-2 px-3 font-mono text-slate-200 break-all" dir="ltr">
                        {a.path}
                      </td>
                      <td className="py-2 px-3 font-mono text-sky-300">{a.kind}</td>
                      <td className="py-2 px-3 font-mono tabular-nums text-slate-300">
                        {a.size_bytes.toLocaleString('en-US')}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {activeTab === 'app_code' && (
        <div className="space-y-6">
          <div>
            <h3 className="text-sm font-semibold text-slate-200 mb-2">
              شاشات التطبيق فقط ({result.screens_index.length})
            </h3>
            {result.screens_index.length === 0 ? (
              <p className="text-xs text-slate-400">لم تُرصد شاشات تطبيق بدليل مباشر في الملفات المفحوصة.</p>
            ) : (
              <div className="overflow-x-auto border border-[#283548] rounded-md">
                <table className="w-full text-xs text-right">
                  <thead className="bg-[#0b111e] text-slate-400 border-b border-[#283548]">
                    <tr>
                      <th className="py-2.5 px-3 font-medium">الشاشة / النشاط</th>
                      <th className="py-2.5 px-3 font-medium">المصدر</th>
                      <th className="py-2.5 px-3 font-medium">الدليل (المسار / الكلاس)</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#283548]">
                    {result.screens_index.map((s) => (
                      <tr key={s.screen_name} className="hover:bg-[#1e293b]/40">
                        <td className="py-2 px-3 font-mono text-slate-100">{s.screen_name}</td>
                        <td className="py-2 px-3 text-slate-300">{s.source}</td>
                        <td className="py-2 px-3 font-mono text-slate-400" dir="ltr">
                          {s.evidence}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          <div>
            <h3 className="text-sm font-semibold text-slate-200 mb-2">
              دوال كود التطبيق فقط ({result.functions_map.app_functions.length})
            </h3>
            {filteredFunctions.length === 0 ? (
              <p className="text-xs text-slate-400">لا توجد دوال مطابقة ضمن كود التطبيق المستخرج.</p>
            ) : (
              <div className="overflow-x-auto border border-[#283548] rounded-md max-h-96 overflow-y-auto">
                <table className="w-full text-xs text-right">
                  <thead className="bg-[#0b111e] text-slate-400 border-b border-[#283548] sticky top-0">
                    <tr>
                      <th className="py-2.5 px-3 font-medium">الكلاس</th>
                      <th className="py-2.5 px-3 font-medium">الدالة</th>
                      <th className="py-2.5 px-3 font-medium">الدليل</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#283548]">
                    {filteredFunctions.map((fn, idx) => (
                      <tr key={`${fn.evidence}-${idx}`} className="hover:bg-[#1e293b]/40">
                        <td className="py-2 px-3 font-mono text-slate-200">{fn.class_name}</td>
                        <td className="py-2 px-3 font-mono text-sky-300">{fn.method_name}()</td>
                        <td className="py-2 px-3 font-mono text-slate-400" dir="ltr">
                          {fn.evidence}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}

      {activeTab === 'libraries' && (
        <div>
          <h3 className="text-sm font-semibold text-slate-200 mb-2">
            حزم مكتبات الطرف الثالث المعزولة ({rep.third_party_libraries.length})
          </h3>
          <p className="text-xs text-slate-400 mb-3">
            هذه الحزم (مثل androidx وkotlin وokhttp وgoogle play services) معزولة تماماً عن إحصائيات شاشات ودوال التطبيق.
          </p>
          {rep.third_party_libraries.length === 0 ? (
            <p className="text-xs text-slate-400">لم تُرصد مكتبات طرف ثالث في جداول DEX.</p>
          ) : (
            <div className="overflow-x-auto border border-[#283548] rounded-md">
              <table className="w-full text-xs text-right">
                <thead className="bg-[#0b111e] text-slate-400 border-b border-[#283548]">
                  <tr>
                    <th className="py-2.5 px-3 font-medium">بادئة الحزمة</th>
                    <th className="py-2.5 px-3 font-medium">عدد الكلاسات المعزولة</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#283548]">
                  {rep.third_party_libraries.map((lib) => (
                    <tr key={lib.package} className="hover:bg-[#1e293b]/40">
                      <td className="py-2 px-3 font-mono text-slate-200" dir="ltr">
                        {lib.package}
                      </td>
                      <td className="py-2 px-3 font-mono tabular-nums text-slate-300">{lib.class_count}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {activeTab === 'strings_perms' && (
        <div className="space-y-6">
          <div>
            <h3 className="text-sm font-semibold text-slate-200 mb-2">
              الصلاحيات المستخرجة بدليل Manifest ({result.permissions.length})
            </h3>
            {result.permissions.length === 0 ? (
              <p className="text-xs text-slate-400">لا توجد صلاحيات مسجلة في AndroidManifest.</p>
            ) : (
              <div className="overflow-x-auto border border-[#283548] rounded-md">
                <table className="w-full text-xs text-right">
                  <thead className="bg-[#0b111e] text-slate-400 border-b border-[#283548]">
                    <tr>
                      <th className="py-2.5 px-3 font-medium">الصلاحية</th>
                      <th className="py-2.5 px-3 font-medium">الدليل</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#283548]">
                    {result.permissions.map((p, idx) => (
                      <tr key={`${p.name}-${idx}`} className="hover:bg-[#1e293b]/40">
                        <td className="py-2 px-3 font-mono text-slate-100">{p.name}</td>
                        <td className="py-2 px-3 font-mono text-slate-400" dir="ltr">
                          {p.evidence}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          <div>
            <h3 className="text-sm font-semibold text-slate-200 mb-2">
              فهرس النصوص المفلترة ({result.strings_index.length})
            </h3>
            <div className="overflow-x-auto border border-[#283548] rounded-md max-h-96 overflow-y-auto">
              <table className="w-full text-xs text-right">
                <thead className="bg-[#0b111e] text-slate-400 border-b border-[#283548] sticky top-0">
                  <tr>
                    <th className="py-2.5 px-3 font-medium">النص</th>
                    <th className="py-2.5 px-3 font-medium">الدليل</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#283548]">
                  {filteredStrings.map((s, idx) => (
                    <tr key={idx} className="hover:bg-[#1e293b]/40">
                      <td className="py-2 px-3 text-slate-200 break-all">{s.value}</td>
                      <td className="py-2 px-3 font-mono text-slate-400 whitespace-nowrap" dir="ltr">
                        {s.evidence}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {activeTab === 'exe' && (
        <div className="space-y-4">
          {rep.exe_reports.map((exe) => (
            <div key={exe.file} className="border border-[#283548] rounded-md p-4 bg-[#0b111e] space-y-4">
              <div className="flex items-center justify-between">
                <span className="font-mono text-sm font-semibold text-slate-100">{exe.file}</span>
                <span className="font-mono text-xs text-sky-400">{exe.sub_type}</span>
              </div>
              {exe.limitations.length > 0 && (
                <div className="text-xs text-amber-300 space-y-1">
                  {exe.limitations.map((l, i) => (
                    <div key={i}>· {l}</div>
                  ))}
                </div>
              )}
              <div>
                <h4 className="text-xs font-semibold text-slate-300 mb-2">أقسام PE ({exe.sections.length})</h4>
                <div className="overflow-x-auto border border-[#283548] rounded">
                  <table className="w-full text-xs text-right">
                    <thead className="bg-[#111827] text-slate-400">
                      <tr>
                        <th className="py-1.5 px-2">القسم</th>
                        <th className="py-1.5 px-2">RVA</th>
                        <th className="py-1.5 px-2">الحجم الخام</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#283548]">
                      {exe.sections.map((sec, idx) => (
                        <tr key={idx}>
                          <td className="py-1.5 px-2 font-mono">{sec.name}</td>
                          <td className="py-1.5 px-2 font-mono">{sec.virtual_address}</td>
                          <td className="py-1.5 px-2 font-mono tabular-nums">{sec.raw_size}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {activeTab === 'rebuild' && (
        <div className="space-y-4">
          <div className="border border-[#283548] rounded-md p-4 bg-[#0b111e]">
            <div className="text-xs text-slate-400 mb-1">تصنيف حالة إعادة البناء</div>
            <div className="text-base font-semibold text-amber-300">{comp.rebuild_classification}</div>
          </div>
          <pre className="bg-[#0b111e] border border-[#283548] rounded-md p-4 text-xs text-slate-200 whitespace-pre-wrap leading-relaxed">
            {result.readme_rebuilt}
          </pre>
        </div>
      )}
    </section>
  );
}
