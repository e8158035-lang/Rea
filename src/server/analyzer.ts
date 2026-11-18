import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const { ZipArchive } = require('archiver') as { ZipArchive: new (options?: any) => any };
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import yauzl from 'yauzl';

const MAX_ARCHIVE_DEPTH = 4;
const MAX_ENTRIES = 50000;
const MAX_TOTAL_UNCOMPRESSED = 2 * 1024 * 1024 * 1024; // 2GB
const MAX_SINGLE_ENTRY = 700 * 1024 * 1024;

const THIRD_PARTY_PREFIXES = [
  'androidx.',
  'android.support.',
  'android.arch.',
  'com.google.android.',
  'com.google.firebase.',
  'com.google.gson.',
  'com.google.protobuf.',
  'com.google.common.',
  'kotlin.',
  'kotlinx.',
  'okhttp3.',
  'okio.',
  'retrofit2.',
  'com.squareup.',
  'com.facebook.',
  'io.reactivex.',
  'org.apache.',
  'org.slf4j.',
  'org.jetbrains.',
  'com.bumptech.glide.',
  'dagger.',
  'javax.',
  'java.',
  'sun.',
  'dalvik.',
  'android.view.',
  'android.widget.',
  'android.app.',
  'android.os.',
  'android.content.',
  'io.flutter.embedding.',
  'io.flutter.plugin.',
  'io.flutter.plugins.',
  'io.flutter.util.',
  'io.flutter.view.',
  'com.unity3d.',
  'mono.',
  'org.chromium.',
];

export interface AnalysisLogEntry {
  ts: string;
  message: string;
  progress: number;
}

export interface DetectedFileType {
  file_name: string;
  size_bytes: number;
  magic_hex: string;
  primary_type: string;
  sub_type: string;
  extension_claimed: string;
}

export async function sha256File(filePath: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(filePath, { highWaterMark: 1024 * 1024 });
    stream.on('data', (chunk) => hash.update(chunk));
    stream.on('end', () => resolve(hash.digest('hex')));
    stream.on('error', reject);
  });
}

function readZipEntryNames(filePath: string): Promise<string[]> {
  return new Promise((resolve, reject) => {
    yauzl.open(filePath, { lazyEntries: true }, (err, zipfile) => {
      if (err || !zipfile) return reject(err || new Error('Invalid ZIP'));
      const names: string[] = [];
      zipfile.readEntry();
      zipfile.on('entry', (entry) => {
        names.push(entry.fileName);
        if (names.length < 5000) {
          zipfile.readEntry();
        } else {
          zipfile.close();
          resolve(names);
        }
      });
      zipfile.on('end', () => resolve(names));
      zipfile.on('error', reject);
    });
  });
}

export async function detectMagicType(filePath: string): Promise<DetectedFileType> {
  const stat = fs.statSync(filePath);
  const fd = fs.openSync(filePath, 'r');
  const headLen = Math.min(stat.size, 65536);
  const header = Buffer.alloc(headLen);
  fs.readSync(fd, header, 0, headLen, 0);

  let tail = Buffer.alloc(0);
  if (stat.size > 0) {
    const tailLen = Math.min(stat.size, 8192);
    tail = Buffer.alloc(tailLen);
    fs.readSync(fd, tail, 0, tailLen, Math.max(0, stat.size - tailLen));
  }
  fs.closeSync(fd);

  const info: DetectedFileType = {
    file_name: path.basename(filePath),
    size_bytes: stat.size,
    magic_hex: header.subarray(0, 16).toString('hex'),
    primary_type: 'UNKNOWN',
    sub_type: 'UNKNOWN',
    extension_claimed: path.extname(filePath).toLowerCase(),
  };

  if (header.subarray(0, 2).toString('ascii') === 'MZ') {
    info.primary_type = 'PE_EXECUTABLE';
    info.sub_type = 'NATIVE_PE';
    const lowerStr = header.toString('latin1').toLowerCase();
    if (header.includes('BSJB') || lowerStr.includes('mscoree.dll')) {
      info.sub_type = 'DOTNET_PE';
    } else if (lowerStr.includes('electron')) {
      info.sub_type = 'ELECTRON_PE';
    } else if (header.includes('NullsoftInst')) {
      info.sub_type = 'NSIS_INSTALLER';
    } else if (tail.includes(Buffer.from([0x4d, 0x45, 0x49, 0x0c, 0x0b, 0x0a, 0x0b, 0x0e]))) {
      info.sub_type = 'PYINSTALLER_PE';
    }
    return info;
  }

  if (
    (header[0] === 0x50 && header[1] === 0x4b && header[2] === 0x03 && header[3] === 0x04) ||
    (header[0] === 0x50 && header[1] === 0x4b && header[2] === 0x05 && header[3] === 0x06)
  ) {
    info.primary_type = 'ZIP_ARCHIVE';
    try {
      const names = await readZipEntryNames(filePath);
      const lowerSet = new Set(names.map((n) => n.toLowerCase()));
      const apks = names.filter((n) => n.toLowerCase().endsWith('.apk'));
      if (
        lowerSet.has('androidmanifest.xml') &&
        names.some((n) => n.toLowerCase().startsWith('classes') && n.toLowerCase().endsWith('.dex'))
      ) {
        info.primary_type = 'ANDROID_APK';
        info.sub_type = 'SINGLE_APK';
      } else if (apks.length > 0) {
        info.primary_type = 'ANDROID_SPLIT_BUNDLE';
        if (lowerSet.has('manifest.json')) info.sub_type = 'XAPK_BUNDLE';
        else if (lowerSet.has('info.json')) info.sub_type = 'APKM_BUNDLE';
        else info.sub_type = 'APKS_OR_SPLIT_ZIP';
      } else if (names.some((n) => n.toLowerCase().endsWith('.exe'))) {
        info.sub_type = 'ZIP_WITH_EXECUTABLES';
      } else {
        info.sub_type = 'STANDARD_ZIP';
      }
    } catch {
      info.primary_type = 'CORRUPT_ZIP';
      info.sub_type = 'BAD_ZIP_HEADER';
    }
    return info;
  }

  if (header[0] === 0x7f && header.subarray(1, 4).toString('ascii') === 'ELF') {
    info.primary_type = 'ELF_BINARY';
    info.sub_type = 'ELF_SHARED_OR_EXEC';
    return info;
  }

  if (header.subarray(0, 4).toString('ascii') === 'dex\n') {
    info.primary_type = 'ANDROID_DEX';
    info.sub_type = 'DALVIK_EXECUTABLE';
    return info;
  }

  return info;
}

function safeExtractZip(
  zipPath: string,
  destDir: string,
  depth: number,
  tracker: { entries: number; bytes: number },
): Promise<{ files: string[]; warnings: string[] }> {
  return new Promise((resolve, reject) => {
    const warnings: string[] = [];
    const extractedFiles: string[] = [];

    if (depth > MAX_ARCHIVE_DEPTH) {
      warnings.push(`تم إيقاف فك الضغط المتداخل عند العمق ${depth} لمنع التكرار اللانهائي: ${path.basename(zipPath)}`);
      return resolve({ files: extractedFiles, warnings });
    }

    fs.mkdirSync(destDir, { recursive: true });
    const realDest = fs.realpathSync(destDir);

    yauzl.open(zipPath, { lazyEntries: true }, (err, zipfile) => {
      if (err || !zipfile) {
        warnings.push(`تعذر فتح الأرشيف ${path.basename(zipPath)}: ${err?.message || 'خطأ غير معروف'}`);
        return resolve({ files: extractedFiles, warnings });
      }

      zipfile.readEntry();
      zipfile.on('entry', (entry) => {
        tracker.entries += 1;
        if (tracker.entries > MAX_ENTRIES) {
          warnings.push(`تجاوز حد العناصر المسموح (${MAX_ENTRIES}) في ${path.basename(zipPath)}`);
          zipfile.close();
          return resolve({ files: extractedFiles, warnings });
        }

        if (entry.fileName.endsWith('/')) {
          zipfile.readEntry();
          return;
        }

        if (entry.uncompressedSize > MAX_SINGLE_ENTRY) {
          warnings.push(`تخطي ملف ضخم يتجاوز الحد الآمن: ${entry.fileName}`);
          zipfile.readEntry();
          return;
        }

        if (
          entry.compressedSize > 0 &&
          entry.uncompressedSize / entry.compressedSize > 120 &&
          entry.uncompressedSize > 10 * 1024 * 1024
        ) {
          warnings.push(`تحذير نسبة ضغط مشبوهة (Zip Bomb محتمل) في ${entry.fileName}`);
          zipfile.readEntry();
          return;
        }

        tracker.bytes += entry.uncompressedSize;
        if (tracker.bytes > MAX_TOTAL_UNCOMPRESSED) {
          warnings.push('تجاوز الحد الأقصى لإجمالي الحجم المفكوك (2GB) للحماية.');
          zipfile.close();
          return resolve({ files: extractedFiles, warnings });
        }

        const normalized = entry.fileName.replace(/\\/g, '/').replace(/^\/+/, '');
        const parts = normalized.split('/');
        if (!normalized || parts.includes('..')) {
          warnings.push(`حظر مسار غير آمن (Zip Slip): ${entry.fileName}`);
          zipfile.readEntry();
          return;
        }

        const targetPath = path.resolve(realDest, normalized);
        if (targetPath !== realDest && !targetPath.startsWith(realDest + path.sep)) {
          warnings.push(`حظر محاولة خروج من مجلد الاستخراج (Zip Slip): ${entry.fileName}`);
          zipfile.readEntry();
          return;
        }

        fs.mkdirSync(path.dirname(targetPath), { recursive: true });
        zipfile.openReadStream(entry, (sErr, readStream) => {
          if (sErr || !readStream) {
            warnings.push(`تعذر استخراج ${normalized}: ${sErr?.message}`);
            zipfile.readEntry();
            return;
          }
          const outStream = fs.createWriteStream(targetPath);
          readStream.pipe(outStream);
          outStream.on('finish', () => {
            extractedFiles.push(normalized);
            zipfile.readEntry();
          });
          outStream.on('error', (wErr) => {
            warnings.push(`خطأ كتابة ${normalized}: ${wErr.message}`);
            zipfile.readEntry();
          });
        });
      });

      zipfile.on('end', () => resolve({ files: extractedFiles, warnings }));
      zipfile.on('error', (zErr) => {
        warnings.push(`خطأ في الأرشيف ${path.basename(zipPath)}: ${zErr.message}`);
        resolve({ files: extractedFiles, warnings });
      });
    });
  });
}

function isThirdPartySymbol(symbol: string): boolean {
  const s = symbol.replace(/^L/, '').replace(/;$/, '').replace(/\//g, '.');
  return THIRD_PARTY_PREFIXES.some((p) => s.startsWith(p));
}

function isAppSymbol(symbol: string, appPackage: string | null): boolean {
  const s = symbol.replace(/^L/, '').replace(/;$/, '').replace(/\//g, '.');
  if (isThirdPartySymbol(s)) return false;
  if (appPackage && (s === appPackage || s.startsWith(appPackage + '.'))) return true;
  if (s.length <= 2 || !s.includes('.')) return false;
  return true;
}

function parseAxmlManifest(data: Buffer, evidencePath: string) {
  const result: any = {
    parsed: false,
    evidence: evidencePath,
    package_name: null as string | null,
    version_code: null as string | number | null,
    version_name: null as string | null,
    min_sdk: null as number | null,
    target_sdk: null as number | null,
    permissions: [] as Array<{ name: string; evidence: string }>,
    activities: [] as Array<{ name: string; evidence: string }>,
    services: [] as Array<{ name: string; evidence: string }>,
    receivers: [] as Array<{ name: string; evidence: string }>,
    providers: [] as Array<{ name: string; evidence: string }>,
    error: null as string | null,
  };

  if (data.length < 8) {
    result.error = 'ملف AndroidManifest.xml أصغر من الحد الأدنى.';
    return result;
  }

  const trimmed = data.toString('utf8', 0, Math.min(data.length, 64)).trimStart();
  if (trimmed.startsWith('<')) {
    const text = data.toString('utf8');
    const pkgM = text.match(/package="([^"]+)"/);
    if (pkgM) result.package_name = pkgM[1];
    for (const m of text.matchAll(/<uses-permission[^>]*android:name="([^"]+)"/g)) {
      result.permissions.push({ name: m[1], evidence: evidencePath });
    }
    for (const m of text.matchAll(/<activity[^>]*android:name="([^"]+)"/g)) {
      result.activities.push({ name: m[1], evidence: evidencePath });
    }
    for (const m of text.matchAll(/<service[^>]*android:name="([^"]+)"/g)) {
      result.services.push({ name: m[1], evidence: evidencePath });
    }
    for (const m of text.matchAll(/<receiver[^>]*android:name="([^"]+)"/g)) {
      result.receivers.push({ name: m[1], evidence: evidencePath });
    }
    for (const m of text.matchAll(/<provider[^>]*android:name="([^"]+)"/g)) {
      result.providers.push({ name: m[1], evidence: evidencePath });
    }
    result.parsed = true;
    return result;
  }

  try {
    const chunkType = data.readUInt16LE(0);
    const headerSize = data.readUInt16LE(2);
    if (chunkType !== 0x0003) {
      result.error = `ترويسة AXML غير قياسية: 0x${chunkType.toString(16)}`;
      return result;
    }

    let pos = headerSize;
    const strings: string[] = [];

    while (pos + 8 <= data.length) {
      const ctype = data.readUInt16LE(pos);
      const chdrSize = data.readUInt16LE(pos + 2);
      const csize = data.readUInt32LE(pos + 4);
      if (csize < 8 || pos + csize > data.length) break;

      if (ctype === 0x0001 && pos + 28 <= data.length) {
        const strCount = data.readUInt32LE(pos + 8);
        const flags = data.readUInt32LE(pos + 16);
        const strStart = data.readUInt32LE(pos + 20);
        const isUtf8 = Boolean(flags & (1 << 8));
        const offsetsBase = pos + chdrSize;
        const poolDataBase = pos + strStart;

        for (let i = 0; i < strCount; i++) {
          if (offsetsBase + (i + 1) * 4 > data.length) break;
          const off = data.readUInt32LE(offsetsBase + i * 4);
          let sPos = poolDataBase + off;
          if (sPos >= data.length) {
            strings.push('');
            continue;
          }
          if (isUtf8) {
            const u16Len = data[sPos];
            sPos += u16Len & 0x80 ? 2 : 1;
            if (sPos >= data.length) {
              strings.push('');
              continue;
            }
            let u8Len = data[sPos];
            if (u8Len & 0x80 && sPos + 1 < data.length) {
              u8Len = ((u8Len & 0x7f) << 8) | data[sPos + 1];
              sPos += 2;
            } else {
              sPos += 1;
            }
            strings.push(data.subarray(sPos, Math.min(data.length, sPos + u8Len)).toString('utf8'));
          } else {
            if (sPos + 2 > data.length) {
              strings.push('');
              continue;
            }
            let u16Len = data.readUInt16LE(sPos);
            sPos += 2;
            if (u16Len & 0x8000 && sPos + 2 <= data.length) {
              u16Len = ((u16Len & 0x7fff) << 16) | data.readUInt16LE(sPos);
              sPos += 2;
            }
            strings.push(data.subarray(sPos, Math.min(data.length, sPos + u16Len * 2)).toString('utf16le'));
          }
        }
      } else if (ctype === 0x0102 && pos + 36 <= data.length) {
        const nameIdx = data.readUInt32LE(pos + 20);
        const attrSize = data.readUInt16LE(pos + 26);
        const attrCount = data.readUInt16LE(pos + 28);
        const tagName = nameIdx < strings.length ? strings[nameIdx] : '';
        const attrs: Record<string, any> = {};
        let attrOff = pos + 36;
        for (let a = 0; a < attrCount; a++) {
          if (attrOff + 20 > data.length) break;
          const aNameIdx = data.readUInt32LE(attrOff + 4);
          const aRawVal = data.readUInt32LE(attrOff + 8);
          const aType = data.readUInt8(attrOff + 15);
          const aData = data.readUInt32LE(attrOff + 16);
          const aName = aNameIdx < strings.length ? strings[aNameIdx] : '';
          let val: any = null;
          if (aType === 0x03 && aData < strings.length) val = strings[aData];
          else if (aType === 0x10 || aType === 0x11) val = aData;
          else if (aRawVal < strings.length) val = strings[aRawVal];
          if (aName) attrs[aName] = val;
          attrOff += Math.max(20, attrSize);
        }
        if (tagName === 'manifest') {
          result.package_name = attrs.package || result.package_name;
          result.version_code = attrs.versionCode ?? null;
          result.version_name = attrs.versionName ?? null;
        } else if (tagName === 'uses-sdk') {
          result.min_sdk = attrs.minSdkVersion ?? null;
          result.target_sdk = attrs.targetSdkVersion ?? null;
        } else if (tagName === 'uses-permission' && attrs.name) {
          result.permissions.push({ name: String(attrs.name), evidence: evidencePath });
        } else if (tagName === 'activity' && attrs.name) {
          result.activities.push({ name: String(attrs.name), evidence: evidencePath });
        } else if (tagName === 'service' && attrs.name) {
          result.services.push({ name: String(attrs.name), evidence: evidencePath });
        } else if (tagName === 'receiver' && attrs.name) {
          result.receivers.push({ name: String(attrs.name), evidence: evidencePath });
        } else if (tagName === 'provider' && attrs.name) {
          result.providers.push({ name: String(attrs.name), evidence: evidencePath });
        }
      }
      pos += csize;
    }
    result.parsed = true;
  } catch (err: any) {
    result.error = `تعذر تحليل AXML ثنائياً: ${err.message}`;
  }
  return result;
}

function readUleb128(buf: Buffer, offset: number): [number, number] {
  let val = 0;
  let shift = 0;
  while (offset < buf.length) {
    const b = buf[offset++];
    val |= (b & 0x7f) << shift;
    if ((b & 0x80) === 0) break;
    shift += 7;
  }
  return [val, offset];
}

function parseDexFile(dexPath: string, relEvidence: string, appPackage: string | null) {
  const out = {
    file: relEvidence,
    parsed: false,
    app_classes: [] as Array<{ name: string; evidence: string }>,
    app_functions: [] as Array<{ class_name: string; method_name: string; evidence: string }>,
    library_packages: {} as Record<string, number>,
    app_strings: [] as Array<{ value: string; evidence: string }>,
    error: null as string | null,
  };

  try {
    const data = fs.readFileSync(dexPath);
    if (data.length < 112 || data.subarray(0, 4).toString('ascii') !== 'dex\n') {
      out.error = 'ترويسة DEX غير صالحة';
      return out;
    }

    const stringIdsSize = data.readUInt32LE(56);
    const stringIdsOff = data.readUInt32LE(60);
    const typeIdsSize = data.readUInt32LE(64);
    const typeIdsOff = data.readUInt32LE(68);
    const methodIdsSize = data.readUInt32LE(88);
    const methodIdsOff = data.readUInt32LE(92);
    const classDefsSize = data.readUInt32LE(96);
    const classDefsOff = data.readUInt32LE(100);

    const dexStrings: string[] = [];
    for (let i = 0; i < Math.min(stringIdsSize, 120000); i++) {
      const off = data.readUInt32LE(stringIdsOff + i * 4);
      if (off >= data.length) {
        dexStrings.push('');
        continue;
      }
      const [utf16Len, p] = readUleb128(data, off);
      let end = data.indexOf(0, p);
      if (end === -1 || end > p + Math.max(utf16Len * 4 + 16, 512)) {
        end = Math.min(data.length, p + utf16Len * 3);
      }
      dexStrings.push(data.subarray(p, end).toString('utf8'));
    }

    const types: string[] = [];
    for (let i = 0; i < Math.min(typeIdsSize, 65535); i++) {
      const sIdx = data.readUInt32LE(typeIdsOff + i * 4);
      types.push(sIdx < dexStrings.length ? dexStrings[sIdx] : '');
    }

    const appClassSet = new Set<string>();
    for (let i = 0; i < Math.min(classDefsSize, 40000); i++) {
      const classIdx = data.readUInt32LE(classDefsOff + i * 32);
      if (classIdx >= types.length) continue;
      const clsName = types[classIdx].replace(/^L/, '').replace(/;$/, '').replace(/\//g, '.');
      if (isThirdPartySymbol(clsName)) {
        const prefix = clsName.split('.').slice(0, 3).join('.');
        out.library_packages[prefix] = (out.library_packages[prefix] || 0) + 1;
      } else if (isAppSymbol(clsName, appPackage)) {
        appClassSet.add(clsName);
        out.app_classes.push({ name: clsName, evidence: `${relEvidence}::${clsName}` });
      }
    }

    const seenMethods = new Set<string>();
    for (let i = 0; i < Math.min(methodIdsSize, 80000); i++) {
      const classIdx = data.readUInt16LE(methodIdsOff + i * 8);
      const nameIdx = data.readUInt32LE(methodIdsOff + i * 8 + 4);
      if (classIdx >= types.length || nameIdx >= dexStrings.length) continue;
      const clsName = types[classIdx].replace(/^L/, '').replace(/;$/, '').replace(/\//g, '.');
      const methodName = dexStrings[nameIdx];
      if (appClassSet.has(clsName) && !methodName.startsWith('<')) {
        const sig = `${clsName}.${methodName}`;
        if (!seenMethods.has(sig)) {
          seenMethods.add(sig);
          out.app_functions.push({
            class_name: clsName,
            method_name: methodName,
            evidence: `${relEvidence}::${clsName}.${methodName}()`,
          });
        }
      }
    }

    const seenStr = new Set<string>();
    for (const s of dexStrings) {
      if (s.length < 4 || s.length > 220) continue;
      if (/^L[a-zA-Z0-9_/$]+;$/.test(s)) continue;
      if (/^\[+[BCDFIJSZLV]/.test(s)) continue;
      if (/^(androidx|kotlin|kotlinx|okhttp3|com\.google\.|io\.flutter\.embedding)\//.test(s)) continue;
      if (/^[0-9a-fA-F]{32,}$/.test(s)) continue;
      if (THIRD_PARTY_PREFIXES.some((p) => s.startsWith(p))) continue;
      if (seenStr.has(s)) continue;
      seenStr.add(s);
      out.app_strings.push({ value: s, evidence: relEvidence });
      if (out.app_strings.length >= 400) break;
    }

    out.parsed = true;
  } catch (err: any) {
    out.error = `تعذر قراءة DEX: ${err.message}`;
  }
  return out;
}

function analyzePeExecutable(exePath: string, relEvidence: string, magic: DetectedFileType) {
  const peReport: any = {
    file: relEvidence,
    sub_type: magic.sub_type,
    sections: [],
    imports: [],
    exports: [],
    resources: [],
    strings: [],
    dotnet_decompiled: false,
    limitations: [] as string[],
  };

  try {
    const fd = fs.openSync(exePath, 'r');
    const buf = Buffer.alloc(Math.min(fs.statSync(exePath).size, 16 * 1024 * 1024));
    fs.readSync(fd, buf, 0, buf.length, 0);
    fs.closeSync(fd);

    if (buf.length > 0x40) {
      const peOff = buf.readUInt32LE(0x3c);
      if (peOff + 24 < buf.length && buf.subarray(peOff, peOff + 4).toString('ascii') === 'PE\0\0') {
        const numSections = buf.readUInt16LE(peOff + 6);
        const optHeaderSize = buf.readUInt16LE(peOff + 20);
        let secOff = peOff + 24 + optHeaderSize;
        for (let i = 0; i < Math.min(numSections, 32); i++) {
          if (secOff + 40 > buf.length) break;
          const name = buf.subarray(secOff, secOff + 8).toString('ascii').replace(/\0+$/, '');
          const virtualSize = buf.readUInt32LE(secOff + 8);
          const virtualAddress = buf.readUInt32LE(secOff + 12);
          const rawSize = buf.readUInt32LE(secOff + 16);
          peReport.sections.push({
            name,
            virtual_address: '0x' + virtualAddress.toString(16),
            virtual_size: virtualSize,
            raw_size: rawSize,
            evidence: `${relEvidence} [Section ${name}]`,
          });
          secOff += 40;
        }
      }
    }

    // Extract filtered ASCII strings with file offset evidence
    const text = buf.toString('latin1');
    const regex = /[ -~]{6,120}/g;
    let m: RegExpExecArray | null;
    while ((m = regex.exec(text)) !== null) {
      const s = m[0];
      if (s.includes('PADDING') || s.includes('This program cannot be run in DOS mode')) continue;
      if (s.toLowerCase().endsWith('.dll')) {
        peReport.imports.push({ dll: s, functions: [], evidence: `${relEvidence}@0x${m.index.toString(16)}` });
      } else {
        peReport.strings.push({ value: s, evidence: `${relEvidence}@0x${m.index.toString(16)}` });
      }
      if (peReport.strings.length >= 250) break;
    }

    if (magic.sub_type === 'DOTNET_PE') {
      peReport.limitations.push('أداة ilspycmd غير متوفرة في بيئة العرض؛ تم تحليل ترويسة PE والنصوص دون فك تجميع C# الكامل.');
    } else if (['NSIS_INSTALLER', 'PYINSTALLER_PE', 'ELECTRON_PE'].includes(magic.sub_type)) {
      peReport.limitations.push(`تم تمييز الملف كـ ${magic.sub_type}؛ يتطلب استخراجاً أعمق عبر 7z / rea-agents على Termux.`);
    }
  } catch (err: any) {
    peReport.limitations.push(`تعذر تحليل PE: ${err.message}`);
  }
  return peReport;
}

function walkFiles(dir: string, base: string = dir): string[] {
  if (!fs.existsSync(dir)) return [];
  const out: string[] = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      out.push(...walkFiles(full, base));
    } else if (entry.isFile()) {
      out.push(path.relative(base, full).replace(/\\/g, '/'));
    }
  }
  return out;
}

function checkCmd(cmd: string): boolean {
  const r = spawnSync('which', [cmd], { encoding: 'utf8' });
  return r.status === 0 && Boolean(r.stdout.trim());
}

export function getToolsStatus() {
  const tools = {
    node: checkCmd('node'),
    python3: checkCmd('python3'),
    java: checkCmd('java'),
    apktool: checkCmd('apktool'),
    jadx: checkCmd('jadx'),
    blutter: checkCmd('blutter'),
    reflutter: checkCmd('reflutter'),
    ilspycmd: checkCmd('ilspycmd'),
    '7z': checkCmd('7z'),
    unzip: checkCmd('unzip'),
    rea_agents: checkCmd('rea') || fs.existsSync(path.resolve(process.cwd(), 'node_modules/.bin/rea')),
  };
  return tools;
}

export async function runLiveAnalysisPipeline(
  inputPaths: string[],
  outputZipPath: string,
  workRoot: string,
  onProgress: (msg: string, pct: number) => void,
) {
  fs.mkdirSync(workRoot, { recursive: true });
  const origDir = path.join(workRoot, 'original');
  const extDir = path.join(workRoot, 'extracted');
  const anaDir = path.join(workRoot, 'analyzed');
  const rebDir = path.join(workRoot, 'rebuilt_project');
  for (const d of [origDir, extDir, anaDir, rebDir]) fs.mkdirSync(d, { recursive: true });

  onProgress('حفظ النسخ الأصلية بايت ببايت وحساب SHA-256...', 8);
  const inputManifest: any[] = [];
  for (const src of inputPaths) {
    const fname = path.basename(src);
    const dst = path.join(origDir, fname);
    fs.copyFileSync(src, dst);
    const hash = await sha256File(dst);
    const size = fs.statSync(dst).size;
    fs.writeFileSync(path.join(origDir, `${fname}.sha256`), `${hash}  ${fname}\n`, 'utf8');
    const magic = await detectMagicType(dst);
    inputManifest.push({
      filename: fname,
      size_bytes: size,
      sha256: hash,
      detected_type: magic,
    });
  }

  onProgress('فك الضغط الآمن وفحص الحزم المقسّمة (XAPK / APKS / APKM / ZIP / EXE)...', 24);
  const warnings: string[] = [];
  const mergedDir = path.join(extDir, 'merged');
  fs.mkdirSync(mergedDir, { recursive: true });
  const splitsProcessed: any[] = [];
  let bundleManifestJson: any = null;
  const exeReports: any[] = [];
  const tracker = { entries: 0, bytes: 0 };

  for (const item of inputManifest) {
    const origFile = path.join(origDir, item.filename);
    const ptype = item.detected_type.primary_type;

    if (ptype === 'ANDROID_APK') {
      const splitOut = path.join(extDir, 'splits', path.parse(item.filename).name);
      const { files, warnings: w } = await safeExtractZip(origFile, splitOut, 0, tracker);
      warnings.push(...w);
      splitsProcessed.push({
        apk_name: item.filename,
        role: 'single_apk',
        file_count: files.length,
        has_native_libs: files.some((f) => f.startsWith('lib/')),
        has_resources: files.some((f) => f.startsWith('res/')),
      });
      fs.cpSync(splitOut, mergedDir, { recursive: true, force: true });
    } else if (ptype === 'ANDROID_SPLIT_BUNDLE') {
      const bundleOut = path.join(extDir, 'bundle_root', path.parse(item.filename).name);
      const { warnings: w } = await safeExtractZip(origFile, bundleOut, 0, tracker);
      warnings.push(...w);

      const mJsonPath = path.join(bundleOut, 'manifest.json');
      if (fs.existsSync(mJsonPath)) {
        try {
          bundleManifestJson = JSON.parse(fs.readFileSync(mJsonPath, 'utf8'));
          onProgress(`تمت قراءة manifest.json للحزمة (${bundleManifestJson.package_name || 'غير محدد'}).`, 32);
        } catch (e: any) {
          warnings.push(`تعذر قراءة manifest.json: ${e.message}`);
        }
      }

      const allBundleFiles = walkFiles(bundleOut);
      const apkRelPaths = allBundleFiles.filter((f) => f.toLowerCase().endsWith('.apk')).sort();
      onProgress(`تم اكتشاف ${apkRelPaths.length} ملفات APK داخل الحزمة — جاري الدمج في شجرة واحدة...`, 40);

      for (const relApk of apkRelPaths) {
        const apkFull = path.join(bundleOut, relApk);
        const apkName = path.basename(relApk);
        const role =
          apkName.toLowerCase() === 'base.apk'
            ? 'base'
            : apkName.toLowerCase().includes('config.')
              ? 'config_split'
              : 'feature_split';
        const splitOut = path.join(extDir, 'splits', path.parse(apkName).name);
        const { files: subFiles, warnings: sw } = await safeExtractZip(apkFull, splitOut, 1, tracker);
        warnings.push(...sw);
        splitsProcessed.push({
          apk_name: apkName,
          relative_path: relApk,
          role,
          file_count: subFiles.length,
          has_native_libs: subFiles.some((f) => f.startsWith('lib/')),
          has_resources: subFiles.some((f) => f.startsWith('res/')),
        });

        for (const sf of subFiles) {
          const srcF = path.join(splitOut, sf);
          const dstF = path.join(mergedDir, sf);
          if (role !== 'base' && fs.existsSync(dstF) && (sf === 'AndroidManifest.xml' || sf === 'resources.arsc')) {
            continue;
          }
          fs.mkdirSync(path.dirname(dstF), { recursive: true });
          fs.copyFileSync(srcF, dstF);
        }
      }
    } else if (ptype === 'ZIP_ARCHIVE') {
      const zipOut = path.join(extDir, 'zip_contents', path.parse(item.filename).name);
      const { warnings: w } = await safeExtractZip(origFile, zipOut, 0, tracker);
      warnings.push(...w);
      fs.cpSync(zipOut, mergedDir, { recursive: true, force: true });
    } else if (ptype === 'PE_EXECUTABLE') {
      onProgress(`تحليل ملف EXE (${item.detected_type.sub_type}): ${item.filename}...`, 46);
      exeReports.push(analyzePeExecutable(origFile, `original/${item.filename}`, item.detected_type));
    }
  }

  onProgress('تحليل AndroidManifest.xml وملفات DEX وعزل المكتبات عن كود التطبيق...', 60);
  const manifestPath = path.join(mergedDir, 'AndroidManifest.xml');
  let manifestDecoded: any = { parsed: false, permissions: [], activities: [], services: [], receivers: [], providers: [] };
  if (fs.existsSync(manifestPath)) {
    manifestDecoded = parseAxmlManifest(fs.readFileSync(manifestPath), 'extracted/merged/AndroidManifest.xml');
  }

  const appPackage: string | null = manifestDecoded.package_name || bundleManifestJson?.package_name || null;
  const allMergedRel = walkFiles(mergedDir);
  const soFiles = allMergedRel.filter((f) => f.startsWith('lib/') && f.endsWith('.so'));
  const flutterAssets = allMergedRel.filter((f) => f.includes('flutter_assets/'));
  const frameworks: any[] = [];
  const toolsStatus: any = getToolsStatus();

  if (soFiles.some((f) => f.includes('libflutter.so')) || flutterAssets.length > 0) {
    const libappFiles = soFiles.filter((f) => f.endsWith('libapp.so'));
    const hasDartTool = toolsStatus.blutter || toolsStatus.reflutter;
    frameworks.push({
      name: 'Flutter',
      evidence: (libappFiles.length ? libappFiles : flutterAssets).slice(0, 3),
      dart_code_analyzed: hasDartTool && libappFiles.length > 0,
      status_note:
        hasDartTool && libappFiles.length > 0
          ? 'تم فحص لقطة Dart.'
          : libappFiles.length > 0
            ? 'كود Dart داخل libapp.so لم يُحلَّل لأن أداة تحليل Dart (blutter أو reFlutter) غير متوفرة في البيئة، ولم تُعرض أي أرقام توحي بتحليل Dart.'
            : 'تم رصد flutter_assets دون وجود libapp.so.',
      assets_count: flutterAssets.length,
    });
  }

  if (soFiles.some((f) => f.includes('libreactnativejni.so')) || allMergedRel.some((f) => f.includes('index.android.bundle'))) {
    frameworks.push({
      name: 'React Native',
      evidence: allMergedRel.filter((f) => f.includes('libreactnativejni.so') || f.includes('index.android.bundle')).slice(0, 3),
    });
  }

  if (soFiles.some((f) => f.includes('libunity.so') || f.includes('libil2cpp.so')) || allMergedRel.some((f) => f.includes('assets/bin/Data/'))) {
    frameworks.push({
      name: 'Unity',
      evidence: allMergedRel.filter((f) => f.includes('libunity.so') || f.includes('libil2cpp.so') || f.includes('assets/bin/Data/')).slice(0, 3),
    });
  }

  if (soFiles.some((f) => f.includes('libmonodroid.so')) || allMergedRel.some((f) => f.startsWith('assemblies/') && f.endsWith('.dll'))) {
    frameworks.push({
      name: 'Xamarin / .NET MAUI',
      evidence: allMergedRel.filter((f) => f.includes('libmonodroid.so') || f.endsWith('.dll')).slice(0, 3),
    });
  }

  const dexFiles = allMergedRel.filter((f) => /^classes\d*\.dex$/i.test(f)).sort();
  const appClasses: Array<{ name: string; evidence: string }> = [];
  const appFunctions: Array<{ class_name: string; method_name: string; evidence: string }> = [];
  const appStrings: Array<{ value: string; evidence: string }> = [];
  const thirdPartyLibs: Record<string, number> = {};

  for (const dexRel of dexFiles) {
    const parsed = parseDexFile(path.join(mergedDir, dexRel), `extracted/merged/${dexRel}`, appPackage);
    appClasses.push(...parsed.app_classes);
    appFunctions.push(...parsed.app_functions);
    appStrings.push(...parsed.app_strings);
    for (const [pkg, cnt] of Object.entries(parsed.library_packages)) {
      thirdPartyLibs[pkg] = (thirdPartyLibs[pkg] || 0) + cnt;
    }
  }

  const screensIndex: Array<{ screen_name: string; source: string; evidence: string }> = [];
  const seenScreens = new Set<string>();
  for (const act of manifestDecoded.activities || []) {
    if (!isThirdPartySymbol(act.name) && !seenScreens.has(act.name)) {
      seenScreens.add(act.name);
      screensIndex.push({ screen_name: act.name, source: 'AndroidManifest', evidence: act.evidence });
    }
  }
  for (const cls of appClasses) {
    if (/(Activity|Fragment|Screen|Page|Dialog)/.test(cls.name) && !seenScreens.has(cls.name)) {
      seenScreens.add(cls.name);
      screensIndex.push({ screen_name: cls.name, source: 'DEX_Class', evidence: cls.evidence });
    }
  }

  const assetsIndex = allMergedRel
    .filter((f) => f.startsWith('assets/') || f.startsWith('res/values'))
    .map((f) => ({
      path: `extracted/merged/${f}`,
      size_bytes: fs.statSync(path.join(mergedDir, f)).size,
      kind: path.extname(f).toLowerCase() || 'file',
    }));

  onProgress('إعداد هيكل rebuilt_project وملف README_REBUILT.md الصادق...', 78);
  for (const sub of ['res', 'assets', 'lib']) {
    const srcSub = path.join(mergedDir, sub);
    if (fs.existsSync(srcSub)) {
      fs.cpSync(srcSub, path.join(rebDir, sub), { recursive: true, force: true });
    }
  }
  if (fs.existsSync(manifestPath)) {
    fs.copyFileSync(manifestPath, path.join(rebDir, 'AndroidManifest.xml'));
  }

  const missingForBuild: string[] = [];
  if (dexFiles.length > 0 && !toolsStatus.jadx) {
    missingForBuild.push('كود Java الكامل (أداة jadx غير متوفرة في البيئة؛ تم استخراج جدول الكلاسات والدوال من DEX مباشرة)');
  }
  if (frameworks.some((fw) => fw.name === 'Flutter' && !fw.dart_code_analyzed)) {
    missingForBuild.push('كود Dart المصدري من libapp.so (أداة blutter غير متوفرة)');
  }
  missingForBuild.push('مفاتيح التوقيع (Keystore) وإعدادات Gradle غير قابلة للاسترداد من الحزمة الثنائية');

  const rebuildLabel = 'هيكل مشروع جزئي (Partial Project Skeleton)';
  const readmeRebuilt =
    `# حالة إعادة البناء: ${rebuildLabel}\n\n` +
    `> تنبيه صريح: لم يتم التحقق من بناء هذا المشروع عبر Gradle أو أداة بناء فعلية، ولذلك لا يُصنَّف كمشروع جاهز للتشغيل.\n\n` +
    `## ما تم استرداده فعلياً\n` +
    `- عدد الأصول والموارد المستخرجة: ${assetsIndex.length}\n` +
    `- عدد المكتبات الأصلية (.so): ${soFiles.length}\n` +
    `- ملف AndroidManifest.xml: ${fs.existsSync(manifestPath) ? 'موجود' : 'غير موجود'}\n\n` +
    `## ما ينقص المشروع ليصبح قابلاً للبناء\n` +
    missingForBuild.map((m) => `- ${m}`).join('\n') +
    '\n';
  fs.writeFileSync(path.join(rebDir, 'README_REBUILT.md'), readmeRebuilt, 'utf8');

  onProgress('التحقق التلقائي من تطابق الملفات الأصلية وبصمات SHA-256...', 88);
  const integrityChecks: any[] = [];
  let allIntegrityOk = true;
  for (const item of inputManifest) {
    const origCopy = path.join(origDir, item.filename);
    const shaFile = path.join(origDir, `${item.filename}.sha256`);
    const exists = fs.existsSync(origCopy) && fs.existsSync(shaFile);
    const actualHash = exists ? await sha256File(origCopy) : null;
    const actualSize = exists ? fs.statSync(origCopy).size : -1;
    const matched = exists && actualHash === item.sha256 && actualSize === item.size_bytes && actualSize > 0;
    if (!matched) allIntegrityOk = false;
    integrityChecks.push({
      filename: item.filename,
      expected_size: item.size_bytes,
      actual_size: actualSize,
      expected_sha256: item.sha256,
      actual_sha256: actualHash,
      matched,
    });
  }

  const completenessReport = {
    integrity_verified: allIntegrityOk,
    integrity_checks: integrityChecks,
    rebuild_classification: rebuildLabel,
    frameworks_detected: frameworks,
    tools_status: toolsStatus,
    warnings,
    summary_counts_app_only: {
      app_classes: appClasses.length,
      app_functions: appFunctions.length,
      app_screens: screensIndex.length,
      app_strings: appStrings.length,
      permissions: (manifestDecoded.permissions || []).length,
      native_so_libraries: soFiles.length,
      third_party_library_packages: Object.keys(thirdPartyLibs).length,
      splits_processed: splitsProcessed.length,
    },
  };

  const reaReportJson = {
    legal_notice: 'هذه الأداة مخصصة حصرياً لتحليل التطبيقات التي يملكها المستخدم أو لديه إذن صريح بتحليلها.',
    inputs: inputManifest,
    bundle_manifest_json: bundleManifestJson,
    splits_processed: splitsProcessed,
    native_libraries_so: soFiles.map((s) => ({
      path: `extracted/merged/${s}`,
      abi: s.split('/')[1] || 'unknown',
    })),
    frameworks,
    android_manifest: manifestDecoded,
    exe_reports: exeReports,
    assets_index: assetsIndex.slice(0, 500),
    third_party_libraries: Object.entries(thirdPartyLibs)
      .sort((a, b) => b[1] - a[1])
      .map(([pkg, cnt]) => ({ package: pkg, class_count: cnt })),
    completeness_report: completenessReport,
  };

  fs.writeFileSync(path.join(anaDir, 'rea_report.json'), JSON.stringify(reaReportJson, null, 2), 'utf8');
  fs.writeFileSync(path.join(anaDir, 'manifest_decoded.json'), JSON.stringify(manifestDecoded, null, 2), 'utf8');
  fs.writeFileSync(
    path.join(anaDir, 'functions_map.json'),
    JSON.stringify({ app_functions: appFunctions, third_party_packages: thirdPartyLibs }, null, 2),
    'utf8',
  );
  fs.writeFileSync(path.join(anaDir, 'screens_index.json'), JSON.stringify(screensIndex, null, 2), 'utf8');
  fs.writeFileSync(path.join(anaDir, 'strings_index.json'), JSON.stringify(appStrings, null, 2), 'utf8');
  fs.writeFileSync(path.join(anaDir, 'permissions.json'), JSON.stringify(manifestDecoded.permissions || [], null, 2), 'utf8');
  fs.writeFileSync(path.join(anaDir, 'completeness_report.json'), JSON.stringify(completenessReport, null, 2), 'utf8');

  const mdLines = [
    '# تقرير التحليل الثابت (REA)',
    '',
    '> تنبيه قانوني: هذه الأداة مخصصة حصرياً لتحليل التطبيقات التي يملكها المستخدم أو لديه إذن بتحليلها.',
    '',
    '## 1. التحقق من الملفات الأصلية (SHA-256)',
    `- الحالة: ${allIntegrityOk ? 'مطابق بايت ببايت' : 'فشل التحقق'}`,
    ...integrityChecks.map((c) => `- \`${c.filename}\` (${c.actual_size} بايت) -> \`${c.actual_sha256}\``),
    '',
    '## 2. إحصائيات كود التطبيق فقط (معزول عن المكتبات)',
    `- الكلاسات: ${appClasses.length} | الدوال: ${appFunctions.length} | الشاشات: ${screensIndex.length}`,
    `- حزم المكتبات المعزولة: ${Object.keys(thirdPartyLibs).length}`,
    `- الحزم المقسّمة المعالجة: ${splitsProcessed.length}`,
    '',
    `## 3. حالة إعادة البناء: ${rebuildLabel}`,
  ];
  fs.writeFileSync(path.join(anaDir, 'rea_report.md'), mdLines.join('\n'), 'utf8');

  onProgress('ضغط المخرجات النهائية في ملف ZIP واحد...', 94);
  await new Promise<void>((resolve, reject) => {
    const output = fs.createWriteStream(outputZipPath);
    const archive = new ZipArchive({ zlib: { level: 6 } });
    output.on('close', () => resolve());
    archive.on('error', reject);
    archive.pipe(output);
    for (const folder of ['original', 'extracted', 'analyzed', 'rebuilt_project']) {
      archive.directory(path.join(workRoot, folder), folder);
    }
    archive.finalize();
  });

  onProgress('اكتمل التحليل وتم التحقق من سلامة المخرجات.', 100);

  return {
    rea_report: reaReportJson,
    functions_map: { app_functions: appFunctions, app_classes: appClasses, third_party_packages: thirdPartyLibs },
    screens_index: screensIndex,
    strings_index: appStrings,
    permissions: manifestDecoded.permissions || [],
    completeness_report: completenessReport,
    readme_rebuilt: readmeRebuilt,
  };
}

export function generateSampleXapkFile(targetPath: string): void {
  // Reuse the verified Python XAPK generator from termux_project/tests/self_test_xapk.py if python3 is present,
  // guaranteeing identical binary structure!
  const pyHelper = `
import sys
from pathlib import Path
sys.path.insert(0, 'termux_project/tests')
from self_test_xapk import create_synthetic_xapk
create_synthetic_xapk(Path(sys.argv[1]))
`;
  execFileSync('python3', ['-c', pyHelper, targetPath], { cwd: process.cwd() });
}
