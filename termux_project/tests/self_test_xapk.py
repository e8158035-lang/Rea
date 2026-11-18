#!/usr/bin/env python3
"""
Self-test verifying Clauses 2 (Split APK/XAPK handling), 5 (App vs Library separation
& evidence-backed precision), and 6 (Byte-for-byte original preservation & SHA-256).
"""

from __future__ import annotations

import hashlib
import io
import json
import shutil
import struct
import sys
import tempfile
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from analyzer_core import run_analysis_pipeline  # noqa: E402


def _uleb128(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)


def build_minimal_dex(strings: list[str], type_indices: list[int], class_type_indices: list[int], methods: list[tuple[int, int]]) -> bytes:
    """Builds a minimal valid Dalvik DEX binary with real string_ids, type_ids, method_ids, and class_defs."""
    header_size = 112
    # Encode string data items
    str_data_chunks = []
    for s in strings:
        enc = s.encode("utf-8")
        str_data_chunks.append(_uleb128(len(s)) + enc + b"\x00")

    string_ids_off = header_size
    string_ids_bytes_len = len(strings) * 4
    type_ids_off = string_ids_off + string_ids_bytes_len
    type_ids_bytes_len = len(type_indices) * 4
    method_ids_off = type_ids_off + type_ids_bytes_len
    method_ids_bytes_len = len(methods) * 8
    class_defs_off = method_ids_off + method_ids_bytes_len
    class_defs_bytes_len = len(class_type_indices) * 32
    data_off = class_defs_off + class_defs_bytes_len

    # Compute string offsets
    cur = data_off
    str_offsets = []
    for ch in str_data_chunks:
        str_offsets.append(cur)
        cur += len(ch)

    buf = bytearray(cur)
    # DEX header
    buf[0:8] = b"dex\n035\x00"
    struct.pack_into("<I", buf, 32, cur)  # file_size
    struct.pack_into("<I", buf, 36, header_size)
    struct.pack_into("<I", buf, 40, 0x12345678)  # endian_tag
    struct.pack_into("<IIIIIIIIIIII", buf, 56,
                     len(strings), string_ids_off,
                     len(type_indices), type_ids_off,
                     0, 0,
                     0, 0,
                     len(methods), method_ids_off,
                     len(class_type_indices), class_defs_off)

    for idx, off in enumerate(str_offsets):
        struct.pack_into("<I", buf, string_ids_off + idx * 4, off)
    for idx, s_idx in enumerate(type_indices):
        struct.pack_into("<I", buf, type_ids_off + idx * 4, s_idx)
    for idx, (cls_idx, name_idx) in enumerate(methods):
        struct.pack_into("<HHI", buf, method_ids_off + idx * 8, cls_idx, 0, name_idx)
    for idx, cls_idx in enumerate(class_type_indices):
        struct.pack_into("<I", buf, class_defs_off + idx * 32, cls_idx)
    for off, ch in zip(str_offsets, str_data_chunks):
        buf[off : off + len(ch)] = ch
    return bytes(buf)


def create_synthetic_xapk(target_path: Path) -> None:
    dex_strings = [
        "Lcom/acme/shopapp/MainActivity;",
        "Lcom/acme/shopapp/CheckoutScreen;",
        "Landroidx/appcompat/app/AppCompatActivity;",
        "Lokhttp3/OkHttpClient;",
        "onCreate",
        "submitOrder",
        "تنفيذ الدفع الآمن",
        "عنوان التوصيل الرئيسي",
    ]
    # Types: 0..3
    # Classes: 0 (MainActivity), 1 (CheckoutScreen), 2 (AppCompatActivity), 3 (OkHttpClient)
    dex_bytes = build_minimal_dex(
        strings=dex_strings,
        type_indices=[0, 1, 2, 3],
        class_type_indices=[0, 1, 2, 3],
        methods=[(0, 4), (1, 5), (2, 4)],
    )

    plain_manifest = (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.acme.shopapp">'
        '<uses-permission android:name="android.permission.INTERNET" />'
        '<application><activity android:name="com.acme.shopapp.MainActivity" /></application>'
        '</manifest>'
    ).encode("utf-8")

    # 1. base.apk
    base_buf = io.BytesIO()
    with zipfile.ZipFile(base_buf, "w") as zbase:
        zbase.writestr("AndroidManifest.xml", plain_manifest)
        zbase.writestr("classes.dex", dex_bytes)
        zbase.writestr("assets/flutter_assets/locales/ar.json", json.dumps({"welcome": "مرحباً بكم"}, ensure_ascii=False))
        zbase.writestr("res/values/strings.xml", "<resources><string name='app_name'>AcmeShop</string></resources>")

    # 2. config.arm64_v8a.apk (native Flutter libs)
    arm_buf = io.BytesIO()
    with zipfile.ZipFile(arm_buf, "w") as zarm:
        zarm.writestr("lib/arm64-v8a/libflutter.so", b"\x7fELF_FAKE_FLUTTER_LIB")
        zarm.writestr("lib/arm64-v8a/libapp.so", b"\x7fELF_FAKE_DART_APP_SNAPSHOT")

    # 3. config.en.apk (locale split resources)
    en_buf = io.BytesIO()
    with zipfile.ZipFile(en_buf, "w") as zen:
        zen.writestr("res/values-en/strings.xml", "<resources><string name='app_name'>AcmeShop EN</string></resources>")

    # Pack XAPK
    xapk_manifest = {
        "xapk_version": 2,
        "package_name": "com.acme.shopapp",
        "name": "AcmeShop Test",
        "version_code": "104",
        "split_apks": [
            {"file": "base.apk", "id": "base"},
            {"file": "config.arm64_v8a.apk", "id": "config.arm64_v8a"},
            {"file": "config.en.apk", "id": "config.en"},
        ],
    }

    with zipfile.ZipFile(target_path, "w") as zx:
        zx.writestr("manifest.json", json.dumps(xapk_manifest, ensure_ascii=False, indent=2))
        zx.writestr("base.apk", base_buf.getvalue())
        zx.writestr("config.arm64_v8a.apk", arm_buf.getvalue())
        zx.writestr("config.en.apk", en_buf.getvalue())


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="rea_xapk_selftest_"))
    try:
        xapk_path = tmp / "acme_shop_test.xapk"
        create_synthetic_xapk(xapk_path)
        expected_hash = hashlib.sha256(xapk_path.read_bytes()).hexdigest()
        expected_size = xapk_path.stat().st_size

        out_zip = tmp / "out.zip"
        result = run_analysis_pipeline([xapk_path], out_zip, tmp / "work")

        rep = result["rea_report"]
        comp = result["completeness_report"]
        funcs = result["functions_map"]
        screens = result["screens_index"]

        # Clause 2 assertions: all 3 splits processed, lib/*.so extracted, res merged, manifest.json read
        assert len(rep["splits_processed"]) == 3, f"Expected 3 splits, got {len(rep['splits_processed'])}"
        so_paths = [x["path"] for x in rep["native_libraries_so"]]
        assert any("lib/arm64-v8a/libapp.so" in p for p in so_paths), "Missing libapp.so from config.arm64_v8a.apk"
        assert any("lib/arm64-v8a/libflutter.so" in p for p in so_paths), "Missing libflutter.so from config.arm64_v8a.apk"
        assert rep["bundle_manifest_json"]["package_name"] == "com.acme.shopapp", "manifest.json not parsed"

        # Verify ZIP contents include merged split resources and required top-level dirs
        with zipfile.ZipFile(out_zip, "r") as zout:
            names = set(zout.namelist())
            assert "extracted/merged/res/values-en/strings.xml" in names, "Missing merged config.en resource"
            assert "extracted/merged/lib/arm64-v8a/libapp.so" in names, "Missing merged libapp.so"
            assert "analyzed/rea_report.md" in names
            assert "analyzed/rea_report.json" in names
            assert "analyzed/completeness_report.json" in names
            assert "rebuilt_project/README_REBUILT.md" in names
            assert f"original/{xapk_path.name}" in names
            assert f"original/{xapk_path.name}.sha256" in names
            orig_bytes_in_zip = zout.read(f"original/{xapk_path.name}")
            assert hashlib.sha256(orig_bytes_in_zip).hexdigest() == expected_hash, "ZIP original/ SHA-256 mismatch!"
            assert len(orig_bytes_in_zip) == expected_size, "ZIP original/ size mismatch!"

        # Clause 5 assertions: strict app vs third-party separation + evidence on every item
        app_func_names = {f"{f['class_name']}.{f['method_name']}" for f in funcs["app_functions"]}
        assert "com.acme.shopapp.MainActivity.onCreate" in app_func_names
        assert "com.acme.shopapp.CheckoutScreen.submitOrder" in app_func_names
        assert all("androidx" not in f["class_name"] for f in funcs["app_functions"]), "Library class leaked into app functions!"
        assert "androidx.appcompat.app" in funcs["third_party_packages"], "androidx not separated into third_party_packages"
        assert all(f.get("evidence") for f in funcs["app_functions"]), "Missing evidence on app_functions"
        assert all(s.get("evidence") for s in screens), "Missing evidence on screens"

        # Honest Flutter limitation reporting when blutter is absent
        flutter_fw = next((fw for fw in rep["frameworks"] if fw["name"] == "Flutter"), None)
        assert flutter_fw is not None, "Flutter framework not detected"

        # Clause 6 assertions: integrity verification
        assert comp["integrity_verified"] is True, "Integrity verification failed!"

        print("[PASS] اجتاز الاختبار الذاتي لـ XAPK جميع شروط البنود (2 و5 و6) بنجاح.")
        print(f"  - الحزم المقسّمة المعالجة: {len(rep['splits_processed'])}")
        print(f"  - دوال التطبيق فقط: {len(funcs['app_functions'])} | حزم المكتبات المعزولة: {len(funcs['third_party_packages'])}")
        print(f"  - تطابق SHA-256 للأصل: {expected_hash}")
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
