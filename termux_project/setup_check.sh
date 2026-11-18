#!/data/data/com.termux/files/usr/bin/bash
set -u

echo "=========================================="
echo "فحص بيئة التشغيل على Termux — مختبر REA"
echo "=========================================="
echo ""

MISSING_REQUIRED=0
MISSING_OPTIONAL=0

check_cmd() {
  local cmd="$1"
  local label="$2"
  local required="$3"
  local hint="$4"

  if command -v "$cmd" >/dev/null 2>&1; then
    local ver
    ver="$($cmd --version 2>&1 | head -n 1 || echo 'متوفر')"
    echo "[متوفر] $label ($cmd) -> $ver"
  else
    if [ "$required" = "yes" ]; then
      echo "[مفقود - مطلوب] $label ($cmd)"
      echo "   للتثبيت: $hint"
      MISSING_REQUIRED=$((MISSING_REQUIRED + 1))
    else
      echo "[مفقود - اختياري] $label ($cmd)"
      echo "   ملاحظة: سيتعطل الجزء الخاص بهذه الأداة فقط مع تحذير واضح ويكمل الباقي."
      echo "   للتثبيت: $hint"
      MISSING_OPTIONAL=$((MISSING_OPTIONAL + 1))
    fi
  fi
}

check_cmd "python" "Python 3" "yes" "pkg install -y python"
check_cmd "pip" "Python pip" "yes" "pkg install -y python-pip"
check_cmd "node" "Node.js" "yes" "pkg install -y nodejs-lts"
check_cmd "npm" "npm" "yes" "pkg install -y nodejs-lts"
check_cmd "java" "OpenJDK (Java)" "no" "pkg install -y openjdk-17"
check_cmd "7z" "p7zip (7z)" "no" "pkg install -y p7zip"
check_cmd "unzip" "unzip" "no" "pkg install -y unzip"
check_cmd "apktool" "Apktool" "no" "تثبيت يدوي عبر apktool.jar + wrapper في \$PREFIX/bin/apktool"
check_cmd "jadx" "JADX Decompiler" "no" "تنزيل إصدار jadx من GitHub وإضافة bin إلى PATH"
check_cmd "blutter" "Blutter (Dart/Flutter)" "no" "يتطلب بناء يدوي لبيئة Dart AOT (اختياري)"
check_cmd "ilspycmd" "ILSpyCmd (.NET)" "no" "dotnet tool install -g ilspycmd (غير متوفر أصلاً على معظم أجهزة ARM Termux)"

echo ""
echo "--- فحص حزم Python ---"
python -c "import fastapi, uvicorn, multipart, pefile; print('[متوفر] جميع حزم Python المطلوبة (fastapi, uvicorn, python-multipart, pefile)')" 2>/dev/null || {
  echo "[مفقود - مطلوب] بعض حزم Python غير مثبتة"
  echo "   للتثبيت: pip install -r requirements.txt"
  MISSING_REQUIRED=$((MISSING_REQUIRED + 1))
}

echo ""
echo "--- فحص REA (morluto/rea) ---"
if command -v rea >/dev/null 2>&1 || npx --no-install rea-agents --version >/dev/null 2>&1; then
  echo "[متوفر] rea-agents"
else
  echo "[مفقود - موصى به] rea-agents غير مثبت عالمياً أو محلياً"
  echo "   للتثبيت: npm install -g rea-agents"
  MISSING_OPTIONAL=$((MISSING_OPTIONAL + 1))
fi

echo ""
echo "=========================================="
echo "ملخص الفحص:"
echo "  عناصر مطلوبة مفقودة : $MISSING_REQUIRED"
echo "  أدوات اختيارية مفقودة: $MISSING_OPTIONAL"
echo "=========================================="

if [ "$MISSING_REQUIRED" -gt 0 ]; then
  echo "يرجى تثبيت العناصر المطلوبة أولاً قبل تشغيل الخادم."
  exit 1
fi

echo "البيئة جاهزة لتشغيل الخادم المحلي: python app.py"
exit 0
