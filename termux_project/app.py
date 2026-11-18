#!/usr/bin/env python3
"""
FastAPI local server for Termux (127.0.0.1:5000) supporting streaming multi-file
uploads (500MB+ without loading into RAM), real-time SSE logs, and ZIP export.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
import tempfile
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List

import uvicorn
from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, StreamingResponse

from analyzer_core import run_analysis_pipeline

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
JOBS_ROOT = Path(tempfile.gettempdir()) / "rea_termux_jobs"
JOBS_ROOT.mkdir(parents=True, exist_ok=True)

app = FastAPI(title="مختبر التحليل الثابت REA — Termux")

JOBS: Dict[str, Dict[str, Any]] = {}
JOBS_LOCK = threading.Lock()
UPLOAD_SESSIONS: Dict[str, Dict[str, Any]] = {}


def _append_log(job_id: str, msg: str, pct: int) -> None:
    ts = time.strftime("%H:%M:%S")
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            return
        job["progress"] = pct
        job["logs"].append({"ts": ts, "message": msg, "progress": pct})


def _worker_run(job_id: str, input_paths: List[Path], work_dir: Path, out_zip: Path) -> None:
    try:
        result = run_analysis_pipeline(
            input_files=input_paths,
            output_zip_path=out_zip,
            work_root=work_dir / "bundle",
            log_cb=lambda m, p: _append_log(job_id, m, p),
        )
        with JOBS_LOCK:
            JOBS[job_id]["status"] = "completed"
            JOBS[job_id]["progress"] = 100
            JOBS[job_id]["result"] = result
            JOBS[job_id]["output_zip"] = str(out_zip)
    except Exception as exc:
        _append_log(job_id, f"خطأ أثناء التحليل: {exc}", 100)
        with JOBS_LOCK:
            JOBS[job_id]["status"] = "failed"
            JOBS[job_id]["error"] = str(exc)
    finally:
        # Clean temporary unpacked workspace and raw uploaded staging files while keeping final output ZIP
        for cleanup_dir in (work_dir / "uploads", work_dir / "bundle"):
            if cleanup_dir.exists():
                shutil.rmtree(cleanup_dir, ignore_errors=True)


@app.get("/", response_class=HTMLResponse)
def index() -> HTMLResponse:
    idx = STATIC_DIR / "index.html"
    if not idx.exists():
        return HTMLResponse("<h1>واجهة التحليل غير موجودة في static/index.html</h1>", status_code=404)
    return HTMLResponse(idx.read_text(encoding="utf-8"))


@app.get("/api/tools/status")
def tools_status() -> JSONResponse:
    tools = {}
    for cmd in ("python", "node", "npm", "java", "apktool", "jadx", "blutter", "reflutter", "ilspycmd", "7z", "unzip"):
        tools[cmd] = bool(shutil.which(cmd))
    rea_info = {"available": False, "reason": "غير مفحوص"}
    bridge = BASE_DIR / "rea_bridge.mjs"
    if shutil.which("node") and bridge.exists():
        try:
            proc = subprocess.run(["node", str(bridge), "doctor"], capture_output=True, text=True, timeout=15)
            rea_info = json.loads(proc.stdout.strip() or "{}")
        except Exception as exc:
            rea_info = {"available": False, "reason": str(exc)}
    return JSONResponse({"tools": tools, "rea": rea_info})


@app.post("/api/uploads/init")
def init_upload() -> JSONResponse:
    upload_id = uuid.uuid4().hex[:12]
    work_dir = JOBS_ROOT / upload_id
    upload_dir = work_dir / "uploads"
    upload_dir.mkdir(parents=True, exist_ok=True)
    with JOBS_LOCK:
        UPLOAD_SESSIONS[upload_id] = {"work_dir": work_dir, "upload_dir": upload_dir, "files": []}
    return JSONResponse({"upload_id": upload_id})


@app.post("/api/uploads/{upload_id}/chunk")
async def upload_chunk(upload_id: str, request: Request, filename: str = "upload.bin", chunkIndex: int = 0) -> JSONResponse:
    with JOBS_LOCK:
        sess = UPLOAD_SESSIONS.get(upload_id)
    if not sess:
        raise HTTPException(status_code=404, detail="جلسة الرفع غير موجودة.")
    safe_name = Path(filename).name
    dest = sess["upload_dir"] / safe_name
    mode = "wb" if chunkIndex == 0 else "ab"
    received = 0
    with dest.open(mode) as out_f:
        async for chunk in request.stream():
            out_f.write(chunk)
            received += len(chunk)
    with JOBS_LOCK:
        if dest not in sess["files"]:
            sess["files"].append(dest)
    return JSONResponse({"ok": True, "filename": safe_name, "chunkIndex": chunkIndex, "bytesReceived": received})


@app.post("/api/uploads/{upload_id}/commit")
def commit_upload(upload_id: str) -> JSONResponse:
    with JOBS_LOCK:
        sess = UPLOAD_SESSIONS.pop(upload_id, None)
    if not sess:
        raise HTTPException(status_code=404, detail="جلسة الرفع غير موجودة.")
    saved_paths = [p for p in sess["files"] if p.exists()]
    if not saved_paths:
        raise HTTPException(status_code=400, detail="لم يتم استلام أي ملفات.")
    work_dir = sess["work_dir"]
    out_zip = work_dir / f"rea_analysis_{upload_id}.zip"
    logs = [
        {"ts": time.strftime("%H:%M:%S"), "message": f"تم استلام الملف: {p.name} ({p.stat().st_size} بايت)", "progress": 4}
        for p in saved_paths
    ]
    with JOBS_LOCK:
        JOBS[upload_id] = {
            "id": upload_id,
            "status": "running",
            "progress": 4,
            "logs": logs,
            "result": None,
            "output_zip": None,
            "error": None,
        }
    t = threading.Thread(target=_worker_run, args=(upload_id, saved_paths, work_dir, out_zip), daemon=True)
    t.start()
    return JSONResponse({"job_id": upload_id})


@app.post("/api/analyze")
async def analyze_upload(files: List[UploadFile] = File(...)) -> JSONResponse:
    if not files:
        raise HTTPException(status_code=400, detail="يرجى رفع ملف واحد على الأقل.")

    job_id = uuid.uuid4().hex[:12]
    work_dir = JOBS_ROOT / job_id
    upload_dir = work_dir / "uploads"
    upload_dir.mkdir(parents=True, exist_ok=True)
    out_zip = work_dir / f"rea_analysis_{job_id}.zip"

    with JOBS_LOCK:
        JOBS[job_id] = {
            "id": job_id,
            "status": "running",
            "progress": 1,
            "logs": [{"ts": time.strftime("%H:%M:%S"), "message": "استلام الملفات عبر الرفع المتدفق على القرص...", "progress": 1}],
            "result": None,
            "output_zip": None,
            "error": None,
        }

    saved_paths: List[Path] = []
    for uf in files:
        safe_name = Path(uf.filename or "uploaded_file.bin").name
        dest = upload_dir / safe_name
        # Stream directly to disk in 1MB chunks without holding full 500MB+ file in memory
        with dest.open("wb") as out_f:
            while True:
                chunk = await uf.read(1024 * 1024)
                if not chunk:
                    break
                out_f.write(chunk)
        await uf.close()
        saved_paths.append(dest)
        _append_log(job_id, f"تم حفظ الملف على القرص: {safe_name} ({dest.stat().st_size} بايت)", 4)

    t = threading.Thread(target=_worker_run, args=(job_id, saved_paths, work_dir, out_zip), daemon=True)
    t.start()
    return JSONResponse({"job_id": job_id})


@app.get("/api/jobs/{job_id}/events")
async def job_events(job_id: str) -> StreamingResponse:
    async def event_gen():
        last_idx = 0
        while True:
            with JOBS_LOCK:
                job = JOBS.get(job_id)
                if not job:
                    yield f"data: {json.dumps({'error': 'المهمة غير موجودة'}, ensure_ascii=False)}\n\n"
                    return
                logs = job["logs"][last_idx:]
                last_idx += len(logs)
                status = job["status"]
                progress = job["progress"]
            for entry in logs:
                yield f"data: {json.dumps({'type': 'log', 'entry': entry, 'status': status, 'progress': progress}, ensure_ascii=False)}\n\n"
            if status in ("completed", "failed"):
                yield f"data: {json.dumps({'type': 'done', 'status': status, 'progress': progress}, ensure_ascii=False)}\n\n"
                return
            await asyncio.sleep(0.35)

    return StreamingResponse(event_gen(), media_type="text/event-stream")


@app.get("/api/jobs/{job_id}")
def get_job(job_id: str) -> JSONResponse:
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="المهمة غير موجودة.")
        return JSONResponse(job)


@app.get("/api/jobs/{job_id}/download")
def download_job_zip(job_id: str) -> FileResponse:
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job or not job.get("output_zip"):
            raise HTTPException(status_code=404, detail="ملف النتائج غير جاهز.")
        zip_path = Path(job["output_zip"])
    if not zip_path.exists():
        raise HTTPException(status_code=404, detail="ملف ZIP غير موجود.")
    return FileResponse(str(zip_path), filename=f"rea_output_{job_id}.zip", media_type="application/zip")


if __name__ == "__main__":
    host = os.environ.get("REA_HOST", "127.0.0.1")
    port = int(os.environ.get("REA_PORT", "5000"))
    print(f"تشغيل مختبر REA المحلي على: http://{host}:{port}")
    uvicorn.run(app, host=host, port=port, log_level="info")
