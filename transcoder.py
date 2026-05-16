import os
import re
import shutil
import subprocess
import modal
import time
import requests
import secrets
import json
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from fastapi import BackgroundTasks

DEBUG = True

def natural_sort_key(s):
    """Sort strings containing numbers numerically."""
    return [int(text) if text.isdigit() else text.lower() 
            for text in re.split(r'(\d+)', s)]

app = modal.App("storva-smart-transcoder")

# بناء البيئة مع كافة الاعتمادات اللازمة
image = (
    modal.Image.debian_slim()
    .apt_install("curl", "xz-utils", "ca-certificates", "libva2", "libva-drm2")
    # 1. Install LATEST Git-Master FFmpeg (v7.1+)
    .run_commands(
        "curl -L https://johnvansickle.com/ffmpeg/builds/ffmpeg-git-amd64-static.tar.xz -o /tmp/ffmpeg.tar.xz",
        "tar -xJf /tmp/ffmpeg.tar.xz -C /tmp",
        "mv /tmp/ffmpeg-git-*-amd64-static/ffmpeg /usr/local/bin/ffmpeg",
        "mv /tmp/ffmpeg-git-*-amd64-static/ffprobe /usr/local/bin/ffprobe",
        "chmod +x /usr/local/bin/ffmpeg /usr/local/bin/ffprobe",
        "rm -rf /tmp/ffmpeg*"
    )
    # 2. Install Static Shaka Packager
    .run_commands(
        "curl -L https://github.com/shaka-project/shaka-packager/releases/download/v3.7.0/packager-linux-x64 -o /usr/local/bin/packager",
        "chmod +x /usr/local/bin/packager"
    )
    # 3. Install Python Dependencies
    .pip_install("shaka-streamer", "boto3", "requests", "fastapi[standard]")
)

r2_secret = modal.Secret.from_name("r2-storage")

@app.function(
    image=image,
    secrets=[r2_secret],
    timeout=14400,
    cpu=14.0, # قوة عالية للمعالجة المتوازية
    memory=16384,
    scaledown_window=5
)
@modal.fastapi_endpoint(method="POST")
def process_video(data: dict, background_tasks: BackgroundTasks):
    background_tasks.add_task(run_transcoding, data)
    return {"status": "accepted"}

def run_transcoding(data: dict):
    from streamer.controller_node import ControllerNode

    start_time = time.perf_counter()
    import boto3
    from botocore.config import Config

    video_id = data.get("video_id")
    file_key = data.get("file_key")
    callback_url = data.get("callback_url")
    license_url = data.get("license_url", "").strip()
    
    if not video_id or not file_key:
        raise ValueError("Missing required fields: video_id and file_key are required")

    drm_key = secrets.token_hex(16)
    drm_kid = secrets.token_hex(16)

    s3 = boto3.client("s3", endpoint_url=os.environ["R2_ENDPOINT"],
                      aws_access_key_id=os.environ["R2_ACCESS_ID"],
                      aws_secret_access_key=os.environ["R2_SECRET_KEY"],
                      config=Config(signature_version="s3v4", max_pool_connections=100))
    bucket = os.environ["R2_BUCKET"]
    
    local_source = Path(f"/tmp/{video_id}_source.mp4")
    local_work_dir = Path(f"/tmp/{video_id}")
    local_output_dir = local_work_dir / "hls_out"
    local_output_dir.mkdir(parents=True, exist_ok=True)

    try:
        # 1. تحميل الملف الأصلي للتحليل والمعالجة
        print(f"[*] Downloading source video: {file_key}")
        s3.download_file(bucket, file_key, str(local_source))
        
        # 2. تحليل الأبعاد والـ Frame Rate لتحديد الجودات تلقائياً (Orientation & FPS Logic)
        probe_cmd = [
            "ffprobe", "-v", "error", 
            "-select_streams", "v:0", 
            "-show_entries", "stream=width,height,avg_frame_rate", 
            "-of", "json", str(local_source)
        ]
        probe_res = json.loads(subprocess.check_output(probe_cmd).decode())
        
        s = probe_res['streams'][0]
        src_width = s['width']
        src_height = s['height']
        
        # تحويل "30/1" أو "29.97/1" إلى رقم عشري 30.0
        try:
            fr_num, fr_den = s['avg_frame_rate'].split('/')
            src_fps = float(fr_num) / float(fr_den) if float(fr_den) != 0 else 30.0
        except (ValueError, ZeroDivisionError):
            src_fps = 30.0

        # التحقق من وجود صوت
        probe_audio = ["ffprobe", "-v", "error", "-select_streams", "a:0", "-show_entries", "stream=index", "-of", "json", str(local_source)]
        has_audio = len(json.loads(subprocess.check_output(probe_audio).decode()).get('streams', [])) > 0

        is_portrait = src_height > src_width
        reference_dim = src_width if is_portrait else src_height
        
        # اختيار أفضل 3 جودات لا تزيد عن جودة المصدر
        all_q = [
            {"name": "1080p", "val": 1080},
            {"name": "720p", "val": 720},
            {"name": "480p", "val": 480},
            {"name": "360p", "val": 360}
        ]
        target_resolutions = [q['name'] for q in all_q if q['val'] <= reference_dim][:3]
        if not target_resolutions: target_resolutions = ["360p"]

        # 3. إعداد محرك Shaka Streamer باستخدام القواميس الخام (Raw Dictionaries)
        print(f"[*] Initializing Shaka Streamer for {target_resolutions} at {round(src_fps, 2)} FPS...")
        
        # ربط الارتفاع بمسمى جودة متوافق مع Shaka
        input_res = "360p" if src_height < 480 else "720p"
        if src_height >= 1080: input_res = "1080p"

        # تعريف خريطة الـ Bitrate يدوياً (Source of Truth)
        bitrate_config_dict = {
            'video_resolutions': {
                '1080p': {'max_width': 1920, 'max_height': 1080, 'bitrates': {'h264': '8M'}},
                '720p':  {'max_width': 1280, 'max_height': 720,  'bitrates': {'h264': '4M'}},
                '480p':  {'max_width': 854,  'max_height': 480,  'bitrates': {'h264': '2M'}},
                '360p':  {'max_width': 640,  'max_height': 360,  'bitrates': {'h264': '1M'}}
            },
            'audio_channel_layouts': {
                'stereo': {'max_channels': 2, 'bitrates': {'aac': '128k'}}
            }
        }

        input_config_dict = {
            'inputs': [
                {
                    'input_type': 'file', 
                    'name': str(local_source), 
                    'media_type': 'video', 
                    'resolution': input_res, 
                    'frame_rate': src_fps
                }
            ]
        }
        if has_audio:
            input_config_dict['inputs'].append({
                'input_type': 'file', 
                'name': str(local_source), 
                'media_type': 'audio'
            })

        pipeline_config_dict = {
            'streaming_mode': 'vod',
            'resolutions': target_resolutions,
            'segment_size': 6.0,
            'manifest_format': ['dash', 'hls'],
            'hls_output': 'master.m3u8',
            'dash_output': 'manifest.mpd',
            'encryption': {
                'enable': True,
                'encryption_mode': 'raw',
                'protection_scheme': 'cbcs',
                'clear_lead': 0,
                'keys': [
                    {
                        'label': '',  # Empty label = Default key for ALL streams (video & audio)
                        'key_id': drm_kid, 
                        'key': drm_key
                    }
                ]
            }
        }

        # إضافة رابط الترخيص للـ HLS إذا وجد
        if license_url and len(license_url) > 5:
            pipeline_config_dict['encryption']['hls_key_uri'] = license_url

        # 4. تشغيل المعالجة (Shaka Controller Module Pattern)
        print("[*] Shaka Streamer Engine started (Dictionary-based configuration)...")
        controller = ControllerNode()
        controller.start(
            output_location=str(local_output_dir),
            input_config_dict=input_config_dict,
            pipeline_config_dict=pipeline_config_dict,
            bitrate_config_dict=bitrate_config_dict,
            use_hermetic=False  # استخدام الـ binaries المثبتة في النظام (ffmpeg, packager)
        )
        
        # مراقبة العملية حتى الانتهاء
        while True:
            status = controller.check_status().name
            if status == 'Finished':
                break
            elif status == 'Errored':
                raise RuntimeError(f"Shaka Streamer Engine failed with error status.")
            time.sleep(5)

        # 5. رفع النتائج النهائية لـ R2 بالتوازي (High-Performance Engine)
        print("[*] Uploading final segments to R2 (100 Concurrent Workers)...")
        all_files = [f for f in local_output_dir.glob("**/*") if f.is_file()]
        total_bytes = 0
        
        def upload_worker(file_path):
            rel_path = file_path.relative_to(local_output_dir)
            remote_path = f"processed/{video_id}/{rel_path}"
            is_playlist = file_path.suffix in [".m3u8", ".mpd"]
            
            # تحديد Content-Type بدقة لضمان التوافق مع المشغلات
            if file_path.suffix == ".m3u8": content_type = "application/x-mpegURL"
            elif file_path.suffix == ".mpd": content_type = "application/dash+xml"
            elif file_path.suffix == ".m4s": content_type = "video/iso.segment"
            elif file_path.suffix == ".mp4": content_type = "video/mp4"
            else: content_type = "application/octet-stream"
            
            cache_control = "no-cache, max-age=0" if is_playlist else "public, max-age=31536000, immutable"
            
            # آلية المحاولة مرة أخرى (Retry Logic) مع التراجع الأسي لضمان وصول كافة الأجزاء لـ R2
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    s3.upload_file(str(file_path), bucket, remote_path, ExtraArgs={
                        'ContentType': content_type,
                        'CacheControl': cache_control
                    })
                    return file_path.stat().st_size
                except Exception as e:
                    if attempt == max_retries - 1:
                        print(f"[!] Upload failed after {max_retries} attempts for {file_path.name}: {str(e)}")
                        raise
                    time.sleep(2 ** attempt) # تراجع أسي (Exponential Backoff)

        with ThreadPoolExecutor(max_workers=100) as executor:
            sizes = list(executor.map(upload_worker, all_files))
            total_bytes = sum(sizes)

        # 6. إرسال Webhook النجاح مع التقرير المالي
        manager_duration = time.perf_counter() - start_time
        
        # حساب التكلفة بناءً على الموارد المستخدمة (14 CPU & 16GB RAM)
        cpu_rate = float(os.environ.get("MODAL_CPU_RATE", "0.0000131"))
        mem_rate = float(os.environ.get("MODAL_MEM_RATE", "0.00000222"))
        cost_usd = round(manager_duration * ((14.0 * cpu_rate) + (16.0 * mem_rate)), 4)
        
        print(f"[*] Success! Total duration: {round(manager_duration, 2)}s, Estimated Cost: ${cost_usd}")

        if callback_url:
            webhook_payload = {
                "video_id": video_id,
                "status": "ready",
                "playback_url": f"{os.environ['R2_PUBLIC_URL']}/processed/{video_id}/master.m3u8",
                "drm": {"key": drm_key, "kid": drm_kid},
                "storage_size_mb": round(total_bytes / (1024*1024), 2),
                "metrics": {
                    "duration_seconds": round(manager_duration, 2),
                    "cost_usd": cost_usd
                }
            }
            
            # محاولة إرسال الـ Webhook مع إعادة المحاولة في حالة الفشل لضمان تحديث حالة الفيديو في Laravel
            for attempt in range(3):
                try:
                    response = requests.post(
                        callback_url, 
                        json=webhook_payload, 
                        headers={"X-MODAL-AUTH-TOKEN": os.environ.get("MODAL_AUTH_TOKEN")}, 
                        timeout=30
                    )
                    if response.status_code in (200, 201):
                        print("[*] Webhook delivered successfully.")
                        break
                    else:
                        print(f"[!] Webhook attempt {attempt + 1} failed (Status: {response.status_code})")
                except Exception as e:
                    print(f"[!] Webhook attempt {attempt + 1} failed: {str(e)}")
                
                if attempt < 2: time.sleep(5)
            else:
                print("[!] CRITICAL: All webhook attempts failed. Video status might not be updated in backend.")

        # حذف الملف الأصلي من R2 بعد النجاح
        s3.delete_object(Bucket=bucket, Key=file_key)
        return {"status": "success"}

    except Exception as e:
        print(f"[!] Critical Failure: {str(e)}")
        if callback_url:
            try:
                requests.post(callback_url, json={"video_id": video_id, "status": "failed", "error": str(e)})
            except: pass
        return {"status": "error", "message": str(e)}
    finally:
        # تنظيف مساحة SSD المحلية
        shutil.rmtree(local_work_dir, ignore_errors=True)
        local_source.unlink(missing_ok=True)