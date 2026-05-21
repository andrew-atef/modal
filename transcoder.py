import os
import shutil
import subprocess
import modal
import time
import requests
import secrets
import json
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import boto3
from botocore.config import Config

app = modal.App("storva-smart-transcoder")

image = (
    modal.Image.debian_slim()
    .apt_install("curl", "xz-utils", "ca-certificates")
    .run_commands(
        "curl -L https://johnvansickle.com/ffmpeg/builds/ffmpeg-git-amd64-static.tar.xz -o /tmp/ffmpeg.tar.xz",
        "tar -xJf /tmp/ffmpeg.tar.xz -C /tmp",
        "mv /tmp/ffmpeg-git-*-amd64-static/ffmpeg /usr/local/bin/ffmpeg",
        "mv /tmp/ffmpeg-git-*-amd64-static/ffprobe /usr/local/bin/ffprobe",
        "chmod +x /usr/local/bin/ffmpeg /usr/local/bin/ffprobe",
        "rm -rf /tmp/ffmpeg*"
    )
    .pip_install("boto3", "requests", "fastapi[standard]")
)

@app.function(
    image=image,
    secrets=[modal.Secret.from_name("r2-storage")],
    timeout=60,
    cpu=0.2,
    memory=512,
    scaledown_window=5
)
@modal.fastapi_endpoint(method="POST")
def process_video(data: dict):
    run_transcoding.spawn(data)
    return {"status": "accepted"}

@app.function(
    image=image,
    secrets=[modal.Secret.from_name("r2-storage")],
    timeout=14400,
    cpu=14.0,
    memory=16384
)
def run_transcoding(data: dict):
    start_time = time.perf_counter()
    video_id = data.get("video_id")
    file_key = data.get("file_key")
    callback_url = data.get("callback_url")
    hls_key_uri = f"https://license.devawi.tech/keys/{video_id}"
    
    if not video_id or not file_key:
        raise ValueError("Missing required fields")

    drm_key = secrets.token_hex(16)
    drm_iv = secrets.token_hex(16)

    s3 = boto3.client("s3", endpoint_url=os.environ["R2_ENDPOINT"],
                      aws_access_key_id=os.environ["R2_ACCESS_ID"],
                      aws_secret_access_key=os.environ["R2_SECRET_KEY"],
                      config=Config(signature_version="s3v4", max_pool_connections=100))
    bucket = os.environ["R2_BUCKET"]
    
    local_work_dir = Path(f"/tmp/{video_id}")
    local_work_dir.mkdir(parents=True, exist_ok=True)
    local_source = local_work_dir / "source.mp4"
    local_output_dir = local_work_dir / "hls_out"
    local_output_dir.mkdir(parents=True, exist_ok=True)

    key_file = local_work_dir / "key.bin"
    key_info_file = local_work_dir / "key_info.txt"

    try:
        print(f"[*] Downloading source: {file_key}")
        s3.download_file(bucket, file_key, str(local_source))
        
        # كتابة المفاتيح التشفيرية وحفظها في R2 كـ keys.json لضمان الـ Strong Consistency
        key_file.write_bytes(bytes.fromhex(drm_key))
        key_info_content = f"{hls_key_uri}\n{str(key_file)}\n"
        key_info_file.write_text(key_info_content)

        probe_cmd = [
            "ffprobe", "-v", "error", "-select_streams", "v:0", 
            "-show_entries", "stream=width,height,avg_frame_rate", 
            "-of", "json", str(local_source)
        ]
        probe_res = json.loads(subprocess.check_output(probe_cmd).decode())
        s = probe_res['streams'][0]
        src_width, src_height = s['width'], s['height']
        
        try:
            fr_num, fr_den = s['avg_frame_rate'].split('/')
            src_fps = float(fr_num) / float(fr_den) if float(fr_den) != 0 else 30.0
        except:
            src_fps = 30.0

        gop_size = int(src_fps * 10.0) # ترميز معتمد على قطع 10 ثواني (FinOps Optimization)
        is_portrait = src_height > src_width
        reference_dim = src_width if is_portrait else src_height

        probe_audio_cmd = [
            "ffprobe", "-v", "error", "-select_streams", "a:0", 
            "-show_entries", "stream=index", 
            "-of", "json", str(local_source)
        ]
        probe_audio_res = json.loads(subprocess.check_output(probe_audio_cmd).decode())
        has_audio = len(probe_audio_res.get('streams', [])) > 0
        
        resolution_map = {
            1080: {"name": "1080p", "w": 1920, "h": 1080, "bitrate": "5000k", "bandwidth": 5200000},
            720:  {"name": "720p",  "w": 1280, "h": 720,  "bitrate": "2800k", "bandwidth": 2900000},
            480:  {"name": "480p",  "w": 854,  "h": 480,  "bitrate": "1400k", "bandwidth": 1500000},
            360:  {"name": "360p",  "w": 640,  "h": 360,  "bitrate": "800k",  "bandwidth": 900000}
        }
        
        active_resolutions = [r for r in resolution_map.values() if r["h"] <= reference_dim][:4]
        if not active_resolutions:
            active_resolutions = [resolution_map[360]]

        num_resolutions = len(active_resolutions)
        threads_per_process = max(1, 12 // num_resolutions)

        def transcode_single_resolution(res):
            res_dir = local_output_dir / res["name"]
            res_dir.mkdir(parents=True, exist_ok=True)
            
            print(f"[*] Starting parallel fMP4 transcode for {res['name']}...")
            scale_filter = f"scale=w={res['w']}:h={res['h']}:force_original_aspect_ratio=decrease,pad={res['w']}:{res['h']}:(ow-iw)/2:(oh-ih)/2"
            
            ffmpeg_cmd = [
                "ffmpeg", "-y", 
                "-threads", str(threads_per_process), 
                "-i", str(local_source),
                "-vf", scale_filter,
                "-c:v", "libx264", "-profile:v", "main", "-level", "3.1",
                "-preset", "veryfast",
                "-crf", "24", # توفير 15% من الحجم بصفر فرق جودة
                "-tune", "stillimage", # الفلتر السحري للشروحات والسبورات لضغط الحجم للنصف
                "-maxrate", res["bitrate"], 
                "-bufsize", str(int(res["bitrate"].replace("k","")) * 2) + "k",
                "-pix_fmt", "yuv420p", # لضمان عمل البث على الشاشات والموبايلات الضعيفة
                "-g", str(gop_size), "-keyint_min", str(gop_size), "-sc_threshold", "0"
            ]

            if has_audio:
                ffmpeg_cmd.extend([
                    "-c:a", "aac", "-b:a", "128k", "-ar", "48000", "-ac", "2", "-async", "1"
                ])
            else:
                ffmpeg_cmd.extend(["-an"])

            # دمج معاملات معيار fMP4 (CMAF) الحديث عالي السرعة وصغير الحجم
            ffmpeg_cmd.extend([
                "-hls_time", "10", # قطع متزامنة بطول 10 ثوان
                "-hls_playlist_type", "vod",
                "-hls_segment_type", "fmp4", # استخدام fMP4 (CMAF) بدلاً من TS
                "-hls_fmp4_index_filename", "init.mp4", # ملف التمهيد والتهيئة للميديا
                "-hls_key_info_file", str(key_info_file),
                "-hls_segment_filename", f"{str(res_dir)}/%d.m4s", # القطع بصيغة m4s فائقة التوفير
                f"{str(res_dir)}/main.m3u8"
            ])

            subprocess.run(ffmpeg_cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(f"[+] Finished parallel fMP4 transcode for {res['name']}")

        with ThreadPoolExecutor(max_workers=num_resolutions) as executor:
            futures = [executor.submit(transcode_single_resolution, res) for res in active_resolutions]
            for future in as_completed(futures):
                future.result() 

        # كتابة ملف keys.json الذي يحتوي على المفتاح ومعرف المدرس لضمان الـ Strong Consistency في الـ Edge
        keys_payload = {
            "key": drm_key,
            "kid": drm_iv,
            "owner_id": str(data.get("user_id", "1")) # دمج المالك الحقيقي للفيديو
        }
        keys_file_path = local_output_dir / "keys.json"
        keys_file_path.write_text(json.dumps(keys_payload))

        # 2. إنشاء ملف الماستر الرئيسي
        master_content = ["#EXTM3U", "#EXT-X-VERSION:3"]
        for res in active_resolutions:
            master_content.append(
                f"#EXT-X-STREAM-INF:BANDWIDTH={res['bandwidth']},RESOLUTION={res['w']}x{res['h']}"
            )
            master_content.append(f"{res['name']}/main.m3u8")
            
        master_file = local_output_dir / "master.m3u8"
        master_file.write_text("\n".join(master_content) + "\n")

        # 3. رفع الملفات بشكل متوازي ومحسن لـ R2
        print("[*] Uploading segments to R2...")
        all_files = [f for f in local_output_dir.glob("**/*") if f.is_file()]
        total_bytes = 0
        
        def upload_worker(file_path):
            rel_path = file_path.relative_to(local_output_dir)
            remote_path = f"processed/{video_id}/{rel_path}"
            is_playlist = file_path.suffix == ".m3u8"
            
            if is_playlist:
                content_type = "application/x-mpegURL"
            elif file_path.suffix == ".m4s":
                content_type = "video/iso.segment"
            elif file_path.name == "keys.json":
                content_type = "application/json"
            else:
                content_type = "video/mp4"
                
            cache_control = "no-cache, no-store, must-revalidate" if is_playlist else "public, max-age=31536000, immutable"
            
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    s3.upload_file(str(file_path), bucket, remote_path, ExtraArgs={
                        'ContentType': content_type,
                        'CacheControl': cache_control
                    })
                    return file_path.stat().st_size
                except Exception as e:
                    if attempt == max_retries - 1: raise
                    time.sleep(2 ** attempt)

        with ThreadPoolExecutor(max_workers=24) as executor:
            sizes = list(executor.map(upload_worker, all_files))
            total_bytes = sum(sizes)

        # حساب عدد قطع الـ m4s للفوترة
        segment_count = len(list(local_output_dir.glob("**/*.m4s")))

        # 4. إرسال Webhook النجاح للـ Laravel
        manager_duration = time.perf_counter() - start_time
        print(f"[+] Total execution time: {round(manager_duration, 2)} seconds")
        
        if callback_url:
            webhook_payload = {
                "video_id": video_id,
                "status": "ready",
                "playback_url": f"{os.environ['R2_PUBLIC_URL']}/processed/{video_id}/master.m3u8",
                "drm": {
                    "key": drm_key,
                    "kid": drm_iv,
                },
                "storage_size_mb": round(total_bytes / (1024*1024), 2),
                "metrics": {
                    "duration_seconds": round(manager_duration, 2),
                    "segment_count": segment_count,
                    "resolutions": [r["name"] for r in active_resolutions]
                }
            }
            
            headers = {"X-MODAL-AUTH-TOKEN": os.environ.get("MODAL_AUTH_TOKEN")}
            requests.post(callback_url, json=webhook_payload, headers=headers, timeout=15)

        s3.delete_object(Bucket=bucket, Key=file_key)
        return {"status": "success"}

    except Exception as e:
        print(f"[!] Failure: {str(e)}")
        if callback_url:
            try:
                requests.post(callback_url, json={"video_id": video_id, "status": "failed", "error": str(e)})
            except: pass
        return {"status": "error", "message": str(e)}
    finally:
        shutil.rmtree(local_work_dir, ignore_errors=True)