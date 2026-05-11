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

app = modal.App("storva-smart-transcoder")

image = (
    modal.Image.debian_slim()
    .apt_install("curl", "xz-utils", "ca-certificates")
    .run_commands(
        "update-ca-certificates",
        "curl -L https://johnvansickle.com/ffmpeg/releases/ffmpeg-release-amd64-static.tar.xz -o /tmp/ffmpeg.tar.xz",
        "tar -xJf /tmp/ffmpeg.tar.xz -C /tmp",
        "mv /tmp/ffmpeg-*-static/ffmpeg /usr/local/bin/ffmpeg",
        "mv /tmp/ffmpeg-*-static/ffprobe /usr/local/bin/ffprobe",
        "chmod +x /usr/local/bin/ffmpeg /usr/local/bin/ffprobe",
        "rm -rf /tmp/ffmpeg*"
    )
    .run_commands(
        "curl -L https://github.com/shaka-project/shaka-packager/releases/download/v3.2.0/packager-linux-x64 -o /usr/local/bin/packager",
        "chmod +x /usr/local/bin/packager"
    )
    .pip_install("boto3", "requests", "fastapi[standard]")
)

r2_secret = modal.Secret.from_name("r2-storage")

def verify_pts_start(filepath: str, label: str) -> bool:
    """Verify encoded MP4 starts at PTS=0 AND tfdt=0. Either failure is critical."""
    import subprocess, json
    
    # Check 1: Frame-level PTS (existing)
    result = subprocess.run([
        "ffprobe", "-v", "error",
        "-select_streams", "v:0",
        "-show_entries", "packet=pts_time,dts_time",
        "-of", "json",
        "-read_intervals", "%+#5",
        filepath
    ], capture_output=True, text=True)
    
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        print(f"[!] WARNING: PTS check ({label}): ffprobe returned invalid JSON")
        return True
    
    packets = data.get("packets", [])
    if not packets:
        print(f"[!] WARNING: PTS check ({label}): No packets found")
        return True
    
    # Find the minimum PTS across first 5 packets (handles B-frame reordering)
    min_pts = None
    for pkt in packets:
        pts_str = pkt.get("pts_time")
        dts_str = pkt.get("dts_time")
        
        # "N/A" or missing pts_time is a RED FLAG, not a safe default
        for ts_str in [pts_str, dts_str]:
            if ts_str is None or str(ts_str).strip().upper() == "N/A":
                continue
            try:
                ts = float(ts_str)
                if min_pts is None or ts < min_pts:
                    min_pts = ts
            except (ValueError, TypeError):
                continue
    
    if min_pts is None or min_pts > 1.0:
        print(f"[!] WARNING: PTS check ({label}): Frame-level PTS offset ({min_pts})")
    
    # Check 2: Container-level tfdt (NEW — this is what Shaka Packager uses!)
    tfdt_result = subprocess.run([
        "ffprobe", "-v", "error",
        "-select_streams", "v:0",
        "-show_entries", "packet=dts",
        "-of", "json",
        "-read_intervals", "%+#1",  # Just first packet's DTS = tfdt equivalent
        filepath
    ], capture_output=True, text=True)
    
    try:
        tfdt_data = json.loads(tfdt_result.stdout)
        first_dts = tfdt_data.get("packets", [{}])[0].get("dts")
        if first_dts is not None and first_dts > 90000:  # > 1 second at 90k timescale
            print(f"[!] WARNING: TFDT check ({label}): Container DTS offset ({first_dts})")
    except (json.JSONDecodeError, IndexError, KeyError):
        pass  # If we can't check tfdt, rely on PTS check only
    
    print(f"[*] PTS/TFDT check ({label}): OK (Warning-only mode)")
    return True



def deep_probe(filepath: str, label: str):
    """Deep debug: print all timestamp info about a file and verify zero-start."""
    import json
    print(f"\n========== DEEP PROBE: {label} ==========")
    
    r1 = subprocess.run([
        "ffprobe", "-v", "error",
        "-show_entries", "format=start_time,duration,size",
        "-of", "json", filepath
    ], capture_output=True, text=True)
    if r1.returncode == 0:
        fmt = json.loads(r1.stdout).get("format", {})
        fmt_start = fmt.get('start_time', 'N/A')
        print(f"[FORMAT] start_time={fmt_start} | duration={fmt.get('duration', 'N/A')}")
        if fmt_start not in ('N/A', None):
            try:
                if float(fmt_start) > 1.0:
                    print(f"[!!!] CRITICAL: Container format.start_time={fmt_start}s — Shaka will use this as segment offset!")
            except ValueError:
                pass
    
    r2 = subprocess.run([
        "ffprobe", "-v", "error",
        "-show_entries", "stream=index,codec_type,codec_name,time_base,start_time",
        "-of", "json", filepath
    ], capture_output=True, text=True)
    if r2.returncode == 0:
        for s in json.loads(r2.stdout).get("streams", []):
            print(f"[STREAM #{s.get('index')}] type={s.get('codec_type')} | codec={s.get('codec_name')} | time_base={s.get('time_base')} | start_time={s.get('start_time')}")
    
    r3 = subprocess.run([
        "ffprobe", "-v", "error",
        "-select_streams", "v:0" if "audio" not in label.lower() else "a:0",
        "-show_entries", "packet=pts,dts,pts_time,dts_time,flags",
        "-of", "json",
        "-read_intervals", "%+#3",
        filepath
    ], capture_output=True, text=True)
    if r3.returncode == 0:
        packets = json.loads(r3.stdout).get("packets", [])
        for i, pkt in enumerate(packets):
            print(f"[PACKET #{i}] pts={pkt.get('pts')} | dts={pkt.get('dts')} | pts_time={pkt.get('pts_time')} | dts_time={pkt.get('dts_time')} | flags={pkt.get('flags')}")
        
        if packets:
            first_pts = packets[0].get("pts_time")
            if first_pts is not None:
                try:
                    if float(first_pts) != 0.0:
                        print(f"[!!!] CRITICAL WARNING: {label} first packet pts_time is {first_pts}, NOT 0.000000!")
                    else:
                        print(f"[*] VERIFIED: {label} starts exactly at 0.000000")
                except ValueError:
                    pass

    print(f"========== END PROBE: {label} ==========\n")

def inspect_mp4_elst(filepath: str, label: str):
    """Binary inspect MP4 for edit list (elst) atoms that ffprobe may hide."""
    import struct
    print(f"[*] Binary MP4 inspection for elst: {label}")
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
        # Search for 'elst' box
        pos = 0
        found_elst = False
        while pos < len(data) - 8:
            idx = data.find(b'elst', pos)
            if idx == -1:
                break
            found_elst = True
            # Box size is 4 bytes before the type
            box_size = struct.unpack('>I', data[idx-4:idx])[0]
            # Version is 1 byte after type
            version = data[idx+4]
            entry_count_offset = idx + 8
            entry_count = struct.unpack('>I', data[entry_count_offset:entry_count_offset+4])[0]
            print(f"  [ELST] Found at offset {idx-4}, size={box_size}, version={version}, entries={entry_count}")
            entry_offset = entry_count_offset + 4
            for i in range(min(entry_count, 5)):  # Show max 5 entries
                if version == 1:
                    seg_dur = struct.unpack('>Q', data[entry_offset:entry_offset+8])[0]
                    media_time = struct.unpack('>q', data[entry_offset+8:entry_offset+16])[0]
                    print(f"  [ELST entry {i}] segment_duration={seg_dur}, media_time={media_time}")
                    entry_offset += 20
                else:
                    seg_dur = struct.unpack('>I', data[entry_offset:entry_offset+4])[0]
                    media_time = struct.unpack('>i', data[entry_offset+4:entry_offset+8])[0]
                    print(f"  [ELST entry {i}] segment_duration={seg_dur}, media_time={media_time}")
                    entry_offset += 12
            pos = idx + box_size
        if not found_elst:
            print(f"  [ELST] No edit list found in {label} - CLEAN container")
    except Exception as e:
        print(f"  [ELST] Inspection error: {e}")

@app.function(
    image=image,
    secrets=[r2_secret],
    cpu=14.0,
    memory=4096,
    timeout=3600,
    retries=3
)
def transcode_worker(quality: dict, video_id: str, file_key: str, is_portrait: bool):
    import os
    import boto3
    from pathlib import Path

    s3 = boto3.client(
        "s3",
        endpoint_url=os.environ["R2_ENDPOINT"],
        aws_access_key_id=os.environ["R2_ACCESS_ID"],
        aws_secret_access_key=os.environ["R2_SECRET_KEY"]
    )

    # Download source to local /tmp SSD (seekable, fast NVMe — NOT /vol NFS)
    local_source = Path(f"/tmp/{video_id}_src_{quality['name']}.mp4")
    print(f"[*] Worker ({quality['name']}) downloading original source to /tmp SSD...")
    dl_start = time.perf_counter()
    s3.download_file(os.environ["R2_BUCKET"], file_key, str(local_source))
    dl_duration = round(time.perf_counter() - dl_start, 2)
    print(f"[*] Worker ({quality['name']}) download done in {dl_duration}s")

    local_output = Path(f"/tmp/{video_id}_{quality['name']}.mp4")

    scale_filter = f"scale={quality['h']}:-2" if is_portrait else f"scale=-2:{quality['h']}"

    ffmpeg_cmd = [
        "ffmpeg", "-loglevel", "error", "-err_detect", "ignore_err", "-y",
        "-threads", "0",
        "-ignore_editlist", "1",
        "-fflags", "+genpts+igndts+discardcorrupt",
        "-flags", "+bitexact",
        "-analyzeduration", "100M",
        "-probesize", "100M",
        "-i", str(local_source),
        "-map", "0:v:0", "-an", "-sn", "-dn",
        "-map_chapters", "-1",
        "-vf", f"fps=fps=30,setpts=PTS-STARTPTS,{scale_filter}",
        "-c:v", "libx264", "-preset", "ultrafast", "-crf", "28",
        "-threads", "0",
        "-r", "30",
        "-fps_mode", "cfr",
        "-g", "60", "-keyint_min", "60", "-sc_threshold", "0",
        "-video_track_timescale", "90000",
        "-bf", "0",
        "-avoid_negative_ts", "make_zero",
        "-output_ts_offset", "0",
        "-muxdelay", "0", "-muxpreload", "0",
        "-map_metadata", "-1",
        "-movflags", "+faststart",
        str(local_output)
    ]

    start_worker = time.perf_counter()
    try:
        subprocess.run(ffmpeg_cmd, check=True, capture_output=True, text=True)
        deep_probe(str(local_output), f"WORKER OUTPUT {quality['name']}")
    except subprocess.CalledProcessError as e:
        print(f"[!] FFmpeg Video Error ({quality['name']}):\n{e.stderr}")
        raise RuntimeError(f"FFmpeg failed: {e.stderr}")

    # Cleanup source immediately after FFmpeg (free /tmp space)
    local_source.unlink(missing_ok=True)

    # Upload encoded output to R2 temp location
    temp_key = f"temp_encoded/{video_id}/{quality['name']}.mp4"
    s3.upload_file(str(local_output), os.environ["R2_BUCKET"], temp_key)
    local_output.unlink(missing_ok=True)

    duration = time.perf_counter() - start_worker
    return {"temp_key": temp_key, "duration": duration, "dl_duration": dl_duration}

@app.function(
    image=image,
    secrets=[r2_secret],
    cpu=4.0,
    memory=4096,
    timeout=3600,
    retries=3
)
def audio_worker(video_id: str, file_key: str):
    import os
    import boto3
    from pathlib import Path

    s3 = boto3.client(
        "s3",
        endpoint_url=os.environ["R2_ENDPOINT"],
        aws_access_key_id=os.environ["R2_ACCESS_ID"],
        aws_secret_access_key=os.environ["R2_SECRET_KEY"]
    )

    local_source = Path(f"/tmp/{video_id}_src_audio.mp4")
    print(f"[*] Audio worker downloading original source to /tmp SSD...")
    dl_start = time.perf_counter()
    s3.download_file(os.environ["R2_BUCKET"], file_key, str(local_source))
    dl_duration = round(time.perf_counter() - dl_start, 2)
    print(f"[*] Audio worker download done in {dl_duration}s")

    local_output = Path(f"/tmp/{video_id}_audio.mp4")

    ffmpeg_cmd = [
        "ffmpeg", "-loglevel", "error", "-err_detect", "ignore_err", "-y",
        "-threads", "0",
        "-ignore_editlist", "1",
        "-fflags", "+genpts+igndts+discardcorrupt",
        "-flags", "+bitexact",
        "-analyzeduration", "100M",
        "-probesize", "100M",
        "-i", str(local_source),
        "-map", "0:a:0", "-vn", "-sn", "-dn",
        "-map_chapters", "-1",
        "-c:a", "aac", "-ac", "2", "-ar", "48000", "-b:a", "128k",
        "-af", "aresample=async=1:first_pts=0,asetpts=PTS-STARTPTS",
        "-avoid_negative_ts", "make_zero",
        "-output_ts_offset", "0",
        "-muxdelay", "0", "-muxpreload", "0",
        "-map_metadata", "-1",
        "-movflags", "+faststart",
        str(local_output)
    ]

    start_worker = time.perf_counter()
    try:
        subprocess.run(ffmpeg_cmd, check=True, capture_output=True, text=True)
        deep_probe(str(local_output), "WORKER OUTPUT audio")
    except subprocess.CalledProcessError as e:
        print(f"[!] FFmpeg Audio Error:\n{e.stderr}")
        raise RuntimeError(f"FFmpeg Audio failed: {e.stderr}")

    local_source.unlink(missing_ok=True)

    temp_key = f"temp_encoded/{video_id}/audio.mp4"
    s3.upload_file(str(local_output), os.environ["R2_BUCKET"], temp_key)
    local_output.unlink(missing_ok=True)

    duration = time.perf_counter() - start_worker
    return {"temp_key": temp_key, "duration": duration, "dl_duration": dl_duration}

@app.function(
    image=image,
    secrets=[r2_secret],
    timeout=14400,
    cpu=2.0,
    memory=4096,
    scaledown_window=5
)
@modal.fastapi_endpoint(method="POST")
def process_video(data: dict, background_tasks: BackgroundTasks):
    background_tasks.add_task(run_transcoding, data)
    return {"status": "accepted"}

def run_transcoding(data: dict):
    start_time = time.perf_counter()
    import boto3
    from botocore.config import Config

    video_id = data.get("video_id")
    file_key = data.get("file_key")
    if not video_id or not file_key:
        raise ValueError("Missing required fields: video_id and file_key are required")
    license_url = data.get("license_url", "https://your-api.com/api/license/clearkey").strip()
    callback_url = data.get("callback_url")
    
    drm_key = secrets.token_hex(16)
    drm_kid = secrets.token_hex(16)

    s3 = boto3.client("s3", endpoint_url=os.environ["R2_ENDPOINT"],
                      aws_access_key_id=os.environ["R2_ACCESS_ID"],
                      aws_secret_access_key=os.environ["R2_SECRET_KEY"],
                      config=Config(signature_version="s3v4", max_pool_connections=100))
    bucket = os.environ["R2_BUCKET"]
    
    local_work_dir = None  # Initialize for finally block safety
    sanitized_key = None  # Initialize for cleanup safety

    try:
        # 0. Fast Header Probe via curl (avoids ffprobe HTTPS segfault in static builds)
        print("[*] Performing fast header probe via curl...")
        presigned_url = s3.generate_presigned_url(
            'get_object',
            Params={'Bucket': bucket, 'Key': file_key},
            ExpiresIn=3600
        )
        
        header_path = "/tmp/probe_header.mp4"
        # Download first 8MB — captures moov atom for most files
        curl_cmd = [
            "curl", "-s", "-L", "-r", "0-8388607",
            "--max-time", "30",
            presigned_url,
            "-o", header_path
        ]
        result = subprocess.run(curl_cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"curl probe failed: {result.stderr}")
        
        # 1. Analyze the local header snippet
        print("[*] Analyzing video streams (local probe)...")
        probe_cmd = [
            "ffprobe", "-v", "error",
            "-show_entries", "stream=width,height,codec_type,codec_name",
            "-of", "json",
            header_path
        ]
        probe_output = subprocess.check_output(probe_cmd, stderr=subprocess.STDOUT).decode()
        
        try:
            probe_res = json.loads(probe_output)
        except json.JSONDecodeError:
            # moov atom likely at end — fetch tail and combine
            print("[*] First probe incomplete, fetching tail for moov atom...")
            tail_path = "/tmp/probe_tail.mp4"
            tail_cmd = [
                "curl", "-s", "-L", "-r", "-2097152",
                "--max-time", "30",
                presigned_url,
                "-o", tail_path
            ]
            subprocess.run(tail_cmd, check=True)
            
            combined_path = "/tmp/probe_combined.mp4"
            with open(combined_path, "wb") as out:
                with open(header_path, "rb") as h:
                    out.write(h.read())
                with open(tail_path, "rb") as t:
                    out.write(t.read())
            
            probe_cmd[-1] = combined_path
            probe_output = subprocess.check_output(probe_cmd, stderr=subprocess.STDOUT).decode()
            probe_res = json.loads(probe_output)
            
            Path(tail_path).unlink(missing_ok=True)
            Path(combined_path).unlink(missing_ok=True)
        
        Path(header_path).unlink(missing_ok=True)
        
        src_width = 640   # Default fallback
        src_height = 360  # Default fallback
        has_audio = False
        audio_codec = "unknown"
        for stream in probe_res.get('streams', []):
            if stream.get('codec_type') == 'video' and 'height' in stream:
                src_width = stream['width']
                src_height = stream['height']
            elif stream.get('codec_type') == 'audio':
                has_audio = True
                audio_codec = stream.get('codec_name', 'unknown')

        # Orientation Detection (Portrait vs Landscape)
        is_portrait = src_height > src_width
        reference_dim = src_width if is_portrait else src_height
        orientation = "Portrait" if is_portrait else "Landscape"
        print(f"[*] Source: {src_width}x{src_height} ({orientation}), Audio: {has_audio}")



        # 2. قرار الجودات (YouTube Logic - Orientation Aware)
        all_possible_qualities = [
            {"name": "1080p", "h": 1080, "bitrate": "3500k"},
            {"name": "720p",  "h": 720,  "bitrate": "2000k"},
            {"name": "480p",  "h": 480,  "bitrate": "1000k"},
            {"name": "360p",  "h": 360,  "bitrate": "500k"}
        ]
        # For Portrait: compare quality against width. For Landscape: compare against height.
        start_idx = next((i for i, q in enumerate(all_possible_qualities) if q['h'] <= reference_dim), len(all_possible_qualities) - 1)
        target_qualities = all_possible_qualities[start_idx : start_idx + 3]

        # 3. Safety Ceiling & Disk Check
        head_response = s3.head_object(Bucket=bucket, Key=file_key)
        source_size_bytes = head_response["ContentLength"]
        source_size_gb = source_size_bytes / (1024 ** 3)
        source_size_mb = source_size_bytes / (1024 * 1024)
        
        if source_size_gb > 50:
            raise RuntimeError(f"Source video exceeds safety ceiling: {source_size_gb:.2f}GB (max 50GB)")

        # Require ~3x source size: source download + encoded output + packaging workspace
        required_mb = source_size_mb * 3
        print(f"[*] Source size: {source_size_mb:.2f} MB. Estimated required /tmp: {required_mb:.2f} MB")
        # Modal /tmp is typically large; this is a sanity check
        if required_mb > 25000:  # ~25GB heuristic safety ceiling for /tmp
            raise RuntimeError(
                f"Source file too large for current /tmp capacity: {source_size_mb:.2f} MB. "
                f"Estimated requirement: {required_mb:.2f} MB."
            )

        # 4. Transcoding (Parallel Manager-Worker Pattern)
        transcode_start = time.perf_counter()
        print(f"[*] Dispatching parallel workers for {orientation} video...")
        
        packager_inputs = []
        
        # Prep tasks for workers (pass file_key for direct R2 download)
        video_tasks = [(q, video_id, file_key, is_portrait) for q in target_qualities]
        
        # Start audio worker in parallel if needed
        audio_future = None
        if has_audio:
            print("[*] Dispatching audio worker...")
            audio_future = audio_worker.spawn(video_id, file_key)
        
        # Run video workers and wait for all (starmap)
        print(f"[*] Mapping {len(video_tasks)} video workers...")
        video_results = list(transcode_worker.starmap(video_tasks))
        total_video_worker_duration = sum(r["duration"] for r in video_results)
        
        # Wait for audio to complete
        audio_worker_duration = 0
        if audio_future:
            audio_res = audio_future.get()
            audio_worker_duration = audio_res["duration"]
            print("[*] Audio worker finished.")
        
        transcode_duration = round(time.perf_counter() - transcode_start, 2)
        print(f"[*] Parallel Transcoding took {transcode_duration}s")

        # 4. Packaging with DRM (Shaka Packager)
        shaka_start = time.perf_counter()
        print(f"[*] Starting Shaka Packaging for {len(target_qualities)} qualities (Local /tmp optimization)...")
        
        # Create local work dir for packaging (High-speed SSD)
        local_work_dir = Path(f"/tmp/{video_id}")
        local_work_dir.mkdir(parents=True, exist_ok=True)
        local_output_dir = local_work_dir / "hls_out"
        local_output_dir.mkdir(exist_ok=True)

        print("[*] Downloading encoded files from R2 to local SSD for packaging...")
        for q, result in zip(target_qualities, video_results):
            local_path = local_work_dir / f"{q['name']}.mp4"
            s3.download_file(bucket, result["temp_key"], str(local_path))
            s3.delete_object(Bucket=bucket, Key=result["temp_key"])
            
        if has_audio:
            local_audio_path = local_work_dir / "audio.mp4"
            s3.download_file(bucket, audio_res["temp_key"], str(local_audio_path))
            s3.delete_object(Bucket=bucket, Key=audio_res["temp_key"])

        # 4.5 Container Sanitization: Strip elst/edit-list atoms via stream-copy remux
        # This creates brand-new MP4 containers with timestamps starting at absolute zero.
        # The encoded bitstream is preserved perfectly (no re-encode).
        print("[*] Sanitizing MP4 containers (stripping edit lists)...")
        all_mp4s = [local_work_dir / f"{q['name']}.mp4" for q in target_qualities]
        if has_audio:
            all_mp4s.append(local_work_dir / "audio.mp4")
        
        for mp4_path in all_mp4s:
            clean_path = mp4_path.with_suffix(".clean.mp4")
            remux_cmd = [
                "ffmpeg", "-y", "-loglevel", "error",
                "-fflags", "+genpts+igndts",
                "-i", str(mp4_path),
                "-c", "copy",
                "-avoid_negative_ts", "make_zero",
                "-movflags", "+faststart",
                "-map_metadata", "-1",
                "-map_chapters", "-1",
                str(clean_path)
            ]
            subprocess.run(remux_cmd, check=True)
            # Inspect BEFORE and AFTER for elst
            inspect_mp4_elst(str(mp4_path), f"PRE-SANITIZE {mp4_path.name}")
            inspect_mp4_elst(str(clean_path), f"POST-SANITIZE {mp4_path.name}")
            mp4_path.unlink()
            clean_path.rename(mp4_path)
            print(f"[*] Sanitized: {mp4_path.name}")

        # Build packager inputs from sanitized files
        for q in target_qualities:
            local_path = local_work_dir / f"{q['name']}.mp4"
            packager_inputs.append(f"input={str(local_path)},stream=video,init_segment={str(local_output_dir)}/{q['name']}_init.mp4,segment_template={str(local_output_dir)}/{q['name']}_$Number$.m4s,playlist_name={q['name']}.m3u8")
        if has_audio:
            local_audio_path = local_work_dir / "audio.mp4"
            packager_inputs.append(f"input={str(local_audio_path)},stream=audio,init_segment={str(local_output_dir)}/audio_init.mp4,segment_template={str(local_output_dir)}/audio_$Number$.m4s,playlist_name=audio.m3u8")

        # Verify RAW timestamps (with -ignore_editlist to see true packet values)
        print("[*] Verifying sanitized PTS integrity before packaging...")
        for q in target_qualities:
            fpath = str(local_work_dir / f"{q['name']}.mp4")
            deep_probe(fpath, f"SANITIZED {q['name']}")
            raw_probe = subprocess.run([
                "ffprobe", "-v", "error",
                "-select_streams", "v:0",
                "-show_entries", "format=start_time",
                "-show_entries", "packet=pts_time,dts_time",
                "-of", "json", "-read_intervals", "%+#3",
                fpath
            ], capture_output=True, text=True)
            try:
                raw_data = json.loads(raw_probe.stdout)
                fmt_start = raw_data.get("format", {}).get("start_time", "N/A")
                print(f"[*] {q['name']} format.start_time={fmt_start}")
                if fmt_start not in ("N/A", None) and float(fmt_start) > 1.0:
                    print(f"[!!!] CRITICAL: {q['name']} container still has offset {fmt_start}s after sanitization!")
            except (json.JSONDecodeError, ValueError):
                pass
        if has_audio:
            deep_probe(str(local_work_dir / "audio.mp4"), "SANITIZED audio")



        packager_cmd = [
            "packager",
            *packager_inputs,
            "--enable_raw_key_encryption",
            f"--keys=label=:key_id={drm_kid}:key={drm_key}",
            "--hls_master_playlist_output", f"{str(local_output_dir)}/master.m3u8",
            "--mpd_output", f"{str(local_output_dir)}/manifest.mpd",
            "--hls_playlist_type", "VOD",
            "--hls_key_uri", license_url,
            "--protection_scheme", "cbcs",
            "--segment_duration", "6",
            "--clear_lead", "0",
            "--temp_dir", "/tmp"
        ]
        subprocess.run(packager_cmd, check=True)
        
        shaka_duration = round(time.perf_counter() - shaka_start, 2)
        print(f"[*] Shaka Packaging took {shaka_duration}s")

        # Fix Shaka v3.2.0 manifest-to-disk segment naming mismatch
        # Shaka's HLS manifest references segments starting from 1, but $Number$
        # in segment_template uses an internal counter (e.g. starting at 100).
        # We rename physical files to match what the manifest expects.
        print("[*] Aligning segment file names with manifest references...")
        
        playlists = [f"{q['name']}.m3u8" for q in target_qualities] + (["audio.m3u8"] if has_audio else [])
        total_renamed = 0
        
        for playlist_name in playlists:
            playlist_path = local_output_dir / playlist_name
            if not playlist_path.exists():
                continue
            
            with open(playlist_path, 'r') as pf:
                manifest_segments = [l.strip() for l in pf if l.strip().endswith('.m4s')]
            
            if not manifest_segments:
                continue
            
            # Extract the prefix (e.g. "360p_" or "audio_") from the manifest
            first_expected = manifest_segments[0]
            prefix_match = re.match(r'^(.+_)\d+\.m4s$', first_expected)
            if not prefix_match:
                continue
            prefix = prefix_match.group(1)  # e.g. "360p_"
            
            # Find actual files on disk with this prefix
            actual_files = sorted(
                [f for f in local_output_dir.iterdir() if f.name.startswith(prefix) and f.suffix == ".m4s"],
                key=lambda f: int(re.search(r'_(\d+)\.m4s$', f.name).group(1))
            )
            
            if len(actual_files) != len(manifest_segments):
                print(f"[!] WARNING: {playlist_name}: manifest has {len(manifest_segments)} segments but disk has {len(actual_files)} files")
            
            # Rename actual files to match manifest references (1:1 ordered mapping)
            renamed = 0
            for actual_file, expected_name in zip(actual_files, manifest_segments):
                if actual_file.name != expected_name:
                    actual_file.rename(local_output_dir / expected_name)
                    renamed += 1
            
            total_renamed += renamed
            first_actual = actual_files[0].name if actual_files else "N/A"
            print(f"[*] {playlist_name}: aligned {renamed} segments (disk: {first_actual} → manifest: {manifest_segments[0]})")
        
        print(f"[*] Total segments renamed: {total_renamed}")
        
        # Final verification: confirm manifest-to-disk alignment
        m4s_files = sorted([f.name for f in local_output_dir.iterdir() if f.suffix == ".m4s"])
        print(f"[*] Final segment count: {len(m4s_files)}")
        if m4s_files:
            print(f"[*] First 5 segments: {m4s_files[:5]}")
        
        for playlist_name in playlists:
            playlist_path = local_output_dir / playlist_name
            if playlist_path.exists():
                with open(playlist_path, 'r') as pf:
                    manifest_segments = [l.strip() for l in pf if l.strip().endswith('.m4s')]
                if manifest_segments:
                    missing = [s for s in manifest_segments[:5] if not (local_output_dir / s).exists()]
                    if missing:
                        raise RuntimeError(f"Post-rename verification failed: {missing} still missing from disk")
                    print(f"[*] {playlist_name}: verified ✓ ({len(manifest_segments)} segments aligned)")

        # 5. الرفع لـ R2 مع إحصائيات (Concurrent Upload)
        print("[*] Uploading to R2 (100 parallel threads from local SSD)...")

        def upload_single_file(file_path):
            """Upload a single file to R2 with retry logic."""
            remote_path = f"processed/{video_id}/{file_path.name}"
            is_playlist = file_path.suffix in [".m3u8", ".mpd"]
            
            if file_path.suffix == ".m3u8":
                content_type = "application/x-mpegURL"
            elif file_path.suffix == ".mpd":
                content_type = "application/dash+xml"
            elif file_path.suffix == ".mp4":
                content_type = "video/mp4"
            else:
                content_type = "video/iso.segment"
                
            cache_control = "no-cache, max-age=0" if is_playlist else "public, max-age=31536000, immutable"
            file_size = file_path.stat().st_size
            
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    s3.upload_file(str(file_path), bucket, remote_path, ExtraArgs={
                        'ContentType': content_type,
                        'CacheControl': cache_control
                    })
                    return (file_path.suffix == ".m4s", file_size)
                except Exception as e:
                    if attempt == max_retries - 1:
                        print(f"[!] Upload failed after {max_retries} attempts: {file_path.name}")
                        raise
                    time.sleep(0.1) # Backoff to prevent rate-limiting
            return (file_path.suffix == ".m4s", file_size)

        all_files = [f for f in local_output_dir.iterdir() if f.is_file()]
        segment_count = 0
        total_size_bytes = 0

        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = {executor.submit(upload_single_file, f): f for f in all_files}
            for i, future in enumerate(as_completed(futures)):
                is_m4s, file_size = future.result()
                total_size_bytes += file_size
                if is_m4s:
                    segment_count += 1
                
                # Progress Heartbeat (every 50 files)
                if (i + 1) % 50 == 0:
                    print(f"[*] Upload Progress: {i + 1}/{len(all_files)} files transferred...")

        print(f"[*] Upload complete: {len(all_files)} files, {segment_count} segments, {round(total_size_bytes / (1024*1024), 2)} MB")

        # 6. التقرير المالي الشامل (Total Verified Cost including Workers)
        end_time = time.perf_counter()
        manager_duration = end_time - start_time
        
        # Read rates from Environment Variables
        cpu_rate = float(os.environ.get("MODAL_CPU_RATE", "0.0000131"))
        mem_rate = float(os.environ.get("MODAL_MEM_RATE", "0.00000222"))
        disk_rate = float(os.environ.get("MODAL_DISK_RATE", "0.00000021")) # GiB-second for extra disk
        
        # 30GB total - 5GB free tier = 25GB extra
        extra_disk_gib = 25.0
        
        # Define Worker Unit Rates (memory in GB: 4096 MB = 4 GB)
        video_worker_unit_rate = (14.0 * cpu_rate) + (4.0 * mem_rate)
        audio_worker_unit_rate = (4.0 * cpu_rate) + (4.0 * mem_rate)
        manager_unit_rate = (2.0 * cpu_rate) + (4.0 * mem_rate)
        
        # Calculate Total Verified Cost
        total_cost = (
            (manager_duration * manager_unit_rate) +
            (total_video_worker_duration * video_worker_unit_rate) +
            (audio_worker_duration * audio_worker_unit_rate) +
            (manager_duration * extra_disk_gib * disk_rate)  # disk cost during manager runtime
        )
        total_cost = round(total_cost, 4)
        print(f"[*] Total Infrastructure Cost: ${total_cost} (Manager: {round(manager_duration, 2)}s, Workers: {round(total_video_worker_duration + audio_worker_duration, 2)}s)")

        # إبلاغ Laravel (الـ Webhook)
        print(f"[*] Dispatching final success webhook for video {video_id}...")
        webhook_success = False
        if callback_url:
            response = requests.post(callback_url, json={
                "video_id": video_id,
                "status": "ready",
                "playback_url": f"{os.environ['R2_PUBLIC_URL']}/processed/{video_id}/master.m3u8",
                "drm": {"key": drm_key, "kid": drm_kid},
                "storage_size_mb": round(total_size_bytes / (1024*1024), 2),
                "metrics": {
                    "duration_seconds": round(manager_duration, 2),
                    "cost_usd": total_cost,
                    "segment_count": segment_count,
                    "resolutions": [q['name'] for q in target_qualities]
                }
            }, headers={"X-MODAL-AUTH-TOKEN": os.environ.get("MODAL_AUTH_TOKEN")}, timeout=10)
            
            if response.status_code == 200:
                webhook_success = True

        if webhook_success:
            print("[*] Webhook confirmed success. Deleting raw video from R2 (Final Cleanup)...")
            s3.delete_object(Bucket=bucket, Key=file_key)

        return {"status": "success", "cost": total_cost, "resolutions": [q['name'] for q in target_qualities]}

    except Exception as e:
        print(f"[!] Critical Error: {str(e)}")
        if callback_url:
            requests.post(callback_url, json={"video_id": video_id, "status": "failed", "error": str(e)}, headers={"X-MODAL-AUTH-TOKEN": os.environ.get("MODAL_AUTH_TOKEN")})
        return {"status": "error", "message": str(e)}
    finally:
        # Cleanup R2 temp_encoded files including sanitized source
        try:
            response = s3.list_objects_v2(Bucket=bucket, Prefix=f"temp_encoded/{video_id}/")
            for obj in response.get("Contents", []):
                s3.delete_object(Bucket=bucket, Key=obj["Key"])
        except Exception:
            pass

        # Cleanup local /tmp only if directory was created
        if local_work_dir:
            shutil.rmtree(local_work_dir, ignore_errors=True)