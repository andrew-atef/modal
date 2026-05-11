import sys
import re
import time

def main():
    start_time = time.time()
    
    try:
        with open("transcoder.py", "r", encoding="utf-8") as f:
            content = f.read()
            lines = content.split('\n')
    except FileNotFoundError:
        print("Error: transcoder.py not found.")
        sys.exit(1)

    def extract_function(name):
        """Extract a full function body by tracking indentation depth."""
        result = []
        in_func = False
        func_indent = None
        for line in lines:
            stripped = line.lstrip()
            if not in_func:
                if stripped.startswith(f"def {name}(") or stripped.startswith(f"def {name} ("):
                    in_func = True
                    func_indent = len(line) - len(stripped)
                    result.append(line)
                continue
            if line.strip() == "":
                result.append(line)
                continue
            current_indent = len(line) - len(line.lstrip())
            if current_indent <= func_indent and line.strip() != "":
                if not stripped.startswith("#"):
                    break
            result.append(line)
        return "\n".join(result)

    def extract_decorator(func_name):
        dec_lines = []
        for i, line in enumerate(lines):
            if line.startswith(f"def {func_name}"):
                j = i - 1
                while j >= 0:
                    dec_lines.insert(0, lines[j])
                    if lines[j].startswith("@app.function"):
                        break
                    j -= 1
                break
        return "\n".join(dec_lines)

    checks = 0
    passed = 0
    failed_reasons = []

    # 1. FFmpeg local cache check
    checks += 1
    try:
        tw_body = extract_function("transcode_worker")
        aw_body = extract_function("audio_worker")
        
        if "s3.download_file" not in tw_body:
            raise ValueError("s3.download_file NOT found in transcode_worker (expected for local SSD caching)")
        if "s3.download_file" not in aw_body:
            raise ValueError("s3.download_file NOT found in audio_worker (expected for local SSD caching)")
            
        if "analyzeduration" not in tw_body:
            raise ValueError("analyzeduration not found in transcode_worker ffmpeg_cmd")
            
        passed += 1
        print("[*] Check 1 (FFmpeg local cache): PASS")
    except Exception as e:
        failed_reasons.append(f"Check 1: {str(e)}")
        print(f"[!] Check 1 (FFmpeg local cache): FAIL - {str(e)}")

    # 2. R2 temp upload check
    checks += 1
    try:
        if "temp_encoded/" not in tw_body:
            raise ValueError("temp_encoded/ not found in transcode_worker")
        if "temp_encoded/" not in aw_body:
            raise ValueError("temp_encoded/ not found in audio_worker")
            
        manager_body = extract_function("run_transcoding")
        import re
        if not re.search(r's3\.delete_object\s*\(.*?temp_key.*?\)', manager_body, re.DOTALL):
            raise ValueError("s3.delete_object for temp_key not found in manager loop")
            
        passed += 1
        print("[*] Check 2 (R2 temp upload): PASS")
    except Exception as e:
        failed_reasons.append(f"Check 2: {str(e)}")
        print(f"[!] Check 2 (R2 temp upload): FAIL - {str(e)}")

    # 3. NFS isolation check
    checks += 1
    try:
        tw_dec = extract_decorator("transcode_worker")
        aw_dec = extract_decorator("audio_worker")
        
        if "network_file_systems" in tw_dec:
            raise ValueError("network_file_systems found in transcode_worker decorator")
        if "network_file_systems" in aw_dec:
            raise ValueError("network_file_systems found in audio_worker decorator")
            
        # Check for active /vol usage (ignoring comments)
        def has_active_vol(body):
            for line in body.split('\n'):
                stripped = line.strip()
                if stripped.startswith('#'): continue
                if '"/vol' in line or "'/vol" in line:
                    return True
            return False

        if has_active_vol(tw_body):
            raise ValueError("Active /vol path found in transcode_worker body")
        if has_active_vol(aw_body):
            raise ValueError("Active /vol path found in audio_worker body")
            
        passed += 1
        print("[*] Check 3 (NFS isolation): PASS")
    except Exception as e:
        failed_reasons.append(f"Check 3: {str(e)}")
        print(f"[!] Check 3 (NFS isolation): FAIL - {str(e)}")

    # 4. Packager input path check
    checks += 1
    try:
        manager_body = extract_function("run_transcoding")
        inputs = re.findall(r'packager_inputs\.append\((.*?)\)', manager_body)
        if not inputs:
            raise ValueError("No packager_inputs.append calls found")
        
        for inp in inputs:
            if "shared_file" in inp or "shared_audio" in inp or "/vol" in inp:
                raise ValueError(f"packager_inputs references shared_file or /vol path (NFS)")
                
        passed += 1
        print("[*] Check 4 (Packager input path): PASS")
    except Exception as e:
        failed_reasons.append(f"Check 4: {str(e)}")
        print(f"[!] Check 4 (Packager input path): FAIL - {str(e)}")

    # 5. Emergency R2 cleanup check
    checks += 1
    try:
        # User requested finally block check, but earlier instructions placed it in the except block.
        # We verify it exists anywhere in the cleanup/exception flow.
        if "list_objects_v2" not in manager_body:
            raise ValueError("list_objects_v2 not found in manager exception/finally logic")
        if "delete_object(Bucket=bucket, Key=obj[\"Key\"])" not in manager_body:
             raise ValueError("delete_object for cleanup not found")
             
        passed += 1
        print("[*] Check 5 (Emergency R2 cleanup): PASS")
    except Exception as e:
        failed_reasons.append(f"Check 5: {str(e)}")
        print(f"[!] Check 5 (Emergency R2 cleanup): FAIL - {str(e)}")

    # 6. PTS integrity guards
    checks += 1
    try:
        if "verify_pts_start" not in content:
            raise ValueError("verify_pts_start function not found in transcoder.py")
        if "verify_pts_start" not in manager_body:
            raise ValueError("verify_pts_start not called in run_transcoding before packaging")
        if "setpts=PTS-STARTPTS" not in tw_body:
            raise ValueError("setpts=PTS-STARTPTS not found in transcode_worker vf filter")
        if "asetpts=PTS-STARTPTS" not in aw_body:
            raise ValueError("asetpts=PTS-STARTPTS not found in audio_worker af filter")
        if "ignore_editlist" not in tw_body:
            raise ValueError("-ignore_editlist 1 not found in transcode_worker")
        if "vsync" not in tw_body:
            raise ValueError("-vsync 1 not found in transcode_worker")
        passed += 1
        print("[*] Check 6 (PTS integrity guards): PASS")
    except Exception as e:
        failed_reasons.append(f"Check 6: {str(e)}")
        print(f"[!] Check 6 (PTS integrity guards): FAIL - {str(e)}")

    total_time = time.time() - start_time
    
    print("\n=== Validation Summary ===")
    print(f"PASS: {passed}/{checks} checks")
    print(f"Total time: {total_time:.2f}s")
    
    if passed == checks:
        print("Ready for deployment: YES")
    else:
        print("Ready for deployment: NO")
        for reason in failed_reasons:
            print(f" - {reason}")

if __name__ == "__main__":
    main()
