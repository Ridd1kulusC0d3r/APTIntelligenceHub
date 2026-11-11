#!/usr/bin/env bash
# Converte as gravações (webm) em MP4 H.264 + GIF e monta o vídeo-tour. Requer ffmpeg e python3.
set -e
RAW="${APT_RAW:-${TMPDIR:-/tmp}/apt-rec}"; OUT="$(dirname "$0")/../assets/media"; mkdir -p "$OUT"
python3 - "$RAW" "$OUT" <<'PY'
import json,subprocess,sys
raw,out=sys.argv[1:3]; t=json.load(open(f"{raw}/times.json")); order=['map','graph','trace','detect','theme']
for n in order:
    r=t[n]
    subprocess.run(["ffmpeg","-v","error","-y","-ss",f"{r+0.3:.2f}","-i",f"{raw}/{n}.webm","-vf","scale=1280:720:flags=lanczos,fps=30,format=yuv420p","-c:v","libx264","-crf","24","-preset","slow","-movflags","+faststart","-an",f"{out}/{n}.mp4"],check=True)
    subprocess.run(["ffmpeg","-v","error","-y","-i",f"{out}/{n}.mp4","-vf","fps=10,scale=720:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors=80:stats_mode=diff[p];[b][p]paletteuse=dither=bayer:bayer_scale=5:diff_mode=rectangle",f"{out}/{n}.gif"],check=True)
open(f"{raw}/list.txt","w").write("".join(f"file '{out}/{n}.mp4'\n" for n in order))
subprocess.run(["ffmpeg","-v","error","-y","-f","concat","-safe","0","-i",f"{raw}/list.txt","-c","copy",f"{out}/apt-threat-map-tour.mp4"],check=True)
PY
echo "ok: $OUT"
