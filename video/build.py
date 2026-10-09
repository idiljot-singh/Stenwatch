"""Build the management video: python video/build.py            (whole video)
                              python video/build.py 3 8 12.5     (just save those moments as PNG to check the look)
Scenes are one animated page (anim.html) driven by setT(seconds); we step it frame by frame in Edge via Playwright and pipe the frames
to ffmpeg together with the narration. Needs video/audio/s1..s5.mp3, video/shots/*.png, Edge, ffmpeg, `pip install playwright`."""
import array, json, math, shutil, subprocess, sys, wave
from pathlib import Path

from playwright.sync_api import sync_playwright

HERE = Path(__file__).resolve().parent
AUDIO, SHOTS, OUT = HERE / "audio", HERE / "shots", HERE / "out"
FFMPEG = next(Path.home().joinpath("AppData/Local/Microsoft/WinGet/Packages").rglob("ffmpeg.exe"), None) or Path(shutil.which("ffmpeg"))
FFPROBE = FFMPEG.with_name("ffprobe.exe")
LEAD, TAIL, TRN, FPS = 0.6, 0.5, 0.5, 30   # narration starts LEAD after its scene starts; scenes overlap by TRN while they cross-fade


def plan():
    durs = [float(subprocess.run([str(FFPROBE), "-v", "error", "-show_entries", "format=duration", "-of", "csv=p=0", str(AUDIO / f"s{i}.mp3")],
                                 capture_output=True, text=True).stdout) for i in range(1, 6)]
    scenes, s = [], 0.0
    for a in durs:
        L = a + LEAD + TAIL
        scenes.append({"s": round(s, 3), "a": a, "L": round(L, 3)})
        s += L - TRN
    return scenes, scenes[-1]["s"] + scenes[-1]["L"]


def envelope(path):
    """Loudness of the narration for every video frame (0..1): drives the mascot's mouth."""
    with wave.open(str(path)) as w:
        ch, sr = w.getnchannels(), w.getframerate()
        data = array.array("h")
        data.frombytes(w.readframes(w.getnframes()))
    mono, step = data[::ch], sr // FPS
    rms = [math.sqrt(sum(x * x for x in mono[i:i + step]) / max(1, len(mono[i:i + step]))) for i in range(0, len(mono), step)]
    ref = sorted(rms)[int(len(rms) * .95)] or 1
    env, cur = [], 0.0
    for r in rms:
        want = min(1.0, r / ref) ** .8
        cur = want if want > cur else cur * .55 + want * .45   # fast attack, soft release
        env.append(round(cur, 3))
    return env


def mix_audio(scenes, total):
    inputs = sum([["-i", str(AUDIO / f"s{i + 1}.mp3")] for i in range(5)], [])
    delays = ";".join(f"[{i}:a]adelay={int((sc['s'] + LEAD) * 1000)}:all=1[a{i}]" for i, sc in enumerate(scenes))
    OUT.mkdir(exist_ok=True)
    mix = OUT / "narration.wav"
    subprocess.run([str(FFMPEG), "-y", "-loglevel", "error", *inputs, "-filter_complex",
                    delays + ";" + "".join(f"[a{i}]" for i in range(5)) + f"amix=inputs=5:normalize=0,apad=whole_dur={total:.3f},atrim=0:{total:.3f}[m]",
                    "-map", "[m]", str(mix)], check=True)
    return mix


def page_for(scenes, total, env):
    html = (HERE / "anim.html").read_text(encoding="utf-8")
    for k, v in {"__SC__": json.dumps(scenes), "__TR__": json.dumps([x["s"] for x in scenes[1:]]), "__TOTAL__": str(total), "__TRN__": str(TRN),
                 "__LEAD__": str(LEAD), "__ENV__": json.dumps(env), "__DASH__": (SHOTS / "dashboard.png").as_uri(), "__REP__": (SHOTS / "report.png").as_uri(),
                 "__BRI__": (SHOTS / "brief.png").as_uri()}.items():
        html = html.replace(k, v)
    OUT.mkdir(exist_ok=True)
    page = OUT / "anim.html"
    page.write_text(html, encoding="utf-8")
    return page


def main():
    scenes, total = plan()
    mix = mix_audio(scenes, total)
    page = page_for(scenes, total, envelope(mix))
    print("scenes:", [(x["s"], x["L"]) for x in scenes], f"total {total:.1f}s")
    with sync_playwright() as p:
        browser = p.chromium.launch(channel="msedge")
        pg = browser.new_page(viewport={"width": 1920, "height": 1080})
        pg.goto(page.as_uri())
        pg.wait_for_function("[...document.images].every(i => i.complete && i.naturalWidth > 0)", timeout=60000)
        pg.wait_for_timeout(500)
        if len(sys.argv) > 1:  # preview mode
            for t in map(float, sys.argv[1:]):
                pg.evaluate(f"setT({t})")
                pg.screenshot(path=str(OUT / f"t{t:g}.png"))
            browser.close()
            return
        final = HERE / "stenwatch-management-video.mp4"
        ff = subprocess.Popen([str(FFMPEG), "-y", "-loglevel", "error", "-f", "image2pipe", "-framerate", str(FPS), "-i", "-", "-i", str(mix),
                               "-c:v", "libx264", "-preset", "medium", "-crf", "17", "-pix_fmt", "yuv420p", "-c:a", "aac", "-b:a", "192k",
                               "-movflags", "+faststart", "-shortest", str(final)], stdin=subprocess.PIPE)
        n = int(total * FPS)
        for f in range(n):
            pg.evaluate(f"setT({f / FPS})")
            for attempt in range(4):   # a browser hiccup on one frame must not kill a 3-minute render
                try:
                    ff.stdin.write(pg.screenshot(type="jpeg", quality=94, timeout=60000))
                    break
                except Exception as e:
                    print(f"frame {f}: retry {attempt + 1} ({type(e).__name__})", flush=True)
                    if attempt == 3:
                        raise
                    pg.wait_for_timeout(1000)
            if f % 150 == 0:
                print(f"frame {f}/{n}", flush=True)
        ff.stdin.close()
        ff.wait()
        browser.close()
    print(final, f"({total:.1f}s)")
    if total > 60:
        sys.exit("longer than 60 s: shorten the script")


if __name__ == "__main__":
    main()
