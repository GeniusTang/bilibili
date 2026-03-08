import yt_dlp
import sys

def download(url):
    ydl_opts = {
        "outtmpl": "%(title)s.%(ext)s",   # save as video title
        "format": "bestvideo+bestaudio/best",
        "ffmpeg_location": "/opt/homebrew/bin/ffmpeg",
        "cookiesfrombrowser": ("firefox",),
    }
    with yt_dlp.YoutubeDL(ydl_opts) as ydl:
        ydl.download([url])

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python download.py <bilibili_url>")
        sys.exit(1)
    download(sys.argv[1])
