# Bilibili Downloader

Download Bilibili videos in the best available quality (up to 4K) using your account.

## Usage

Always wrap the URL in quotes:

```bash
bili "https://www.bilibili.com/video/BV1ZSfqBSEUW/"
```

The video will be saved in `/Users/kujin/Projects/bilibili/` named after the video title.

## If cookies expire (login stops working)

Run this once to refresh your cookies from Chrome:

```bash
cd /Users/kujin/Projects/bilibili
.venv/bin/yt-dlp --cookies-from-browser chrome --cookies cookies.txt --skip-download "https://www.bilibili.com/video/BV1rNAXz6E8a/"
```

## Manual run (without bili command)

```bash
cd /Users/kujin/Projects/bilibili
.venv/bin/python3 download.py "https://www.bilibili.com/video/BV1ZSfqBSEUW/"
```

## Notes

- URLs must always be wrapped in double quotes (they contain `?` and `&` which the shell interprets as special characters)
- 4K requires a Bilibili premium account (already configured via cookies)
- Videos are saved as `.mp4` — open with IINA for best playback experience
