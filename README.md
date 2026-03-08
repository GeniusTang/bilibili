# Bilibili Downloader

Download Bilibili videos in the best available quality (up to 4K) using your account.

## Setup

```bash
git clone https://github.com/GeniusTang/bilibili.git
cd bilibili
python3 -m venv .venv
.venv/bin/pip install yt-dlp
```

Add the `bili` script to your PATH or create a symlink:

```bash
ln -s "$(pwd)/bili" /usr/local/bin/bili
```

## Usage

Always wrap the URL in quotes:

```bash
bili "https://www.bilibili.com/video/BV1xxxxx/"
```

The video will be saved in the current directory, named after the video title.

## Manual run (without bili command)

```bash
.venv/bin/python3 download.py "https://www.bilibili.com/video/BV1xxxxx/"
```

## Notes

- URLs must always be wrapped in double quotes (they contain `?` and `&` which the shell interprets as special characters)
- 4K requires a Bilibili premium account
- Cookies are read from Firefox automatically — make sure you're logged into Bilibili in Firefox
- Videos are saved as `.mp4` — open with IINA for best playback experience
