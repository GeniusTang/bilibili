# Bilibili Favorites Downloader

A web-based tool to browse and batch download videos from your Bilibili favorites.

## Features

- **QR Code & Password Login** — Log in with your Bilibili account via QR code scan or username/password (with GeeTest captcha and SMS verification support)
- **Persistent Sessions** — Stay logged in across server restarts (30-day sessions)
- **Browse Favorites** — View all your favorite folders and videos with thumbnails
- **Search & Filter** — Search videos by title or uploader, filter by upload date or date added to favorites
- **Multi-Select & Batch Download** — Select individual videos or use "select all" to batch download
- **Parallel Downloads** — Configure 1-10 simultaneous downloads for faster batch processing
- **Download Management** — Real-time progress, speed, ETA per video and for the entire batch; cancel individual or all downloads
- **Custom Download Directory** — Browse and select any local or network-mounted directory (e.g., NAS via `/Volumes/`)
- **Video Preview** — Click the play button on any thumbnail to preview via Bilibili's embedded player
- **Video Info** — Shows best available resolution, quality label, estimated size, upload date, and date added to favorites

## Requirements

- Python 3.8+
- [yt-dlp](https://github.com/yt-dlp/yt-dlp)
- [FFmpeg](https://ffmpeg.org/)

## Setup

```bash
# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install flask qrcode requests pycryptodome yt-dlp

# Run the server
python app.py
```

Open http://localhost:5000 in your browser.

## Usage

1. Log in with your Bilibili account (QR code or password)
2. Select a favorites folder from the sidebar
3. Browse, search, or filter videos
4. Select videos and click "Download Selected", or click "Download All"
5. Adjust the simultaneous download count (1-10) as needed
6. Change the download directory via the folder picker at the top

## Notes

- FFmpeg must be installed for merging video and audio streams (`brew install ffmpeg` on macOS)
- yt-dlp must be installed in the virtual environment
- Downloads are saved as MP4 files
- Network shares (e.g., MyCloud NAS) are accessible via `/Volumes/` after mounting in Finder
