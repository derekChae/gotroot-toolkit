#!/bin/bash
# GOTROOT Recon Agent - Shell Commands

case "$1" in
  install)
    echo "[*] Installing dependencies..."
    pip install -r requirements.txt
    ;;
  start)
    echo ""
    echo "  GOTROOT Recon Agent"
    echo "  ===================="
    echo "  Starting server..."
    echo "  Open: http://localhost:8000"
    echo ""
    python3 server.py
    ;;
  init)
    echo "[*] Initializing git repository..."
    git init
    [ -n "$2" ] && git remote add origin "$2"
    git add -A
    git commit -m "init: GOTROOT Recon Agent"
    echo "[OK] Repository initialized. Run: ./gr.sh push"
    ;;
  save)
    git add -A
    git commit -m "${2:-update: $(date '+%Y-%m-%d %H:%M')}"
    echo "[OK] Changes saved."
    ;;
  push) git push -u origin main ;;
  pull) git pull origin main ;;
  status) git status ;;
  log) git log --oneline -10 ;;
  *)
    echo ""
    echo "  GOTROOT Recon Agent - Commands"
    echo "  ================================"
    echo "  ./gr.sh install     Install Python dependencies"
    echo "  ./gr.sh start       Start the web server"
    echo "  ./gr.sh init [url]  Initialize git + add remote"
    echo "  ./gr.sh save [msg]  Git add + commit"
    echo "  ./gr.sh push        Push to GitHub"
    echo "  ./gr.sh pull        Pull from GitHub"
    echo "  ./gr.sh status      Git status"
    echo "  ./gr.sh log         Show recent commits"
    echo ""
    ;;
esac
