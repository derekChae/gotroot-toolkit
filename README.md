# GOTROOT Recon Agent

**Attack Surface Graph + Management Platform**

실시간 Recon 데이터를 D3.js 그래프로 시각화하고, 웹 UI에서 세션/타겟/발견사항을 관리하는 플랫폼.

## Quick Start

```bash
# 1. Install
pip install -r requirements.txt

# 2. Run
python server.py

# 3. Open
http://localhost:8000
```

Windows:
```cmd
gr install
gr start
```

## Architecture

```
gr-recon-agent/
├── server.py          ← FastAPI 서버 (API + UI 서빙)
├── db.py              ← SQLite 데이터베이스 (모든 CRUD)
├── ui.html            ← Web UI (D3 그래프 + 관리 대시보드)
├── requirements.txt   ← Python 의존성
├── gr.bat             ← Windows 명령어
├── gr.sh              ← Linux/Mac 명령어
└── gr_recon.db        ← SQLite DB (자동 생성)
```

## Features

### Web UI (http://localhost:8000)
- **Dashboard** — 전체 통계 (세션, 타겟, 발견사항)
- **Sessions** — 세션 등록/수정/삭제 (CRUD)
- **Import** — Recon JSON 데이터 임포트 → 자동 그래프 생성
- **Graph** — D3.js Force-Directed Attack Surface 그래프
- **Targets** — 타겟 상세 정보 + 리스크 스코어
- **Findings** — 발견사항 등록/수정/삭제 + 심각도 관리
- **Timeline** — 세션 이벤트 타임라인 (Correlation 데이터)

### Graph Visualization
- 노드 타입별 색상: Domain(cyan), IP(purple), Port(orange), Path(red), URL(yellow)
- Risk Score 기반 노드 크기 + 고위험 노드 Glow 효과
- 줌/패닝/드래그 지원
- 클릭 시 노드 상세 패널 + 공격 액션 목록

### Auto Risk Scoring
- Apache 2.4.49 → CVE-2021-41773 → +40점
- /phpmyadmin, /.htaccess, /.env → CRITICAL/HIGH 자동 탐지
- 포트별 위험도 가중치 (3306:+30, 6379:+35, 8080:+15)
- 인프라 타입 반영 (Cloud: +5)

### Data Persistence
- SQLite DB (`gr_recon.db`) — 서버 재시작해도 데이터 유지
- 세션 삭제 시 관련 타겟/노드/엣지 CASCADE 삭제

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /api/health | 서버 상태 |
| GET | /api/stats | 전체 통계 |
| GET | /api/sessions | 세션 목록 |
| POST | /api/sessions | 세션 생성 |
| PUT | /api/sessions/:id | 세션 수정 |
| DELETE | /api/sessions/:id | 세션 삭제 |
| POST | /api/import | Recon JSON 임포트 |
| GET | /api/graph/:sid | 그래프 데이터 (D3 format) |
| GET | /api/targets/:sid | 타겟 목록 |
| POST | /api/targets | 타겟 추가 |
| DELETE | /api/targets/:id | 타겟 삭제 |
| GET | /api/findings/:sid | 발견사항 목록 |
| POST | /api/findings | 발견사항 추가 |
| PUT | /api/findings/:id | 발견사항 수정 |
| DELETE | /api/findings/:id | 발견사항 삭제 |
| GET | /api/correlations/:sid | 타임라인 이벤트 |

## Import Data Format

```json
{
  "root_domain": "kmong.com",
  "targets": [
    {
      "domain": "subdomain.kmong.com",
      "ips": ["1.2.3.4"],
      "ports": [80, 443, 8080],
      "port_detail": {"80": "apache 2.4.49", "443": "unknown"},
      "dns_meta": {"ptr": {"exists": true, "values": ["ec2-...amazonaws.com"]}},
      "alive": [{"url": "https://...", "final_url": "https://...", "status": 200, "server": "nginx"}],
      "dirb": ["/login", "/phpmyadmin", "/.htaccess"],
      "infra": {"type": "cloud"}
    }
  ]
}
```

## Roadmap

- [x] #0 Prompt: Data Model + DB
- [x] #1 Prompt: D3 Force Graph
- [x] #2 Prompt: FastAPI Backend
- [x] Web UI CRUD (Sessions, Targets, Findings)
- [ ] #3 Prompt: DOM State Tracker (Playwright)
- [ ] #4 Prompt: Context-Aware Risk Scoring
- [ ] #5 Prompt: Auth Session Scanner
- [ ] #6 Prompt: Auto Fuzzing
- [ ] #7 Prompt: Pentest Session Recorder (AI GUI Agent)
- [ ] #8 Prompt: Report Generator + KISA
- [ ] #9 Prompt: Campaign Mode + Docker

## Git Workflow

```cmd
gr init https://github.com/yourusername/gr-recon-agent.git
gr save "feat: add session management"
gr push
```

## License

GOTROOT Internal Use
