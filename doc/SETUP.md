# Setup & Installation

## Local Setup (Without Docker)

### Requirements

- Python **3.11** or newer
- Node.js **20** or newer
- `pip` and `npm`
- macOS: `brew install libpcap` for Scapy support
- Debian/Ubuntu: `sudo apt-get install libpcap-dev`

### 1. Clone the repository

```bash
git clone https://github.com/myblacksloth/aPCAPerX.git
cd aPCAPerX
```

### 2. Start the backend

```bash
cd backend

python -m venv .venv
source .venv/bin/activate          # Linux/macOS
# .venv\Scripts\activate          # Windows

pip install -r requirements.txt
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

The backend is available at `http://localhost:8000`.

Interactive API documentation is available at `http://localhost:8000/docs`.

### 3. Start the frontend

Open a new terminal:

```bash
cd frontend
npm install
npm run dev
```

The frontend is available at `http://localhost:5173`.

> Vite automatically proxies `/api/*` requests to `localhost:8000`, so no manual configuration is required for local development.

---

## Docker Setup

### Requirements

- Docker **24+**
- Docker Compose **v2**

### Start the full stack

```bash
git clone https://github.com/myblacksloth/aPCAPerX.git
cd aPCAPerX

docker compose up --build
```

Open `http://localhost:3000` in your browser.

### Useful commands

```bash
# Start in detached mode
docker compose up --build -d

# Follow logs
docker compose logs -f

# Stop containers without removing them
docker compose stop

# Stop and remove containers and networks
docker compose down

# Rebuild only the backend
docker compose up --build backend
```

### Exposed ports

| Service | Host port | Container port | Notes |
| --- | --- | --- | --- |
| Frontend | 3000 | 80 | Web interface |
| Backend | 8000 | 8000 | REST API, mostly for debugging |
