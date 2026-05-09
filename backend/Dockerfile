# ─── Stage unico: immagine Python slim ───────────────────────────────────────
# Usiamo python:3.11-slim per avere un'immagine leggera (~130 MB)
# con il minimo indispensabile per eseguire FastAPI e Scapy.
FROM python:3.11-slim

# Imposta la directory di lavoro all'interno del container
WORKDIR /app

# ── Installazione delle dipendenze di sistema ──────────────────────────────
# libpcap-dev: libreria C necessaria a Scapy per leggere i file PCAP
# build-essential: compilatore C usato da alcune dipendenze Python native
# La pulizia finale riduce la dimensione dell'immagine finale.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libpcap-dev \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

# ── Installazione delle dipendenze Python ─────────────────────────────────
# Copia prima solo requirements.txt per sfruttare la cache dei layer Docker:
# se il codice cambia ma le dipendenze no, questo layer non viene rieseguito.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── Copia del codice source ──────────────────────────────────────────────
COPY . .

# Porta su cui Uvicorn accetta le connessioni
EXPOSE 8000

# ── Server startup ───────────────────────────────────────────────────────
# --host 0.0.0.0 rende il serviceso raggiungibile dall'external del container
# --workers 1 is enough for this application (synchronous analysis)
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
