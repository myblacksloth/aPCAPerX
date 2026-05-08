"""
Entry point dell'API REST — PCAPCaper Backend.

Espone tre endpoint:
  GET  /api/health   → verifica che il servizio sia attivo
  POST /api/analyze  → riceve un file PCAP e restituisce l'analisi completa
  POST /api/enrich-ips → arricchisce IP pubblici tramite servizi esterni

Il file ricevuto viene scritto in una directory temporanea del sistema operativo,
analizzato, e poi cancellato. Nessun dato persiste sul server tra una richiesta e l'altra.
"""

import os
import tempfile
import logging

from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from models import AnalysisResult, IPEnrichmentRequest, IPEnrichmentResponse
from analyzer import analyze_pcap, MAX_FILE_SIZE
from external_enrichment import enrich_ips

# ── Configurazione del logging ─────────────────────────────────────────────────
# Mostra timestamp, livello e messaggio su stdout (visibile in `docker logs`)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# ── Inizializzazione dell'applicazione FastAPI ─────────────────────────────────
app = FastAPI(
    title="PCAPCaper API",
    description=(
        "Analizza file PCAP/PCAPNG ed estrae statistiche dettagliate: "
        "indirizzi IP, porte, protocolli, conversazioni e timeline del traffico."
    ),
    version="1.0.0",
    # Indirizzo della documentazione interattiva Swagger UI
    docs_url="/docs",
    redoc_url="/redoc",
)

# ── Middleware CORS ────────────────────────────────────────────────────────────
# Permette al frontend (Vite in locale o Nginx in Docker) di chiamare l'API.
# In produzione, sostituire allow_origins=["*"] con il dominio effettivo.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["POST", "GET", "OPTIONS"],
    allow_headers=["*"],
)

# ── Estensioni file accettate ──────────────────────────────────────────────────
ALLOWED_EXTENSIONS = {".pcap", ".pcapng", ".cap"}


# ─── Endpoint: health check ───────────────────────────────────────────────────

@app.get(
    "/api/health",
    tags=["Utility"],
    summary="Verifica che il servizio sia attivo",
)
def health_check():
    """
    Restituisce sempre {"status": "ok"} se il server è in esecuzione.
    Utilizzato dai health-check di Docker Compose e dai proxy inversi.
    """
    return {"status": "ok", "service": "pcap-analyzer"}


# ─── Endpoint: arricchimento IP tramite tool esterni ──────────────────────────

@app.post(
    "/api/enrich-ips",
    response_model=IPEnrichmentResponse,
    tags=["Analisi"],
    summary="Arricchisce indirizzi IP usando servizi esterni",
    response_description="Mappa IP -> dati esterni recuperati",
)
def enrich_ips_endpoint(payload: IPEnrichmentRequest):
    """
    Riceve una lista di indirizzi IP già estratti dal PCAP e interroga servizi
    esterni per recuperare ASN, prefissi BGP, RDAP, reverse DNS e dati GeoIP.

    Nota privacy: gli indirizzi privati, locali e riservati vengono scartati
    prima di qualunque chiamata esterna. L'endpoint viene chiamato solo su
    azione esplicita dell'utente dal pulsante "Analizza con tool esterni".
    """
    try:
        logger.info("Avvio arricchimento esterno per %d IP", len(payload.ips))
        results = enrich_ips(payload.ips)
        logger.info("Arricchimento esterno completato per %d IP", len(results))
        return IPEnrichmentResponse(results=results)
    except Exception as exc:
        # Un errore inatteso viene loggato per poter diagnosticare problemi di rete/API.
        logger.exception("Errore imprevisto durante l'arricchimento IP")
        raise HTTPException(
            status_code=500,
            detail="Errore durante l'arricchimento esterno degli IP.",
        ) from exc


# ─── Endpoint: analisi PCAP ───────────────────────────────────────────────────

@app.post(
    "/api/analyze",
    response_model=AnalysisResult,
    tags=["Analisi"],
    summary="Analizza un file PCAP/PCAPNG",
    response_description="Report completo con statistiche di rete",
)
async def analyze(file: UploadFile = File(..., description="File PCAP, PCAPNG o CAP da analizzare")):
    """
    Riceve un file di cattura di rete e restituisce:

    - **summary**: statistiche generali (pacchetti totali, byte, durata, ecc.)
    - **protocols**: distribuzione dei protocolli di rete
    - **top_src_ips / top_dst_ips**: indirizzi IP più attivi
    - **top_src_ports / top_dst_ports**: porte più utilizzate
    - **conversations**: conversazioni bidirezionali tra coppie di IP
    - **timeline**: andamento del traffico nel tempo
    - **packets**: lista dettagliata di tutti i pacchetti

    **Limite dimensione**: 100 MB.
    """

    # ── Validazione dell'estensione del file ──────────────────────────────
    filename = file.filename or "upload.pcap"
    ext = os.path.splitext(filename)[1].lower()

    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Formato file non supportato: '{ext}'. "
                f"Estensioni accettate: {', '.join(ALLOWED_EXTENSIONS)}"
            ),
        )

    # ── Lettura del contenuto e controllo dimensione ──────────────────────
    logger.info("File ricevuto: %s", filename)
    content = await file.read()

    if len(content) == 0:
        raise HTTPException(status_code=400, detail="Il file è vuoto.")

    if len(content) > MAX_FILE_SIZE:
        size_mb = len(content) / 1_048_576
        raise HTTPException(
            status_code=413,
            detail=f"File troppo grande ({size_mb:.1f} MB). Limite massimo: 100 MB.",
        )

    # ── Scrittura del file temporaneo ed esecuzione dell'analisi ─────────
    # Il file temporaneo viene eliminato nel blocco `finally`, anche in caso di errore.
    tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix=ext)

    try:
        # Scrivi il contenuto del file caricato sul disco temporaneo
        tmp_file.write(content)
        tmp_file.flush()
        tmp_file.close()

        logger.info(
            "Avvio analisi: %s (%d byte, %.2f MB)",
            filename, len(content), len(content) / 1_048_576
        )

        # Delega l'analisi al modulo analyzer.py
        result = analyze_pcap(tmp_file.name, filename)

        logger.info(
            "Analisi completata: %d pacchetti, %.3f s di cattura",
            result.summary.total_packets,
            result.summary.duration_seconds,
        )
        return result

    except ValueError as exc:
        # Errori noti: file corrotto, nessun pacchetto, formato non valido
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    except Exception as exc:
        # Errori imprevisti: logga il traceback completo per il debugging
        logger.exception("Errore imprevisto durante l'analisi di '%s'", filename)
        raise HTTPException(
            status_code=500,
            detail="Errore interno del server. Controlla i log per i dettagli.",
        ) from exc

    finally:
        # Elimina sempre il file temporaneo per non lasciare dati sul server
        try:
            os.unlink(tmp_file.name)
        except OSError:
            pass
