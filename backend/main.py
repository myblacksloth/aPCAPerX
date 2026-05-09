"""
Entry point dell'API REST — PCAPCaper Backend.

Espone cinque endpoint:
  GET  /api/health   -> checks whether the service is active
  POST /api/analyze  → riceve un file PCAP e restituisce l'analysis completa
  POST /api/enrich-ips → arricchisce IP pubblici tramite external services
  POST /api/security-analysis → runs opt-in threat intelligence on traffico
  POST /api/dns-reputation → confronta domains DNS con liste esterne opt-in

The received file is written to an operating-system temporary directory,
analyzed, and then deleted. No data persists on the server between requests.
"""

import os
import tempfile
import logging

from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from starlette.concurrency import run_in_threadpool

from models import (
    AnalysisResult,
    IPEnrichmentRequest,
    IPEnrichmentResponse,
    DNSReputationRequest,
    DNSReputationResponse,
    SecurityAnalysisRequest,
    SecurityAnalysisResponse,
)
from analyzer import analyze_pcap
from external_enrichment import enrich_ips
from security_analysis import analyze_security
from dns_intelligence import analyze_dns_reputation
from config import TEMP_DIR, UPLOAD_CHUNK_SIZE, UPLOAD_MAX_MB

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
        "Analyzes PCAP/PCAPNG files and extracts detailed statistics: "
        "IP addresses, ports, protocolli, conversazioni e timeline del traffico."
    ),
    version="1.0.0",
    # Indirizzo della documentazione interactive Swagger UI
    docs_url="/docs",
    redoc_url="/redoc",
)

# ── Middleware CORS ────────────────────────────────────────────────────────────
# Allows the frontend (local Vite or Docker Nginx) to call the API.
# In production, replace allow_origins=["*"] with the actual domain.
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
    summary="Checks whether the service is active",
)
def health_check():
    """
    Restituisce sempre {"status": "ok"} se il server is in esecuzione.
    Utilizzato dai health-check di Docker Compose e dai proxy inversi.
    """
    return {"status": "ok", "service": "pcap-analyzer"}


# ─── Endpoint: IP enrichment through external tools ──────────────────────────

@app.post(
    "/api/enrich-ips",
    response_model=IPEnrichmentResponse,
    tags=["Analysis"],
    summary="Enriches IP addresses using external services",
    response_description="IP map -> retrieved external data",
)
def enrich_ips_endpoint(payload: IPEnrichmentRequest):
    """
    Receives a list of IP addresses already extracted from the PCAP and queries services
    external services to retrieve ASN, BGP prefixes, RDAP, reverse DNS, and GeoIP data.

    Privacy note: private, local, and reserved addresses are discarded
    prima di qualunque chiamata esterna. L'endpoint viene chiamato solo su
    explicit user action from the "Analyze with external tools" button.
    """
    try:
        logger.info("Starting external enrichment per %d IP", len(payload.ips))
        results = enrich_ips(payload.ips)
        logger.info("External enrichment completed per %d IP", len(results))
        return IPEnrichmentResponse(results=results)
    except Exception as exc:
        # Un error inatteso viene loggato per poter diagnosticare problemi di rete/API.
        logger.exception("Error imprevisto durante l'arricchimento IP")
        raise HTTPException(
            status_code=500,
            detail="Error durante l'arricchimento external degli IP.",
        ) from exc


# ─── Endpoint: analysis di sicurezza advanced ───────────────────────────────

@app.post(
    "/api/security-analysis",
    response_model=SecurityAnalysisResponse,
    tags=["Analysis"],
    summary="Analyzes traffic with the Security engine and threat intelligence",
    response_description="Finding, score e raccomandazioni di sicurezza",
)
def security_analysis_endpoint(payload: SecurityAnalysisRequest):
    """
    Receives packets already extracted from the PCAP and enriched IP information.

    Nota privacy: questo endpoint puo interrogare fonti esterne di threat
    intelligence for observed public IPs. The frontend calls it only after
    explicit user confirmation in the Advanced Security tab popup.
    """
    try:
        logger.info(
            "Starting advanced security analysis on %d packets",
            len(payload.packets),
        )
        result = analyze_security(payload)
        logger.info(
            "Security analysis completed: %d finding, %d IP pubblici",
            result.summary.total_findings,
            result.summary.analyzed_public_ips,
        )
        return result
    except Exception as exc:
        # L'error viene loggato per distinguere problemi di rete da bug del motore.
        logger.exception("Unexpected error during Security analysis")
        raise HTTPException(
            status_code=500,
            detail="Error durante l'analysis di sicurezza advanced.",
        ) from exc


# ─── Endpoint: reputazione DNS esterna ─────────────────────────────────────

@app.post(
    "/api/dns-reputation",
    response_model=DNSReputationResponse,
    tags=["Analysis"],
    summary="Checks observed DNS domains against external lists",
    response_description="Domain reputation -> sources and categories",
)
def dns_reputation_endpoint(payload: DNSReputationRequest):
    """
    Compares DNS-requested domains with open external lists.

    Privacy note: this endpoint is called only after explicit confirmation
    from the user in the DNS tab. The backend receives domains already extracted from the PCAP
    e non effettua alcun controllo external durante la normale analysis.
    """
    try:
        logger.info("Starting DNS reputation for %d domains", len(payload.domains))
        result = analyze_dns_reputation(payload.domains, payload.max_domains)
        logger.info("DNS reputation completed for %d domains", len(result.results))
        return result
    except Exception as exc:
        # Log completo per distinguere problemi di download liste da errori applicativi.
        logger.exception("Error imprevisto durante la reputazione DNS")
        raise HTTPException(
            status_code=500,
            detail="Error durante l'analysis reputazionale DNS.",
        ) from exc


# ─── Endpoint: analysis PCAP ───────────────────────────────────────────────────

@app.post(
    "/api/analyze",
    response_model=AnalysisResult,
    tags=["Analysis"],
    summary="Analyzes a PCAP/PCAPNG file",
    response_description="Report completo con statistiche di rete",
)
async def analyze(file: UploadFile = File(..., description="File PCAP, PCAPNG o CAP da analizzare")):
    """
    Receives a network capture file and returns:

    - **summary**: general statistics (total packets, bytes, duration, etc.)
    - **protocols**: distribuzione dei protocolli di rete
    - **top_src_ips / top_dst_ips**: IP addresses most active
    - **top_src_ports / top_dst_ports**: ports most used
    - **conversations**: conversazioni bidirezionali tra coppie di IP
    - **timeline**: traffic trend over time
    - **packets**: lista detailsata di tutti i packets

    The file is streamed to temporary disk storage to avoid keeping it in RAM.
    Se `PCAPCAPER_UPLOAD_MAX_MB=0` non viene applicato alcun limite applicativo.
    """

    # ── Validazione dell'estensione del file ──────────────────────────────
    filename = file.filename or "upload.pcap"
    ext = os.path.splitext(filename)[1].lower()

    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Unsupported file format: '{ext}'. "
                f"Estensioni accettate: {', '.join(ALLOWED_EXTENSIONS)}"
            ),
        )

    # ── Lettura streaming e controllo dimensione opzionale ────────────────
    logger.info("File ricevuto: %s", filename)
    os.makedirs(TEMP_DIR, exist_ok=True)
    max_bytes = UPLOAD_MAX_MB * 1_048_576 if UPLOAD_MAX_MB > 0 else 0
    total_bytes = 0

    # The temporary file is removed in the `finally` block, even in case of
    # error. Usiamo dir configurabile per Docker/produzione.
    tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix=ext, dir=TEMP_DIR)

    try:
        # Scrive l'upload a chunk per evitare di caricare PCAP grandi in memoria.
        while True:
            chunk = await file.read(UPLOAD_CHUNK_SIZE)
            if not chunk:
                break
            total_bytes += len(chunk)
            if max_bytes and total_bytes > max_bytes:
                raise HTTPException(
                    status_code=413,
                    detail=f"File troppo grande ({total_bytes / 1_048_576:.1f} MB). Limite configurato: {UPLOAD_MAX_MB} MB.",
                )
            tmp_file.write(chunk)

        tmp_file.flush()
        tmp_file.close()

        if total_bytes == 0:
            raise HTTPException(status_code=400, detail="The file is empty.")

        logger.info(
            "Starting analysis: %s (%d byte, %.2f MB)",
            filename, total_bytes, total_bytes / 1_048_576
        )

        # Delega l'analysis CPU-bound a un thread per non bloccare l'event loop
        # FastAPI mentre altri endpoint servono requests leggere o progress UI.
        result = await run_in_threadpool(analyze_pcap, tmp_file.name, filename)

        logger.info(
            "Analysis completed: %d packets, %.3f s capture",
            result.summary.total_packets,
            result.summary.duration_seconds,
        )
        return result

    except HTTPException:
        raise

    except ValueError as exc:
        # Errori noti: file corrotto, nessun packet, format non valido
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    except Exception as exc:
        # Errori imprevisti: logga il traceback completo per il debugging
        logger.exception("Error imprevisto durante l'analysis di '%s'", filename)
        raise HTTPException(
            status_code=500,
            detail="Internal server error. Check logs for details.",
        ) from exc

    finally:
        # Elimina sempre il file temporaneo per non lasciare data sul server
        try:
            tmp_file.close()
        except OSError:
            pass
        try:
            os.unlink(tmp_file.name)
        except OSError:
            pass
