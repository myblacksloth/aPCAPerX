"""
Entry point dell'API REST — PCAPCaper Backend.

Espone cinque endpoint:
  GET  /api/health   → verifica che il servizio sia attivo
  POST /api/analyze  → riceve un file PCAP, salva e restituisce l'analisi completa
  GET  /api/analyses → elenca analisi salvate
  GET  /api/analyses/{analysis_id} → ricarica un'analisi salvata
  POST /api/enrich-ips → arricchisce IP pubblici tramite servizi esterni
  POST /api/security-analysis → esegue threat intelligence opt-in sul traffico
  POST /api/dns-reputation → confronta domini DNS con liste esterne opt-in

Il file ricevuto viene scritto in una directory temporanea del sistema operativo,
analizzato, e poi cancellato. Il report JSON risultante può persistere sul server
in una directory configurabile.
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
    AIChatRequest,
    AIChatResponse,
    StoredAnalysisSummary,
)
from analyzer import analyze_pcap
from external_enrichment import enrich_ips
from security_analysis import analyze_security
from dns_intelligence import analyze_dns_reputation
from ai_chat import AIModelError, ask_ai
from analysis_storage import list_analyses, load_analysis, save_analysis, update_analysis
from config import AI_ENABLED, ANALYSIS_STORAGE_ENABLED, TEMP_DIR, UPLOAD_CHUNK_SIZE, UPLOAD_MAX_MB

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
    allow_methods=["POST", "GET", "PUT", "OPTIONS"],
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


# ─── Endpoint: analisi di sicurezza avanzata ───────────────────────────────

@app.post(
    "/api/security-analysis",
    response_model=SecurityAnalysisResponse,
    tags=["Analisi"],
    summary="Analizza il traffico con motore Security e threat intelligence",
    response_description="Finding, score e raccomandazioni di sicurezza",
)
def security_analysis_endpoint(payload: SecurityAnalysisRequest):
    """
    Riceve i pacchetti gia estratti dal PCAP e le informazioni IP arricchite.

    Nota privacy: questo endpoint puo interrogare fonti esterne di threat
    intelligence per gli IP pubblici osservati. Il frontend lo chiama solo dopo
    conferma esplicita dell'utente nel popup della tab Security avanzata.
    """
    try:
        logger.info(
            "Avvio analisi di sicurezza avanzata su %d pacchetti",
            len(payload.packets),
        )
        result = analyze_security(payload)
        logger.info(
            "Analisi Security completata: %d finding, %d IP pubblici",
            result.summary.total_findings,
            result.summary.analyzed_public_ips,
        )
        return result
    except Exception as exc:
        # L'errore viene loggato per distinguere problemi di rete da bug del motore.
        logger.exception("Errore imprevisto durante l'analisi Security")
        raise HTTPException(
            status_code=500,
            detail="Errore durante l'analisi di sicurezza avanzata.",
        ) from exc


# ─── Endpoint: reputazione DNS esterna ─────────────────────────────────────

@app.post(
    "/api/dns-reputation",
    response_model=DNSReputationResponse,
    tags=["Analisi"],
    summary="Controlla domini DNS osservati su liste esterne",
    response_description="Reputazione dominio -> fonti e categorie",
)
def dns_reputation_endpoint(payload: DNSReputationRequest):
    """
    Confronta i domini richiesti via DNS con liste esterne aperte.

    Nota privacy: l'endpoint viene chiamato solo dopo conferma esplicita
    dell'utente nella tab DNS. Il backend riceve domini gia estratti dal PCAP
    e non effettua alcun controllo esterno durante la normale analisi.
    """
    try:
        logger.info("Avvio reputazione DNS per %d domini", len(payload.domains))
        result = analyze_dns_reputation(payload.domains, payload.max_domains)
        logger.info("Reputazione DNS completata per %d domini", len(result.results))
        return result
    except Exception as exc:
        # Log completo per distinguere problemi di download liste da errori applicativi.
        logger.exception("Errore imprevisto durante la reputazione DNS")
        raise HTTPException(
            status_code=500,
            detail="Errore durante l'analisi reputazionale DNS.",
        ) from exc


# ─── Endpoint: lightweight technical AI assistant ─────────────────────────

@app.post(
    "/api/ai-chat",
    response_model=AIChatResponse,
    tags=["AI"],
    summary="Ask the technical AI assistant about the analyzed PCAP",
    response_description="AI answer plus packet and technical-context metadata",
)
async def ai_chat_endpoint(payload: AIChatRequest):
    """
    Answers a user question using a small model running in a separate container.

    The backend receives a sanitized analysis snapshot, builds technical
    evidence from the full report, and sends only that bounded evidence to the
    model. Raw bytes and full packet layer dumps are never forwarded.
    """
    if not AI_ENABLED:
        raise HTTPException(status_code=503, detail="AI assistant is disabled by configuration.")
    if not payload.question.strip():
        raise HTTPException(status_code=400, detail="Question cannot be empty.")

    try:
        return await run_in_threadpool(ask_ai, payload)
    except TimeoutError as exc:
        raise HTTPException(
            status_code=504,
            detail="The AI model took too long to answer. The request was interrupted; try a narrower question.",
        ) from exc
    except AIModelError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Unexpected error while querying the AI assistant")
        raise HTTPException(
            status_code=502,
            detail="AI assistant is unavailable or returned an invalid response.",
        ) from exc


# ─── Endpoint: stored analysis reports ─────────────────────────────────────

@app.get(
    "/api/analyses",
    response_model=list[StoredAnalysisSummary],
    tags=["Analisi"],
    summary="List saved analysis reports",
    response_description="Saved report metadata ordered from newest to oldest",
)
def list_saved_analyses_endpoint():
    """Return lightweight metadata for reports persisted on the backend."""
    return list_analyses()


@app.get(
    "/api/analyses/{analysis_id}",
    response_model=AnalysisResult,
    tags=["Analisi"],
    summary="Load a saved analysis report",
    response_description="Full persisted analysis report",
)
def load_saved_analysis_endpoint(analysis_id: str):
    """Load one persisted analysis report by its server-side identifier."""
    result = load_analysis(analysis_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Analysis report not found.")
    return result


@app.put(
    "/api/analyses/{analysis_id}",
    response_model=AnalysisResult,
    tags=["Analisi"],
    summary="Update a saved analysis report",
    response_description="Updated persisted analysis report",
)
def update_saved_analysis_endpoint(analysis_id: str, payload: AnalysisResult):
    """Persist frontend-side report enrichments, such as external IP data."""
    result = update_analysis(analysis_id, payload)
    if result is None:
        raise HTTPException(status_code=404, detail="Analysis report not found.")
    return result


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

    Il file viene copiato su disco temporaneo in streaming per non tenerlo in RAM.
    Se `PCAPCAPER_UPLOAD_MAX_MB=0` non viene applicato alcun limite applicativo.
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

    # ── Lettura streaming e controllo dimensione opzionale ────────────────
    logger.info("File ricevuto: %s", filename)
    os.makedirs(TEMP_DIR, exist_ok=True)
    max_bytes = UPLOAD_MAX_MB * 1_048_576 if UPLOAD_MAX_MB > 0 else 0
    total_bytes = 0

    # Il file temporaneo viene eliminato nel blocco `finally`, anche in caso di
    # errore. Usiamo dir configurabile per Docker/produzione.
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
            raise HTTPException(status_code=400, detail="Il file è vuoto.")

        logger.info(
            "Avvio analisi: %s (%d byte, %.2f MB)",
            filename, total_bytes, total_bytes / 1_048_576
        )

        # Delega l'analisi CPU-bound a un thread per non bloccare l'event loop
        # FastAPI mentre altri endpoint servono richieste leggere o progress UI.
        result = await run_in_threadpool(analyze_pcap, tmp_file.name, filename)
        result = await run_in_threadpool(save_analysis, result, total_bytes)

        logger.info(
            "Analisi completata: %d pacchetti, %.3f s di cattura, storage=%s",
            result.summary.total_packets,
            result.summary.duration_seconds,
            "enabled" if ANALYSIS_STORAGE_ENABLED else "disabled",
        )
        return result

    except HTTPException:
        raise

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
            tmp_file.close()
        except OSError:
            pass
        try:
            os.unlink(tmp_file.name)
        except OSError:
            pass
