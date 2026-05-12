# Local AI with Ollama on macOS

<!--
which ollama

-->

Questa guida spiega come usare i modelli installati su Ollama nella macchina macOS locale con PCAPCaper.

Fonti utili:

- Ollama macOS: <https://docs.ollama.com/macos>
- Ollama FAQ e variabili ambiente: <https://docs.ollama.com/faq>
- Libreria modelli Ollama: <https://ollama.com/library>

## Installare Ollama

1. Scarica Ollama per macOS da <https://ollama.com/download>.
2. Apri il file `.dmg` e trascina `Ollama.app` in `Applications`.
3. Avvia Ollama almeno una volta. L'app può creare il comando CLI `ollama` in `/usr/local/bin`.
4. Verifica dal terminale:

```bash
ollama --version
ollama list
```

Requisiti ufficiali macOS: macOS Sonoma 14 o superiore; Apple Silicon usa CPU/GPU, Mac x86 usa CPU.

## Configurare Ollama

### Rendere Ollama raggiungibile via IP e porta

Per default Ollama ascolta sulla porta `11434`. Se vuoi che sia raggiungibile dall'app via IP della macchina, configura `OLLAMA_HOST`.

Se Ollama gira come app macOS:

```bash
launchctl setenv OLLAMA_HOST "0.0.0.0:11434"
launchctl setenv OLLAMA_NUM_PARALLEL "1"
launchctl setenv OLLAMA_MAX_LOADED_MODELS "1"
```

Poi chiudi e riapri Ollama dall'icona nella menu bar.

Verifica:

```bash
curl http://127.0.0.1:11434/api/tags
```

Trova l'IP del Mac sulla rete:

```bash
ipconfig getifaddr en0
```

Se sei collegato via Ethernet e `en0` non restituisce nulla:

```bash
ipconfig getifaddr en1
```

Esempio: se l'IP del Mac e' `192.168.1.20`, l'endpoint Ollama diventa:

```text
http://192.168.1.20:11434
```

### Scaricare modelli

Modello leggero predefinito:

```bash
ollama pull qwen2.5:0.5b
```

Modelli piu' potenti:

```bash
ollama pull llama3.2:3b
ollama pull qwen3:8b
ollama pull qwen3:14b
ollama pull deepseek-r1:14b
ollama pull qwen3:30b
ollama pull llama3.3:70b
```

Puoi testarli così:

```bash
ollama run qwen3:8b
```

### Scelta modello per RAM disponibile

Le dimensioni sono quelle pubblicate nella libreria Ollama e non includono tutto l'overhead runtime. Lascia sempre RAM libera per macOS, Docker, browser e backend. Contesti piu' grandi aumentano il consumo memoria.

| RAM Mac | Modello consigliato | Dimensione download indicativa | Config app consigliata | Note |
|---:|---|---:|---|---|
| 4 GB | `qwen2.5:0.5b` o `qwen3:0.6b` | circa 0.5 GB | `PCAPCAPER_AI_NUM_CTX=2048`, `PCAPCAPER_AI_NUM_PREDICT=384` | Scelta minima per chat tecnica breve. |
| 8 GB | `llama3.2:3b` o `qwen3:4b` | circa 2.0-2.5 GB | `PCAPCAPER_AI_NUM_CTX=4096`, `PCAPCAPER_AI_NUM_PREDICT=512` | Buon compromesso per PCAP piccoli/medi. |
| 16 GB | `qwen3:8b` o `deepseek-r1:8b` | circa 5.2 GB | `PCAPCAPER_AI_NUM_CTX=8192`, `PCAPCAPER_AI_NUM_PREDICT=768` | Risposte migliori, latenza ancora gestibile su Apple Silicon. |
| 24 GB | `qwen3:14b` o `deepseek-r1:14b` | circa 9.0-9.3 GB | `PCAPCAPER_AI_NUM_CTX=8192`, `PCAPCAPER_AI_NUM_PREDICT=1024` | Migliore ragionamento, richiede piu' pazienza. |
| 32 GB | `qwen3:30b` o `deepseek-r1:32b` | circa 19-20 GB | `PCAPCAPER_AI_NUM_CTX=8192`, `PCAPCAPER_AI_NUM_PREDICT=1024` | Adatto a Mac potenti; evita altre app pesanti. |
| 64 GB o piu' | `llama3.3:70b` o `deepseek-r1:70b` | circa 43 GB | `PCAPCAPER_AI_NUM_CTX=8192`, `PCAPCAPER_AI_NUM_PREDICT=1024` | Qualita' alta, avvio e risposte piu' lenti. |

Per questa app, i modelli da 8B a 14B sono spesso il punto migliore: abbastanza forti per analisi tecniche, senza rendere la UI troppo lenta.

## Usare Ollama con questa app

Copia la configurazione:

```bash
cp .env.example .env
```

Apri `.env` e imposta la modalità `host`.

Se il backend gira dentro Docker su macOS, usa `host.docker.internal`:

```dotenv
PCAPCAPER_AI_ENABLED=1
PCAPCAPER_AI_OLLAMA_MODE=host
PCAPCAPER_AI_OLLAMA_HOST=host.docker.internal
PCAPCAPER_AI_OLLAMA_PORT=11434
PCAPCAPER_AI_MODEL=qwen3:8b
PCAPCAPER_AI_NUM_CTX=8192
PCAPCAPER_AI_NUM_PREDICT=768
```

Se vuoi usare esplicitamente l'IP LAN del Mac:

```dotenv
PCAPCAPER_AI_ENABLED=1
PCAPCAPER_AI_OLLAMA_MODE=host
PCAPCAPER_AI_OLLAMA_HOST=192.168.1.20
PCAPCAPER_AI_OLLAMA_PORT=11434
PCAPCAPER_AI_MODEL=qwen3:8b
```

Se il backend gira direttamente sullo stesso Mac, puoi usare:

```dotenv
PCAPCAPER_AI_ENABLED=1
PCAPCAPER_AI_OLLAMA_MODE=host
PCAPCAPER_AI_OLLAMA_HOST=127.0.0.1
PCAPCAPER_AI_OLLAMA_PORT=11434
PCAPCAPER_AI_MODEL=qwen3:8b
```

`PCAPCAPER_AI_BASE_URL` e' un override completo. Usalo solo se vuoi bypassare `PCAPCAPER_AI_OLLAMA_MODE`, `PCAPCAPER_AI_OLLAMA_HOST` e `PCAPCAPER_AI_OLLAMA_PORT`:

```dotenv
PCAPCAPER_AI_BASE_URL=http://192.168.1.20:11434
```

Avvia l'app:

```bash
docker compose up --build
```

Apri:

```text
http://localhost:3000
```

Carica un PCAP e usa la chat AI. Il backend invia a Ollama solo evidenze tecniche compatte: non invia raw bytes dei pacchetti ne' dump completi dei layer Scapy.

## Spegnere il server Ollama

Se usi l'app macOS:

1. Clicca l'icona Ollama nella menu bar.
2. Seleziona `Quit Ollama`.

Da terminale puoi verificare che la porta sia chiusa:

```bash
curl http://127.0.0.1:11434/api/tags
```

Se avevi avviato Ollama manualmente con `ollama serve`, interrompilo con `Ctrl+C` nel terminale in cui gira.

Se usi l'Ollama container incluso nel progetto:

```bash
docker compose stop ai
```

## Pulire il sistema locale

### Spegnere Ollama

Chiudi prima Ollama dalla menu bar oppure ferma il processo `ollama serve`.

Per rimuovere le variabili launchctl impostate in questa guida:

```bash
launchctl unsetenv OLLAMA_HOST
launchctl unsetenv OLLAMA_NUM_PARALLEL
launchctl unsetenv OLLAMA_MAX_LOADED_MODELS
```

Poi riavvia Ollama se vuoi applicare una configurazione pulita.

### Eliminare i modelli scaricati

Lista modelli:

```bash
ollama list
```

Elimina un modello specifico:

```bash
ollama rm qwen3:8b
```

Ripeti per ogni modello installato. Su macOS i modelli sono in:

```text
~/.ollama/models
```

Se vuoi eliminare tutti i modelli e la configurazione Ollama locale:

```bash
rm -rf ~/.ollama
```

### Eliminare cache e residui macOS

La documentazione Ollama per macOS indica questi percorsi per una rimozione completa:

```bash
sudo rm -rf /Applications/Ollama.app
sudo rm -f /usr/local/bin/ollama
rm -rf "$HOME/Library/Application Support/Ollama"
rm -rf "$HOME/Library/Saved Application State/com.electron.ollama.savedState"
rm -rf "$HOME/Library/Caches/com.electron.ollama"
rm -rf "$HOME/Library/Caches/ollama"
rm -rf "$HOME/Library/WebKit/com.electron.ollama"
rm -rf "$HOME/.ollama"
```

Se hai usato il servizio Docker del progetto, rimuovi anche i volumi del Compose project:

```bash
docker compose down -v
```

Se vuoi verificare eventuali volumi Ollama rimasti:

```bash
docker volume ls | grep ollama
```

# Comandi utili

```bash
brew services list
curl http://localhost:11434/api/tags
lsof -i :11434
ls ~/Library/LaunchAgents | grep -i ollama

ls /Library/LaunchAgents | grep -i ollama
ls /Library/LaunchDaemons | grep -i ollama

launchctl list | grep -i ollama

ps aux | grep '[o]llama'
kill PID

pkill ollama
```

# Avvio per servire su ogni host

```bash
OLLAMA_HOST=0.0.0.0:11434 ollama serve
```
