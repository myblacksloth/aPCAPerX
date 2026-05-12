# Local AI with Ollama on macOS

<!--
which ollama

-->

This guide explains how to use models installed on a local macOS machine with Ollama together with PCAPCaper.

Useful sources:

- Ollama macOS: <https://docs.ollama.com/macos>
- Ollama FAQ and environment variables: <https://docs.ollama.com/faq>
- Ollama model library: <https://ollama.com/library>

## Install Ollama

1. Download Ollama for macOS from <https://ollama.com/download>.
2. Open the `.dmg` file and drag `Ollama.app` into `Applications`.
3. Launch Ollama at least once. The app may create the `ollama` CLI command in `/usr/local/bin`.
4. Verify from the terminal:

```bash
ollama --version
ollama list
```

Official macOS requirements: macOS Sonoma 14 or later; Apple Silicon uses CPU/GPU, Intel Macs use CPU.

## Configure Ollama

### Make Ollama reachable via IP and port

By default Ollama listens on port `11434`. If you want it to be reachable from the app through the machine IP, configure `OLLAMA_HOST`.

If Ollama runs as a macOS app:

```bash
launchctl setenv OLLAMA_HOST "0.0.0.0:11434"
launchctl setenv OLLAMA_NUM_PARALLEL "1"
launchctl setenv OLLAMA_MAX_LOADED_MODELS "1"
```

Then close and reopen Ollama from the menu bar icon.

Verify:

```bash
curl http://127.0.0.1:11434/api/tags
```

Find the Mac IP address on the network:

```bash
ipconfig getifaddr en0
```

If you are connected through Ethernet and `en0` returns nothing:

```bash
ipconfig getifaddr en1
```

Example: if the Mac IP is `192.168.1.20`, the Ollama endpoint becomes:

```text
http://192.168.1.20:11434
```

### Download models

Default lightweight model:

```bash
ollama pull qwen2.5:0.5b
```

More powerful models:

```bash
ollama pull llama3.2:3b
ollama pull qwen3:8b
ollama pull qwen3:14b
ollama pull deepseek-r1:14b
ollama pull qwen3:30b
ollama pull llama3.3:70b
```

You can test them like this:

```bash
ollama run qwen3:8b
```

### Model selection based on available RAM

The sizes are those published in the Ollama library and do not include all runtime overhead. Always leave free RAM for macOS, Docker, browsers, and backend services. Larger contexts increase memory usage.

| Mac RAM | Recommended model | Approximate download size | Recommended app config | Notes |
|---:|---|---:|---|---|
| 4 GB | `qwen2.5:0.5b` or `qwen3:0.6b` | about 0.5 GB | `PCAPCAPER_AI_NUM_CTX=2048`, `PCAPCAPER_AI_NUM_PREDICT=384` | Minimum choice for short technical chat. |
| 8 GB | `llama3.2:3b` or `qwen3:4b` | about 2.0-2.5 GB | `PCAPCAPER_AI_NUM_CTX=4096`, `PCAPCAPER_AI_NUM_PREDICT=512` | Good compromise for small/medium PCAPs. |
| 16 GB | `qwen3:8b` or `deepseek-r1:8b` | about 5.2 GB | `PCAPCAPER_AI_NUM_CTX=8192`, `PCAPCAPER_AI_NUM_PREDICT=768` | Better responses, still manageable latency on Apple Silicon. |
| 24 GB | `qwen3:14b` or `deepseek-r1:14b` | about 9.0-9.3 GB | `PCAPCAPER_AI_NUM_CTX=8192`, `PCAPCAPER_AI_NUM_PREDICT=1024` | Better reasoning, requires more patience. |
| 32 GB | `qwen3:30b` or `deepseek-r1:32b` | about 19-20 GB | `PCAPCAPER_AI_NUM_CTX=8192`, `PCAPCAPER_AI_NUM_PREDICT=1024` | Suitable for powerful Macs; avoid other heavy apps. |
| 64 GB or more | `llama3.3:70b` or `deepseek-r1:70b` | about 43 GB | `PCAPCAPER_AI_NUM_CTX=8192`, `PCAPCAPER_AI_NUM_PREDICT=1024` | High quality, slower startup and responses. |

For this app, 8B to 14B models are often the best balance: strong enough for technical analysis without making the UI too slow.

## Use Ollama with this app

Copy the configuration:

```bash
cp .env.example .env
```

Open `.env` and set the mode to `host`.

If the backend runs inside Docker on macOS, use `host.docker.internal`:

```dotenv
PCAPCAPER_AI_ENABLED=1
PCAPCAPER_AI_OLLAMA_MODE=host
PCAPCAPER_AI_OLLAMA_HOST=host.docker.internal
PCAPCAPER_AI_OLLAMA_PORT=11434
PCAPCAPER_AI_MODEL=qwen3:8b
PCAPCAPER_AI_NUM_CTX=8192
PCAPCAPER_AI_NUM_PREDICT=768
```

If you want to explicitly use the Mac LAN IP:

```dotenv
PCAPCAPER_AI_ENABLED=1
PCAPCAPER_AI_OLLAMA_MODE=host
PCAPCAPER_AI_OLLAMA_HOST=192.168.1.20
PCAPCAPER_AI_OLLAMA_PORT=11434
PCAPCAPER_AI_MODEL=qwen3:8b
```

If the backend runs directly on the same Mac, you can use:

```dotenv
PCAPCAPER_AI_ENABLED=1
PCAPCAPER_AI_OLLAMA_MODE=host
PCAPCAPER_AI_OLLAMA_HOST=127.0.0.1
PCAPCAPER_AI_OLLAMA_PORT=11434
PCAPCAPER_AI_MODEL=qwen3:8b
```

`PCAPCAPER_AI_BASE_URL` is a complete override. Use it only if you want to bypass `PCAPCAPER_AI_OLLAMA_MODE`, `PCAPCAPER_AI_OLLAMA_HOST`, and `PCAPCAPER_AI_OLLAMA_PORT`:

```dotenv
PCAPCAPER_AI_BASE_URL=http://192.168.1.20:11434
```

Start the app:

```bash
docker compose up --build
```

Open:

```text
http://localhost:3000
```

Upload a PCAP and use the AI chat. The backend sends Ollama only compact technical evidence: it does not send raw packet bytes nor full Scapy layer dumps.

## Shut down the Ollama server

If you use the macOS app:

1. Click the Ollama icon in the menu bar.
2. Select `Quit Ollama`.

From the terminal you can verify the port is closed:

```bash
curl http://127.0.0.1:11434/api/tags
```

If you started Ollama manually with `ollama serve`, stop it with `Ctrl+C` in the terminal where it is running.

If you use the Ollama container included in the project:

```bash
docker compose stop ai
```

## Clean up the local system

### Shut down Ollama

First close Ollama from the menu bar or stop the `ollama serve` process.

To remove the launchctl variables configured in this guide:

```bash
launchctl unsetenv OLLAMA_HOST
launchctl unsetenv OLLAMA_NUM_PARALLEL
launchctl unsetenv OLLAMA_MAX_LOADED_MODELS
```

Then restart Ollama if you want to apply a clean configuration.

### Delete downloaded models

List models:

```bash
ollama list
```

Delete a specific model:

```bash
ollama rm qwen3:8b
```

Repeat for each installed model. On macOS the models are located in:

```text
~/.ollama/models
```

If you want to delete all models and the local Ollama configuration:

```bash
rm -rf ~/.ollama
```

### Delete macOS cache and leftovers

The Ollama macOS documentation indicates these paths for a complete removal:

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

If you used the project Docker service, also remove the Compose project volumes:

```bash
docker compose down -v
```

If you want to verify any remaining Ollama volumes:

```bash
docker volume ls | grep ollama
```

# Useful commands

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

# Startup to serve on every host

```bash
OLLAMA_HOST=0.0.0.0:11434 ollama serve
```
