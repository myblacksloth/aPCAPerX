- [Install AI model locally](#install-ai-model-locally)
- [Launch AI local model](#launch-ai-local-model)
- [Set environment](#set-environment)
- [Launch environment](#launch-environment)
- [Improve AI context handling](#improve-ai-context-handling)
- [Stop containers](#stop-containers)
- [Clean local system](#clean-local-system)


# Install AI model locally

```bash
ollama # start server
ollama pull deepseek-r1:32b # download model ~19gb
```

# Launch AI local model

```bash
# OLLAMA_HOST=0.0.0.0:11434 ollama run deepseek-r1:32b
OLLAMA_HOST=0.0.0.0:11434 ollama serve
```

# Set environment

- Upload to server

Set env file

```bash
cp .env.ialocal.example .env
```

then configure the system via .env file

# Launch environment

```bash
docker compose -f docker-compose-ialocal.yml up --build
```

# Improve AI context handling

If Ollama logs a warning like:

```text
truncating input prompt limit=8192 prompt=14870
```

the model context window is smaller than the prompt sent by the backend. In this
case Ollama truncates the prompt internally, which can hide packets or report
sections from the model.

The backend now prunes the technical evidence before calling Ollama. Tune these
values in `.env`:

```dotenv
PCAPCAPER_AI_NUM_CTX=8192
PCAPCAPER_AI_PROMPT_MAX_CHARS=12000
PCAPCAPER_AI_MAX_PACKETS=40
PCAPCAPER_AI_MAX_HISTORY_MESSAGES=8
```

Use a larger `PCAPCAPER_AI_NUM_CTX` only if the remote Ollama host has enough
RAM. Keep `PCAPCAPER_AI_PROMPT_MAX_CHARS` below the real model window; a useful
starting point is about `PCAPCAPER_AI_NUM_CTX * 1.5` characters.

For DNS questions such as "list IPs and related domains", the backend provides
a compact `dns.resolutions` context built from DNS queries, answers, CNAMEs and
flow correlations. This is more reliable than asking the model to infer DNS
mappings from individual packet summaries.

# Stop containers

```bash
docker compose down -v
```

# Clean local system

```bash
ollama ls
OLLAMA_MY_MODEL="deepseek-r1:32b"
ollama rm $OLLAMA_MY_MODELC
```

<!-- 

```bash
```

-->
