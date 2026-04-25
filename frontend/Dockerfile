# ─── Stage 1: Build dell'app React ────────────────────────────────────────────
# Usa Node 20 Alpine (immagine molto leggera) per compilare il frontend.
FROM node:20-alpine AS builder

WORKDIR /app

# Copia prima solo i file di manifest per sfruttare la cache dei layer:
# se solo il codice cambia (ma non le dipendenze), npm install non viene rieseguito.
COPY package.json ./

# Installa le dipendenze. Usiamo npm install (non npm ci) perché non è
# presente un package-lock.json pre-generato nel repository.
RUN npm install

# Copia il resto del codice sorgente
COPY . .

# Genera la build di produzione ottimizzata nella cartella /app/dist
RUN npm run build


# ─── Stage 2: Serve con Nginx ─────────────────────────────────────────────────
# L'immagine finale contiene solo Nginx e i file statici compilati,
# non Node.js né il codice sorgente → immagine molto più piccola.
FROM nginx:1.27-alpine

# Copia i file statici dalla stage di build
COPY --from=builder /app/dist /usr/share/nginx/html

# Copia la configurazione Nginx personalizzata (proxy verso il backend)
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Porta HTTP standard
EXPOSE 80

# Nginx in foreground (Docker richiede che il processo principale non termini)
CMD ["nginx", "-g", "daemon off;"]
